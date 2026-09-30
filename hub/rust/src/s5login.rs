//! S5 only: a passwordless login through the hub, then an app session.
//! Off unless `DEV_S5` is "1".
//!
//! - `GET /spike/s5/login` is a page with one button.
//! - `POST /spike/s5/login/begin` asks auth for a passwordless challenge
//!   with the hub identity and returns it for `navigator.credentials.get`.
//! - `POST /spike/s5/login/finish` takes the browser's assertion and calls
//!   `AuthenticateWebUser` with the hub identity, then `GetWebSession` for
//!   the user's cert and key, then `CreateAppSession` with that cert and
//!   `GetAppSession` with the hub identity.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;
use worker::*;

use crate::authpipe::Pool;
use crate::authrpc::{self, *};

pub const LOGIN: &str = "/spike/s5/login";
pub const BEGIN: &str = "/spike/s5/login/begin";
pub const FINISH: &str = "/spike/s5/login/finish";

pub async fn handle(mut req: Request, env: &Env, pool: &Pool) -> Result<Response> {
    let enabled = env.var("DEV_S5").map(|v| v.to_string() == "1").unwrap_or(false);
    if !enabled {
        return Response::error("not found", 404);
    }
    let res = match (req.method(), req.path().as_str()) {
        (Method::Get, LOGIN) => return Response::from_html(PAGE),
        (Method::Post, BEGIN) => begin(env, pool).await,
        (Method::Post, FINISH) => {
            let body = req.bytes().await?;
            finish(env, pool, body).await
        }
        _ => return Response::error("not found", 404),
    };
    match res {
        Ok(v) => Response::from_json(&v),
        Err(err) => {
            console_error!("s5 login: {err}");
            Response::error(err, 502)
        }
    }
}

fn hub_tls(env: &Env) -> std::result::Result<Arc<rustls::ClientConfig>, String> {
    authrpc::tls_config(env, "HUB_TLS_CERT", "HUB_TLS_KEY")
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

async fn begin(env: &Env, pool: &Pool) -> std::result::Result<serde_json::Value, String> {
    let hub = authrpc::connect(pool.take().ok_or("no auth pipe stream")?, hub_tls(env)?).await?;
    let chal: MfaAuthenticateChallenge = unary(
        &hub,
        CREATE_AUTHENTICATE_CHALLENGE,
        &CreateAuthenticateChallengeRequest {
            passwordless: Some(Passwordless {}),
            challenge_extensions: Some(ChallengeExtensions { scope: SCOPE_PASSWORDLESS_LOGIN }),
        },
    )
    .await?;
    let opts = chal
        .webauthn
        .and_then(|w| w.public_key)
        .ok_or("no WebAuthn challenge from auth")?;
    console_log!("s5 login: challenge for rp {:?}", opts.rp_id);
    Ok(json!({
        "challenge": URL_SAFE_NO_PAD.encode(&opts.challenge),
        "rpId": opts.rp_id,
        "timeout": opts.timeout_ms,
        "userVerification": opts.user_verification,
        "allowCredentials": opts.allow_credentials.iter().map(|c| json!({
            "type": c.r#type,
            "id": URL_SAFE_NO_PAD.encode(&c.id),
        })).collect::<Vec<_>>(),
    }))
}

async fn finish(env: &Env, pool: &Pool, assertion: Vec<u8>) -> std::result::Result<serde_json::Value, String> {
    let assertion: serde_json::Value = serde_json::from_slice(&assertion).map_err(|e| format!("assertion: {e}"))?;
    let hub_tls = hub_tls(env)?;
    let body = json!({ "username": "", "webauthn": assertion }).to_string().into_bytes();
    let stream = pool.take().ok_or("no auth pipe stream")?;
    let (status, body) = authrpc::post_json(stream, &hub_tls, AUTHENTICATE_WEB_USER_PASSWORDLESS, body).await?;
    if status != 200 {
        return Err(format!("AuthenticateWebUser: http {status}: {}", String::from_utf8_lossy(&body)));
    }
    let web: serde_json::Value = serde_json::from_slice(&body).map_err(|e| format!("web session: {e}"))?;
    let web_id = web["metadata"]["name"].as_str().ok_or("web session has no name")?.to_string();
    let user = web["spec"]["user"].as_str().ok_or("web session has no user")?.to_string();
    console_log!("s5 login: web session for {user:?}");

    let hub = authrpc::connect(pool.take().ok_or("no auth pipe stream")?, hub_tls).await?;

    let got: AppSessionResponse = unary(&hub, GET_WEB_SESSION, &GetWebSessionRequest { user: user.clone(), session_id: web_id }).await?;
    let spec = got.session.and_then(|s| s.spec).ok_or("GetWebSession returned no spec")?;
    let key = if spec.tls_priv.is_empty() { spec.priv_key } else { spec.tls_priv };
    let user_tls = Arc::new(authrpc::tls_config_from_pem(env, &spec.tls_cert, &key).map_err(|e| e.to_string())?);

    let as_user = authrpc::connect(pool.take().ok_or("no second auth pipe stream")?, user_tls).await?;
    let created: AppSessionResponse = unary(
        &as_user,
        CREATE_APP_SESSION,
        &CreateAppSessionRequest {
            username: user.clone(),
            public_addr: env.var("S5_APP_HOST").map_err(|e| e.to_string())?.to_string(),
            cluster_name: env.var("CLUSTER_NAME").map_err(|e| e.to_string())?.to_string(),
            app_name: env.var("S5_APP_NAME").map_err(|e| e.to_string())?.to_string(),
        },
    )
    .await?;
    let app_id = created
        .session
        .and_then(|s| s.metadata)
        .map(|m| m.name)
        .ok_or("CreateAppSession returned no session name")?;
    let app: AppSessionResponse = unary(&hub, GET_APP_SESSION, &GetAppSessionRequest { session_id: app_id }).await?;
    let app = app.session.and_then(|s| s.spec).ok_or("GetAppSession returned no spec")?;
    console_log!("s5 login: app session for {:?}", app.user);

    Ok(json!({
        "web_session": { "user": user, "tls_cert_bytes": spec.tls_cert.len(), "has_key": !key.is_empty() },
        "app_session": { "user": app.user, "tls_cert_bytes": app.tls_cert.len(), "has_tls_private_key": !app.tls_priv.is_empty() },
    }))
}

const PAGE: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>sallyport S5 login</title>
<button id="go">Log in with passkey</button>
<pre id="out"></pre>
<script>
const out = document.getElementById('out');
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
document.getElementById('go').onclick = async () => {
  try {
    out.textContent = 'asking the hub for a challenge...';
    const r = await fetch('/spike/s5/login/begin', { method: 'POST' });
    if (!r.ok) throw new Error(r.status + ' ' + await r.text());
    const c = await r.json();
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: dec(c.challenge), rpId: c.rpId, timeout: c.timeout || undefined,
      userVerification: c.userVerification || 'required',
      allowCredentials: c.allowCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
    } });
    out.textContent = 'sending the assertion...';
    const body = {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type,
      extensions: cred.getClientExtensionResults(),
      response: {
        authenticatorData: enc(cred.response.authenticatorData),
        clientDataJSON: enc(cred.response.clientDataJSON),
        signature: enc(cred.response.signature),
        userHandle: cred.response.userHandle ? enc(cred.response.userHandle) : null,
      },
    };
    const f = await fetch('/spike/s5/login/finish', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    out.textContent = f.status + '\n' + await f.text();
  } catch (e) {
    out.textContent = 'error: ' + e;
  }
};
</script>
"#;
