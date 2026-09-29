//! The browser side of the hub: invite, login, launcher and app hosts.
//!
//! Hosts are flat, one level below `DOMAIN` (see Hostnames in the plan):
//!
//! - `<owner>.<domain>` is the login host. It serves the invite page, the
//!   passkey login and a dashboard with one launch button per app. Its
//!   cookie is `__Host-sp_session`, the user and the web session ID.
//! - `<app>-<owner>.<domain>` is an app host. A launch creates an app
//!   session and redirects to `/x-teleport-auth` on the app host with the
//!   session ID and its bearer token in the URL fragment. The page there
//!   posts them back and the hub sets `__Host-sp_app` and
//!   `__Host-sp_subject`. Every other request is checked with
//!   `GetAppSession` and forwarded to the app service over the tunnel.
//!
//! Every `POST` must have an `Origin` equal to its own host.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use worker::*;

use crate::app::TunnelSlot;
use crate::authpipe::Pool;
use crate::authrpc::{self, *};

const SESSION_COOKIE: &str = "__Host-sp_session";
const APP_COOKIE: &str = "__Host-sp_app";
const SUBJECT_COOKIE: &str = "__Host-sp_subject";
const AUTH_PATH: &str = "/x-teleport-auth";

/// What the hub needs to answer a browser request.
pub struct Ctx<'a> {
    pub env: &'a Env,
    pub pool: &'a Pool,
    pub auth: &'a HubAuth,
    pub tunnel: &'a TunnelSlot,
}

/// The kind of host a request is for.
pub enum Host {
    Login,
    App(String),
}

/// Returns the host kind for `host`, or None if the hub does not serve it.
/// App names match `^[a-z][a-z0-9]*$`, so `<app>-<owner>` splits once.
pub fn classify(env: &Env, host: &str) -> Option<Host> {
    let (owner, domain) = owner_domain(env)?;
    let label = host.strip_suffix(&format!(".{domain}"))?;
    if label == owner {
        return Some(Host::Login);
    }
    let app = label.strip_suffix(&format!("-{owner}"))?;
    valid_name(app).then(|| Host::App(app.to_string()))
}

fn owner_domain(env: &Env) -> Option<(String, String)> {
    Some((env.var("OWNER").ok()?.to_string(), env.var("DOMAIN").ok()?.to_string()))
}

/// Returns true when `name` matches `^[a-z][a-z0-9]*$` and is at most 30
/// bytes.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty() && b.len() <= 30 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn login_host(env: &Env) -> Result<String> {
    let (owner, domain) = owner_domain(env).ok_or_else(|| Error::RustError("OWNER and DOMAIN must be set".into()))?;
    Ok(format!("{owner}.{domain}"))
}

/// Answers a request for the login host.
pub async fn login_host_request(mut req: Request, cx: &Ctx<'_>) -> Result<Response> {
    let host = login_host(cx.env)?;
    let path = req.path();
    if req.method() == Method::Post && !same_origin(&req, &host)? {
        return Response::error("bad origin", 403);
    }
    let res = match (req.method(), path.as_str()) {
        (Method::Get, "/") => return dashboard(&req, cx).await,
        (Method::Get, "/web/login") => return Response::from_html(LOGIN_PAGE),
        (Method::Post, "/webapi/login/begin") => login_begin(cx).await,
        (Method::Post, "/webapi/login/finish") => {
            let body = req.bytes().await?;
            return login_finish(cx, body).await;
        }
        (Method::Post, "/web/logout") => {
            let mut res = redirect("/web/login")?;
            res.headers_mut().append("Set-Cookie", &expire_cookie(SESSION_COOKIE))?;
            return Ok(res);
        }
        (Method::Get, p) if p.starts_with("/web/invite/") => return Response::from_html(INVITE_PAGE),
        (Method::Post, p) if p.starts_with("/webapi/invite/") => {
            let rest = &p["/webapi/invite/".len()..];
            let Some((token, step)) = rest.split_once('/') else {
                return Response::error("not found", 404);
            };
            let token = token.to_string();
            match step {
                "begin" => invite_begin(cx, &token).await,
                "finish" => {
                    let body = req.bytes().await?;
                    return invite_finish(cx, &token, body).await;
                }
                _ => return Response::error("not found", 404),
            }
        }
        (Method::Post, p) if p.starts_with("/web/launch/") => return launch(&req, cx, &p["/web/launch/".len()..]).await,
        _ => return Response::error("not found", 404),
    };
    match res {
        Ok(v) => Response::from_json(&v),
        Err(err) => {
            console_error!("web: {err}");
            Response::error("request failed", 502)
        }
    }
}

/// Answers a request for an app host.
pub async fn app_host_request(mut req: Request, cx: &Ctx<'_>, app: &str) -> Result<Response> {
    let url = req.url()?;
    let host = url.host_str().unwrap_or_default().to_string();
    let path = req.path();
    if path == AUTH_PATH {
        return match req.method() {
            Method::Get => Response::from_html(HANDOFF_PAGE),
            Method::Post => {
                if !same_origin(&req, &host)? {
                    return Response::error("bad origin", 403);
                }
                let body: Value = req.json().await?;
                handoff(cx, &body).await
            }
            _ => Response::error("method not allowed", 405),
        };
    }
    if path == "/teleport-logout" {
        let mut res = redirect(&format!("https://{}/", login_host(cx.env)?))?;
        res.headers_mut().append("Set-Cookie", &expire_cookie(APP_COOKIE))?;
        res.headers_mut().append("Set-Cookie", &expire_cookie(SUBJECT_COOKIE))?;
        return Ok(res);
    }
    if path.starts_with("/x-teleport-dbsc") {
        return Response::error("not found", 404);
    }

    let to_login = || -> Result<Response> {
        let mut res = redirect(&format!("https://{}/", login_host(cx.env)?))?;
        res.headers_mut().append("Set-Cookie", &expire_cookie(APP_COOKIE))?;
        res.headers_mut().append("Set-Cookie", &expire_cookie(SUBJECT_COOKIE))?;
        Ok(res)
    };
    // Every `<app>-<owner>.<domain>` is the same site, so SameSite=Lax still
    // sends the app cookies on a POST from a sibling app host. Only this
    // host may send a request that can change state.
    if !matches!(req.method(), Method::Get | Method::Head | Method::Options) && !same_origin_fetch(&req, &host)? {
        return Response::error("bad origin", 403);
    }
    let (Some(sid), Some(subject)) = (cookie(&req, APP_COOKIE)?, cookie(&req, SUBJECT_COOKIE)?) else {
        return to_login();
    };
    // Auth is asked on every request, and any error denies.
    let got: std::result::Result<AppSessionResponse, String> = cx.auth.call(cx.env, cx.pool, GET_APP_SESSION, &GetAppSessionRequest { session_id: sid }).await;
    let spec = match got.map(|r| r.session.and_then(|s| s.spec)) {
        Ok(Some(spec)) if spec.unexpired() && ct_eq(spec.bearer_token.as_bytes(), subject.as_bytes()) => spec,
        Ok(_) => return to_login(),
        Err(err) => {
            console_error!("web: GetAppSession for {app}: {err}");
            return Response::error("auth unavailable", 503);
        }
    };
    let Some(tunnel) = cx.tunnel.lock().unwrap().clone() else {
        console_error!("web: {app}: app service offline, no tunnel");
        return Response::error("app service offline", 503);
    };
    let tls = Arc::new(crate::appproxy::tls_from_pem(cx.env, &spec.tls_cert, &spec.tls_priv)?);
    let cluster = cx.env.var("CLUSTER_NAME")?.to_string();
    crate::appproxy::forward(&tunnel, tls, &cluster, &host, req).await
}

/// Checks the handoff from the launcher and sets the app cookies.
async fn handoff(cx: &Ctx<'_>, body: &Value) -> Result<Response> {
    let sid = body["sid"].as_str().unwrap_or_default().to_string();
    let subject = body["subject"].as_str().unwrap_or_default().to_string();
    if sid.is_empty() || subject.is_empty() {
        return Response::error("bad handoff", 400);
    }
    let got: std::result::Result<AppSessionResponse, String> = cx.auth.call(cx.env, cx.pool, GET_APP_SESSION, &GetAppSessionRequest { session_id: sid.clone() }).await;
    match got.map(|r| r.session.and_then(|s| s.spec)) {
        Ok(Some(spec)) if spec.unexpired() && ct_eq(spec.bearer_token.as_bytes(), subject.as_bytes()) => {}
        Ok(_) => return Response::error("bad handoff", 403),
        Err(err) => {
            console_error!("web: handoff GetAppSession: {err}");
            return Response::error("auth unavailable", 503);
        }
    }
    let mut res = Response::empty()?.with_status(204);
    res.headers_mut().append("Set-Cookie", &set_cookie(APP_COOKIE, &sid))?;
    res.headers_mut().append("Set-Cookie", &set_cookie(SUBJECT_COOKIE, &subject))?;
    Ok(res)
}

/// Returns the logged-in user and web session ID, if the session cookie
/// names a web session that auth has and that has not expired.
async fn web_session(req: &Request, cx: &Ctx<'_>) -> Result<Option<(String, String, WebSessionSpecV2)>> {
    let Some(value) = cookie(req, SESSION_COOKIE)? else {
        return Ok(None);
    };
    let Some((user, sid)) = value.split_once(':') else {
        return Ok(None);
    };
    let got: std::result::Result<AppSessionResponse, String> = cx
        .auth
        .call(cx.env, cx.pool, GET_WEB_SESSION, &GetWebSessionRequest { user: user.to_string(), session_id: sid.to_string() })
        .await;
    match got.map(|r| r.session.and_then(|s| s.spec)) {
        Ok(Some(spec)) if spec.unexpired() => Ok(Some((user.to_string(), sid.to_string(), spec))),
        Ok(_) => Ok(None),
        Err(err) => {
            console_log!("web: GetWebSession: {err}");
            Ok(None)
        }
    }
}

async fn dashboard(req: &Request, cx: &Ctx<'_>) -> Result<Response> {
    let Some((user, _, _)) = web_session(req, cx).await? else {
        return redirect("/web/login");
    };
    let buttons: String = app_list(cx.env)?
        .iter()
        .map(|(a, _)| format!(r#"<form method="post" action="/web/launch/{a}"><button>{a}</button></form>"#))
        .collect();
    Response::from_html(format!(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">{STYLE}<title>sallyport</title>
<p>Logged in as {user}.</p>{buttons}<form method="post" action="/web/logout"><button>Log out</button></form>"#
    ))
}

/// Returns the dashboard apps from `APPS`, a comma-separated list of
/// `name` or `name:/start/path`. The start path is where a launch lands.
fn app_list(env: &Env) -> Result<Vec<(String, String)>> {
    Ok(env
        .var("APPS")?
        .to_string()
        .split(',')
        .filter_map(|e| {
            let (name, path) = e.trim().split_once(':').unwrap_or((e.trim(), "/"));
            let path_ok = path.starts_with('/') && !path.starts_with("//") && path.bytes().all(|b| b.is_ascii_graphic());
            (valid_name(name) && path_ok).then(|| (name.to_string(), path.to_string()))
        })
        .collect())
}

async fn launch(req: &Request, cx: &Ctx<'_>, app: &str) -> Result<Response> {
    let Some(start) = app_list(cx.env)?.into_iter().find(|(a, _)| a == app).map(|(_, p)| p) else {
        return Response::error("not found", 404);
    };
    let Some((user, _, spec)) = web_session(req, cx).await? else {
        return redirect("/web/login");
    };
    let (owner, domain) = owner_domain(cx.env).ok_or_else(|| Error::RustError("OWNER and DOMAIN must be set".into()))?;
    let public_addr = format!("{app}-{owner}.{domain}");
    let res = async {
        let key = if spec.tls_priv.is_empty() { &spec.priv_key } else { &spec.tls_priv };
        let tls = Arc::new(authrpc::tls_config_from_pem(cx.env, &spec.tls_cert, key).map_err(|e| e.to_string())?);
        let as_user = authrpc::connect(cx.pool.take().ok_or("no auth pipe stream")?, tls).await?;
        let created: AppSessionResponse = unary(
            &as_user,
            CREATE_APP_SESSION,
            &CreateAppSessionRequest {
                username: user.clone(),
                public_addr: public_addr.clone(),
                cluster_name: cx.env.var("CLUSTER_NAME").map_err(|e| e.to_string())?.to_string(),
                app_name: app.to_string(),
            },
        )
        .await?;
        let sid = created.session.and_then(|s| s.metadata).map(|m| m.name).ok_or("no app session name")?;
        let got: AppSessionResponse = cx.auth.call(cx.env, cx.pool, GET_APP_SESSION, &GetAppSessionRequest { session_id: sid.clone() }).await?;
        let bearer = got.session.and_then(|s| s.spec).map(|s| s.bearer_token).filter(|b| !b.is_empty()).ok_or("no bearer token")?;
        Ok::<_, String>((sid, bearer))
    }
    .await;
    match res {
        Ok((sid, bearer)) => {
            let mut res = Response::empty()?.with_status(303);
            res.headers_mut().set("Location", &format!("https://{public_addr}{AUTH_PATH}#{sid}.{bearer}.{}", b64(start.as_bytes())))?;
            res.headers_mut().set("Referrer-Policy", "no-referrer")?;
            Ok(res)
        }
        Err(err) => {
            console_error!("web: launch {app}: {err}");
            Response::error("launch failed", 502)
        }
    }
}

async fn login_begin(cx: &Ctx<'_>) -> std::result::Result<Value, String> {
    let chal: MfaAuthenticateChallenge = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            CREATE_AUTHENTICATE_CHALLENGE,
            &CreateAuthenticateChallengeRequest {
                passwordless: Some(Passwordless {}),
                challenge_extensions: Some(ChallengeExtensions { scope: SCOPE_PASSWORDLESS_LOGIN }),
            },
        )
        .await?;
    let o = chal.webauthn.and_then(|w| w.public_key).ok_or("no WebAuthn challenge")?;
    Ok(json!({
        "challenge": b64(&o.challenge),
        "rpId": o.rp_id,
        "timeout": o.timeout_ms,
        "userVerification": o.user_verification,
        "allowCredentials": o.allow_credentials.iter().map(|c| json!({"type": c.r#type, "id": b64(&c.id)})).collect::<Vec<_>>(),
    }))
}

async fn login_finish(cx: &Ctx<'_>, assertion: Vec<u8>) -> Result<Response> {
    let res = async {
        let assertion: Value = serde_json::from_slice(&assertion).map_err(|e| format!("assertion: {e}"))?;
        let tls = authrpc::tls_config(cx.env, "HUB_TLS_CERT", "HUB_TLS_KEY").map_err(|e| e.to_string())?;
        let body = json!({ "username": "", "webauthn": assertion }).to_string().into_bytes();
        let stream = cx.pool.take().ok_or("no auth pipe stream")?;
        let (status, body) = authrpc::post_json(stream, &tls, AUTHENTICATE_WEB_USER_PASSWORDLESS, body).await?;
        if status != 200 {
            return Err(format!("AuthenticateWebUser: http {status}: {}", String::from_utf8_lossy(&body)));
        }
        let web: Value = serde_json::from_slice(&body).map_err(|e| format!("web session: {e}"))?;
        let sid = web["metadata"]["name"].as_str().ok_or("no web session name")?.to_string();
        let user = web["spec"]["user"].as_str().ok_or("no web session user")?.to_string();
        Ok::<_, String>((user, sid))
    }
    .await;
    session_response(res)
}

async fn invite_begin(cx: &Ctx<'_>, token: &str) -> std::result::Result<Value, String> {
    let chal: MfaRegisterChallenge = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            CREATE_REGISTER_CHALLENGE,
            &CreateRegisterChallengeRequest {
                token_id: token.to_string(),
                device_type: DEVICE_TYPE_WEBAUTHN,
                device_usage: DEVICE_USAGE_PASSWORDLESS,
            },
        )
        .await?;
    let o = chal.webauthn.and_then(|w| w.public_key).ok_or("no WebAuthn creation options")?;
    let rp = o.rp.unwrap_or_default();
    let user = o.user.unwrap_or_default();
    let sel = o.authenticator_selection.unwrap_or_default();
    let mut selection = json!({
        "requireResidentKey": sel.require_resident_key,
        "residentKey": if sel.require_resident_key { "required" } else { "preferred" },
        "userVerification": sel.user_verification,
    });
    if !sel.authenticator_attachment.is_empty() {
        selection["authenticatorAttachment"] = json!(sel.authenticator_attachment);
    }
    Ok(json!({
        "challenge": b64(&o.challenge),
        "rp": { "id": rp.id, "name": rp.name },
        "user": { "id": b64(&user.id), "name": user.name, "displayName": user.display_name },
        "pubKeyCredParams": o.credential_parameters.iter().map(|p| json!({"type": p.r#type, "alg": p.alg})).collect::<Vec<_>>(),
        "timeout": o.timeout_ms,
        "excludeCredentials": o.exclude_credentials.iter().map(|c| json!({"type": c.r#type, "id": b64(&c.id)})).collect::<Vec<_>>(),
        "attestation": o.attestation,
        "authenticatorSelection": selection,
    }))
}

async fn invite_finish(cx: &Ctx<'_>, token: &str, body: Vec<u8>) -> Result<Response> {
    let res = async {
        let cred: Value = serde_json::from_slice(&body).map_err(|e| format!("credential: {e}"))?;
        let field = |v: &Value| -> std::result::Result<Vec<u8>, String> { URL_SAFE_NO_PAD.decode(v.as_str().unwrap_or_default()).map_err(|e| e.to_string()) };
        let resp = CredentialCreationResponse {
            r#type: cred["type"].as_str().unwrap_or("public-key").to_string(),
            raw_id: field(&cred["rawId"])?,
            response: Some(AttestationResponse {
                client_data_json: field(&cred["response"]["clientDataJSON"])?,
                attestation_object: field(&cred["response"]["attestationObject"])?,
            }),
        };
        let changed: ChangeUserAuthenticationResponse = cx
            .auth
            .call(
                cx.env,
                cx.pool,
                CHANGE_USER_AUTHENTICATION,
                &ChangeUserAuthenticationRequest {
                    token_id: token.to_string(),
                    new_mfa_register_response: Some(MfaRegisterResponse { webauthn: Some(resp) }),
                    new_device_name: "passkey".into(),
                },
            )
            .await?;
        let ws = changed.web_session.ok_or("no web session")?;
        let sid = ws.metadata.map(|m| m.name).ok_or("no web session name")?;
        let user = ws.spec.map(|s| s.user).ok_or("no web session user")?;
        Ok::<_, String>((user, sid))
    }
    .await;
    session_response(res)
}

/// Sets the session cookie for a new web session, or reports the failure.
fn session_response(res: std::result::Result<(String, String), String>) -> Result<Response> {
    match res {
        Ok((user, sid)) => {
            console_log!("web: web session for {user:?}");
            let mut res = Response::from_json(&json!({ "ok": true }))?;
            res.headers_mut().append("Set-Cookie", &set_cookie(SESSION_COOKIE, &format!("{user}:{sid}")))?;
            Ok(res)
        }
        Err(err) => {
            console_error!("web: {err}");
            Response::error("login failed", 401)
        }
    }
}

fn same_origin(req: &Request, host: &str) -> Result<bool> {
    Ok(req.headers().get("Origin")?.as_deref() == Some(format!("https://{host}").as_str()))
}

/// Returns false when the browser says the request came from another
/// origin. A request with neither `Sec-Fetch-Site` nor `Origin` is not from
/// a browser page and passes.
fn same_origin_fetch(req: &Request, host: &str) -> Result<bool> {
    if let Some(site) = req.headers().get("Sec-Fetch-Site")? {
        return Ok(site == "same-origin" || site == "none");
    }
    match req.headers().get("Origin")? {
        Some(origin) => Ok(origin == format!("https://{host}")),
        None => Ok(true),
    }
}

fn cookie(req: &Request, name: &str) -> Result<Option<String>> {
    let header = req.headers().get("Cookie")?.unwrap_or_default();
    Ok(header.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string()))
}

fn set_cookie(name: &str, value: &str) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax")
}

fn expire_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Returns a 303 to `location`. `Response::redirect` has immutable headers,
/// so it cannot also set cookies.
fn redirect(location: &str) -> Result<Response> {
    let mut res = Response::empty()?.with_status(303);
    res.headers_mut().set("Location", location)?;
    Ok(res)
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Compares two byte strings in time that depends only on their lengths.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Larger text and buttons, so they are easy to tap on a phone.
const STYLE: &str = "<style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style>";

const LOGIN_PAGE: &str = concat!(
    r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport login</title>
<button id="go">Log in with passkey</button><pre id="out"></pre><script>
"#,
    r#"const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
document.getElementById('go').onclick = async () => {
  try {
    const c = await post('/webapi/login/begin');
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: dec(c.challenge), rpId: c.rpId, timeout: c.timeout || undefined,
      userVerification: c.userVerification || 'required',
      allowCredentials: c.allowCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
    } });
    await post('/webapi/login/finish', {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type, extensions: cred.getClientExtensionResults(),
      response: {
        authenticatorData: enc(cred.response.authenticatorData), clientDataJSON: enc(cred.response.clientDataJSON),
        signature: enc(cred.response.signature), userHandle: cred.response.userHandle ? enc(cred.response.userHandle) : null,
      },
    });
    location.href = '/';
  } catch (e) { out.textContent = 'error: ' + e; }
};
</script>"#
);

const INVITE_PAGE: &str = r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport invite</title>
<button id="go">Register a passkey</button><pre id="out"></pre><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
const token = location.pathname.split('/').pop();
document.getElementById('go').onclick = async () => {
  try {
    const c = await post('/webapi/invite/' + token + '/begin');
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: dec(c.challenge), rp: c.rp,
      user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
      pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
      excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
      attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
    } });
    await post('/webapi/invite/' + token + '/finish', {
      type: cred.type, rawId: enc(cred.rawId),
      response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
    });
    location.href = '/';
  } catch (e) { out.textContent = 'error: ' + e; }
};
</script>"#;

const HANDOFF_PAGE: &str = r#"<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport</title>
<pre id="out">Signing in...</pre><script>
const [sid, subject, start] = location.hash.slice(1).split('.');
let path = '/';
try { const p = atob((start || '').replace(/-/g, '+').replace(/_/g, '/')); if (p.startsWith('/') && !p.startsWith('//') && !p.includes('\\')) path = p; } catch (e) {}
history.replaceState(null, '', location.pathname);
fetch(location.pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid, subject }) })
  .then(r => r.ok ? location.replace(path) : r.text().then(t => { document.getElementById('out').textContent = 'error: ' + r.status + ' ' + t; }));
</script>"#;
