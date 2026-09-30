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
use futures::StreamExt;
use serde::Deserialize;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use worker::*;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Tag, Tagged};
use x509_cert::name::Name;

use crate::app::TunnelSlot;
use crate::authpipe::Pool;
use crate::authrpc::{self, *};

const SESSION_COOKIE: &str = "__Host-sp_session";
const APP_COOKIE: &str = "__Host-sp_app";
const SUBJECT_COOKIE: &str = "__Host-sp_subject";
const AUTH_PATH: &str = "/x-teleport-auth";
/// The largest body the login host and the handoff read. A WebAuthn
/// assertion or attestation is a few KiB.
const MAX_BODY: usize = 64 * 1024;
/// The subject attribute in which Teleport's `tlsca` writes an app
/// session's public address, `AppPublicAddrASN1ExtensionOID`.
const APP_PUBLIC_ADDR_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.1.6");
/// How [`authrpc::unary`] reports gRPC status `RESOURCE_EXHAUSTED`, which
/// auth returns when a client address makes too many login or invite calls.
const RATE_LIMITED: &str = "grpc-status \"8\"";

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
            let Some(body) = read_body(&mut req).await? else {
                return Response::error("request too large", 413);
            };
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
                    let Some(body) = read_body(&mut req).await? else {
                        return Response::error("request too large", 413);
                    };
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
        Err(err) if err.contains(RATE_LIMITED) => {
            console_error!("web: {err}");
            Response::error("too many requests, try again in a minute", 429)
        }
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
                let Some(body) = read_body(&mut req).await? else {
                    return Response::error("request too large", 413);
                };
                let Some(h) = parse_handoff(&body) else {
                    return Response::error("bad handoff", 400);
                };
                handoff(cx, h, &host).await
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
    let spec = match valid_app_session(cx, &sid, &subject, &host).await {
        Ok(Some(spec)) => spec,
        Ok(None) => return to_login(),
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

/// The body the handoff page posts: the app session ID and its bearer
/// token.
#[derive(Deserialize)]
struct Handoff {
    sid: String,
    subject: String,
}

/// Returns the handoff in `body`, or None when it is not JSON or either
/// field is missing or empty.
fn parse_handoff(body: &[u8]) -> Option<Handoff> {
    serde_json::from_slice::<Handoff>(body).ok().filter(|h| !h.sid.is_empty() && !h.subject.is_empty())
}

/// Checks the handoff from the launcher for the app host `host` and sets
/// the app cookies.
async fn handoff(cx: &Ctx<'_>, Handoff { sid, subject }: Handoff, host: &str) -> Result<Response> {
    match valid_app_session(cx, &sid, &subject, host).await {
        Ok(Some(_)) => {}
        Ok(None) => return Response::error("bad handoff", 403),
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

/// Returns the app session `sid` from auth when it has not expired, its
/// bearer token is `subject`, and its certificate is for the app host
/// `host`. It returns Ok(None) when any of these checks fails, and an
/// error when auth cannot be asked.
async fn valid_app_session(cx: &Ctx<'_>, sid: &str, subject: &str, host: &str) -> std::result::Result<Option<WebSessionSpecV2>, String> {
    let got: std::result::Result<AppSessionResponse, _> = cx.auth.call(cx.env, cx.pool, GET_APP_SESSION, &GetAppSessionRequest { session_id: sid.to_string() }).await;
    let spec = got.map_err(|e| e.to_string())?.session.and_then(|s| s.spec);
    Ok(spec.filter(|spec| spec.unexpired() && ct_eq(spec.bearer_token.as_bytes(), subject.as_bytes()) && cert_public_addr(&spec.tls_cert).as_deref() == Some(host)))
}

/// Returns the app public address in the first certificate of `cert_pem`,
/// or None when there is none or the PEM or DER does not parse.
fn cert_public_addr(cert_pem: &[u8]) -> Option<String> {
    let der = CertificateDer::pem_slice_iter(cert_pem).next()?.ok()?;
    let cert = x509_cert::Certificate::from_der(&der).ok()?;
    name_public_addr(&cert.tbs_certificate.subject)
}

/// Returns the value of the [`APP_PUBLIC_ADDR_OID`] attribute in `name`.
/// Go's `encoding/asn1` writes a string as `PrintableString` when it can,
/// and as `UTF8String` otherwise.
fn name_public_addr(name: &Name) -> Option<String> {
    let atv = name.0.iter().flat_map(|rdn| rdn.0.iter()).find(|atv| atv.oid == APP_PUBLIC_ADDR_OID)?;
    matches!(atv.value.tag(), Tag::PrintableString | Tag::Utf8String | Tag::Ia5String).then(|| String::from_utf8(atv.value.value().to_vec()).ok())?
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
    let user = html_escape(&user);
    Response::from_html(format!(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">{STYLE}<title>sallyport</title>
<p>Logged in as {user}.</p>{buttons}<form method="post" action="/web/logout"><button>Log out</button></form>"#
    ))
}

/// Returns the dashboard apps from `APPS`, a comma-separated list of
/// `name` or `name:/start/path`. The start path is where a launch lands.
fn app_list(env: &Env) -> Result<Vec<(String, String)>> {
    Ok(parse_apps(&env.var("APPS")?.to_string()))
}

/// Parses an `APPS` value. It drops an entry whose name fails
/// [`valid_name`] or whose start path fails [`start_path_ok`].
fn parse_apps(apps: &str) -> Vec<(String, String)> {
    apps.split(',')
        .filter_map(|e| {
            let (name, path) = e.trim().split_once(':').unwrap_or((e.trim(), "/"));
            (valid_name(name) && start_path_ok(path)).then(|| (name.to_string(), path.to_string()))
        })
        .collect()
}

/// Returns true when `path` starts with one `/` and every byte is in 0x21
/// to 0x7e except `\`. The URL parser removes tab, CR and LF, and reads
/// `\` as `/`, so either could turn the path into `//host`.
/// `HANDOFF_PAGE` applies the same rule to the start path it is sent.
fn start_path_ok(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
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
        let as_user = authrpc::connect(cx.pool.take_wait().await?, tls).await?;
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
        let stream = cx.pool.take_wait().await?;
        let (status, body) = authrpc::post_json(stream, &tls, AUTHENTICATE_WEB_USER_PASSWORDLESS, body).await?;
        if status != 200 {
            return Err(format!("AuthenticateWebUser: http {status}: {}", String::from_utf8_lossy(&body)));
        }
        parse_web_session(&body)
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
        let resp = parse_credential(&body)?;
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

/// The parts of auth's `AuthenticateWebUser` JSON reply the hub reads.
#[derive(Deserialize)]
struct WebSessionJson {
    metadata: WebSessionMetadata,
    spec: WebSessionUser,
}

#[derive(Deserialize)]
struct WebSessionMetadata {
    name: String,
}

#[derive(Deserialize)]
struct WebSessionUser {
    user: String,
}

/// Returns the user and the web session ID from auth's
/// `AuthenticateWebUser` reply.
fn parse_web_session(body: &[u8]) -> std::result::Result<(String, String), String> {
    let web: WebSessionJson = serde_json::from_slice(body).map_err(|e| format!("web session: {e}"))?;
    if web.metadata.name.is_empty() || web.spec.user.is_empty() {
        return Err("web session has no name or user".into());
    }
    Ok((web.spec.user, web.metadata.name))
}

/// The credential the invite page posts, from `navigator.credentials.create`.
/// The byte fields are base64url without padding.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialJson {
    #[serde(default = "public_key")]
    r#type: String,
    raw_id: String,
    response: AttestationJson,
}

#[derive(Deserialize)]
struct AttestationJson {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

fn public_key() -> String {
    "public-key".into()
}

/// Returns the credential the invite page posted in `body`, decoded for
/// `ChangeUserAuthentication`.
fn parse_credential(body: &[u8]) -> std::result::Result<CredentialCreationResponse, String> {
    let cred: CredentialJson = serde_json::from_slice(body).map_err(|e| format!("credential: {e}"))?;
    let field = |name: &str, v: &str| URL_SAFE_NO_PAD.decode(v).map_err(|e| format!("credential {name}: {e}"));
    Ok(CredentialCreationResponse {
        r#type: cred.r#type,
        raw_id: field("rawId", &cred.raw_id)?,
        response: Some(AttestationResponse {
            client_data_json: field("clientDataJSON", &cred.response.client_data_json)?,
            attestation_object: field("attestationObject", &cred.response.attestation_object)?,
        }),
    })
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

/// Reads the body of `req`. It returns None, without reading the rest,
/// when the body is over [`MAX_BODY`].
async fn read_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    let length = req.headers().get("Content-Length")?;
    if length.and_then(|l| l.trim().parse::<usize>().ok()).is_some_and(|l| l > MAX_BODY) {
        return Ok(None);
    }
    if req.inner().body().is_none() {
        return Ok(Some(Vec::new()));
    }
    let mut stream = req.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BODY {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
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

/// Returns `s` with `&`, `<`, `>`, `"` and `'` written as HTML character
/// references.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
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
// The start path must pass the same rule as start_path_ok. The page then
// passes the resolved full URL to location.replace, because a path such as
// "/.//host" resolves to the path "//host".
try {
  const p = atob((start || '').replace(/-/g, '+').replace(/_/g, '/'));
  if (/^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/.test(p)) {
    const u = new URL(p, location.origin);
    if (u.origin === location.origin) path = u.href;
  }
} catch (e) {}
history.replaceState(null, '', location.pathname);
fetch(location.pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid, subject }) })
  .then(r => r.ok ? location.replace(path) : r.text().then(t => { document.getElementById('out').textContent = 'error: ' + r.status + ' ' + t; }));
</script>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_path_ok_cases() {
        for (path, want) in [
            ("/", true),
            ("/stream", true),
            ("/a?b=1#c", true),
            ("/%2F/x", true),
            ("", false),
            ("stream", false),
            ("//evil.example", false),
            ("/\t/evil.example", false),
            ("/\n/evil.example", false),
            ("/\r/evil.example", false),
            ("/\\evil.example", false),
            ("/ /x", false),
            ("/\u{e9}", false),
        ] {
            assert_eq!(start_path_ok(path), want, "{path:?}");
        }
    }

    #[test]
    fn parse_handoff_cases() {
        let h = parse_handoff(br#"{"sid":"s","subject":"t"}"#).unwrap();
        assert_eq!((h.sid.as_str(), h.subject.as_str()), ("s", "t"));
        for body in [&b""[..], b"not json", br#"{"sid":"s"}"#, br#"{"sid":"","subject":"t"}"#, br#"{"sid":"s","subject":""}"#, br#"{"sid":1,"subject":"t"}"#] {
            assert!(parse_handoff(body).is_none(), "{:?}", String::from_utf8_lossy(body));
        }
    }

    fn app_cert(attrs: &[(&[u64], rcgen::DnValue)]) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "alice");
        for (oid, value) in attrs {
            params.distinguished_name.push(rcgen::DnType::CustomDnType(oid.to_vec()), value.clone());
        }
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem().into_bytes()
    }

    #[test]
    fn cert_public_addr_cases() {
        let addr: &[u64] = &[1, 3, 9999, 1, 6];
        let name: &[u64] = &[1, 3, 9999, 1, 10];
        let utf8 = |v: &str| rcgen::DnValue::Utf8String(v.into());
        let printable = |v: &str| rcgen::DnValue::PrintableString(v.try_into().unwrap());
        let bmp = |v: &str| rcgen::DnValue::BmpString(v.try_into().unwrap());
        assert_eq!(cert_public_addr(&app_cert(&[(name, utf8("bench")), (addr, printable("bench-julia.example.com"))])).as_deref(), Some("bench-julia.example.com"));
        assert_eq!(cert_public_addr(&app_cert(&[(addr, utf8("bench-julia.example.com"))])).as_deref(), Some("bench-julia.example.com"));
        assert_eq!(cert_public_addr(&app_cert(&[(name, utf8("bench"))])), None);
        assert_eq!(cert_public_addr(&app_cert(&[(addr, bmp("bench-julia.example.com"))])), None);
        assert_eq!(cert_public_addr(b"not a pem"), None);
        assert_eq!(cert_public_addr(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), None);
    }

    #[test]
    fn html_escape_cases() {
        assert_eq!(html_escape("alice"), "alice");
        assert_eq!(html_escape(r#"<a href="x">'&'</a>"#), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
    }

    #[test]
    fn parse_web_session_cases() {
        assert_eq!(parse_web_session(br#"{"kind":"web_session","metadata":{"name":"s1"},"spec":{"user":"alice","pub":"x"}}"#), Ok(("alice".into(), "s1".into())));
        for body in [&b"null"[..], b"{}", br#"{"metadata":{"name":"s1"}}"#, br#"{"metadata":{"name":""},"spec":{"user":"alice"}}"#, br#"{"metadata":{"name":1},"spec":{"user":"alice"}}"#] {
            assert!(parse_web_session(body).is_err(), "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn parse_credential_cases() {
        let got = parse_credential(br#"{"rawId":"AQI","response":{"clientDataJSON":"Aw","attestationObject":"BAU"}}"#).unwrap();
        assert_eq!(got.r#type, "public-key");
        assert_eq!(got.raw_id, vec![1, 2]);
        let att = got.response.unwrap();
        assert_eq!((att.client_data_json, att.attestation_object), (vec![3], vec![4, 5]));
        for body in [
            &b"[]"[..],
            br#"{"response":{"clientDataJSON":"Aw","attestationObject":"BAU"}}"#,
            br#"{"rawId":"AQI","response":{"attestationObject":"BAU"}}"#,
            br#"{"rawId":"AQ==","response":{"clientDataJSON":"Aw","attestationObject":"BAU"}}"#,
        ] {
            assert!(parse_credential(body).is_err(), "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn parse_apps_cases() {
        let got = parse_apps(" a , b:/x,c:x,d://x,E,f:/\t/x,g:/y:z ");
        let want: Vec<(String, String)> = [("a", "/"), ("b", "/x"), ("g", "/y:z")].iter().map(|(n, p)| (n.to_string(), p.to_string())).collect();
        assert_eq!(got, want);
    }
}
