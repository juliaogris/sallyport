//! The browser side of the hub: invite, login, launcher and app hosts.
//!
//! Hosts are flat, one level below `DOMAIN`:
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

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures::StreamExt;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::{json, Value};
use worker::*;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Tag, Tagged};
use x509_cert::name::Name;

use crate::app::TunnelSlot;
use crate::authpipe::Pool;
use crate::authrpc::{
    self, unary, AttestationResponse, CallError, ChallengeExtensions,
    ChangeUserAuthenticationRequest, ChangeUserAuthenticationResponse, CreateAppSessionRequest,
    CreateAuthenticateChallengeRequest, CreateRegisterChallengeRequest, CredentialCreationResponse,
    GetAppSessionRequest, GetWebSessionRequest, HubAuth, MfaAuthenticateChallenge,
    MfaRegisterChallenge, MfaRegisterResponse, Passwordless, SessionResponse, WebSessionSpecV2,
    AUTHENTICATE_WEB_USER_PASSWORDLESS, CHANGE_USER_AUTHENTICATION, CREATE_APP_SESSION,
    CREATE_AUTHENTICATE_CHALLENGE, CREATE_REGISTER_CHALLENGE, DEVICE_TYPE_WEBAUTHN,
    DEVICE_USAGE_PASSWORDLESS, GET_APP_SESSION, GET_WEB_SESSION, SCOPE_PASSWORDLESS_LOGIN,
};

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

/// How many `begin` calls, and separately how many `finish` calls, one
/// client address may make at once, and how often it gets one more. Each
/// call spends auth's login rate limit for the hub's one address, which is
/// a burst of 40 and then 20 a minute.
const RATE_BURST: f64 = 10.0;
const RATE_REFILL_MS: f64 = 6_000.0;
/// How many client addresses [`RateLimit`] tracks.
const RATE_CLIENTS: usize = 4096;

thread_local! {
    static BEGIN_LIMIT: RefCell<RateLimit> = RefCell::new(RateLimit::default());
    static FINISH_LIMIT: RefCell<RateLimit> = RefCell::new(RateLimit::default());
}

/// A token bucket per client address for the `begin` and `finish` calls of
/// login and invite.
#[derive(Default)]
struct RateLimit {
    buckets: HashMap<String, Bucket>,
}

/// The tokens one client address has left.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    /// When `tokens` was counted, in ms.
    at_ms: u64,
}

impl RateLimit {
    /// Takes one token for `client` at `now_ms`, and returns false when
    /// there is none. It also returns false for a new address when
    /// [`RATE_CLIENTS`] addresses have tokens missing.
    fn allow(&mut self, client: &str, now_ms: u64) -> bool {
        let refill = |b: Bucket| {
            (b.tokens + now_ms.saturating_sub(b.at_ms) as f64 / RATE_REFILL_MS).min(RATE_BURST)
        };
        if !self.buckets.contains_key(client) && self.buckets.len() >= RATE_CLIENTS {
            self.buckets.retain(|_, b| refill(*b) < RATE_BURST);
            if self.buckets.len() >= RATE_CLIENTS {
                return false;
            }
        }
        let bucket = self.buckets.entry(client.to_string()).or_insert(Bucket {
            tokens: RATE_BURST,
            at_ms: now_ms,
        });
        let tokens = refill(*bucket);
        if tokens < 1.0 {
            return false;
        }
        *bucket = Bucket {
            tokens: tokens - 1.0,
            at_ms: now_ms,
        };
        true
    }
}

/// Returns false when the client address of `req` has made too many
/// `begin` calls. An IPv6 address counts as its /64.
fn begin_allowed(req: &Request) -> Result<bool> {
    let client = crate::tunnel::client_key(req)?;
    Ok(BEGIN_LIMIT.with(|l| l.borrow_mut().allow(&client, Date::now().as_millis())))
}

/// Returns false when the client address of `req` has made too many
/// `finish` calls. A login finish takes an auth pipe stream, so without a
/// limit one client could empty the pool. It has its own bucket, so that a
/// login's begin and finish each spend one token.
fn finish_allowed(req: &Request) -> Result<bool> {
    let client = crate::tunnel::client_key(req)?;
    Ok(FINISH_LIMIT.with(|l| l.borrow_mut().allow(&client, Date::now().as_millis())))
}

/// What the hub needs to answer a browser request.
pub struct Ctx<'a> {
    pub env: &'a Env,
    pub pool: &'a Pool,
    pub auth: &'a HubAuth,
    pub tunnel: &'a TunnelSlot,
    pub used_tokens: &'a crate::passkeys::UsedTokens,
}

/// The kind of host a request is for.
pub enum Host {
    Login,
    App(String),
}

/// Returns the host kind for `host`, or None if the hub does not serve it.
/// App names match `^[a-z][a-z0-9]*$`, so `<app>-<owner>` splits once.
pub fn classify(env: &Env, host: &str) -> Option<Host> {
    let (owner, domain) = owner_domain(env).ok()?;
    classify_host(&owner, &domain, host)
}

/// Returns the host kind for `host` under `owner` and `domain`, as
/// [`classify`] does.
fn classify_host(owner: &str, domain: &str, host: &str) -> Option<Host> {
    let label = host.strip_suffix(&format!(".{domain}"))?;
    if label == owner {
        return Some(Host::Login);
    }
    let app = label.strip_suffix(&format!("-{owner}"))?;
    valid_name(app).then(|| Host::App(app.to_string()))
}

fn owner_domain(env: &Env) -> Result<(String, String)> {
    match (env.var("OWNER"), env.var("DOMAIN")) {
        (Ok(owner), Ok(domain)) => Ok((owner.to_string(), domain.to_string())),
        _ => Err(Error::RustError("OWNER and DOMAIN must be set".into())),
    }
}

/// Returns true when `name` matches `^[a-z][a-z0-9]*$` and is at most 30
/// bytes.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 30
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub(crate) fn login_host(env: &Env) -> Result<String> {
    let (owner, domain) = owner_domain(env)?;
    Ok(format!("{owner}.{domain}"))
}

/// Answers a request for the login host.
pub async fn login_host_request(mut req: Request, cx: &Ctx<'_>) -> Result<Response> {
    let host = login_host(cx.env)?;
    let path = req.path();
    // The body is read before routing and before the Origin check, so that
    // one limit holds for every route on the login host.
    let body = if matches!(req.method(), Method::Get | Method::Head) {
        Vec::new()
    } else {
        let Some(body) = read_body(&mut req).await? else {
            return too_large();
        };
        body
    };
    if req.method() == Method::Post && !same_origin(&req, &host)? {
        return Response::error("bad origin", 403);
    }
    if req.method() == Method::Post {
        if let Some(rest) = path.strip_prefix("/webapi/invite/") {
            return invite(&req, cx, rest, body).await;
        }
        if let Some(app) = path.strip_prefix("/web/launch/") {
            return launch(&req, cx, app).await;
        }
    }
    match (req.method(), path.as_str()) {
        (Method::Get, "/") => dashboard(&req, cx).await,
        (Method::Get, "/web/login") => Response::from_html(LOGIN_PAGE),
        (Method::Get, p) if p.starts_with("/web/invite/") => Response::from_html(INVITE_PAGE),
        (Method::Post, "/webapi/login/begin") => {
            if !begin_allowed(&req)? {
                return too_many_requests();
            }
            json_or_error(login_begin(cx).await)
        }
        (Method::Post, "/webapi/login/finish") => {
            if !finish_allowed(&req)? {
                return too_many_requests();
            }
            session_response(login_finish(cx, body).await)
        }
        (Method::Post, "/web/logout") => {
            let mut res = redirect("/web/login")?;
            res.headers_mut()
                .append("Set-Cookie", &expire_cookie(SESSION_COOKIE))?;
            Ok(res)
        }
        (Method::Get, "/web/passkeys") => crate::passkeys::show(&req, cx).await,
        (_, p) if p == "/webapi/passkeys" || p.starts_with("/webapi/passkeys/") => {
            let action = &p["/webapi/passkeys".len()..];
            let action = action.strip_prefix('/').unwrap_or(action);
            crate::passkeys::api(&req, cx, action, body).await
        }
        (Method::Get, "/web/add-passkey") => Response::from_html(crate::passkeys::ADD_PASSKEY_PAGE),
        (Method::Post, "/webapi/add-passkey/begin") => crate::passkeys::add_begin(cx, &body).await,
        (Method::Post, "/webapi/add-passkey/finish") => {
            crate::passkeys::add_finish(cx, &body).await
        }
        _ => Response::error("not found", 404),
    }
}

/// Answers `POST /webapi/invite/<token>/begin` and `.../finish`. `rest` is
/// the path after `/webapi/invite/`, and `body` is the request body.
async fn invite(req: &Request, cx: &Ctx<'_>, rest: &str, body: Vec<u8>) -> Result<Response> {
    let Some((token, step)) = rest.split_once('/') else {
        return Response::error("not found", 404);
    };
    match step {
        "begin" => {
            if !begin_allowed(req)? {
                return too_many_requests();
            }
            json_or_error(invite_begin(cx, token).await)
        }
        "finish" => {
            if !finish_allowed(req)? {
                return too_many_requests();
            }
            session_response(invite_finish(cx, token, body).await)
        }
        _ => Response::error("not found", 404),
    }
}

/// Answers with `res` as JSON, or maps its error to 429 when auth rate
/// limited the call and to 502 otherwise. A finish route answers through
/// [`session_response`] instead, which maps every error to 401.
fn json_or_error(res: std::result::Result<Value, CallError>) -> Result<Response> {
    match res {
        Ok(v) => Response::from_json(&v),
        Err(err) if err.is_rate_limited() => {
            console_error!("web: {err}");
            too_many_requests()
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
                    return too_large();
                };
                let Some(h) = parse_handoff(&body) else {
                    return Response::error("bad handoff", 400);
                };
                handoff(cx, h, &host).await
            }
            _ => Response::error("method not allowed", 405),
        };
    }
    let to_login = || -> Result<Response> {
        let mut res = redirect(&format!("https://{}/", login_host(cx.env)?))?;
        res.headers_mut()
            .append("Set-Cookie", &expire_cookie(APP_COOKIE))?;
        res.headers_mut()
            .append("Set-Cookie", &expire_cookie(SUBJECT_COOKIE))?;
        Ok(res)
    };
    if path == "/teleport-logout" {
        return to_login();
    }
    // Teleport's proxy registers device-bound session credentials on this
    // path (lib/web/app/dbsc.go). The hub does not, and the app service must
    // never see the request.
    if path.starts_with("/x-teleport-dbsc") {
        return Response::error("not found", 404);
    }

    // Every `<app>-<owner>.<domain>` is the same site, so SameSite=Lax still
    // sends the app cookies on a POST from a sibling app host. Only this
    // host may send a request that can change state.
    if !matches!(req.method(), Method::Get | Method::Head | Method::Options)
        && !same_origin_fetch(&req, &host)?
    {
        return Response::error("bad origin", 403);
    }
    let (Some(sid), Some(subject)) = (cookie(&req, APP_COOKIE)?, cookie(&req, SUBJECT_COOKIE)?)
    else {
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
    let tls = Arc::new(authrpc::client_tls(cx.env, &spec.tls_cert, &spec.tls_priv)?);
    let cluster = cx.env.var("CLUSTER_NAME")?.to_string();
    if let Some(lazy) = crate::lazy::get() {
        if !lazy.connected() {
            console_error!("web: {app}: app service offline, auth is not connected");
            return Response::error("app service offline", 503);
        }
        return crate::appproxy::forward(crate::appproxy::AppDialer::Lazy(lazy), tls, &cluster, &host, req).await;
    }
    let Some(tunnel) = cx.tunnel.lock().unwrap().clone() else {
        console_error!("web: {app}: app service offline, no tunnel");
        return Response::error("app service offline", 503);
    };
    crate::appproxy::forward(crate::appproxy::AppDialer::Tunnel(&tunnel), tls, &cluster, &host, req).await
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
    serde_json::from_slice::<Handoff>(body)
        .ok()
        .filter(|h| !h.sid.is_empty() && !h.subject.is_empty())
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
    res.headers_mut()
        .append("Set-Cookie", &set_cookie(APP_COOKIE, &sid))?;
    res.headers_mut()
        .append("Set-Cookie", &set_cookie(SUBJECT_COOKIE, &subject))?;
    Ok(res)
}

/// Returns the app session `sid` from auth when it has not expired, its
/// bearer token is `subject`, and [`cert_for_host`] accepts its certificate
/// for the app host `host`. It returns Ok(None) when any of these checks
/// fails, and an error when auth cannot be asked.
async fn valid_app_session(
    cx: &Ctx<'_>,
    sid: &str,
    subject: &str,
    host: &str,
) -> std::result::Result<Option<WebSessionSpecV2>, String> {
    let got: std::result::Result<SessionResponse, _> = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            GET_APP_SESSION,
            &GetAppSessionRequest {
                session_id: sid.to_string(),
            },
        )
        .await;
    let spec = got.map_err(|e| e.to_string())?.session.and_then(|s| s.spec);
    Ok(spec.filter(|spec| {
        spec.unexpired()
            && ct_eq(spec.bearer_token.as_bytes(), subject.as_bytes())
            && cert_for_host(&spec.tls_cert, host)
    }))
}

/// Returns true when the first certificate in `cert_pem` parses and its
/// app public address is `host`. A certificate with no address is refused.
fn cert_for_host(cert_pem: &[u8], host: &str) -> bool {
    let Some(Ok(der)) = CertificateDer::pem_slice_iter(cert_pem).next() else {
        return false;
    };
    let Ok(cert) = x509_cert::Certificate::from_der(&der) else {
        return false;
    };
    name_public_addr(&cert.tbs_certificate.subject) == Some(host)
}

/// Returns the value of the [`APP_PUBLIC_ADDR_OID`] attribute in `name`,
/// or None when it has none or the value is not a string. Go's
/// `encoding/asn1` writes a string as `PrintableString` when it can, and as
/// `UTF8String` otherwise.
fn name_public_addr(name: &Name) -> Option<&str> {
    let atv = name
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid == APP_PUBLIC_ADDR_OID)?;
    let is_string = matches!(
        atv.value.tag(),
        Tag::PrintableString | Tag::Utf8String | Tag::Ia5String
    );
    if !is_string {
        return None;
    }
    std::str::from_utf8(atv.value.value()).ok()
}

/// Returns the logged-in user and the web session, if the session cookie
/// is for a web session that auth has and that has not expired.
async fn web_session(req: &Request, cx: &Ctx<'_>) -> Result<Option<(String, WebSessionSpecV2)>> {
    Ok(find_web_session(req, cx).await?.unwrap_or_default())
}

/// Returns what [`web_session`] does, or the error of the call to auth when
/// there is no session because of one. A session that auth does not have
/// is also an error, auth's NotFound.
pub(crate) async fn find_web_session(
    req: &Request,
    cx: &Ctx<'_>,
) -> Result<std::result::Result<Option<(String, WebSessionSpecV2)>, CallError>> {
    let Some(value) = cookie(req, SESSION_COOKIE)? else {
        return Ok(Ok(None));
    };
    let Some((user, sid)) = value.split_once(':') else {
        return Ok(Ok(None));
    };
    let got: std::result::Result<SessionResponse, CallError> = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            GET_WEB_SESSION,
            &GetWebSessionRequest {
                user: user.to_string(),
                session_id: sid.to_string(),
            },
        )
        .await;
    match got.map(|r| r.session.and_then(|s| s.spec)) {
        Ok(Some(spec)) if spec.unexpired() => Ok(Ok(Some((user.to_string(), spec)))),
        Ok(_) => Ok(Ok(None)),
        Err(err) => {
            console_log!("web: GetWebSession: {err}");
            Ok(Err(err))
        }
    }
}

/// Returns the TLS config for calls to auth as the user of the web session
/// `spec`. Auth sets `tls_priv` only when it issues separate SSH and TLS
/// keys. Otherwise `priv_key` is both.
pub(crate) fn session_tls(env: &Env, spec: &WebSessionSpecV2) -> Result<Arc<rustls::ClientConfig>> {
    let key = if spec.tls_priv.is_empty() {
        &spec.priv_key
    } else {
        &spec.tls_priv
    };
    Ok(Arc::new(authrpc::tls_config_from_pem(
        env,
        &spec.tls_cert,
        key,
    )?))
}

async fn dashboard(req: &Request, cx: &Ctx<'_>) -> Result<Response> {
    let Some((user, _)) = web_session(req, cx).await? else {
        return redirect("/web/login");
    };
    let buttons: String = app_list(cx.env)?
        .iter()
        .map(|(a, _)| {
            format!(r#"<form method="post" action="/web/launch/{a}"><button>{a}</button></form>"#)
        })
        .collect();
    let user = html_escape(&user);
    Response::from_html(format!(
        r#"{HEAD}<title>sallyport</title>
<p>Logged in as {user}.</p>{buttons}<p><a href="/web/passkeys">Passkeys</a></p><form method="post" action="/web/logout"><button>Log out</button></form>"#
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
    path.starts_with('/')
        && !path.starts_with("//")
        && path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
        && !has_dot_segment(path)
}

/// Returns true when the path part of `path` has a `.` or `..` segment,
/// also written `%2e`. A browser removes these, so `/.//host` becomes
/// `//host`, which names another host.
fn has_dot_segment(path: &str) -> bool {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    path[..end].split('/').any(|seg| {
        matches!(
            seg.to_ascii_lowercase().replace("%2e", ".").as_str(),
            "." | ".."
        )
    })
}

async fn launch(req: &Request, cx: &Ctx<'_>, app: &str) -> Result<Response> {
    let Some(start) = app_list(cx.env)?
        .into_iter()
        .find(|(a, _)| a == app)
        .map(|(_, p)| p)
    else {
        return Response::error("not found", 404);
    };
    let Some((user, spec)) = web_session(req, cx).await? else {
        return redirect("/web/login");
    };
    let (owner, domain) = owner_domain(cx.env)?;
    let public_addr = format!("{app}-{owner}.{domain}");
    match create_app_session(cx, &user, &spec, app, &public_addr).await {
        Ok((sid, bearer)) => {
            let mut res = redirect(&format!(
                "https://{public_addr}{AUTH_PATH}#{sid}.{bearer}.{}",
                b64(start.as_bytes())
            ))?;
            // The URL has the session ID and bearer token in its fragment.
            // Browsers leave fragments out of `Referer`, and `no-referrer`
            // keeps the rest of the URL from leaving the page too.
            res.headers_mut().set("Referrer-Policy", "no-referrer")?;
            Ok(res)
        }
        Err(err) => {
            console_error!("web: launch {app}: {err}");
            Response::error("launch failed", 502)
        }
    }
}

/// Creates an app session for `app` at `public_addr` as `user`, with the
/// user's web session `spec`, and returns its ID and bearer token.
async fn create_app_session(
    cx: &Ctx<'_>,
    user: &str,
    spec: &WebSessionSpecV2,
    app: &str,
    public_addr: &str,
) -> std::result::Result<(String, String), String> {
    let tls = session_tls(cx.env, spec).map_err(|e| e.to_string())?;
    let as_user = authrpc::connect(cx.pool.take_wait().await?, tls).await?;
    let created: SessionResponse = unary(
        &as_user,
        CREATE_APP_SESSION,
        &CreateAppSessionRequest {
            username: user.to_string(),
            public_addr: public_addr.to_string(),
            cluster_name: cx
                .env
                .var("CLUSTER_NAME")
                .map_err(|e| e.to_string())?
                .to_string(),
            app_name: app.to_string(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let sid = created
        .session
        .and_then(|s| s.metadata)
        .map(|m| m.name)
        .ok_or("no app session name")?;
    let got: SessionResponse = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            GET_APP_SESSION,
            &GetAppSessionRequest {
                session_id: sid.clone(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    let bearer = got
        .session
        .and_then(|s| s.spec)
        .map(|s| s.bearer_token)
        .filter(|b| !b.is_empty())
        .ok_or("no bearer token")?;
    Ok((sid, bearer))
}

async fn login_begin(cx: &Ctx<'_>) -> std::result::Result<Value, CallError> {
    let chal: MfaAuthenticateChallenge = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            CREATE_AUTHENTICATE_CHALLENGE,
            &CreateAuthenticateChallengeRequest {
                context_user: None,
                passwordless: Some(Passwordless {}),
                challenge_extensions: Some(ChallengeExtensions {
                    scope: SCOPE_PASSWORDLESS_LOGIN,
                }),
            },
        )
        .await?;
    request_options(chal)
}

/// Returns the WebAuthn request options in `chal` as the pages read them,
/// or an error when it has none.
pub(crate) fn request_options(
    chal: MfaAuthenticateChallenge,
) -> std::result::Result<Value, CallError> {
    let o = chal
        .webauthn
        .and_then(|w| w.public_key)
        .ok_or("no WebAuthn challenge")?;
    Ok(json!({
        "challenge": b64(&o.challenge),
        "rpId": o.rp_id,
        "timeout": o.timeout_ms,
        "userVerification": o.user_verification,
        "allowCredentials": o.allow_credentials.iter().map(|c| json!({"type": c.r#type, "id": b64(&c.id)})).collect::<Vec<_>>(),
    }))
}

/// Logs in with the passkey assertion in `assertion`, and returns the user
/// and the new web session ID.
async fn login_finish(
    cx: &Ctx<'_>,
    assertion: Vec<u8>,
) -> std::result::Result<(String, String), String> {
    // Each call takes a pool stream, so a body that is not an assertion
    // is refused before one is taken.
    let assertion: Value =
        serde_json::from_slice(&assertion).map_err(|e| format!("assertion: {e}"))?;
    let a: Assertion =
        serde_json::from_value(assertion.clone()).map_err(|e| format!("assertion: {e}"))?;
    if a.id.is_empty() || a.r#type != "public-key" {
        return Err("assertion: not a public-key credential".into());
    }
    let tls = authrpc::http1_tls_config(cx.env, "HUB_TLS_CERT", "HUB_TLS_KEY")
        .map_err(|e| e.to_string())?;
    let body = json!({ "username": "", "webauthn": assertion })
        .to_string()
        .into_bytes();
    let stream = cx.pool.take_wait().await?;
    let (status, body) = authrpc::post_json(
        stream,
        Arc::new(tls),
        AUTHENTICATE_WEB_USER_PASSWORDLESS,
        body,
    )
    .await?;
    if status != 200 {
        return Err(format!(
            "AuthenticateWebUser: http {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    parse_web_session(&body)
}

async fn invite_begin(cx: &Ctx<'_>, token: &str) -> std::result::Result<Value, CallError> {
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
                existing_mfa_response: None,
            },
        )
        .await?;
    creation_options(chal)
}

/// Returns the WebAuthn creation options in `chal` as the pages read them,
/// or an error when it has none.
pub(crate) fn creation_options(
    chal: MfaRegisterChallenge,
) -> std::result::Result<Value, CallError> {
    let o = chal
        .webauthn
        .and_then(|w| w.public_key)
        .ok_or("no WebAuthn creation options")?;
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

/// Registers the passkey credential in `body` for the invite `token`, and
/// returns the user and the new web session ID.
async fn invite_finish(
    cx: &Ctx<'_>,
    token: &str,
    body: Vec<u8>,
) -> std::result::Result<(String, String), String> {
    let resp = parse_credential(&body)?;
    let changed: ChangeUserAuthenticationResponse = cx
        .auth
        .call(
            cx.env,
            cx.pool,
            CHANGE_USER_AUTHENTICATION,
            &ChangeUserAuthenticationRequest {
                token_id: token.to_string(),
                new_mfa_register_response: Some(MfaRegisterResponse {
                    webauthn: Some(resp),
                }),
                new_device_name: "passkey".into(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    let ws = changed.web_session.ok_or("no web session")?;
    let sid = ws.metadata.map(|m| m.name).ok_or("no web session name")?;
    let user = ws.spec.map(|s| s.user).ok_or("no web session user")?;
    Ok((user, sid))
}

/// The fields every WebAuthn assertion has. The hub sends the assertion on
/// as it came, so this only checks that they are there.
#[derive(Deserialize)]
struct Assertion {
    id: String,
    r#type: String,
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
    let web: WebSessionJson =
        serde_json::from_slice(body).map_err(|e| format!("web session: {e}"))?;
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
    let cred: CredentialJson =
        serde_json::from_slice(body).map_err(|e| format!("credential: {e}"))?;
    let field = |name: &str, v: &str| {
        URL_SAFE_NO_PAD
            .decode(v)
            .map_err(|e| format!("credential {name}: {e}"))
    };
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
            res.headers_mut().append(
                "Set-Cookie",
                &set_cookie(SESSION_COOKIE, &format!("{user}:{sid}")),
            )?;
            Ok(res)
        }
        Err(err) => {
            console_error!("web: {err}");
            Response::error("login failed", 401)
        }
    }
}

/// Reads the body of `req`, or returns None when it is over [`MAX_BODY`].
/// The rest of a long body is read and dropped, because an answer sent
/// before the body is read, or a cancelled body, breaks keep-alive under
/// `wrangler dev`.
async fn read_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    if req.inner().body().is_none() {
        return Ok(Some(Vec::new()));
    }
    let mut stream = req.stream()?;
    let mut body = Vec::new();
    let mut over = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        over = over || body.len() + chunk.len() > MAX_BODY;
        if !over {
            body.extend_from_slice(&chunk);
        }
    }
    Ok((!over).then_some(body))
}

fn same_origin(req: &Request, host: &str) -> Result<bool> {
    Ok(origin_is(req.headers().get("Origin")?.as_deref(), host))
}

/// Returns true when `origin` is `https://<host>`.
fn origin_is(origin: Option<&str>, host: &str) -> bool {
    origin == Some(format!("https://{host}").as_str())
}

/// Returns false when the browser says the request came from another
/// origin. A request with neither `Sec-Fetch-Site` nor `Origin` is not from
/// a browser page and passes.
fn same_origin_fetch(req: &Request, host: &str) -> Result<bool> {
    Ok(fetch_is_same_origin(
        req.headers().get("Sec-Fetch-Site")?.as_deref(),
        req.headers().get("Origin")?.as_deref(),
        host,
    ))
}

/// Returns the [`same_origin_fetch`] answer for the `Sec-Fetch-Site` and
/// `Origin` header values.
fn fetch_is_same_origin(site: Option<&str>, origin: Option<&str>, host: &str) -> bool {
    match (site, origin) {
        (Some(site), _) => site == "same-origin" || site == "none",
        (None, Some(_)) => origin_is(origin, host),
        (None, None) => true,
    }
}

fn cookie(req: &Request, name: &str) -> Result<Option<String>> {
    Ok(cookie_value(&req.headers().get("Cookie")?.unwrap_or_default(), name).map(str::to_string))
}

/// Returns the value of the cookie `name` in a `Cookie` header value.
fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn set_cookie(name: &str, value: &str) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax")
}

fn expire_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Returns a 303 to `location`. `Response::redirect` has immutable headers,
/// so it cannot also set cookies.
pub(crate) fn redirect(location: &str) -> Result<Response> {
    let mut res = Response::empty()?.with_status(303);
    res.headers_mut().set("Location", location)?;
    Ok(res)
}

/// Returns a 429 for a call that the hub or auth rate limited.
fn too_many_requests() -> Result<Response> {
    Response::error("too many requests, try again in a minute", 429)
}

/// Returns a 413 for a body over [`MAX_BODY`].
fn too_large() -> Result<Response> {
    Response::error("request body too large", 413)
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

pub(crate) fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Compares two byte strings in time that depends only on their lengths.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The start of every page: the doctype, the charset, the viewport and
/// the style, with larger text and buttons so they are easy to tap on a
/// phone. `concat!` takes only literals, so this is a macro.
macro_rules! head {
    () => {
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style>"#
    };
}

/// The script helpers the login and invite pages share: base64url decode
/// and encode, and a JSON `post`.
macro_rules! passkey_js {
    () => {
        r#"const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
"#
    };
}

/// [`head!`] as a constant, for pages built with `format!`.
const HEAD: &str = head!();

const LOGIN_PAGE: &str = concat!(
    head!(),
    r#"<title>sallyport login</title>
<button id="go">Log in with passkey</button><pre id="out"></pre><script>
"#,
    passkey_js!(),
    r#"document.getElementById('go').onclick = async () => {
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

const INVITE_PAGE: &str = concat!(
    head!(),
    r#"<title>sallyport invite</title>
<button id="go">Register a passkey</button><pre id="out"></pre><script>
"#,
    passkey_js!(),
    r#"const token = location.pathname.split('/').pop();
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
</script>"#
);

const HANDOFF_PAGE: &str = concat!(
    head!(),
    r#"<meta name="referrer" content="no-referrer"><title>sallyport</title>
<pre id="out">Signing in...</pre><script>
const [sid, subject, start] = location.hash.slice(1).split('.');
let path = '/';
// The start path must pass the same rule as start_path_ok, including no
// "." or ".." segment, because a path such as "/.//host" resolves to the
// path "//host".
try {
  const p = atob((start || '').replace(/-/g, '+').replace(/_/g, '/'));
  const segs = p.split(/[?#]/)[0].toLowerCase().replace(/%2e/g, '.').split('/');
  if (/^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/.test(p) && !segs.some(s => s === '.' || s === '..')) path = p;
} catch (e) {}
history.replaceState(null, '', location.pathname);
fetch(location.pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid, subject }) })
  .then(r => r.ok ? location.replace(path) : r.text().then(t => { document.getElementById('out').textContent = 'error: ' + r.status + ' ' + t; }));
</script>"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_name_cases() {
        assert!(valid_name("a"));
        assert!(valid_name("octo2"));
        assert!(!valid_name(""));
        assert!(!valid_name("2octo"));
        assert!(!valid_name("oc-to"));
        assert!(!valid_name("Octo"));
        assert!(!valid_name(&"a".repeat(31)));
    }

    #[test]
    fn classify_host_cases() {
        let kind = |host: &str| match classify_host("julia", "example.com", host) {
            Some(Host::Login) => "login".to_string(),
            Some(Host::App(app)) => format!("app {app}"),
            None => "none".to_string(),
        };
        let long = format!("{}-julia.example.com", "a".repeat(31));
        let max = format!("{}-julia.example.com", "a".repeat(30));
        for (host, want) in [
            ("julia.example.com", "login"),
            ("bench-julia.example.com", "app bench"),
            ("octo2-julia.example.com", "app octo2"),
            (max.as_str(), "app aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("example.com", "none"),
            ("evil.julia.example.com", "none"),
            ("julia.example.com.evil", "none"),
            ("bench-julia.example.com.evil", "none"),
            ("foo-bar-julia.example.com", "none"),
            ("Bench-julia.example.com", "none"),
            ("2bench-julia.example.com", "none"),
            ("-julia.example.com", "none"),
            ("bench-bob.example.com", "none"),
            (long.as_str(), "none"),
        ] {
            assert_eq!(kind(host), want, "{host}");
        }
    }

    #[test]
    fn cookie_value_cases() {
        let header = "a=1; __Host-sp_app2=x;__Host-sp_app=s1=; b";
        assert_eq!(cookie_value(header, "a"), Some("1"));
        assert_eq!(cookie_value(header, "__Host-sp_app"), Some("s1="));
        assert_eq!(cookie_value(header, "__Host-sp_app2"), Some("x"));
        assert_eq!(cookie_value(header, "b"), None);
        assert_eq!(cookie_value(header, "__host-sp_app"), None);
        assert_eq!(cookie_value("", "a"), None);
    }

    #[test]
    fn origin_is_cases() {
        assert!(origin_is(
            Some("https://julia.example.com"),
            "julia.example.com"
        ));
        assert!(!origin_is(None, "julia.example.com"));
        assert!(!origin_is(
            Some("http://julia.example.com"),
            "julia.example.com"
        ));
        assert!(!origin_is(
            Some("https://bench-julia.example.com"),
            "julia.example.com"
        ));
        assert!(!origin_is(
            Some("https://julia.example.com:443"),
            "julia.example.com"
        ));
        assert!(!origin_is(Some("null"), "julia.example.com"));
    }

    #[test]
    fn fetch_is_same_origin_cases() {
        let host = "bench-julia.example.com";
        let same = Some("https://bench-julia.example.com");
        let sibling = Some("https://octo-julia.example.com");
        for (site, origin, want) in [
            (Some("same-origin"), None, true),
            (Some("none"), None, true),
            (Some("same-site"), same, false),
            (Some("cross-site"), same, false),
            (Some("same-origin"), sibling, true),
            (None, same, true),
            (None, sibling, false),
            (None, None, true),
        ] {
            assert_eq!(
                fetch_is_same_origin(site, origin, host),
                want,
                "{site:?} {origin:?}"
            );
        }
    }

    #[test]
    fn ct_eq_cases() {
        assert!(ct_eq(b"token", b"token"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"token", b"tokens"));
        assert!(!ct_eq(b"token", b"tokem"));
    }

    #[test]
    fn html_escape_cases() {
        assert_eq!(html_escape("alice"), "alice");
        assert_eq!(
            html_escape(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn parse_web_session_cases() {
        assert_eq!(parse_web_session(br#"{"kind":"web_session","metadata":{"name":"s1"},"spec":{"user":"alice","pub":"x"}}"#), Ok(("alice".into(), "s1".into())));
        for body in [
            &b"null"[..],
            b"{}",
            br#"{"metadata":{"name":"s1"}}"#,
            br#"{"metadata":{"name":""},"spec":{"user":"alice"}}"#,
            br#"{"metadata":{"name":1},"spec":{"user":"alice"}}"#,
        ] {
            assert!(
                parse_web_session(body).is_err(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn parse_credential_cases() {
        let got = parse_credential(
            br#"{"rawId":"AQI","response":{"clientDataJSON":"Aw","attestationObject":"BAU"}}"#,
        )
        .unwrap();
        assert_eq!(got.r#type, "public-key");
        assert_eq!(got.raw_id, vec![1, 2]);
        let att = got.response.unwrap();
        assert_eq!(
            (att.client_data_json, att.attestation_object),
            (vec![3], vec![4, 5])
        );
        for body in [
            &b"[]"[..],
            br#"{"response":{"clientDataJSON":"Aw","attestationObject":"BAU"}}"#,
            br#"{"rawId":"AQI","response":{"attestationObject":"BAU"}}"#,
            br#"{"rawId":"AQ==","response":{"clientDataJSON":"Aw","attestationObject":"BAU"}}"#,
        ] {
            assert!(
                parse_credential(body).is_err(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn parse_handoff_cases() {
        let h = parse_handoff(br#"{"sid":"s","subject":"t"}"#).unwrap();
        assert_eq!((h.sid.as_str(), h.subject.as_str()), ("s", "t"));
        for body in [
            &b""[..],
            b"not json",
            br#"{"sid":"s"}"#,
            br#"{"sid":"","subject":"t"}"#,
            br#"{"sid":"s","subject":""}"#,
            br#"{"sid":1,"subject":"t"}"#,
        ] {
            assert!(
                parse_handoff(body).is_none(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn parse_apps_cases() {
        let got = parse_apps(" a , b:/x,c:x,d://x,E,f:/\t/x,g:/y:z ");
        let want: Vec<(String, String)> = [("a", "/"), ("b", "/x"), ("g", "/y:z")]
            .iter()
            .map(|(n, p)| (n.to_string(), p.to_string()))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn start_path_ok_cases() {
        for (path, want) in [
            ("/", true),
            ("/stream", true),
            ("/a?b=1#c", true),
            ("/%2F/x", true),
            ("/a/./b", false),
            ("/.//evil.example", false),
            ("/a/%2E%2e/b", false),
            ("/a/..", false),
            ("/a/b?x=/../", true),
            ("/a.b/.c", true),
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

    fn app_cert(attrs: &[(&[u64], rcgen::DnValue)]) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice");
        for (oid, value) in attrs {
            params
                .distinguished_name
                .push(rcgen::DnType::CustomDnType(oid.to_vec()), value.clone());
        }
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem().into_bytes()
    }

    #[test]
    fn cert_for_host_cases() {
        let addr: &[u64] = &[1, 3, 9999, 1, 6];
        let app_name: &[u64] = &[1, 3, 9999, 1, 10];
        let utf8 = |v: &str| rcgen::DnValue::Utf8String(v.into());
        let printable = |v: &str| rcgen::DnValue::PrintableString(v.try_into().unwrap());
        let ia5 = |v: &str| rcgen::DnValue::Ia5String(v.try_into().unwrap());
        let bmp = |v: &str| rcgen::DnValue::BmpString(v.try_into().unwrap());
        let host = "bench-julia.example.com";
        let cases: Vec<(&str, Vec<u8>, bool)> = vec![
            (
                "PrintableString after another attribute",
                app_cert(&[(app_name, utf8("bench")), (addr, printable(host))]),
                true,
            ),
            ("UTF8String", app_cert(&[(addr, utf8(host))]), true),
            ("IA5String", app_cert(&[(addr, ia5(host))]), true),
            ("no address", app_cert(&[(app_name, utf8("bench"))]), false),
            (
                "another app",
                app_cert(&[(addr, printable("octo-julia.example.com"))]),
                false,
            ),
            (
                "host as a prefix",
                app_cert(&[(addr, printable("bench-julia.example.com.evil"))]),
                false,
            ),
            ("BMPString", app_cert(&[(addr, bmp(host))]), false),
            ("not a PEM", b"not a pem".to_vec(), false),
            (
                "not a certificate",
                b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
                false,
            ),
        ];
        for (name, pem, want) in cases {
            assert_eq!(cert_for_host(&pem, host), want, "{name}");
        }
    }

    #[test]
    fn rate_limit_refills() {
        let mut l = RateLimit::default();
        for _ in 0..10 {
            assert!(l.allow("a", 0));
        }
        assert!(!l.allow("a", 0));
        assert!(l.allow("b", 0));
        assert!(!l.allow("a", 5_999));
        assert!(l.allow("a", 6_000));
        assert!(!l.allow("a", 6_000));
        for _ in 0..10 {
            assert!(l.allow("a", 1_000_000));
        }
        assert!(!l.allow("a", 1_000_000));
    }

    #[test]
    fn rate_limit_caps_clients() {
        let mut l = RateLimit::default();
        for i in 0..RATE_CLIENTS {
            assert!(l.allow(&i.to_string(), 0));
        }
        assert!(!l.allow("new", 0));
        assert!(l.allow("0", 0));
        assert!(l.allow("new", 6_000));
        assert_eq!(l.buckets.len(), 2);
    }
}
