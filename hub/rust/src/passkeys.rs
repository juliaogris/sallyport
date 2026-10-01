//! Passkey management on the login host, for the logged-in user. Every call
//! to auth is made as the user, with the web session's certificate.
//!
//! - `GET /web/passkeys` is the page. Without a session it redirects to
//!   `/web/login`.
//! - `GET /webapi/passkeys` lists the user's passkeys as
//!   `{"passkeys": [{"name": ..., "addedAt": ...}]}`.
//! - `POST /webapi/passkeys/challenge` creates an authenticate challenge
//!   with the manage devices scope and returns WebAuthn request options, as
//!   `/webapi/login/begin` does.
//! - `POST /webapi/passkeys/begin` takes the browser's answer to that
//!   challenge and returns WebAuthn creation options, as an invite's begin
//!   does.
//! - `POST /webapi/passkeys/finish` takes `{"name": ..., "credential": ...}`
//!   and adds the passkey.
//! - `POST /webapi/passkeys/delete` takes `{"name": ..., "assertion": ...}`,
//!   a fresh answer to a challenge, and removes the passkey. The last
//!   passkey is not removed: 409 "cannot remove the last passkey".
//! - `POST /webapi/passkeys/link` takes a fresh answer to a challenge and
//!   returns `{"expires": ..., "url": ...}`: a link for another device with
//!   a privilege token, and when the token expires in RFC 3339.
//!
//! The JSON routes answer 401 "not logged in" without a valid session, 503
//! "auth unavailable" when auth could not be asked for the session, and
//! `{"ok": true}` when a finish or delete worked. Errors from auth are
//! mapped by [`auth_error`].
//!
//! The other device opens the link, with no session. The token is in the
//! URL fragment, so it reaches neither a request log nor a `Referer`, and
//! the page takes it out of the address bar and sends it in the body of
//! each `POST`:
//!
//! - `GET /web/add-passkey` is the page.
//! - `POST /webapi/add-passkey/begin` takes `{"token": ...}` and returns
//!   WebAuthn creation options for the token's user.
//! - `POST /webapi/add-passkey/finish` takes `{"token": ..., "name": ...,
//!   "credential": ...}` and adds the passkey.
//!
//! A token that does not have auth's form is refused before auth is asked:
//! 403 "invalid token", which is also auth's answer for a token it does not
//! know or that has expired.
//!
//! A token adds one passkey. Auth keeps a privilege token until it expires,
//! so the hub records the ID of a token whose finish added a passkey, in
//! Durable Object SQLite, and answers 403 "invalid token" for it on begin
//! and finish from then on. A finish that auth refused does not use the
//! token up.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use futures::lock::{Mutex, OwnedMutexGuard};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use worker::*;

use crate::authrpc::{
    call_as, AddMfaDeviceSyncRequest, AttestationResponse, AuthenticatorAssertionResponse,
    CallError, ChallengeExtensions, ContextUser, CreateAuthenticateChallengeRequest,
    CreatePrivilegeTokenRequest, CreateRegisterChallengeRequest, CredentialAssertionResponse,
    CredentialCreationResponse, DeleteMfaDeviceSyncRequest, GetMfaDevicesRequest,
    GetMfaDevicesResponse, Ignored, MfaAuthenticateChallenge, MfaAuthenticateResponse,
    MfaRegisterChallenge, MfaRegisterResponse, UserToken, ADD_MFA_DEVICE_SYNC,
    CREATE_AUTHENTICATE_CHALLENGE, CREATE_PRIVILEGE_TOKEN, CREATE_REGISTER_CHALLENGE,
    DELETE_MFA_DEVICE_SYNC, DEVICE_TYPE_WEBAUTHN, DEVICE_USAGE_PASSWORDLESS, GET_MFA_DEVICES,
    SCOPE_MANAGE_DEVICES,
};
use crate::web::{self, Ctx};

/// gRPC status `NOT_FOUND`.
const GRPC_NOT_FOUND: &str = "5";

/// How long auth keeps a privilege token, Teleport's
/// `defaults.PrivilegeTokenTTL`, in ms.
const PRIVILEGE_TOKEN_TTL_MS: i64 = 5 * 60 * 1000;

/// Answers `GET /web/passkeys`: the page, or a redirect to log in.
pub async fn show(req: &Request, cx: &Ctx<'_>) -> Result<Response> {
    match web::find_web_session(req, cx).await? {
        Ok(Some(_)) => Response::from_html(PASSKEYS_PAGE),
        _ => web::redirect("/web/login"),
    }
}

/// A route under `/webapi/passkeys`.
#[derive(Debug, PartialEq)]
enum Action {
    List,
    Challenge,
    Begin,
    Finish,
    Delete,
    Link,
}

/// Returns the route for `method` and `action`, the path after
/// `/webapi/passkeys/`, or None when there is no such route.
fn route(method: &Method, action: &str) -> Option<Action> {
    match (method, action) {
        (Method::Get, "") => Some(Action::List),
        (Method::Post, "challenge") => Some(Action::Challenge),
        (Method::Post, "begin") => Some(Action::Begin),
        (Method::Post, "finish") => Some(Action::Finish),
        (Method::Post, "delete") => Some(Action::Delete),
        (Method::Post, "link") => Some(Action::Link),
        _ => None,
    }
}

/// Answers the `/webapi/passkeys` routes. `action` is the path after
/// `/webapi/passkeys/`, or "" for the list, and `body` is the request body.
pub async fn api(req: &Request, cx: &Ctx<'_>, action: &str, body: Vec<u8>) -> Result<Response> {
    let Some(action) = route(&req.method(), action) else {
        return passkey_error("not found", 404);
    };
    let spec = match web::find_web_session(req, cx).await? {
        Ok(Some((_, spec))) => spec,
        Ok(None) => return passkey_error("not logged in", 401),
        Err(err) if err.grpc_code() == Some(GRPC_NOT_FOUND) => {
            return passkey_error("not logged in", 401)
        }
        Err(_) => return passkey_error("auth unavailable", 503),
    };
    let tls = match web::session_tls(cx.env, &spec) {
        Ok(tls) => tls,
        Err(err) => return passkey_error(&err.to_string(), 500),
    };
    let user = User { cx, tls };
    match action {
        Action::List => user.list().await,
        Action::Challenge => user.challenge().await,
        Action::Begin => user.begin(&body).await,
        Action::Finish => user.finish(&body).await,
        Action::Delete => user.delete(&body).await,
        Action::Link => user.link(&body).await,
    }
}

/// The logged-in user, with the TLS identity of the web session.
struct User<'a> {
    cx: &'a Ctx<'a>,
    tls: Arc<rustls::ClientConfig>,
}

impl User<'_> {
    async fn call<Req: prost::Message, Resp: prost::Message + Default>(
        &self,
        path: &str,
        req: &Req,
    ) -> std::result::Result<Resp, CallError> {
        call_as(self.cx.pool, self.tls.clone(), path, req).await
    }

    async fn devices(&self) -> std::result::Result<GetMfaDevicesResponse, CallError> {
        self.call(GET_MFA_DEVICES, &GetMfaDevicesRequest {}).await
    }

    async fn list(&self) -> Result<Response> {
        match self.devices().await {
            Ok(devices) => Response::from_json(&PasskeyList {
                passkeys: passkeys_of(&devices),
            }),
            Err(err) => auth_error(&err),
        }
    }

    async fn challenge(&self) -> Result<Response> {
        let req = CreateAuthenticateChallengeRequest {
            context_user: Some(ContextUser {}),
            passwordless: None,
            challenge_extensions: Some(ChallengeExtensions {
                scope: SCOPE_MANAGE_DEVICES,
            }),
        };
        let res = self
            .call::<_, MfaAuthenticateChallenge>(CREATE_AUTHENTICATE_CHALLENGE, &req)
            .await
            .and_then(web::request_options);
        json_or_auth_error(res)
    }

    async fn begin(&self, body: &[u8]) -> Result<Response> {
        let Some(existing) = decode::<AssertionJson>(body).and_then(|a| a.proto()) else {
            return passkey_error("bad request", 400);
        };
        let req = CreateRegisterChallengeRequest {
            token_id: String::new(),
            device_type: DEVICE_TYPE_WEBAUTHN,
            device_usage: DEVICE_USAGE_PASSWORDLESS,
            existing_mfa_response: Some(existing),
        };
        let res = self
            .call::<_, MfaRegisterChallenge>(CREATE_REGISTER_CHALLENGE, &req)
            .await
            .and_then(web::creation_options);
        json_or_auth_error(res)
    }

    async fn finish(&self, body: &[u8]) -> Result<Response> {
        let Some((name, cred)) =
            decode::<FinishJson>(body).and_then(|f| Some((f.name, f.credential.proto()?)))
        else {
            return passkey_error("bad request", 400);
        };
        let req = AddMfaDeviceSyncRequest {
            token_id: String::new(),
            new_device_name: name,
            new_mfa_response: Some(MfaRegisterResponse {
                webauthn: Some(cred),
            }),
            device_usage: DEVICE_USAGE_PASSWORDLESS,
            context_user: Some(ContextUser {}),
        };
        match self.call::<_, Ignored>(ADD_MFA_DEVICE_SYNC, &req).await {
            Ok(_) => ok(),
            Err(err) => auth_error(&err),
        }
    }

    /// Removes a passkey after a fresh challenge answer. It lists the
    /// user's passkeys first and refuses to remove the last one, before the
    /// answer reaches auth. Auth allows that when the user has a password,
    /// and the hub has no password login.
    async fn delete(&self, body: &[u8]) -> Result<Response> {
        let Some((name, existing)) =
            decode::<DeleteJson>(body).and_then(|d| Some((d.name, d.assertion.proto()?)))
        else {
            return passkey_error("bad request", 400);
        };
        match self.devices().await {
            Ok(devices) if passkeys_of(&devices).len() <= 1 => {
                return passkey_error("cannot remove the last passkey", 409)
            }
            Ok(_) => {}
            Err(err) => return auth_error(&err),
        }
        let req = DeleteMfaDeviceSyncRequest {
            device_name: name,
            existing_mfa_response: Some(existing),
        };
        match self.call::<_, Ignored>(DELETE_MFA_DEVICE_SYNC, &req).await {
            Ok(_) => ok(),
            Err(err) => auth_error(&err),
        }
    }

    /// Makes a link for another device after a fresh challenge answer. The
    /// privilege token in the link adds one passkey. It expires after
    /// [`PRIVILEGE_TOKEN_TTL_MS`], and a new link replaces it.
    async fn link(&self, body: &[u8]) -> Result<Response> {
        let Some(existing) = decode::<AssertionJson>(body).and_then(|a| a.proto()) else {
            return passkey_error("bad request", 400);
        };
        let req = CreatePrivilegeTokenRequest {
            existing_mfa_response: Some(existing),
        };
        let token = match self
            .call::<_, UserToken>(CREATE_PRIVILEGE_TOKEN, &req)
            .await
        {
            Ok(UserToken {
                metadata: Some(meta),
            }) if !meta.name.is_empty() => meta,
            Ok(_) => return auth_error(&"no privilege token".into()),
            Err(err) => return auth_error(&err),
        };
        let expires = token.expires.as_ref().map_or(0, |t| t.seconds);
        Response::from_json(&Link {
            expires: rfc3339(expires),
            url: format!(
                "https://{}/web/add-passkey#{}",
                web::login_host(self.cx.env)?,
                token.name
            ),
        })
    }
}

/// The answer of the link route. The keys are in the Go hub's order,
/// which sorts them.
#[derive(Serialize)]
struct Link {
    expires: String,
    url: String,
}

/// The body of the add-passkey routes. A begin has only the token.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AddPasskeyJson {
    #[serde(deserialize_with = "nullable")]
    token: String,
    #[serde(deserialize_with = "nullable")]
    name: String,
    #[serde(deserialize_with = "object")]
    credential: CredentialJson,
}

/// Returns the add-passkey request in `body`, or the answer that refuses
/// it: 400 for a body that is not JSON of the right form, and 403 for a
/// token that does not have auth's form.
fn parse_add(body: &[u8]) -> std::result::Result<AddPasskeyJson, (&'static str, u16)> {
    let add = decode::<AddPasskeyJson>(body).ok_or(("bad request", 400))?;
    if !valid_token_id(&add.token) {
        return Err(("invalid token", 403));
    }
    Ok(add)
}

/// Returns true when `id` has the form of a user token ID from auth: 32
/// lower case hex characters.
fn valid_token_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Answers `POST /webapi/add-passkey/begin`: WebAuthn creation options for
/// the user of the token in `body`.
pub async fn add_begin(cx: &Ctx<'_>, body: &[u8]) -> Result<Response> {
    let add = match parse_add(body) {
        Ok(add) => add,
        Err((msg, status)) => return passkey_error(msg, status),
    };
    if cx.used_tokens.used(&add.token)? {
        return passkey_error("invalid token", 403);
    }
    let res = cx
        .auth
        .call::<_, MfaRegisterChallenge>(
            cx.env,
            cx.pool,
            CREATE_REGISTER_CHALLENGE,
            &CreateRegisterChallengeRequest {
                token_id: add.token,
                device_type: DEVICE_TYPE_WEBAUTHN,
                device_usage: DEVICE_USAGE_PASSWORDLESS,
                existing_mfa_response: None,
            },
        )
        .await
        .and_then(web::creation_options);
    json_or_auth_error(res)
}

/// Answers `POST /webapi/add-passkey/finish`: adds the credential in
/// `body` as a passkey of the user of the token in `body`, and uses the
/// token up. It sets no session cookie.
pub async fn add_finish(cx: &Ctx<'_>, body: &[u8]) -> Result<Response> {
    let add = match parse_add(body) {
        Ok(add) => add,
        Err((msg, status)) => return passkey_error(msg, status),
    };
    let Some(cred) = add.credential.proto() else {
        return passkey_error("bad request", 400);
    };
    // Two finishes with one token must not both add a passkey, so the
    // check, the call and the record run under the token's lock.
    let _lock = cx.used_tokens.locks.lock(&add.token).await;
    if cx.used_tokens.used(&add.token)? {
        return passkey_error("invalid token", 403);
    }
    let req = AddMfaDeviceSyncRequest {
        token_id: add.token.clone(),
        new_device_name: add.name,
        new_mfa_response: Some(MfaRegisterResponse {
            webauthn: Some(cred),
        }),
        device_usage: DEVICE_USAGE_PASSWORDLESS,
        context_user: None,
    };
    let res: std::result::Result<Ignored, _> = cx
        .auth
        .call(cx.env, cx.pool, ADD_MFA_DEVICE_SYNC, &req)
        .await;
    if let Err(err) = res {
        return auth_error(&err);
    }
    cx.used_tokens
        .record(&add.token, Date::now().as_millis() as i64)?;
    ok()
}

/// The privilege tokens that have added a passkey, in the Durable Object's
/// SQLite table `used_tokens`. Storage outlives a deploy, which restarts
/// the hub.
pub struct UsedTokens {
    sql: SqlStorage,
    locks: TokenLocks,
}

impl UsedTokens {
    pub fn new(sql: SqlStorage) -> Self {
        let created = sql.exec(
            "CREATE TABLE IF NOT EXISTS used_tokens (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)",
            None::<Vec<SqlStorageValue>>,
        );
        if let Err(err) = created {
            console_error!("passkeys: create used_tokens: {err}");
        }
        Self {
            sql,
            locks: TokenLocks::default(),
        }
    }

    /// Returns true when the privilege token `id` has added a passkey.
    fn used(&self, id: &str) -> Result<bool> {
        let rows = self
            .sql
            .exec("SELECT 1 FROM used_tokens WHERE id = ?", vec![id.into()])?;
        Ok(rows.raw().next().transpose()?.is_some())
    }

    /// Records that the privilege token `id` added a passkey at `now_ms`,
    /// and forgets the tokens whose record expired by then.
    fn record(&self, id: &str, now_ms: i64) -> Result<()> {
        self.sql.exec(
            "DELETE FROM used_tokens WHERE expires <= ?",
            vec![now_ms.into()],
        )?;
        self.sql.exec(
            "INSERT OR REPLACE INTO used_tokens (id, expires) VALUES (?, ?)",
            vec![id.into(), used_until(now_ms).into()],
        )?;
        Ok(())
    }
}

/// Returns until when, in Unix ms, the record of a token used at `now_ms`
/// is kept. Auth made the token before it was used, so auth has expired
/// it by then.
fn used_until(now_ms: i64) -> i64 {
    now_ms + PRIVILEGE_TOKEN_TTL_MS
}

/// One lock per privilege token ID. Two finishes with one token run one
/// after the other, and a finish with another token does not wait.
#[derive(Default)]
struct TokenLocks {
    held: Rc<RefCell<HashMap<String, Arc<Mutex<()>>>>>,
}

/// The lock of one token ID, released on drop.
struct TokenGuard {
    held: Rc<RefCell<HashMap<String, Arc<Mutex<()>>>>>,
    id: String,
    guard: Option<OwnedMutexGuard<()>>,
}

impl TokenLocks {
    async fn lock(&self, id: &str) -> TokenGuard {
        let mutex = {
            let mut held = self.held.borrow_mut();
            // An entry that only the map holds is left by a finish that
            // was dropped while it waited.
            held.retain(|_, m| Arc::strong_count(m) > 1);
            held.entry(id.to_string()).or_default().clone()
        };
        let guard = mutex.lock_owned().await;
        TokenGuard {
            held: self.held.clone(),
            id: id.to_string(),
            guard: Some(guard),
        }
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        let mut held = self.held.borrow_mut();
        // The map holds one reference, and a finish that waits for this
        // lock holds another and still needs the entry.
        if held
            .get(&self.id)
            .is_some_and(|m| Arc::strong_count(m) == 1)
        {
            held.remove(&self.id);
        }
    }
}

/// Answers `{"ok":true}`.
fn ok() -> Result<Response> {
    Response::from_json(&json!({ "ok": true }))
}

fn json_or_auth_error(res: std::result::Result<serde_json::Value, CallError>) -> Result<Response> {
    match res {
        Ok(v) => Response::from_json(&v),
        Err(err) => auth_error(&err),
    }
}

/// Returns an error on a passkey route: `msg` as plain text that the
/// browser must not sniff, because auth's messages can hold a device name.
fn passkey_error(msg: &str, status: u16) -> Result<Response> {
    let mut res = Response::error(msg, status)?;
    res.headers_mut()
        .set("Content-Type", "text/plain; charset=utf-8")?;
    res.headers_mut().set("X-Content-Type-Options", "nosniff")?;
    Ok(res)
}

/// Answers a failed call to auth on a passkey route, with the status and
/// body from [`auth_error_status`]. A 502 is logged.
fn auth_error(err: &CallError) -> Result<Response> {
    let (msg, status) = auth_error_status(err);
    if status == 502 {
        console_error!("web: passkeys: {err}");
    }
    passkey_error(&msg, status)
}

/// Returns the body and status for a failed call to auth. A gRPC client
/// error, InvalidArgument, NotFound, AlreadyExists, PermissionDenied or
/// Unauthenticated, becomes the matching 4xx with auth's message as the
/// body. These are the errors for a used name, a too long name, an unknown
/// device and a bad or stale passkey answer, and auth writes their messages
/// for the user. ResourceExhausted becomes 429. Every other error,
/// including a transport error, becomes 502 "request failed".
fn auth_error_status(err: &CallError) -> (String, u16) {
    let CallError::Status { code, message, .. } = err else {
        return ("request failed".into(), 502);
    };
    let status = match code.as_str() {
        "8" => return ("too many requests, try again in a minute".into(), 429),
        "3" => 400,
        "5" => 404,
        "6" => 409,
        "7" => 403,
        "16" => 401,
        _ => return ("request failed".into(), 502),
    };
    let msg = if message.is_empty() {
        "request refused".to_string()
    } else {
        message.clone()
    };
    (msg, status)
}

/// A passkey as the page shows it.
#[derive(Debug, PartialEq, Serialize)]
struct Passkey {
    name: String,
    /// RFC 3339 in UTC, to the second.
    #[serde(rename = "addedAt")]
    added_at: String,
}

#[derive(Serialize)]
struct PasskeyList {
    passkeys: Vec<Passkey>,
}

/// Returns the WebAuthn devices in `resp`. A device of another kind, such
/// as TOTP, is left out.
fn passkeys_of(resp: &GetMfaDevicesResponse) -> Vec<Passkey> {
    resp.devices
        .iter()
        .filter(|d| d.webauthn.is_some())
        .map(|d| Passkey {
            name: d
                .metadata
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_default(),
            added_at: rfc3339(d.added_at.as_ref().map_or(0, |t| t.seconds)),
        })
        .collect()
}

/// Returns the Unix time `secs` in RFC 3339 in UTC, to the second.
fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // The civil date of a day count, from Howard Hinnant's days_from_civil
    // inverse, which holds for every day in the proleptic Gregorian
    // calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Decodes `body` as Go's `encoding/json` decodes into a struct: `null`
/// gives the zero value, and a missing field is left at its zero value.
/// Returns None when `body` is not JSON of that form.
fn decode<T: DeserializeOwned + Default>(body: &[u8]) -> Option<T> {
    let mut d = serde_json::Deserializer::from_slice(body);
    let v = object(&mut d).ok()?;
    d.end().ok()?;
    Some(v)
}

/// Reads a JSON `null` as the zero value, as Go does for a struct field.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Reads a JSON object, or `null` as the zero value. Serde also reads a
/// struct from an array, which Go refuses.
fn object<'de, D: Deserializer<'de>, T: DeserializeOwned + Default>(
    d: D,
) -> std::result::Result<T, D::Error> {
    use serde::de::Error as _;
    match Option::<serde_json::Value>::deserialize(d)? {
        None => Ok(T::default()),
        Some(v @ serde_json::Value::Object(_)) => T::deserialize(v).map_err(D::Error::custom),
        Some(_) => Err(D::Error::custom("not a JSON object")),
    }
}

/// Base64url without padding, as the pages encode bytes. Like Go's
/// `base64.RawURLEncoding`, it accepts nonzero bits after the last byte.
const PAGE_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

fn unb64(v: &str) -> Option<Vec<u8>> {
    PAGE_B64.decode(v).ok()
}

/// Returns `t`, or "public-key" when it is empty.
fn or_public_key(t: String) -> String {
    if t.is_empty() {
        "public-key".into()
    } else {
        t
    }
}

/// The browser's answer to an authenticate challenge, as the pages send
/// it. The byte fields are base64url without padding.
#[derive(Default, Deserialize)]
#[serde(default)]
struct AssertionJson {
    #[serde(deserialize_with = "nullable")]
    r#type: String,
    #[serde(rename = "rawId", deserialize_with = "nullable")]
    raw_id: String,
    #[serde(deserialize_with = "object")]
    response: AssertionResponseJson,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct AssertionResponseJson {
    #[serde(rename = "clientDataJSON", deserialize_with = "nullable")]
    client_data_json: String,
    #[serde(rename = "authenticatorData", deserialize_with = "nullable")]
    authenticator_data: String,
    #[serde(deserialize_with = "nullable")]
    signature: String,
    #[serde(rename = "userHandle", deserialize_with = "nullable")]
    user_handle: String,
}

impl AssertionJson {
    /// Returns the answer as an `MFAAuthenticateResponse`, or None when a
    /// byte field is not base64url.
    fn proto(self) -> Option<MfaAuthenticateResponse> {
        let r = self.response;
        Some(MfaAuthenticateResponse {
            webauthn: Some(CredentialAssertionResponse {
                r#type: or_public_key(self.r#type),
                raw_id: unb64(&self.raw_id)?,
                response: Some(AuthenticatorAssertionResponse {
                    client_data_json: unb64(&r.client_data_json)?,
                    authenticator_data: unb64(&r.authenticator_data)?,
                    signature: unb64(&r.signature)?,
                    user_handle: unb64(&r.user_handle)?,
                }),
            }),
        })
    }
}

/// The browser's new credential, as the pages send it.
#[derive(Default, Deserialize)]
#[serde(default)]
struct CredentialJson {
    #[serde(deserialize_with = "nullable")]
    r#type: String,
    #[serde(rename = "rawId", deserialize_with = "nullable")]
    raw_id: String,
    #[serde(deserialize_with = "object")]
    response: AttestationJson,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct AttestationJson {
    #[serde(rename = "clientDataJSON", deserialize_with = "nullable")]
    client_data_json: String,
    #[serde(rename = "attestationObject", deserialize_with = "nullable")]
    attestation_object: String,
}

impl CredentialJson {
    /// Returns the credential as a `CredentialCreationResponse`, or None
    /// when a byte field is not base64url.
    fn proto(self) -> Option<CredentialCreationResponse> {
        let r = self.response;
        Some(CredentialCreationResponse {
            r#type: or_public_key(self.r#type),
            raw_id: unb64(&self.raw_id)?,
            response: Some(AttestationResponse {
                client_data_json: unb64(&r.client_data_json)?,
                attestation_object: unb64(&r.attestation_object)?,
            }),
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct FinishJson {
    #[serde(deserialize_with = "nullable")]
    name: String,
    #[serde(deserialize_with = "object")]
    credential: CredentialJson,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct DeleteJson {
    #[serde(deserialize_with = "nullable")]
    name: String,
    #[serde(deserialize_with = "object")]
    assertion: AssertionJson,
}

/// The passkeys page: the list, add and remove, and the link and QR code
/// for another device. It is the Go hub's page, byte for byte, and reads
/// all its data from the JSON routes.
pub const PASSKEYS_PAGE: &str = r##"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport passkeys</title>
<style>main{max-width:40em}h1{font-size:28px;margin:8px 0 16px}h2{font-size:20px;margin:28px 0 4px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 12px 8px 0;border-bottom:1px solid #ccc;vertical-align:middle}th{font-weight:600;color:#555}td.act{text-align:right;padding-right:0}td button{min-width:0;margin:0;padding:6px 14px;font-size:16px}label{display:block;margin:8px 0 4px}input{font-size:18px;padding:10px;width:100%;max-width:20em;box-sizing:border-box}#out{color:#b00;white-space:pre-wrap}#qr{display:block;margin-top:8px}</style>
<main><p><a href="/">Back</a></p><h1>Passkeys</h1>
<table><thead><tr><th>Name</th><th>Added</th><th></th></tr></thead><tbody id="list"></tbody></table>
<h2>Add a passkey on this device</h2><label for="name">Name</label><input id="name" maxlength="30"><br><button id="add">Add a passkey</button>
<h2>Add a passkey on another device</h2><button id="link">Show a link and QR code</button>
<div id="other" hidden><p>Open this link on the other device, or scan the code. <span id="until"></span></p><p><a id="url" style="word-break:break-all"></a></p><canvas id="qr"></canvas></div>
<pre id="out"></pre></main><script>
// qr returns the modules of a QR code for text as rows of 0 and 1: byte mode, error correction level M, version 1 to 6, mask 0.
function qr(text) {
  const bytes = new TextEncoder().encode(text);
  const T = [[26, 10, 1], [44, 16, 1], [70, 26, 1], [100, 18, 2], [134, 24, 2], [172, 16, 4]];
  const v = T.findIndex(([n, ec, b]) => n - ec * b >= bytes.length + 2);
  if (v < 0) throw new Error('text too long for a QR code');
  const [total, ecLen, blocks] = T[v], dataLen = total - ecLen * blocks, n = 21 + 4 * v;
  const bits = [];
  const put = (val, k) => { for (let i = k - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  put(4, 4); put(bytes.length, 8); bytes.forEach(b => put(b, 8)); put(0, 4);
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let p = 0xec; data.length < dataLen; p ^= 0xfd) data.push(p);
  const exp = [], log = [];
  for (let i = 0, x = 1; i < 255; i++, x = (x << 1) ^ (x & 128 ? 0x11d : 0)) { exp[i] = x; log[x] = i; }
  const mul = (a, b) => a && b ? exp[(log[a] + log[b]) % 255] : 0;
  let gen = [1];
  for (let i = 0; i < ecLen; i++) {
    const next = new Array(gen.length + 1).fill(0);
    gen.forEach((g, j) => { next[j] ^= g; next[j + 1] ^= mul(g, exp[i]); });
    gen = next;
  }
  const rs = block => {
    const res = new Array(ecLen).fill(0);
    for (const b of block) {
      const f = b ^ res.shift();
      res.push(0);
      gen.slice(1).forEach((g, j) => { res[j] ^= mul(g, f); });
    }
    return res;
  };
  const cw = [], per = dataLen / blocks, ecs = [];
  for (let b = 0; b < blocks; b++) ecs.push(rs(data.slice(b * per, (b + 1) * per)));
  for (let i = 0; i < per; i++) for (let b = 0; b < blocks; b++) cw.push(data[b * per + i]);
  for (let i = 0; i < ecLen; i++) for (let b = 0; b < blocks; b++) cw.push(ecs[b][i]);
  const m = Array.from({ length: n }, () => new Array(n).fill(-1));
  const set = (r, c, val) => { if (r >= 0 && r < n && c >= 0 && c < n) m[r][c] = val ? 1 : 0; };
  for (const [r0, c0] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
    for (let r = -1; r < 8; r++) for (let c = -1; c < 8; c++) set(r0 + r, c0 + c, r >= 0 && r < 7 && c >= 0 && c < 7 && Math.max(Math.abs(r - 3), Math.abs(c - 3)) != 2);
  }
  for (let i = 8; i < n - 8; i++) { set(6, i, i % 2 == 0); set(i, 6, i % 2 == 0); }
  if (v > 0) for (let r = -2; r < 3; r++) for (let c = -2; c < 3; c++) set(n - 7 + r, n - 7 + c, Math.max(Math.abs(r), Math.abs(c)) != 1);
  for (let i = 0; i < 15; i++) {
    const bit = (0x5412 >> i) & 1;
    if (i < 6) set(i, 8, bit); else if (i < 8) set(i + 1, 8, bit); else if (i == 8) set(8, 7, bit); else set(8, 14 - i, bit);
    if (i < 8) set(8, n - 1 - i, bit); else set(n - 15 + i, 8, bit);
  }
  set(n - 8, 8, 1);
  let i = 0;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right == 6) right = 5;
    for (let vert = 0; vert < n; vert++) for (let j = 0; j < 2; j++) {
      const c = right - j, r = ((right + 1) & 2) == 0 ? n - 1 - vert : vert;
      if (m[r][c] < 0) { m[r][c] = (i < cw.length * 8 ? (cw[i >> 3] >> (7 - (i & 7))) & 1 : 0) ^ ((r + c) % 2 == 0 ? 1 : 0); i++; }
    }
  }
  return m;
}
// drawQR draws the QR code for text on canvas, 6 pixels a module with a quiet zone of 4 modules.
function drawQR(canvas, text) {
  const m = qr(text), s = 6, q = 4;
  canvas.width = canvas.height = (m.length + 2 * q) * s;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  m.forEach((row, r) => row.forEach((d, c) => { if (d) ctx.fillRect((c + q) * s, (r + q) * s, s, s); }));
}
</script><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out'), list = document.getElementById('list'), nameInput = document.getElementById('name');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
async function answer() {
  const c = await post('/webapi/passkeys/challenge');
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: dec(c.challenge), rpId: c.rpId, timeout: c.timeout || undefined,
    userVerification: c.userVerification || 'required',
    allowCredentials: c.allowCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
  } });
  return {
    id: cred.id, rawId: enc(cred.rawId), type: cred.type, extensions: cred.getClientExtensionResults(),
    response: {
      authenticatorData: enc(cred.response.authenticatorData), clientDataJSON: enc(cred.response.clientDataJSON),
      signature: enc(cred.response.signature), userHandle: cred.response.userHandle ? enc(cred.response.userHandle) : null,
    },
  };
}
async function load() {
  const { passkeys } = await get('/webapi/passkeys');
  list.replaceChildren(...passkeys.map(p => {
    const tr = document.createElement('tr'), name = document.createElement('td'), added = document.createElement('td'), act = document.createElement('td');
    name.textContent = p.name;
    added.textContent = p.addedAt.slice(0, 10);
    act.className = 'act';
    const b = document.createElement('button');
    b.textContent = 'Remove';
    b.onclick = () => remove(p.name);
    act.append(b);
    tr.append(name, added, act);
    return tr;
  }));
}
async function run(f) {
  try { out.textContent = ''; await f(); await load(); } catch (e) { out.textContent = 'error: ' + e; }
}
function remove(name) {
  if (confirm('Remove ' + name + '?')) run(async () => { await post('/webapi/passkeys/delete', { name, assertion: await answer() }); });
}
document.getElementById('add').onclick = () => run(async () => {
  const a = await answer();
  const c = await post('/webapi/passkeys/begin', a);
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: dec(c.challenge), rp: c.rp,
    user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
    pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
    excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
    attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
  } });
  await post('/webapi/passkeys/finish', { name: nameInput.value, credential: {
    type: cred.type, rawId: enc(cred.rawId),
    response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
  } });
});
let hideOther;
document.getElementById('link').onclick = () => run(async () => {
  const r = await post('/webapi/passkeys/link', await answer());
  const a = document.getElementById('url'), other = document.getElementById('other'), expires = new Date(r.expires);
  a.href = a.textContent = r.url;
  drawQR(document.getElementById('qr'), r.url);
  document.getElementById('until').textContent = 'Valid until ' + expires.toLocaleTimeString() + '.';
  other.hidden = false;
  clearTimeout(hideOther);
  hideOther = setTimeout(() => { other.hidden = true; }, expires - Date.now());
});
nameInput.value = 'passkey ' + new Date().toISOString().slice(0, 10);
load().catch(e => { out.textContent = 'error: ' + e; });
</script>"##;

/// The page for the other device. It is the Go hub's page, byte for byte.
pub const ADD_PASSKEY_PAGE: &str = r##"<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport add passkey</title>
<p>Add a passkey for this device, then log in with it.</p>
<p><input id="name" maxlength="30" size="24"> <button id="go">Add a passkey</button></p><pre id="out"></pre><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out'), nameInput = document.getElementById('name');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
const token = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
document.getElementById('go').onclick = async () => {
  try {
    out.textContent = '';
    const c = await post('/webapi/add-passkey/begin', { token });
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: dec(c.challenge), rp: c.rp,
      user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
      pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
      excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
      attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
    } });
    await post('/webapi/add-passkey/finish', { token, name: nameInput.value, credential: {
      type: cred.type, rawId: enc(cred.rawId),
      response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
    } });
    location.href = '/web/login';
  } catch (e) { out.textContent = 'error: ' + e; }
};
nameInput.value = 'passkey ' + new Date().toISOString().slice(0, 10);
</script>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authrpc::{Metadata, MfaDevice, Timestamp, WebauthnDevice};

    fn status(code: &str, message: &str) -> CallError {
        CallError::Status {
            path: "/p".into(),
            http: 200,
            code: code.into(),
            message: message.into(),
        }
    }

    #[test]
    fn auth_error_status_cases() {
        for (err, want) in [
            (status("3", "bad name"), ("bad name", 400)),
            (status("5", "no device"), ("no device", 404)),
            (status("6", "used"), ("used", 409)),
            (status("7", "denied"), ("denied", 403)),
            (status("16", "who"), ("who", 401)),
            (status("7", ""), ("request refused", 403)),
            (
                status("8", "limit"),
                ("too many requests, try again in a minute", 429),
            ),
            (status("14", "unavailable"), ("request failed", 502)),
            (status("13", "internal"), ("request failed", 502)),
            (CallError::Other("eof".into()), ("request failed", 502)),
        ] {
            let got = auth_error_status(&err);
            assert_eq!((got.0.as_str(), got.1), want, "{err}");
        }
    }

    #[test]
    fn route_cases() {
        for (method, action, want) in [
            (Method::Get, "", Some(Action::List)),
            (Method::Post, "challenge", Some(Action::Challenge)),
            (Method::Post, "begin", Some(Action::Begin)),
            (Method::Post, "finish", Some(Action::Finish)),
            (Method::Post, "delete", Some(Action::Delete)),
            (Method::Post, "link", Some(Action::Link)),
            (Method::Get, "link", None),
            (Method::Post, "", None),
            (Method::Get, "challenge", None),
            (Method::Head, "", None),
            (Method::Post, "nope", None),
            (Method::Post, "/begin", None),
        ] {
            assert_eq!(route(&method, action), want, "{method:?} {action:?}");
        }
    }

    #[test]
    fn rfc3339_cases() {
        for (secs, want) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_788_264_000, "2026-09-01T12:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (4_107_542_399, "2100-02-28T23:59:59Z"),
            (-1, "1969-12-31T23:59:59Z"),
        ] {
            assert_eq!(rfc3339(secs), want, "{secs}");
        }
    }

    #[test]
    fn passkeys_of_keeps_webauthn_devices() {
        let device = |name: &str, secs: i64, webauthn: bool| MfaDevice {
            metadata: Some(Metadata {
                name: name.into(),
                expires: None,
            }),
            added_at: Some(Timestamp {
                seconds: secs,
                nanos: 0,
            }),
            webauthn: webauthn.then_some(WebauthnDevice {}),
        };
        let resp = GetMfaDevicesResponse {
            devices: vec![
                device("passkey", 1_788_264_000, true),
                device("totp", 0, false),
                device("laptop", 0, true),
            ],
        };
        let list = PasskeyList {
            passkeys: passkeys_of(&resp),
        };
        assert_eq!(
            serde_json::to_string(&list).unwrap(),
            r#"{"passkeys":[{"name":"passkey","addedAt":"2026-09-01T12:00:00Z"},{"name":"laptop","addedAt":"1970-01-01T00:00:00Z"}]}"#
        );
        let empty = PasskeyList {
            passkeys: passkeys_of(&GetMfaDevicesResponse::default()),
        };
        assert_eq!(serde_json::to_string(&empty).unwrap(), r#"{"passkeys":[]}"#);
    }

    #[test]
    fn assertion_decodes_as_go_does() {
        let a = decode::<AssertionJson>(
            br#"{"id":"x","rawId":"AQI","type":"","extensions":{},"response":{"clientDataJSON":"Aw","authenticatorData":"BA","signature":"BQ","userHandle":null}}"#,
        )
        .and_then(AssertionJson::proto)
        .unwrap();
        let w = a.webauthn.unwrap();
        assert_eq!(w.r#type, "public-key");
        assert_eq!(w.raw_id, vec![1, 2]);
        let r = w.response.unwrap();
        assert_eq!(
            (
                r.client_data_json,
                r.authenticator_data,
                r.signature,
                r.user_handle
            ),
            (vec![3], vec![4], vec![5], vec![])
        );
        for body in [&b"{}"[..], b"null", br#"{"response":null}"#] {
            assert!(
                decode::<AssertionJson>(body)
                    .and_then(AssertionJson::proto)
                    .is_some(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
        for body in [
            &b""[..],
            b"not json",
            b"[]",
            br#"{"response":[]}"#,
            br#"{} {}"#,
            br#"{"rawId":1}"#,
            br#"{"rawId":"AQ=="}"#,
            br#"{"rawId":"A+"}"#,
        ] {
            assert!(
                decode::<AssertionJson>(body)
                    .and_then(AssertionJson::proto)
                    .is_none(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
        // Go's RawURLEncoding accepts nonzero bits after the last byte.
        assert_eq!(unb64("AR"), Some(vec![1]));
    }

    #[test]
    fn finish_decodes_name_and_credential() {
        let f = decode::<FinishJson>(
            br#"{"name":"laptop","credential":{"type":"public-key","rawId":"AQ","response":{"clientDataJSON":"Ag","attestationObject":"Aw"}}}"#,
        )
        .unwrap();
        assert_eq!(f.name, "laptop");
        let c = f.credential.proto().unwrap();
        assert_eq!((c.r#type.as_str(), c.raw_id), ("public-key", vec![1]));
        let r = c.response.unwrap();
        assert_eq!(
            (r.client_data_json, r.attestation_object),
            (vec![2], vec![3])
        );
        assert!(decode::<FinishJson>(br#"{"name":1}"#).is_none());
        assert!(decode::<FinishJson>(br#"{"credential":{"rawId":"!"}}"#)
            .and_then(|f| f.credential.proto())
            .is_none());
    }

    #[test]
    fn valid_token_id_cases() {
        let ok = "0123456789abcdef0123456789abcdef";
        assert!(valid_token_id(ok));
        for id in [
            "",
            "tok-bob",
            &"a".repeat(31),
            &"a".repeat(33),
            &"A".repeat(32),
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcd\u{e9}",
        ] {
            assert!(!valid_token_id(id), "{id:?}");
        }
    }

    #[test]
    fn parse_add_cases() {
        let token = "0123456789abcdef0123456789abcdef";
        let add = parse_add(format!(r#"{{"token":"{token}"}}"#).as_bytes()).unwrap();
        assert_eq!((add.token.as_str(), add.name.as_str()), (token, ""));
        assert!(add.credential.proto().is_some());
        for (body, want) in [
            ("not json", ("bad request", 400)),
            ("[]", ("bad request", 400)),
            (r#"{"token":1}"#, ("bad request", 400)),
            ("{}", ("invalid token", 403)),
            ("null", ("invalid token", 403)),
            (r#"{"token":"tok-bob"}"#, ("invalid token", 403)),
        ] {
            assert_eq!(parse_add(body.as_bytes()).err(), Some(want), "{body}");
        }
    }

    #[test]
    fn used_until_is_five_minutes_on() {
        assert_eq!(used_until(1_000), 301_000);
    }

    #[test]
    fn link_keys_are_in_go_order() {
        let link = Link {
            expires: "2026-09-01T12:05:00Z".into(),
            url: "https://julia.example.com/web/add-passkey#t".into(),
        };
        assert_eq!(
            serde_json::to_string(&link).unwrap(),
            r#"{"expires":"2026-09-01T12:05:00Z","url":"https://julia.example.com/web/add-passkey#t"}"#
        );
    }

    #[test]
    fn token_locks_serialise_one_token() {
        use futures::executor::block_on;
        use futures::FutureExt as _;
        let locks = TokenLocks::default();
        let first = block_on(locks.lock("a"));
        let mut second = Box::pin(locks.lock("a"));
        assert!((&mut second).now_or_never().is_none());
        let other = block_on(locks.lock("b"));
        drop(other);
        drop(first);
        let second = second.now_or_never().expect("the second lock waits");
        assert_eq!(locks.held.borrow().len(), 1);
        drop(second);
        assert!(locks.held.borrow().is_empty());
    }

    #[test]
    fn token_locks_forget_a_dropped_waiter() {
        use futures::executor::block_on;
        use futures::FutureExt as _;
        let locks = TokenLocks::default();
        let first = block_on(locks.lock("a"));
        let mut waiter = Box::pin(locks.lock("a"));
        assert!((&mut waiter).now_or_never().is_none());
        drop(waiter);
        drop(first);
        assert!(locks.held.borrow().is_empty());
    }
}
