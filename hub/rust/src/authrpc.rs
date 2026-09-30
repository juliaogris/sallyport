//! Unary gRPC calls to auth over an auth pipe stream.
//!
//! The hub runs TLS to auth with SNI `teleport.cluster.local` and ALPN
//! `h2`, verifies auth's cert against the cluster host CA, and presents a
//! client cert: the hub TLS identity or a user's cert. gRPC framing is
//! written by hand over the `h2` crate. Messages are `prost` structs with
//! only the fields the hub reads. prost skips the other fields.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use futures::future::{select, Either};
use futures::FutureExt;
use h2::client::SendRequest;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::DuplexStream;
use worker::*;

use crate::tunnel::secret_bytes;

/// The SNI that selects auth's default CA pool.
const AUTH_SNI: &str = "teleport.cluster.local";
const ALPN_H2: &[u8] = b"h2";
/// Every call to auth has this deadline.
pub const CALL_DEADLINE: Duration = Duration::from_secs(5);

pub const CREATE_APP_SESSION: &str = "/proto.AuthService/CreateAppSession";
pub const GET_APP_SESSION: &str = "/proto.AuthService/GetAppSession";
pub const CREATE_AUTHENTICATE_CHALLENGE: &str = "/proto.AuthService/CreateAuthenticateChallenge";
pub const GET_WEB_SESSION: &str = "/proto.AuthService/GetWebSession";
pub const CREATE_REGISTER_CHALLENGE: &str = "/proto.AuthService/CreateRegisterChallenge";
pub const CHANGE_USER_AUTHENTICATION: &str = "/proto.AuthService/ChangeUserAuthentication";
/// The legacy HTTP route for `AuthenticateWebUser`. A passwordless login has
/// an empty user, so the path has an empty segment, as the Go proxy sends it.
pub const AUTHENTICATE_WEB_USER_PASSWORDLESS: &str = "/v2/users//web/authenticate";

/// `teleport.mfa.v1.ChallengeScope` value for a passwordless login.
pub const SCOPE_PASSWORDLESS_LOGIN: i32 = 2;
/// `proto.DeviceType` value for WebAuthn.
pub const DEVICE_TYPE_WEBAUTHN: i32 = 3;
/// `proto.DeviceUsage` value for a passkey.
pub const DEVICE_USAGE_PASSWORDLESS: i32 = 2;

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateAuthenticateChallengeRequest {
    #[prost(message, optional, tag = "4")]
    pub passwordless: Option<Passwordless>,
    #[prost(message, optional, tag = "6")]
    pub challenge_extensions: Option<ChallengeExtensions>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Passwordless {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ChallengeExtensions {
    #[prost(int32, tag = "1")]
    pub scope: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MfaAuthenticateChallenge {
    #[prost(message, optional, tag = "3")]
    pub webauthn: Option<CredentialAssertion>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CredentialAssertion {
    #[prost(message, optional, tag = "1")]
    pub public_key: Option<RequestOptions>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RequestOptions {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: Vec<u8>,
    #[prost(int64, tag = "2")]
    pub timeout_ms: i64,
    #[prost(string, tag = "3")]
    pub rp_id: String,
    #[prost(message, repeated, tag = "4")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[prost(string, tag = "6")]
    pub user_verification: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CredentialDescriptor {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetWebSessionRequest {
    #[prost(string, tag = "1")]
    pub user: String,
    #[prost(string, tag = "2")]
    pub session_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateAppSessionRequest {
    #[prost(string, tag = "1")]
    pub username: String,
    #[prost(string, tag = "3")]
    pub public_addr: String,
    #[prost(string, tag = "4")]
    pub cluster_name: String,
    #[prost(string, tag = "9")]
    pub app_name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetAppSessionRequest {
    #[prost(string, tag = "1")]
    pub session_id: String,
}

/// The response of `CreateAppSession`, `GetAppSession` and `GetWebSession`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SessionResponse {
    #[prost(message, optional, tag = "1")]
    pub session: Option<WebSessionV2>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WebSessionV2 {
    #[prost(message, optional, tag = "4")]
    pub metadata: Option<Metadata>,
    #[prost(message, optional, tag = "5")]
    pub spec: Option<WebSessionSpecV2>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Metadata {
    #[prost(string, tag = "1")]
    pub name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WebSessionSpecV2 {
    #[prost(string, tag = "1")]
    pub user: String,
    #[prost(bytes = "vec", tag = "3")]
    pub priv_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub tls_cert: Vec<u8>,
    #[prost(string, tag = "5")]
    pub bearer_token: String,
    #[prost(message, optional, tag = "7")]
    pub expires: Option<Timestamp>,
    #[prost(bytes = "vec", tag = "15")]
    pub tls_priv: Vec<u8>,
}

/// `google.protobuf.Timestamp`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Timestamp {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

impl WebSessionSpecV2 {
    /// Returns true when the session has an expiry and it has not passed.
    pub fn unexpired(&self) -> bool {
        let now = (Date::now().as_millis() / 1000) as i64;
        self.expires.as_ref().is_some_and(|t| t.seconds > now)
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateRegisterChallengeRequest {
    #[prost(string, tag = "1")]
    pub token_id: String,
    #[prost(int32, tag = "2")]
    pub device_type: i32,
    #[prost(int32, tag = "3")]
    pub device_usage: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MfaRegisterChallenge {
    #[prost(message, optional, tag = "3")]
    pub webauthn: Option<CredentialCreation>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CredentialCreation {
    #[prost(message, optional, tag = "1")]
    pub public_key: Option<CreationOptions>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreationOptions {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub rp: Option<RelyingParty>,
    #[prost(message, optional, tag = "3")]
    pub user: Option<UserEntity>,
    #[prost(message, repeated, tag = "4")]
    pub credential_parameters: Vec<CredentialParameter>,
    #[prost(int64, tag = "5")]
    pub timeout_ms: i64,
    #[prost(message, repeated, tag = "6")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[prost(string, tag = "7")]
    pub attestation: String,
    #[prost(message, optional, tag = "9")]
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RelyingParty {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UserEntity {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub display_name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CredentialParameter {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(int32, tag = "2")]
    pub alg: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AuthenticatorSelection {
    #[prost(string, tag = "1")]
    pub authenticator_attachment: String,
    #[prost(bool, tag = "2")]
    pub require_resident_key: bool,
    #[prost(string, tag = "3")]
    pub user_verification: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ChangeUserAuthenticationRequest {
    #[prost(string, tag = "1")]
    pub token_id: String,
    #[prost(message, optional, tag = "3")]
    pub new_mfa_register_response: Option<MfaRegisterResponse>,
    #[prost(string, tag = "4")]
    pub new_device_name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MfaRegisterResponse {
    #[prost(message, optional, tag = "3")]
    pub webauthn: Option<CredentialCreationResponse>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CredentialCreationResponse {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    pub raw_id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub response: Option<AttestationResponse>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AttestationResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub client_data_json: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub attestation_object: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ChangeUserAuthenticationResponse {
    #[prost(message, optional, tag = "1")]
    pub web_session: Option<WebSessionV2>,
}

/// Builds a TLS client config toward auth with ALPN `h2`, with the client
/// cert and key in the named base64 PEM secrets.
pub fn tls_config(env: &Env, cert_secret: &str, key_secret: &str) -> Result<rustls::ClientConfig> {
    let mut config = http1_tls_config(env, cert_secret, key_secret)?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(config)
}

/// Builds the TLS client config for [`post_json`]: like [`tls_config`], but
/// with no ALPN.
pub fn http1_tls_config(
    env: &Env,
    cert_secret: &str,
    key_secret: &str,
) -> Result<rustls::ClientConfig> {
    client_tls(
        env,
        &secret_bytes(env, cert_secret)?,
        &secret_bytes(env, key_secret)?,
    )
    .map_err(|e| Error::RustError(format!("{cert_secret}: {e}")))
}

/// Builds a TLS client config toward auth from a PEM cert and key, with
/// ALPN `h2`.
pub fn tls_config_from_pem(
    env: &Env,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<rustls::ClientConfig> {
    let mut config = client_tls(env, cert_pem, key_pem)?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(config)
}

/// Builds a TLS client config that trusts the cluster host CA in the
/// `HOST_CA_TLS` secret and presents a PEM cert chain and key, with no
/// ALPN. Auth and the app service both have certificates from that CA.
pub fn client_tls(env: &Env, cert_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&secret_bytes(env, "HOST_CA_TLS")?) {
        let cert = cert.map_err(|e| Error::RustError(format!("HOST_CA_TLS: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| Error::RustError(format!("HOST_CA_TLS: {e}")))?;
    }
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::RustError(format!("cert: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| Error::RustError(format!("key: {e}")))?;
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::RustError(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::RustError(format!("client identity: {e}")))
}

/// Runs `fut` until it finishes or [`CALL_DEADLINE`] passes. On the
/// deadline, it drops `fut` and returns an error that names `what`.
async fn with_deadline<T, E: From<String>>(
    what: &str,
    fut: impl Future<Output = std::result::Result<T, E>>,
) -> std::result::Result<T, E> {
    match select(pin!(fut), pin!(crate::sockets::sleep(CALL_DEADLINE))).await {
        Either::Left((res, _)) => res,
        Either::Right(_) => Err(format!("{what}: no answer within {CALL_DEADLINE:?}").into()),
    }
}

/// Runs TLS and the HTTP/2 handshake on an auth pipe stream within
/// [`CALL_DEADLINE`]. The returned sender makes calls until the stream
/// closes.
pub async fn connect(
    stream: DuplexStream,
    tls: Arc<rustls::ClientConfig>,
) -> std::result::Result<SendRequest<Bytes>, String> {
    with_deadline("connect to auth", connect_inner(stream, tls)).await
}

async fn connect_inner(
    stream: DuplexStream,
    tls: Arc<rustls::ClientConfig>,
) -> std::result::Result<SendRequest<Bytes>, String> {
    let name = ServerName::try_from(AUTH_SNI).map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(tls)
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls to auth: {e}"))?;
    let alpn = tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec();
    if alpn != ALPN_H2 {
        return Err(format!(
            "auth chose ALPN {:?}, want h2",
            String::from_utf8_lossy(&alpn)
        ));
    }
    let (send, conn) = h2::client::handshake(tls)
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(err) = conn.await {
            console_log!("authrpc: h2 connection ended: {err}");
        }
    });
    Ok(send)
}

/// The error of a call to auth.
#[derive(Debug)]
pub enum CallError {
    /// Auth answered with a gRPC status other than OK.
    Status {
        path: String,
        http: u16,
        code: String,
        message: String,
    },
    /// Any other failure: the transport, the deadline, or a response the hub
    /// cannot decode.
    Other(String),
}

/// gRPC status `RESOURCE_EXHAUSTED`, which auth returns when a client
/// address makes too many login or invite calls.
const GRPC_RESOURCE_EXHAUSTED: &str = "8";

impl CallError {
    /// Returns true when auth refused the call because of its rate limit.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, CallError::Status { code, .. } if code == GRPC_RESOURCE_EXHAUSTED)
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Status {
                path,
                http,
                code,
                message,
            } => write!(f, "{path}: http {http}, grpc-status {code:?}: {message}"),
            CallError::Other(err) => f.write_str(err),
        }
    }
}

impl From<String> for CallError {
    fn from(err: String) -> Self {
        CallError::Other(err)
    }
}

impl From<&str> for CallError {
    fn from(err: &str) -> Self {
        CallError::Other(err.to_string())
    }
}

/// Makes one unary call within [`CALL_DEADLINE`].
pub async fn unary<Req: prost::Message, Resp: prost::Message + Default>(
    send: &SendRequest<Bytes>,
    path: &str,
    req: &Req,
) -> std::result::Result<Resp, CallError> {
    with_deadline(path, unary_inner(send.clone(), path, req)).await
}

async fn unary_inner<Req: prost::Message, Resp: prost::Message + Default>(
    send: SendRequest<Bytes>,
    path: &str,
    req: &Req,
) -> std::result::Result<Resp, CallError> {
    let mut frame = BytesMut::with_capacity(5 + req.encoded_len());
    frame.put_u8(0);
    frame.put_u32(req.encoded_len() as u32);
    req.encode(&mut frame).map_err(|e| format!("{path}: {e}"))?;

    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{AUTH_SNI}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| format!("{path}: {e}"))?;
    let mut send = send.ready().await.map_err(|e| format!("{path}: {e}"))?;
    let (response, mut body_tx) = send
        .send_request(request, false)
        .map_err(|e| format!("{path}: {e}"))?;
    body_tx
        .send_data(frame.freeze(), true)
        .map_err(|e| format!("{path}: {e}"))?;

    let response = response.await.map_err(|e| format!("{path}: {e}"))?;
    let (parts, mut body) = response.into_parts();
    let mut data = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("{path}: {e}"))?;
        let _ = body.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
    }
    let trailers = body.trailers().await.map_err(|e| format!("{path}: {e}"))?;
    // A call that fails before any data sends its status in the headers.
    let status_from = trailers.as_ref().unwrap_or(&parts.headers);
    let status = status_from
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if status != "0" {
        let message = status_from
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        return Err(CallError::Status {
            path: path.to_string(),
            http: parts.status.as_u16(),
            code: status.to_string(),
            message: percent_decode(message),
        });
    }
    let msg = unframe(&data).map_err(|e| format!("{path}: {e}"))?;
    Resp::decode(msg).map_err(|e| format!("{path}: {e}").into())
}

/// Returns the message in the first gRPC frame of `data`: a zero
/// compression flag, a 4-byte big-endian length, and the message.
fn unframe(data: &[u8]) -> std::result::Result<&[u8], String> {
    let Some((&[0, a, b, c, d], rest)) = data.split_first_chunk::<5>() else {
        return Err("bad gRPC frame".into());
    };
    let len = u32::from_be_bytes([a, b, c, d]) as usize;
    rest.get(..len).ok_or_else(|| "short gRPC frame".into())
}

/// Sends one JSON `POST` to auth's legacy HTTP API on its own stream,
/// within [`CALL_DEADLINE`]. Auth's TLS offers only `h2`, and `h2` goes to
/// gRPC, so this runs HTTP/1.1, and `tls` must have no ALPN, as from
/// [`http1_tls_config`]. Returns the HTTP status and the body.
pub async fn post_json(
    stream: DuplexStream,
    tls: Arc<rustls::ClientConfig>,
    path: &str,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    with_deadline(path, post_json_inner(stream, tls, path, body)).await
}

async fn post_json_inner(
    stream: DuplexStream,
    tls: Arc<rustls::ClientConfig>,
    path: &str,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let name = ServerName::try_from(AUTH_SNI).map_err(|e| e.to_string())?;
    let mut tls = tokio_rustls::TlsConnector::from(tls)
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls to auth: {e}"))?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {AUTH_SNI}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes())
        .await
        .map_err(|e| format!("{path}: {e}"))?;
    tls.write_all(&body)
        .await
        .map_err(|e| format!("{path}: {e}"))?;
    let mut resp = Vec::new();
    match tls.read_to_end(&mut resp).await {
        Ok(_) => {}
        // Auth may close without a TLS close_notify.
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(err) => return Err(format!("{path}: {err}")),
    }
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("{path}: no HTTP header end"))?;
    let head = String::from_utf8_lossy(&resp[..end]).to_ascii_lowercase();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("{path}: bad status line"))?;
    let body = &resp[end + 4..];
    let body = if head.contains("transfer-encoding: chunked") {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

/// Decodes an HTTP/1.1 chunked body.
fn dechunk(mut b: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line = b.windows(2).position(|w| w == b"\r\n").ok_or("bad chunk")?;
        let size = std::str::from_utf8(&b[..line]).map_err(|e| e.to_string())?;
        let size = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| e.to_string())?;
        b = &b[line + 2..];
        if size == 0 {
            return Ok(out);
        }
        // `size` comes from the peer, so `size + 2` can wrap on wasm32.
        let (Some(chunk), Some(rest)) = (
            b.get(..size),
            size.checked_add(2).and_then(|end| b.get(end..)),
        ) else {
            return Err("short chunk".into());
        };
        out.extend_from_slice(chunk);
        b = rest;
    }
}

/// Decodes the percent-encoding gRPC uses in `grpc-message`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One HTTP/2 connection to auth with the hub TLS identity, reused across
/// calls. A call that fails at the transport opens a new connection from
/// the pool and is retried once. A gRPC error status is not retried. When
/// the pool has no stream, opening a connection waits up to
/// [`crate::authpipe::TAKE_WAIT`] for auth to open one.
///
/// The lock is held while a connection opens, so callers that arrive
/// together share one connection instead of each taking a pool stream.
/// The wait for a stream and [`connect`] each have a deadline, so the lock
/// is held for at most their sum.
#[derive(Clone, Default)]
pub struct HubAuth {
    cached: Arc<futures::lock::Mutex<Cached>>,
}

#[derive(Default)]
struct Cached {
    /// Counts connections opened.
    generation: u64,
    send: Option<SendRequest<Bytes>>,
}

impl HubAuth {
    /// Returns the cached connection and its generation, unless it has
    /// closed. When `broken` names the cached generation, that connection
    /// failed, so a new one is opened. A caller whose broken connection
    /// another caller already replaced gets the replacement.
    async fn conn(
        &self,
        env: &Env,
        pool: &crate::authpipe::Pool,
        broken: Option<u64>,
    ) -> std::result::Result<(u64, SendRequest<Bytes>), String> {
        let mut cached = self.cached.lock().await;
        if let Some(send) = cached.send.clone() {
            // `ready` waits when the connection is at its stream limit, so
            // it is polled once. A closed connection fails at once. A
            // connection that is open but stalled fails in the call, and
            // the call asks for a new one.
            let closed = matches!(send.clone().ready().now_or_never(), Some(Err(_)));
            if broken != Some(cached.generation) && !closed {
                return Ok((cached.generation, send));
            }
        }
        cached.send = None;
        let tls =
            Arc::new(tls_config(env, "HUB_TLS_CERT", "HUB_TLS_KEY").map_err(|e| e.to_string())?);
        let send = connect(pool.take_wait().await?, tls).await?;
        cached.generation += 1;
        cached.send = Some(send.clone());
        Ok((cached.generation, send))
    }

    /// Makes one unary call with the hub identity.
    pub async fn call<Req: prost::Message, Resp: prost::Message + Default>(
        &self,
        env: &Env,
        pool: &crate::authpipe::Pool,
        path: &str,
        req: &Req,
    ) -> std::result::Result<Resp, CallError> {
        let (generation, send) = self.conn(env, pool, None).await?;
        match unary(&send, path, req).await {
            Err(err @ CallError::Other(_)) => {
                console_log!("authrpc: {err}, reconnecting");
                let (_, send) = self.conn(env, pool, Some(generation)).await?;
                unary(&send, path, req).await
            }
            res => res,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_error_rate_limit_is_status_8() {
        let status = |code: &str| CallError::Status {
            path: "/p".into(),
            http: 200,
            code: code.into(),
            message: "m".into(),
        };
        assert!(status("8").is_rate_limited());
        assert!(!status("14").is_rate_limited());
        assert!(!CallError::Other("grpc-status \"8\"".into()).is_rate_limited());
        assert_eq!(
            status("8").to_string(),
            "/p: http 200, grpc-status \"8\": m"
        );
    }

    #[test]
    fn dechunk_joins_chunks() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap(),
            b"abcde"
        );
    }

    #[test]
    fn dechunk_ignores_chunk_extensions() {
        assert_eq!(dechunk(b"5;ext=1\r\nhello\r\n0\r\n\r\n").unwrap(), b"hello");
    }

    #[test]
    fn dechunk_rejects_bad_input() {
        let cases: &[(&str, &[u8])] = &[
            ("no CRLF after the size", b"3abc"),
            ("size is not hex", b"zz\r\nabc\r\n0\r\n\r\n"),
            ("size past the body", b"10\r\nabc\r\n0\r\n\r\n"),
            ("no CRLF after the data", b"3\r\nabc"),
            ("32-bit maximum size", b"ffffffff\r\nabc\r\n0\r\n\r\n"),
            (
                "64-bit maximum size",
                b"ffffffffffffffff\r\nabc\r\n0\r\n\r\n",
            ),
        ];
        for (name, input) in cases {
            assert!(dechunk(input).is_err(), "{name}");
        }
    }

    #[test]
    fn percent_decode_decodes_escapes() {
        assert_eq!(percent_decode("a%41b"), "aAb");
        assert_eq!(percent_decode("100%25"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("trailing %4"), "trailing %4");
        assert_eq!(percent_decode("%"), "%");
    }

    #[test]
    fn unframe_returns_the_message() {
        assert_eq!(unframe(&[0, 0, 0, 0, 2, 7, 8]).unwrap(), &[7, 8]);
        assert_eq!(unframe(&[0, 0, 0, 0, 0]).unwrap(), &[] as &[u8]);
        // Bytes after the first frame are not part of the message.
        assert_eq!(unframe(&[0, 0, 0, 0, 1, 7, 8]).unwrap(), &[7]);
    }

    #[test]
    fn unframe_rejects_bad_frames() {
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("short header", &[0, 0, 0, 1]),
            ("compressed", &[1, 0, 0, 0, 1, 7]),
            ("length past the end", &[0, 0, 0, 0, 3, 7, 8]),
            ("maximum length", &[0, 0xff, 0xff, 0xff, 0xff, 7]),
        ];
        for (name, data) in cases {
            assert!(unframe(data).is_err(), "{name}");
        }
    }
}
