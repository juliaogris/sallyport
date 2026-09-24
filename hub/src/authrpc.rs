//! Unary gRPC calls to auth over an auth pipe stream.
//!
//! The hub runs TLS to auth with SNI `teleport.cluster.local` and ALPN
//! `h2`, verifies auth's cert against the cluster host CA, and presents a
//! client cert: the hub TLS identity or a user's cert. gRPC framing is
//! written by hand over the `h2` crate. Messages are `prost` structs with
//! only the fields the hub reads. prost skips the other fields.

use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use futures::future::{select, Either};
use h2::client::SendRequest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::io::DuplexStream;
use worker::*;

use crate::tunnel::secret_bytes;

/// The SNI that selects auth's default CA pool.
const AUTH_SNI: &str = "teleport.cluster.local";
const ALPN_H2: &[u8] = b"h2";
/// Every call to auth has this deadline.
pub const CALL_DEADLINE: Duration = Duration::from_secs(5);

pub const PING: &str = "/proto.AuthService/Ping";
pub const GET_CLUSTER_NAME: &str = "/teleport.clusterconfig.v1.ClusterConfigService/GetClusterName";
pub const CREATE_APP_SESSION: &str = "/proto.AuthService/CreateAppSession";
pub const GET_APP_SESSION: &str = "/proto.AuthService/GetAppSession";
pub const CREATE_AUTHENTICATE_CHALLENGE: &str = "/proto.AuthService/CreateAuthenticateChallenge";
pub const GET_WEB_SESSION: &str = "/proto.AuthService/GetWebSession";
/// The legacy HTTP route for `AuthenticateWebUser`. A passwordless login has
/// an empty user, so the path has an empty segment, as the Go proxy sends it.
pub const AUTHENTICATE_WEB_USER_PASSWORDLESS: &str = "/v2/users//web/authenticate";

/// `teleport.mfa.v1.ChallengeScope` value for a passwordless login.
pub const SCOPE_PASSWORDLESS_LOGIN: i32 = 2;

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
pub struct PingRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PingResponse {
    #[prost(string, tag = "1")]
    pub cluster_name: String,
    #[prost(string, tag = "2")]
    pub server_version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetClusterNameRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterNameV2 {
    #[prost(message, optional, tag = "5")]
    pub spec: Option<ClusterNameSpecV2>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterNameSpecV2 {
    #[prost(string, tag = "1")]
    pub cluster_name: String,
    #[prost(string, tag = "2")]
    pub cluster_id: String,
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

/// The response of both `CreateAppSession` and `GetAppSession`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct AppSessionResponse {
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

pub const CREATE_REGISTER_CHALLENGE: &str = "/proto.AuthService/CreateRegisterChallenge";
pub const CHANGE_USER_AUTHENTICATION: &str = "/proto.AuthService/ChangeUserAuthentication";
/// `proto.DeviceType` value for WebAuthn.
pub const DEVICE_TYPE_WEBAUTHN: i32 = 3;
/// `proto.DeviceUsage` value for a passkey.
pub const DEVICE_USAGE_PASSWORDLESS: i32 = 2;

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

/// Builds a TLS client config toward auth, with the client cert and key in
/// the named base64 PEM secrets.
pub fn tls_config(env: &Env, cert_secret: &str, key_secret: &str) -> Result<rustls::ClientConfig> {
    tls_config_from_pem(env, &secret_bytes(env, cert_secret)?, &secret_bytes(env, key_secret)?)
        .map_err(|e| Error::RustError(format!("{cert_secret}: {e}")))
}

/// Builds a TLS client config toward auth from a PEM cert and key.
pub fn tls_config_from_pem(env: &Env, cert_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ClientConfig> {
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
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| Error::RustError(format!("key: {e}")))?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::RustError(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::RustError(format!("client identity: {e}")))?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(config)
}

/// Runs TLS and the HTTP/2 handshake on an auth pipe stream. The returned
/// sender makes calls until the stream closes.
pub async fn connect(stream: DuplexStream, tls: Arc<rustls::ClientConfig>) -> std::result::Result<SendRequest<Bytes>, String> {
    let name = ServerName::try_from(AUTH_SNI).map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(tls)
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls to auth: {e}"))?;
    let alpn = tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec();
    if alpn != ALPN_H2 {
        return Err(format!("auth chose ALPN {:?}, want h2", String::from_utf8_lossy(&alpn)));
    }
    let (send, conn) = h2::client::handshake(tls).await.map_err(|e| format!("h2 handshake: {e}"))?;
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(err) = conn.await {
            console_log!("authrpc: h2 connection ended: {err}");
        }
    });
    Ok(send)
}

/// Makes one unary call within [`CALL_DEADLINE`]. The error is the gRPC
/// status and message, or the transport error.
pub async fn unary<Req: prost::Message, Resp: prost::Message + Default>(send: &SendRequest<Bytes>, path: &str, req: &Req) -> std::result::Result<Resp, String> {
    let call = Box::pin(unary_inner(send.clone(), path, req));
    match select(call, Box::pin(Delay::from(CALL_DEADLINE))).await {
        Either::Left((res, _)) => res,
        Either::Right(_) => Err(format!("{path}: no answer within {CALL_DEADLINE:?}")),
    }
}

async fn unary_inner<Req: prost::Message, Resp: prost::Message + Default>(send: SendRequest<Bytes>, path: &str, req: &Req) -> std::result::Result<Resp, String> {
    let mut frame = BytesMut::with_capacity(5 + req.encoded_len());
    frame.put_u8(0);
    frame.put_u32(req.encoded_len() as u32);
    req.encode(&mut frame).map_err(|e| e.to_string())?;

    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{AUTH_SNI}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| e.to_string())?;
    let mut send = send.ready().await.map_err(|e| format!("{path}: {e}"))?;
    let (response, mut body_tx) = send.send_request(request, false).map_err(|e| format!("{path}: {e}"))?;
    body_tx.send_data(frame.freeze(), true).map_err(|e| format!("{path}: {e}"))?;

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
    let status = status_from.get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("");
    if status != "0" {
        let message = status_from.get("grpc-message").and_then(|v| v.to_str().ok()).unwrap_or("");
        return Err(format!("{path}: http {}, grpc-status {status:?}: {}", parts.status, percent_decode(message)));
    }
    if data.len() < 5 || data[0] != 0 {
        return Err(format!("{path}: bad gRPC frame"));
    }
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() < 5 + len {
        return Err(format!("{path}: short gRPC frame"));
    }
    Resp::decode(&data[5..5 + len]).map_err(|e| format!("{path}: {e}"))
}

/// Sends one JSON `POST` to auth's legacy HTTP API on its own stream,
/// within [`CALL_DEADLINE`]. Auth's TLS offers only `h2`, and `h2` goes to
/// gRPC, so this runs TLS with no ALPN and HTTP/1.1. Returns the HTTP status
/// and the body.
pub async fn post_json(stream: DuplexStream, tls: &rustls::ClientConfig, path: &str, body: Vec<u8>) -> std::result::Result<(u16, Vec<u8>), String> {
    let mut tls = tls.clone();
    tls.alpn_protocols.clear();
    let call = Box::pin(post_json_inner(stream, Arc::new(tls), path, body));
    match select(call, Box::pin(Delay::from(CALL_DEADLINE))).await {
        Either::Left((res, _)) => res,
        Either::Right(_) => Err(format!("{path}: no answer within {CALL_DEADLINE:?}")),
    }
}

async fn post_json_inner(stream: DuplexStream, tls: Arc<rustls::ClientConfig>, path: &str, body: Vec<u8>) -> std::result::Result<(u16, Vec<u8>), String> {
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
    tls.write_all(head.as_bytes()).await.map_err(|e| format!("{path}: {e}"))?;
    tls.write_all(&body).await.map_err(|e| format!("{path}: {e}"))?;
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
    let body = if head.contains("transfer-encoding: chunked") { dechunk(body)? } else { body.to_vec() };
    Ok((status, body))
}

/// Decodes an HTTP/1.1 chunked body.
fn dechunk(mut b: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line = b.windows(2).position(|w| w == b"\r\n").ok_or("bad chunk")?;
        let size = std::str::from_utf8(&b[..line]).map_err(|e| e.to_string())?;
        let size = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16).map_err(|e| e.to_string())?;
        b = &b[line + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size + 2 {
            return Err("short chunk".into());
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
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
