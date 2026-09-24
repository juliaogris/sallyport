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
    #[prost(bytes = "vec", tag = "15")]
    pub tls_priv: Vec<u8>,
}

/// Builds a TLS client config toward auth, with the client cert and key in
/// the named base64 PEM secrets.
pub fn tls_config(env: &Env, cert_secret: &str, key_secret: &str) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&secret_bytes(env, "HOST_CA_TLS")?) {
        let cert = cert.map_err(|e| Error::RustError(format!("HOST_CA_TLS: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| Error::RustError(format!("HOST_CA_TLS: {e}")))?;
    }
    let certs = CertificateDer::pem_slice_iter(&secret_bytes(env, cert_secret)?)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::RustError(format!("{cert_secret}: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&secret_bytes(env, key_secret)?)
        .map_err(|e| Error::RustError(format!("{key_secret}: {e}")))?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::RustError(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::RustError(format!("{cert_secret}: {e}")))?;
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
