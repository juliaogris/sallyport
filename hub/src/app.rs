//! The hub as a TLS client to the app service, over the agent's tunnel.
//!
//! The hub opens `teleport-transport` into the agent with an `@local-node`
//! dial request, then runs TLS with the user's app session certificate.
//! The app service picks the app and the session from that certificate.
//!
//! S4 only: `/spike/s4?path=<path>` sends one `GET` for `path` and answers
//! with the status and the time taken. The session certificate comes from
//! `appsessmint` in the `S4_APP_CERT` and `S4_APP_KEY` secrets.

use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::*;

use crate::ssh::{AppTunnel, CHAN_TRANSPORT, REQ_DIAL};
use crate::tunnel::secret_bytes;

/// The dev-only endpoint that runs one request through the tunnel.
pub const PATH: &str = "/spike/s4";
/// The SNI suffix the app service expects after the hex cluster name
/// (api/utils/cluster.go, EncodeClusterName).
const API_DOMAIN: &str = "teleport.cluster.local";
/// Read buffer for the response body.
const READ_BYTES: usize = 64 * 1024;

/// The authenticated `App` connection the hub dials apps through. The
/// newest connection replaces the previous one. S4 has one agent.
pub type TunnelSlot = Arc<Mutex<Option<AppTunnel>>>;

/// Answers `/spike/s4`. Off unless `DEV_S4` is "1".
pub async fn handle(req: &Request, env: &Env, slot: &TunnelSlot) -> Result<Response> {
    let enabled = env.var("DEV_S4").map(|v| v.to_string() == "1").unwrap_or(false);
    if !enabled {
        return Response::error("not found", 404);
    }
    let url = req.url()?;
    let path = url
        .query_pairs()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| "/".into());
    if !path.starts_with('/') || path.contains(['\r', '\n', ' ']) {
        return Response::error("bad path", 400);
    }
    let Some(tunnel) = slot.lock().unwrap().clone() else {
        return Response::error("no app tunnel", 503);
    };
    let host = env.var("S4_APP_HOST")?.to_string();
    let cluster = env.var("CLUSTER_NAME")?.to_string();
    let tls = Arc::new(client_tls_config(env)?);
    match get(&tunnel, tls, &cluster, &host, &path).await {
        Ok(res) => Response::from_json(&res),
        Err(err) => {
            console_error!("app: {err}");
            Response::error(err, 502)
        }
    }
}

/// Sends one `GET` to the app service through the tunnel and reads the
/// whole response. Returns the status line, the body size and the timing.
async fn get(tunnel: &AppTunnel, tls: Arc<rustls::ClientConfig>, cluster: &str, host: &str, path: &str) -> std::result::Result<serde_json::Value, String> {
    let start = Date::now().as_millis();
    let ch = tunnel
        .handle
        .channel_open_custom(CHAN_TRANSPORT, Vec::new())
        .await
        .map_err(|e| format!("transport open: {e}"))?;
    let dial = json!({
        "address": "@local-node",
        "server_id": tunnel.server_id,
        "conn_type": "app",
    });
    let accepted = ch
        .request_custom(REQ_DIAL, true, dial.to_string().into_bytes())
        .await
        .map_err(|e| format!("dial request: {e}"))?;
    if !accepted {
        return Err("dial refused by agent".into());
    }
    let dialed = Date::now().as_millis();

    let sni = format!("{}.{API_DOMAIN}", hex(cluster.as_bytes()));
    let name = ServerName::try_from(sni.clone()).map_err(|e| format!("sni {sni:?}: {e}"))?;
    let mut stream = tokio_rustls::TlsConnector::from(tls)
        .connect(name, ch.into_stream())
        .await
        .map_err(|e| format!("tls connect: {e}"))?;
    let handshook = Date::now().as_millis();

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write request: {e}"))?;

    // Keep the head for the status line and count the rest as body.
    let mut head = Vec::new();
    let mut in_head = true;
    let mut body_bytes: usize = 0;
    let mut buf = vec![0u8; READ_BYTES];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            // The app service may close without a TLS close_notify.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(format!("read response: {err}")),
        };
        if !in_head {
            body_bytes += n;
            continue;
        }
        head.extend_from_slice(&buf[..n]);
        if let Some(end) = head_end(&head) {
            in_head = false;
            body_bytes = head.len() - end;
            head.truncate(end);
        }
    }
    let done = Date::now().as_millis();

    let head = String::from_utf8_lossy(&head);
    let status = head.lines().next().unwrap_or_default().to_string();
    let transfer_ms = done.saturating_sub(handshook).max(1);
    let mb_per_s = body_bytes as f64 / (1024.0 * 1024.0) / (transfer_ms as f64 / 1000.0);
    console_log!("app: GET {path} {status:?}, {body_bytes} bytes in {transfer_ms} ms, {mb_per_s:.2} MB/s");
    Ok(json!({
        "status": status,
        "body_bytes": body_bytes,
        "dial_ms": dialed - start,
        "tls_ms": handshook - dialed,
        "transfer_ms": transfer_ms,
        "mb_per_s": (mb_per_s * 100.0).round() / 100.0,
    }))
}

/// Returns the offset just past the blank line that ends the headers.
fn head_end(head: &[u8]) -> Option<usize> {
    head.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Builds the TLS client config: the app service's cert must chain to the
/// cluster host CA, and the hub presents the user's app session cert.
fn client_tls_config(env: &Env) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&secret_bytes(env, "HOST_CA_TLS")?) {
        let cert = cert.map_err(|e| Error::RustError(format!("HOST_CA_TLS: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| Error::RustError(format!("HOST_CA_TLS: {e}")))?;
    }
    let certs = CertificateDer::pem_slice_iter(&secret_bytes(env, "S4_APP_CERT")?)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::RustError(format!("S4_APP_CERT: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&secret_bytes(env, "S4_APP_KEY")?)
        .map_err(|e| Error::RustError(format!("S4_APP_KEY: {e}")))?;

    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::RustError(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::RustError(format!("app session identity: {e}")))
}
