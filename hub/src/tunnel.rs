//! The Durable Object that terminates agent tunnels.
//!
//! An agent connection arrives as a WebSocket on
//! `/webapi/connectionupgrade` with subprotocol `alpn-ping`. Inside it the
//! agent runs TLS with ALPN `teleport-reversetunnel`, pinned to the cluster
//! host CA, and inside that SSH.

use std::sync::Arc;

use base64::Engine as _;
use futures::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use worker::*;

/// The WebSocket subprotocol a stock agent asks for on reverse tunnel
/// connections (api/client/alpn.go).
const SUBPROTOCOL: &str = "alpn-ping";
/// The ALPN value the agent offers inside the upgraded connection.
const ALPN_REVERSE_TUNNEL: &[u8] = b"teleport-reversetunnel";
/// Buffer size of the in-memory pipe between the WebSocket and TLS.
const PIPE_BYTES: usize = 64 * 1024;

#[durable_object]
pub struct Hub {
    env: Env,
}

impl DurableObject for Hub {
    fn new(_state: State, env: Env) -> Self {
        console_log!("hub: durable object started");
        Self { env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let protocols = req
            .headers()
            .get("Sec-WebSocket-Protocol")?
            .unwrap_or_default();
        if !protocols.split(',').any(|p| p.trim() == SUBPROTOCOL) {
            return Response::error("unsupported subprotocol", 400);
        }

        let tls = Arc::new(server_tls_config(&self.env)?);
        let pair = WebSocketPair::new()?;
        let ws = pair.server;
        // Newer compatibility dates deliver binary messages as Blob, which
        // workers-rs 0.8 reads as zero bytes. Ask for ArrayBuffer instead.
        worker::js_sys::Reflect::set(ws.as_ref(), &"binaryType".into(), &"arraybuffer".into())
            .map_err(|_| Error::RustError("setting binaryType".into()))?;
        ws.accept()?;

        let (ws_side, tls_side) = tokio::io::duplex(PIPE_BYTES);
        wasm_bindgen_futures::spawn_local(bridge(ws, ws_side));
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(err) = serve(tls_side, tls).await {
                console_error!("tunnel: {err}");
            }
        });

        let headers = Headers::new();
        headers.set("Sec-WebSocket-Protocol", SUBPROTOCOL)?;
        Ok(Response::from_websocket(pair.client)?.with_headers(headers))
    }
}

/// Copies bytes between the WebSocket and one end of an in-memory pipe
/// until either side closes.
async fn bridge(ws: WebSocket, pipe: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(pipe);

    let ws_out = ws.clone();
    let outbound = async move {
        let mut buf = vec![0u8; PIPE_BYTES];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    console_log!("tunnel: pipe -> ws {n} bytes");
                    if ws_out.send_with_bytes(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_out.close(Some(1000), Some("pipe closed"));
    };

    let inbound = async move {
        let mut events = match ws.events() {
            Ok(events) => events,
            Err(err) => {
                console_error!("tunnel: websocket events: {err}");
                return;
            }
        };
        while let Some(event) = events.next().await {
            match event {
                Ok(WebsocketEvent::Message(msg)) => {
                    let Some(bytes) = msg.bytes() else {
                        console_log!("tunnel: ws message without bytes, text {:?}", msg.text().map(|t| t.len()));
                        continue;
                    };
                    console_log!("tunnel: ws -> pipe {} bytes", bytes.len());
                    if wr.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Ok(WebsocketEvent::Close(close)) => {
                    console_log!("tunnel: websocket closed, code {}", close.code());
                    break;
                }
                Err(err) => {
                    console_error!("tunnel: websocket error: {err}");
                    break;
                }
            }
        }
        let _ = wr.shutdown().await;
    };

    futures::join!(outbound, inbound);
}

/// Runs the TLS server on one end of the pipe. SSH comes next; until then
/// this reads the agent's SSH identification line to prove the TLS layer.
async fn serve(pipe: DuplexStream, tls: Arc<rustls::ServerConfig>) -> std::result::Result<(), String> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let mut stream = acceptor.accept(pipe).await.map_err(|e| format!("tls accept: {e}"))?;
    let alpn = stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default();
    console_log!("tunnel: tls established, alpn {alpn:?}");

    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < 255 {
        stream.read_exact(&mut byte).await.map_err(|e| format!("read ssh id: {e}"))?;
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    console_log!("tunnel: agent ssh id {:?}", String::from_utf8_lossy(&line).trim_end());
    Ok(())
}

/// Builds the rustls server config from the hub TLS identity. The agent
/// verifies this certificate against the cluster host CA.
fn server_tls_config(env: &Env) -> Result<rustls::ServerConfig> {
    let cert_pem = secret_bytes(env, "HUB_TLS_CERT")?;
    let key_pem = secret_bytes(env, "HUB_TLS_KEY")?;

    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::RustError(format!("HUB_TLS_CERT: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| Error::RustError(format!("HUB_TLS_KEY: {e}")))?;

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::RustError(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| Error::RustError(format!("tls identity: {e}")))?;
    config.alpn_protocols = vec![ALPN_REVERSE_TUNNEL.to_vec()];
    Ok(config)
}

/// Reads a base64-encoded secret. Secrets are base64 so that multi-line
/// PEM survives `.dev.vars` and `wrangler secret put`.
fn secret_bytes(env: &Env, name: &str) -> Result<Vec<u8>> {
    let value = env.secret(name)?.to_string();
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| Error::RustError(format!("{name}: {e}")))
}
