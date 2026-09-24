//! The Durable Object that terminates agent tunnels.
//!
//! An agent connection arrives as a WebSocket on
//! `/webapi/connectionupgrade` with subprotocol `alpn-ping`. Inside it the
//! agent runs TLS with ALPN `teleport-reversetunnel`, pinned to the cluster
//! host CA, and inside that SSH.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use russh::keys::ssh_key::{Certificate, PrivateKey, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::app::TunnelSlot;
use crate::authpipe;
use crate::ssh::{AgentHandler, Shared};
use worker::*;

/// The WebSocket subprotocol a stock agent asks for on reverse tunnel
/// connections (api/client/alpn.go).
const SUBPROTOCOL: &str = "alpn-ping";
/// The ALPN value the agent offers inside the upgraded connection.
const ALPN_REVERSE_TUNNEL: &[u8] = b"teleport-reversetunnel";
/// Buffer size of the in-memory pipe between the WebSocket and TLS.
pub const PIPE_BYTES: usize = 64 * 1024;
/// A connection that has not authenticated by then is closed. Without it an
/// unauthenticated client can hold a tunnel open forever.
const AUTH_DEADLINE: Duration = Duration::from_secs(30);
/// Open tunnels the Durable Object accepts. One app service uses about
/// three: its auth client, its tunnel, and a short-lived probe.
const MAX_CONNECTIONS: usize = 16;

#[durable_object]
pub struct Hub {
    env: Env,
    /// Open tunnels, for [`MAX_CONNECTIONS`]. The object is single-threaded.
    connections: Rc<Cell<usize>>,
    passthroughs: Arc<AtomicUsize>,
    app_tunnel: TunnelSlot,
    auth_pipe: authpipe::Pool,
}

impl DurableObject for Hub {
    fn new(_state: State, env: Env) -> Self {
        console_log!("hub: durable object started");
        Self {
            env,
            connections: Rc::new(Cell::new(0)),
            passthroughs: Arc::new(AtomicUsize::new(0)),
            app_tunnel: Default::default(),
            auth_pipe: Default::default(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match req.path().as_str() {
            crate::app::PATH => return crate::app::handle(&req, &self.env, &self.app_tunnel).await,
            authpipe::PATH => return authpipe::accept(&self.env, &self.auth_pipe),
            crate::s5::PATH => return crate::s5::handle(&self.env, &self.auth_pipe).await,
            p if p.starts_with(crate::s5login::LOGIN) => return crate::s5login::handle(req, &self.env, &self.auth_pipe).await,
            _ => {}
        }
        let protocols = req
            .headers()
            .get("Sec-WebSocket-Protocol")?
            .unwrap_or_default();
        if !protocols.split(',').any(|p| p.trim() == SUBPROTOCOL) {
            return Response::error("unsupported subprotocol", 400);
        }

        if self.connections.get() >= MAX_CONNECTIONS {
            console_log!("tunnel: connection limit reached");
            return Response::error("too many connections", 503);
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
        let connections = self.connections.clone();
        connections.set(connections.get() + 1);
        let bridge_ws = ws.clone();
        wasm_bindgen_futures::spawn_local(async move {
            bridge(bridge_ws, ws_side).await;
            connections.set(connections.get().saturating_sub(1));
        });

        let shared = Shared {
            authed: Arc::new(AtomicBool::new(false)),
            passthroughs: self.passthroughs.clone(),
            app_tunnel: self.app_tunnel.clone(),
            auth_pipe: self.auth_pipe.clone(),
        };
        let authed = shared.authed.clone();
        let deadline_ws = ws.clone();
        wasm_bindgen_futures::spawn_local(async move {
            worker::Delay::from(AUTH_DEADLINE).await;
            if !authed.load(Ordering::Relaxed) {
                console_log!("tunnel: not authenticated after {AUTH_DEADLINE:?}, closing");
                let _ = deadline_ws.close(Some(1008), Some("auth timeout"));
            }
        });
        let (ssh, proxy_name) = ssh_config(&self.env)?;
        let ssh = Arc::new(ssh);
        let handler = AgentHandler::new(
            host_ca(&self.env)?,
            self.env.var("CLUSTER_NAME")?.to_string(),
            proxy_name,
            shared,
        );
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(err) = serve(tls_side, tls, ssh, handler).await {
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
    let events = match ws.events() {
        Ok(events) => events,
        Err(err) => {
            console_error!("tunnel: websocket events: {err}");
            return;
        }
    };
    pump(&ws, events, pipe).await;
}

/// Copies bytes between a WebSocket, read from `events`, and one end of an
/// in-memory pipe until either side closes.
pub async fn pump(ws: &WebSocket, mut events: EventStream<'_>, pipe: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(pipe);

    let outbound = async move {
        let mut buf = vec![0u8; PIPE_BYTES];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws.send_with_bytes(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws.close(Some(1000), Some("pipe closed"));
    };

    let inbound = async move {
        while let Some(event) = events.next().await {
            match event {
                Ok(WebsocketEvent::Message(msg)) => {
                    let Some(bytes) = msg.bytes() else {
                        continue;
                    };
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

/// Runs TLS and then the reverse tunnel SSH server on one end of the pipe.
async fn serve(pipe: DuplexStream, tls: Arc<rustls::ServerConfig>, ssh: Arc<russh::server::Config>, handler: AgentHandler) -> std::result::Result<(), String> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let stream = acceptor.accept(pipe).await.map_err(|e| format!("tls accept: {e}"))?;
    let alpn = stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default();
    console_log!("tunnel: tls established, alpn {alpn:?}");

    let session = russh::server::run_stream(ssh, stream, handler)
        .await
        .map_err(|e| format!("ssh handshake: {e}"))?;
    session.await.map_err(|e| format!("ssh session: {e}"))?;
    console_log!("tunnel: ssh session ended");
    Ok(())
}

/// Builds the SSH server config: the hub host key presented with its
/// host-CA-signed certificate, which is the only form the agent accepts.
/// Also returns the proxy name, the host UUID in the cert's first principal.
fn ssh_config(env: &Env) -> Result<(russh::server::Config, String)> {
    let key = String::from_utf8(secret_bytes(env, "HUB_SSH_KEY")?).map_err(|e| Error::RustError(e.to_string()))?;
    let cert = String::from_utf8(secret_bytes(env, "HUB_SSH_CERT")?).map_err(|e| Error::RustError(e.to_string()))?;
    let key = PrivateKey::from_openssh(rewrap_openssh(&key)).map_err(|e| Error::RustError(format!("HUB_SSH_KEY: {e}")))?;
    let cert = Certificate::from_openssh(cert.trim()).map_err(|e| Error::RustError(format!("HUB_SSH_CERT: {e}")))?;
    let cluster = env.var("CLUSTER_NAME")?.to_string();
    let proxy_name = cert
        .valid_principals()
        .first()
        .map(|p| p.trim_end_matches(&format!(".{cluster}")).to_string())
        .ok_or_else(|| Error::RustError("HUB_SSH_CERT: no principals".into()))?;
    let config = russh::server::Config {
        keys: vec![key],
        host_certificates: vec![cert],
        // Timers are off: the agent drives keepalives, and hibernation is
        // not used, so an idle connection needs no server-side timeout.
        inactivity_timeout: None,
        keepalive_interval: None,
        // A delay on each rejected attempt, so failing auth is not a free
        // CPU loop. The handler also drops the connection after 3 attempts.
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    };
    Ok((config, proxy_name))
}

/// Re-wraps an OpenSSH private key at 70 columns. Go's PEM encoder wraps
/// at 64, and the ssh-key crate only accepts OpenSSH's own 70.
fn rewrap_openssh(pem: &str) -> String {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in body.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out
}

fn host_ca(env: &Env) -> Result<PublicKey> {
    let line = String::from_utf8(secret_bytes(env, "HOST_CA_SSH")?).map_err(|e| Error::RustError(e.to_string()))?;
    PublicKey::from_openssh(line.trim()).map_err(|e| Error::RustError(format!("HOST_CA_SSH: {e}")))
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
pub fn secret_bytes(env: &Env, name: &str) -> Result<Vec<u8>> {
    let value = env.secret(name)?.to_string();
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| Error::RustError(format!("{name}: {e}")))
}
