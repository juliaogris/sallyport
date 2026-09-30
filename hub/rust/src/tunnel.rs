//! The Durable Object that terminates agent tunnels.
//!
//! An agent connection arrives as a WebSocket on
//! `/webapi/connectionupgrade` with subprotocol `alpn-ping`. Inside it the
//! agent runs TLS with ALPN `teleport-reversetunnel`, pinned to the cluster
//! host CA, and inside that SSH.

use std::cell::Cell;
use std::collections::VecDeque;
use std::pin::pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures::channel::oneshot;
use futures::future::{select, Either};
use futures::StreamExt;
use russh::keys::ssh_key::{Certificate, PrivateKey, PublicKey};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::app::TunnelSlot;
use crate::authpipe;
use crate::ssh::{AgentHandler, Shared};
use worker::*;

/// The WebSocket subprotocol a stock agent asks for on reverse tunnel
/// connections (api/client/alpn_conn_upgrade.go).
const SUBPROTOCOL: &str = "alpn-ping";
/// The ALPN value the agent offers inside the upgraded connection.
const ALPN_REVERSE_TUNNEL: &[u8] = b"teleport-reversetunnel";
/// Buffer size of the in-memory pipe between the WebSocket and TLS.
pub const PIPE_BYTES: usize = 64 * 1024;
/// A connection that has not authenticated by then is closed. Without it an
/// unauthenticated client can hold a tunnel open forever. A stock agent
/// finishes TLS and SSH auth in well under this.
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
/// Authenticated tunnels the Durable Object accepts. One app service uses
/// about three: its auth client, its tunnel, and a short-lived probe.
const MAX_CONNECTIONS: usize = 16;
/// Tunnels that have not authenticated, which do not count toward
/// [`MAX_CONNECTIONS`]. A new one above this closes the oldest, so clients
/// that never authenticate cannot keep a redialing agent out.
const MAX_UNAUTHENTICATED: usize = 8;
/// Messages queued per SSH channel before the channel is closed.
const CHANNEL_BUFFER: usize = 256;
/// How often the hub logs its counters.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(60);

#[durable_object]
pub struct Hub {
    env: Env,
    /// Open tunnels, for [`MAX_CONNECTIONS`]. The object is single-threaded.
    connections: Rc<Cell<usize>>,
    /// The open tunnels that have not authenticated.
    unauthenticated: Pending,
    /// Passthroughs to auth, for [`crate::ssh::MAX_PASSTHROUGHS_TOTAL`]. It
    /// is atomic because russh requires the SSH handler to be `Send`.
    passthroughs: Arc<AtomicUsize>,
    app_tunnel: TunnelSlot,
    auth_pipe: authpipe::Pool,
    hub_auth: crate::authrpc::HubAuth,
}

impl DurableObject for Hub {
    fn new(_state: State, env: Env) -> Self {
        // After a trap, the WebSockets and timers of the previous Wasm
        // instance are still live. The peers redial once their WebSockets
        // close.
        let timers = crate::sockets::clear_timers();
        let stale = crate::sockets::close_all();
        console_log!("hub: durable object started, closed {stale} WebSockets and {timers} timers of the previous instance");
        if let Some(msg) = crate::sockets::take_last_panic() {
            console_error!("hub: the previous instance panicked: {msg}");
        }
        let hub = Self {
            env,
            connections: Rc::new(Cell::new(0)),
            unauthenticated: Pending::default(),
            passthroughs: Arc::new(AtomicUsize::new(0)),
            app_tunnel: Default::default(),
            auth_pipe: Default::default(),
            hub_auth: Default::default(),
        };
        wasm_bindgen_futures::spawn_local(heartbeat(
            hub.connections.clone(),
            hub.unauthenticated.clone(),
            hub.passthroughs.clone(),
            hub.app_tunnel.clone(),
            hub.auth_pipe.clone(),
        ));
        hub
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let host = req.url()?.host_str().unwrap_or_default().to_string();
        // The login host is also the agents' `PUBLIC_ADDR` and auth's
        // `CALLOUT_HOST`, so the agent and auth reach these paths on it.
        // They are not browser requests.
        let peer_path = matches!(
            req.path().as_str(),
            "/webapi/connectionupgrade" | authpipe::PATH
        );
        if let Some(kind) = crate::web::classify(&self.env, &host) {
            let cx = crate::web::Ctx {
                env: &self.env,
                pool: &self.auth_pipe,
                auth: &self.hub_auth,
                tunnel: &self.app_tunnel,
            };
            match kind {
                crate::web::Host::App(app) => {
                    return crate::web::app_host_request(req, &cx, &app).await
                }
                crate::web::Host::Login if !peer_path => {
                    return crate::web::login_host_request(req, &cx).await
                }
                crate::web::Host::Login => {}
            }
        }
        match req.path().as_str() {
            authpipe::PATH => return authpipe::accept(&req, &self.env, &self.auth_pipe),
            #[cfg(feature = "spikes")]
            crate::s4::PATH => return crate::s4::handle(&req, &self.env, &self.app_tunnel).await,
            #[cfg(feature = "spikes")]
            crate::s5::PATH => return crate::s5::handle(&self.env, &self.auth_pipe).await,
            #[cfg(feature = "spikes")]
            p if p.starts_with(crate::s5login::LOGIN) => {
                return crate::s5login::handle(req, &self.env, &self.auth_pipe).await
            }
            _ => {}
        }
        let protocols = req
            .headers()
            .get("Sec-WebSocket-Protocol")?
            .unwrap_or_default();
        if !protocols.split(',').any(|p| p.trim() == SUBPROTOCOL) {
            return Response::error("unsupported subprotocol", 400);
        }

        // A stock agent sends no `Origin`, and a browser always sends one.
        // Refusing it keeps web pages from using their visitors to fill the
        // slots below.
        if req.headers().get("Origin")?.is_some() {
            return Response::error("origin not allowed", 403);
        }
        let authenticated = self
            .connections
            .get()
            .saturating_sub(self.unauthenticated.waiting());
        if authenticated >= MAX_CONNECTIONS {
            console_log!("tunnel: connection limit reached");
            return Response::error("too many connections", 503);
        }
        // Load the config before any state changes, so that a bad secret
        // leaves nothing behind.
        let tls = Arc::new(server_tls_config(&self.env)?);
        let (ssh, proxy_name) = ssh_config(&self.env)?;
        let ssh = Arc::new(ssh);
        let host_ca = host_ca(&self.env)?;
        let cluster = self.env.var("CLUSTER_NAME")?.to_string();

        let pair = WebSocketPair::new()?;
        let ws = pair.server;
        // Newer compatibility dates deliver binary messages as Blob, which
        // workers-rs 0.8 reads as zero bytes. Ask for ArrayBuffer instead.
        worker::js_sys::Reflect::set(ws.as_ref(), &"binaryType".into(), &"arraybuffer".into())
            .map_err(|_| Error::RustError("setting binaryType".into()))?;
        ws.accept()?;

        let (ticket, evicted, evicted_one) = self.unauthenticated.admit(MAX_UNAUTHENTICATED);
        if evicted_one {
            console_log!(
                "tunnel: {MAX_UNAUTHENTICATED} connections not authenticated, closed the oldest"
            );
        }
        let (ws_side, tls_side) = tokio::io::duplex(PIPE_BYTES);
        let connections = self.connections.clone();
        connections.set(connections.get() + 1);
        let bridge_ws = ws.clone();
        wasm_bindgen_futures::spawn_local(async move {
            bridge(bridge_ws, ws_side).await;
            connections.set(connections.get().saturating_sub(1));
        });

        let shared = Shared {
            passthroughs: self.passthroughs.clone(),
            app_tunnel: self.app_tunnel.clone(),
            auth_pipe: self.auth_pipe.clone(),
        };
        let authed = Arc::new(AtomicBool::new(false));
        let handler =
            AgentHandler::new(host_ca, cluster, proxy_name, shared, authed.clone(), ticket);
        wasm_bindgen_futures::spawn_local(async move {
            let session = pin!(serve(tls_side, tls, ssh, handler));
            // Resolves at the deadline, when a newer connection evicts this
            // one, or when the handler drops its ticket after auth.
            let watch = pin!(async {
                match select(pin!(crate::sockets::sleep(AUTH_DEADLINE)), evicted).await {
                    Either::Left(_) => format!("not authenticated after {AUTH_DEADLINE:?}"),
                    Either::Right(_) => {
                        "closed for a newer connection that is not authenticated".to_string()
                    }
                }
            });
            let res = match select(session, watch).await {
                Either::Left((res, _)) => res,
                Either::Right((_, session)) if authed.load(Ordering::Relaxed) => session.await,
                // Dropping the session drops the pipe, which ends the bridge
                // and frees the connection's slot.
                Either::Right((reason, _)) => {
                    console_log!("tunnel: {reason}, closing");
                    let _ = ws.close(Some(1008), Some("auth timeout"));
                    return;
                }
            };
            if let Err(err) = res {
                console_error!("tunnel: {err}");
            }
        });

        let headers = Headers::new();
        headers.set("Sec-WebSocket-Protocol", SUBPROTOCOL)?;
        Ok(Response::from_websocket(pair.client)?.with_headers(headers))
    }
}

/// Logs the hub's counters every [`HEARTBEAT_EVERY`], so that `wrangler
/// tail` shows whether the object is alive and what it holds.
async fn heartbeat(
    connections: Rc<Cell<usize>>,
    unauthenticated: Pending,
    passthroughs: Arc<AtomicUsize>,
    app_tunnel: TunnelSlot,
    auth_pipe: authpipe::Pool,
) {
    loop {
        crate::sockets::sleep(HEARTBEAT_EVERY).await;
        let last = crate::ssh::LAST_DISCOVERY_MS.load(Ordering::Relaxed);
        let discovery = if last == 0 {
            "never".to_string()
        } else {
            format!(
                "{}s ago",
                Date::now().as_millis().saturating_sub(last) / 1000
            )
        };
        console_log!(
            "hub: heartbeat, {} tunnels ({} not authenticated), app tunnel {}, auth streams {} open {} ready {} in the challenge, {} passthroughs, discovery {discovery}, memory {} MiB",
            connections.get(),
            unauthenticated.waiting(),
            if app_tunnel.lock().unwrap().is_some() { "up" } else { "down" },
            auth_pipe.open(),
            auth_pipe.ready(),
            auth_pipe.unverified(),
            passthroughs.load(Ordering::Relaxed),
            wasm_memory_mib(),
        );
    }
}

/// Returns the size of the Wasm linear memory. It grows and never shrinks,
/// so it is the peak the instance has needed.
fn wasm_memory_mib() -> usize {
    #[cfg(target_arch = "wasm32")]
    return core::arch::wasm32::memory_size(0) * 64 / 1024;
    #[cfg(not(target_arch = "wasm32"))]
    return 0;
}

/// Copies bytes between the WebSocket and one end of an in-memory pipe
/// until either side closes.
async fn bridge(ws: WebSocket, pipe: DuplexStream) {
    let events = match crate::wsevents::events(&ws) {
        Ok(events) => events,
        Err(err) => {
            console_error!("tunnel: websocket events: {err}");
            return;
        }
    };
    pump(&ws, events, pipe).await;
}

/// Copies bytes between a WebSocket, read from `events`, and one end of an
/// in-memory pipe until either side closes. When it returns, the pipe end
/// is dropped, so the far end reads EOF.
pub async fn pump(ws: &WebSocket, events: crate::wsevents::Events, pipe: DuplexStream) {
    crate::sockets::add(ws);
    pump_inner(ws, events, pipe).await;
    crate::sockets::remove(ws);
}

async fn pump_inner(ws: &WebSocket, mut events: crate::wsevents::Events, pipe: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(pipe);

    let outbound = async move {
        let mut buf = vec![0u8; PIPE_BYTES];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Err(err) => {
                    console_error!("tunnel: pipe read: {err}");
                    break;
                }
                Ok(n) => {
                    if let Err(err) = ws.send_with_bytes(&buf[..n]) {
                        console_error!("tunnel: websocket send: {err}");
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
                    if let Err(err) = wr.write_all(&bytes).await {
                        console_error!("tunnel: pipe write: {err}");
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

    // A stream that waits in the auth pipe pool has nobody reading or
    // writing its far end. When the WebSocket closes, only `inbound` ends,
    // so waiting for both would never return.
    select(pin!(outbound), pin!(inbound)).await;
}

/// Runs TLS and then the reverse tunnel SSH server on one end of the pipe.
async fn serve(
    pipe: DuplexStream,
    tls: Arc<rustls::ServerConfig>,
    ssh: Arc<russh::server::Config>,
    handler: AgentHandler,
) -> std::result::Result<(), String> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let stream = acceptor
        .accept(pipe)
        .await
        .map_err(|e| format!("tls accept: {e}"))?;
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
    let key = secret_string(env, "HUB_SSH_KEY")?;
    let cert = secret_string(env, "HUB_SSH_CERT")?;
    let key = PrivateKey::from_openssh(rewrap_openssh(&key))
        .map_err(|e| Error::RustError(format!("HUB_SSH_KEY: {e}")))?;
    let cert = Certificate::from_openssh(cert.trim())
        .map_err(|e| Error::RustError(format!("HUB_SSH_CERT: {e}")))?;
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
        // CPU loop. The handler also drops the connection after
        // `MAX_AUTH_FAILURES` attempts.
        auth_rejection_time: Duration::from_secs(1),
        // The patched russh closes a channel whose reader falls this many
        // messages behind, up to 32 KiB each, so one slow browser cannot
        // stall the tunnel. 256 allows a lag of up to 8 MiB.
        channel_buffer_size: CHANNEL_BUFFER,
        ..Default::default()
    };
    Ok((config, proxy_name))
}

/// Re-wraps an OpenSSH private key at 70 columns. Go's PEM encoder wraps
/// at 64, and the ssh-key crate only accepts OpenSSH's own 70.
fn rewrap_openssh(pem: &str) -> String {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in body.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out
}

fn host_ca(env: &Env) -> Result<PublicKey> {
    let line = secret_string(env, "HOST_CA_SSH")?;
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

/// Reads a base64-encoded secret that is UTF-8 text.
fn secret_string(env: &Env, name: &str) -> Result<String> {
    String::from_utf8(secret_bytes(env, name)?)
        .map_err(|e| Error::RustError(format!("{name}: {e}")))
}

/// Connections that have not proved who they are, oldest first. Each one
/// holds a [`Ticket`] until it has.
#[derive(Clone, Default)]
pub struct Pending {
    inner: Arc<Mutex<PendingInner>>,
}

#[derive(Default)]
struct PendingInner {
    next: u64,
    /// Each connection's ID and the sender that evicts it.
    queue: VecDeque<(u64, oneshot::Sender<()>)>,
}

/// One connection's place in [`Pending`]. Dropping it removes the
/// connection.
pub struct Ticket {
    id: u64,
    pending: Pending,
}

impl Pending {
    /// Adds a connection. If `cap` connections are already waiting, it
    /// evicts the oldest first. Returns the new connection's ticket, a
    /// receiver, and true if it evicted one. The receiver resolves with
    /// `Ok(())` when a later call evicts this connection, and with an error
    /// once the ticket is dropped.
    pub fn admit(&self, cap: usize) -> (Ticket, oneshot::Receiver<()>, bool) {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().unwrap();
        let mut evicted = false;
        while inner.queue.len() >= cap.max(1) {
            if let Some((_, evict)) = inner.queue.pop_front() {
                let _ = evict.send(());
                evicted = true;
            }
        }
        let id = inner.next;
        inner.next += 1;
        inner.queue.push_back((id, tx));
        (
            Ticket {
                id,
                pending: self.clone(),
            },
            rx,
            evicted,
        )
    }

    /// Returns the number of connections waiting.
    pub fn waiting(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.pending
            .inner
            .lock()
            .unwrap()
            .queue
            .retain(|(id, _)| *id != self.id);
    }
}

/// Reads a base64-encoded secret. Secrets are base64 so that multi-line
/// PEM survives `.dev.vars` and `wrangler secret put`.
pub fn secret_bytes(env: &Env, name: &str) -> Result<Vec<u8>> {
    let value = env.secret(name)?.to_string();
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| Error::RustError(format!("{name}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn pending_counts_until_the_ticket_drops() {
        let pending = Pending::default();
        let (a, mut a_rx, evicted) = pending.admit(2);
        assert!(!evicted);
        assert_eq!(pending.waiting(), 1);
        drop(a);
        assert_eq!(pending.waiting(), 0);
        assert!(block_on(&mut a_rx).is_err());
    }

    #[test]
    fn pending_evicts_the_oldest_at_the_cap() {
        let pending = Pending::default();
        let (_a, a_rx, _) = pending.admit(2);
        let (_b, mut b_rx, _) = pending.admit(2);
        let (_c, mut c_rx, evicted) = pending.admit(2);
        assert!(evicted);
        assert_eq!(pending.waiting(), 2);
        assert_eq!(block_on(a_rx), Ok(()));
        assert_eq!(b_rx.try_recv(), Ok(None));
        assert_eq!(c_rx.try_recv(), Ok(None));
    }

    #[test]
    fn pending_ticket_of_an_evicted_connection_removes_nothing() {
        let pending = Pending::default();
        let (a, _a_rx, _) = pending.admit(1);
        let (_b, _b_rx, _) = pending.admit(1);
        drop(a);
        assert_eq!(pending.waiting(), 1);
    }

    #[test]
    fn rewrap_openssh_wraps_at_70_columns() {
        let body: String = (0..150)
            .map(|i| char::from(b'A' + (i % 26) as u8))
            .collect();
        let wrap = |width: usize, eol: &str| {
            let mut pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----{eol}");
            for chunk in body.as_bytes().chunks(width) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push_str(eol);
            }
            pem.push_str(&format!("-----END OPENSSH PRIVATE KEY-----{eol}"));
            pem
        };
        let want = wrap(70, "\n");
        assert_eq!(rewrap_openssh(&wrap(64, "\n")), want);
        assert_eq!(rewrap_openssh(&want), want);
        assert_eq!(rewrap_openssh(&wrap(64, "\r\n")), want);
    }
}
