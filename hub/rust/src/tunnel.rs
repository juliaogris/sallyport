//! The Durable Object that terminates agent tunnels.
//!
//! An agent connection arrives as a WebSocket on
//! `/webapi/connectionupgrade` with subprotocol `alpn-ping`. Inside it the
//! agent runs TLS with ALPN `teleport-reversetunnel`, pinned to the cluster
//! host CA, and inside that SSH.

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::pin::pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use crate::web;
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
const AUTH_DEADLINE: Duration = Duration::from_secs(30);
/// Authenticated tunnels the Durable Object accepts. One app service uses
/// about three: its auth client, its tunnel, and a short-lived probe.
const MAX_CONNECTIONS: usize = 16;
/// Tunnels that have not authenticated, which do not count toward
/// [`MAX_CONNECTIONS`]. A new one above this closes the oldest tunnel of
/// the client address with the most waiting, so clients that never
/// authenticate cannot keep a redialing agent out.
const MAX_UNAUTHENTICATED: usize = 8;
/// Messages queued per SSH channel before the channel is closed.
const CHANNEL_BUFFER: usize = 256;
/// WebSocket messages and bytes through all pumps since the last heartbeat,
/// so that the heartbeat shows the message rate a tunnel carries.
static WS_IN_MSGS: AtomicU64 = AtomicU64::new(0);
static WS_IN_BYTES: AtomicU64 = AtomicU64::new(0);
static WS_OUT_MSGS: AtomicU64 = AtomicU64::new(0);
static WS_OUT_BYTES: AtomicU64 = AtomicU64::new(0);
/// The longest and the total time, in ms, that inbound writes into the pipe
/// waited for room since the last heartbeat.
static PIPE_WAIT_MAX_MS: AtomicU64 = AtomicU64::new(0);
static PIPE_WAIT_TOTAL_MS: AtomicU64 = AtomicU64::new(0);
/// How often the hub logs its counters.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(60);

#[durable_object]
pub struct Hub {
    env: Env,
    /// Open tunnels, authenticated or not. Those not in `unauthenticated`
    /// count toward [`MAX_CONNECTIONS`]. The object is single-threaded.
    connections: Rc<Cell<usize>>,
    /// The open tunnels that have not authenticated.
    unauthenticated: Pending,
    /// Passthroughs to auth, for [`crate::ssh::MAX_PASSTHROUGHS_TOTAL`]. It
    /// is atomic because russh requires the SSH handler to be `Send`.
    passthroughs: Arc<AtomicUsize>,
    app_tunnel: TunnelSlot,
    auth_pipe: authpipe::Pool,
    hub_auth: crate::authrpc::HubAuth,
    /// The privilege tokens that have added a passkey.
    used_tokens: crate::passkeys::UsedTokens,
    /// The lazy hub, when `HUB_MODE` is `lazy`.
    lazy: Option<Rc<crate::lazy::Lazy>>,
    /// True when `HUB_MODE` is `lazy` but the lazy hub failed to install.
    lazy_misconfigured: bool,
}

impl DurableObject for Hub {
    fn new(state: State, env: Env) -> Self {
        // After a trap, the WebSockets and timers of the previous Wasm
        // instance are still live. The peers redial once their WebSockets
        // close.
        let timers = crate::sockets::clear_timers();
        let stale = crate::sockets::close_all();
        console_log!("hub: durable object started, closed {stale} WebSockets and {timers} timers of the previous instance");
        if let Some(msg) = crate::sockets::take_last_panic() {
            console_error!("hub: the previous instance panicked: {msg}");
        }
        crate::lazy::clear();
        let used_tokens = crate::passkeys::UsedTokens::new(state.storage().sql());
        // The lazy hub starts no timers, so that the object can hibernate.
        let lazy_mode = crate::lazy::enabled(&env);
        let lazy = if lazy_mode {
            match crate::lazy::Lazy::install(state, &env) {
                Ok(l) => Some(l),
                Err(err) => {
                    console_error!("lazy: the lazy hub is misconfigured, answering 503: {err}");
                    None
                }
            }
        } else {
            None
        };
        let hub = Self {
            env,
            connections: Rc::new(Cell::new(0)),
            unauthenticated: Pending::default(),
            passthroughs: Arc::new(AtomicUsize::new(0)),
            app_tunnel: Default::default(),
            auth_pipe: Default::default(),
            hub_auth: Default::default(),
            used_tokens,
            lazy_misconfigured: lazy_mode && lazy.is_none(),
            lazy,
        };
        // A misconfigured lazy hub must not run as the full hub either.
        if lazy_mode {
            return hub;
        }
        wasm_bindgen_futures::spawn_local(heartbeat(
            hub.connections.clone(),
            hub.unauthenticated.clone(),
            hub.passthroughs.clone(),
            hub.app_tunnel.clone(),
            hub.auth_pipe.clone(),
        ));
        hub
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        match &self.lazy {
            Some(lazy) => lazy.on_message(ws, message),
            None => {
                let _ = ws.close(Some(1011), Some("no handler"));
                Ok(())
            }
        }
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        console_log!("lazy: control socket closed, code {code} {reason:?}");
        // The runtime completes the close handshake only when the object
        // closes its end too.
        let _ = ws.close(Some(1000), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, error: Error) -> Result<()> {
        console_log!("lazy: control socket error: {error}");
        Ok(())
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if self.lazy_misconfigured {
            return Response::error("lazy hub misconfigured", 503);
        }
        let host = req.url()?.host_str().unwrap_or_default().to_string();
        // The login host is also the agents' `PUBLIC_ADDR` and auth's
        // `CALLOUT_HOST`, so the agent and auth reach these paths on it.
        // They are not browser requests.
        let peer_path = matches!(
            req.path().as_str(),
            "/webapi/connectionupgrade" | authpipe::PATH
        );
        if let Some(kind) = web::classify(&self.env, &host) {
            let cx = web::Ctx {
                env: &self.env,
                pool: &self.auth_pipe,
                auth: &self.hub_auth,
                tunnel: &self.app_tunnel,
                used_tokens: &self.used_tokens,
            };
            match kind {
                web::Host::App(app) => return web::app_host_request(req, &cx, &app).await,
                web::Host::Login if !peer_path => return web::login_host_request(req, &cx).await,
                web::Host::Login => {}
            }
        }
        if let Some(lazy) = &self.lazy {
            // The lazy hub has no reverse tunnel and no auth pipe pool.
            if req.path() != authpipe::PATH {
                return Response::error("not found", 404);
            }
            let mode = req
                .url()?
                .query_pairs()
                .find(|(k, _)| k == "mode")
                .map(|(_, v)| v.to_string());
            return match mode.as_deref() {
                Some("control") => lazy.accept_control(&req),
                Some("stream") => lazy.accept_stream(&req),
                _ => Response::error("not found", 404),
            };
        }
        if req.path() == authpipe::PATH {
            return authpipe::accept(&req, &self.env, &self.auth_pipe);
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
        // connection slots.
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

        let (ticket, evict_rx, evicted_other) = self
            .unauthenticated
            .admit(MAX_UNAUTHENTICATED, &client_key(&req)?);
        if evicted_other {
            console_log!(
                "tunnel: {MAX_UNAUTHENTICATED} connections not authenticated, closed the busiest client's oldest"
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
                match select(pin!(crate::sockets::sleep(AUTH_DEADLINE)), evict_rx).await {
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
    let mut prev = Date::now().as_millis();
    loop {
        crate::sockets::sleep(HEARTBEAT_EVERY).await;
        // A heartbeat that fires late shows that the event loop was busy.
        let now = Date::now().as_millis();
        let late = now
            .saturating_sub(prev)
            .saturating_sub(HEARTBEAT_EVERY.as_millis() as u64);
        prev = now;
        let (queue_max, queue_wait_max) = crate::wsevents::take_stats();
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
            "hub: heartbeat, {} tunnels ({} not authenticated), app tunnel {}, auth streams {} open {} ready {} in the challenge, {} passthroughs, discovery {discovery}, memory {} MiB, websocket in {} msgs {} bytes, out {} msgs {} bytes, queue max {queue_max} wait max {queue_wait_max} ms, pipe wait max {} total {} ms, late {late} ms",
            connections.get(),
            unauthenticated.waiting(),
            if app_tunnel.lock().unwrap().is_some() { "up" } else { "down" },
            auth_pipe.open(),
            auth_pipe.ready(),
            auth_pipe.unverified(),
            passthroughs.load(Ordering::Relaxed),
            wasm_memory_mib(),
            WS_IN_MSGS.swap(0, Ordering::Relaxed),
            WS_IN_BYTES.swap(0, Ordering::Relaxed),
            WS_OUT_MSGS.swap(0, Ordering::Relaxed),
            WS_OUT_BYTES.swap(0, Ordering::Relaxed),
            PIPE_WAIT_MAX_MS.swap(0, Ordering::Relaxed),
            PIPE_WAIT_TOTAL_MS.swap(0, Ordering::Relaxed),
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
    pump(&ws, events, pipe, PumpMode::Tunnel).await;
}

/// How [`pump`] runs.
#[derive(Clone, Copy, Debug)]
pub enum PumpMode {
    /// A tunnel or an auth pipe stream. The WebSocket closes when the pipe
    /// closes.
    Tunnel,
    /// A lazy hub stream, which serves one connection. When the hub's end
    /// stops writing, the pump keeps reading until the WebSocket closes,
    /// because the far end may still be sending: an HTTP/1.1 client shuts
    /// down its write side while the response arrives. The pump sends
    /// `ack <n>` after every [`crate::lazy::ACK_EVERY`] bytes it passes on
    /// to the pipe, and it closes the WebSocket when no bytes have crossed
    /// in either direction for `idle`. With `window`, the far end acks what
    /// it receives the same way, and the pump keeps at most
    /// [`crate::lazy::UPLOAD_WINDOW`] bytes sent and not acked. An ack that
    /// is not a number, goes backwards, or is above the bytes sent closes
    /// the WebSocket with 1008.
    Stream { idle: Duration, window: bool },
}

/// Copies bytes between a WebSocket, read from `events`, and one end of an
/// in-memory pipe until either side closes, as `mode` says. When it
/// returns, the pipe end is dropped, so the far end reads EOF.
pub async fn pump(
    ws: &WebSocket,
    mut events: crate::wsevents::Events,
    pipe: DuplexStream,
    mode: PumpMode,
) {
    let (half_close, idle, window) = match mode {
        PumpMode::Tunnel => (false, None, false),
        PumpMode::Stream { idle, window } => (true, Some(idle), window),
    };
    // The bytes sent and the far end's latest ack of them, with `window`.
    let sent = Cell::new(0u64);
    let peer_acked = Cell::new(0u64);
    let ack_arrived = tokio::sync::Notify::new();
    let delivered = Cell::new(0u64);
    let acked = Cell::new(0u64);
    let (mut rd, mut wr) = tokio::io::split(pipe);
    let started = Date::now().as_millis();
    let last_any = Cell::new(started);
    let out_msgs = Cell::new(0u64);
    let in_msgs = Cell::new(0u64);
    let in_largest = Cell::new(0usize);
    let last_in = Cell::new(started);
    let pipe_wait_max = Cell::new(0u64);

    let outbound = async {
        let mut buf = vec![0u8; PIPE_BYTES];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Err(err) => {
                    console_error!("tunnel: pipe read: {err}");
                    break;
                }
                Ok(n) => {
                    while window
                        && sent.get() + n as u64 - peer_acked.get() > crate::lazy::UPLOAD_WINDOW
                    {
                        ack_arrived.notified().await;
                    }
                    sent.set(sent.get() + n as u64);
                    if let Err(err) = ws.send_with_bytes(&buf[..n]) {
                        console_error!("tunnel: websocket send: {err}");
                        break;
                    }
                    out_msgs.set(out_msgs.get() + 1);
                    last_any.set(Date::now().as_millis());
                    WS_OUT_MSGS.fetch_add(1, Ordering::Relaxed);
                    WS_OUT_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        if !half_close {
            let _ = ws.close(Some(1000), Some("pipe closed"));
        }
    };

    let inbound = async {
        let mut close_code = None;
        while let Some(event) = events.next().await {
            match event {
                Ok(WebsocketEvent::Message(msg)) => {
                    let Some(bytes) = msg.bytes() else {
                        if !window {
                            continue;
                        }
                        match msg.text().as_deref().and_then(parse_ack) {
                            Some(n) if n >= peer_acked.get() && n <= sent.get() => {
                                peer_acked.set(n);
                                ack_arrived.notify_one();
                                continue;
                            }
                            _ => {
                                let _ = ws.close(Some(1008), Some("bad ack"));
                                close_code = Some("1008, a bad ack".to_string());
                                break;
                            }
                        }
                    };
                    in_msgs.set(in_msgs.get() + 1);
                    in_largest.set(in_largest.get().max(bytes.len()));
                    WS_IN_MSGS.fetch_add(1, Ordering::Relaxed);
                    WS_IN_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    let before = Date::now().as_millis();
                    last_in.set(before);
                    last_any.set(before);
                    let written = wr.write_all(&bytes).await;
                    let wait = Date::now().as_millis().saturating_sub(before);
                    pipe_wait_max.set(pipe_wait_max.get().max(wait));
                    PIPE_WAIT_MAX_MS.fetch_max(wait, Ordering::Relaxed);
                    PIPE_WAIT_TOTAL_MS.fetch_add(wait, Ordering::Relaxed);
                    if let Err(err) = written {
                        console_error!("tunnel: pipe write: {err}");
                        break;
                    }
                    // A lazy stream has no flow control of its own, so the
                    // sender keeps at most a window unacknowledged. Without
                    // it, a fast sender fills the buffer between it and the
                    // hub, and the runtime drops the WebSocket.
                    if half_close {
                        delivered.set(delivered.get() + bytes.len() as u64);
                        if delivered.get() - acked.get() >= crate::lazy::ACK_EVERY {
                            acked.set(delivered.get());
                            let _ = ws.send_with_str(format!("ack {}", delivered.get()));
                        }
                    }
                }
                Ok(WebsocketEvent::Close(close)) => {
                    close_code = Some(format!(
                        "{} reason {:?} clean {}",
                        close.code(),
                        close.reason(),
                        close.was_clean()
                    ));
                    break;
                }
                Err(err) => {
                    console_error!("tunnel: websocket error: {err}");
                    break;
                }
            }
        }
        let (queue_max, queue_wait_max) = events.stats();
        let _ = wr.shutdown().await;
        (close_code, queue_max, queue_wait_max)
    };

    let idle_watch = async {
        let Some(idle) = idle else {
            return futures::future::pending::<()>().await;
        };
        loop {
            // Polls, so a stream ends up to 5 s after `idle`.
            crate::sockets::sleep(Duration::from_secs(5)).await;
            if Date::now().as_millis().saturating_sub(last_any.get()) >= idle.as_millis() as u64 {
                let _ = ws.close(Some(1000), Some("idle"));
                return;
            }
        }
    };
    let outbound = pin!(outbound);
    let inbound = pin!(inbound);
    // A stream that waits in the auth pipe pool has nobody reading or
    // writing its far end. When the WebSocket closes, only `inbound` ends,
    // so waiting for both would never return.
    let main = async {
        match select(outbound, inbound).await {
            // A half-closing stream keeps reading until the WebSocket closes.
            Either::Left(((), inbound)) if half_close => inbound.await,
            Either::Left(((), _)) => (Some("none, the pipe closed first".to_string()), 0, 0),
            Either::Right((stats, _)) => stats,
        }
    };
    let (close_code, queue_max, queue_wait_max) = match select(pin!(main), pin!(idle_watch)).await {
        Either::Left((stats, _)) => stats,
        Either::Right(_) => (Some(format!("idle for {idle:?}")), 0, 0),
    };
    // A half-closing stream can end without a close, for example after a
    // pipe write error when the hub's end was dropped. An open WebSocket
    // keeps the Durable Object awake and the sender waits for acks, so
    // close it. Closing a closed WebSocket does nothing.
    if half_close {
        let _ = ws.close(Some(1000), Some("stream done"));
    }
    // Tunnel drops close with 1006. The counts show whether a drop follows a
    // burst of messages, and the waits whether the hub fell behind.
    let now = Date::now().as_millis();
    console_log!(
        "tunnel: websocket closed, code {}, after {} s, in {} msgs largest {} bytes, out {} msgs, last in {} ms before, queue max {queue_max} wait max {queue_wait_max} ms, pipe wait max {} ms",
        close_code.unwrap_or_else(|| "none".to_string()),
        now.saturating_sub(started) / 1000,
        in_msgs.get(),
        in_largest.get(),
        out_msgs.get(),
        now.saturating_sub(last_in.get()),
        pipe_wait_max.get(),
    );
}

/// Returns `n` from a message "ack <n>", where `n` is decimal digits only,
/// or None when `text` is any other message.
fn parse_ack(text: &str) -> Option<u64> {
    let n = text.strip_prefix("ack ")?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
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
/// holds a [`Ticket`] until it has. At the cap, the client with the most
/// connections waiting loses its oldest, so one client address that opens
/// many connections evicts its own, not the agent's or auth's.
#[derive(Clone, Default)]
pub struct Pending {
    inner: Arc<Mutex<PendingInner>>,
}

#[derive(Default)]
struct PendingInner {
    next: u64,
    /// Each connection's ID, its client, and the sender that evicts it.
    queue: VecDeque<(u64, String, oneshot::Sender<()>)>,
}

/// One connection's place in [`Pending`]. Dropping it removes the
/// connection.
pub struct Ticket {
    id: u64,
    pending: Pending,
}

impl Pending {
    /// Adds a connection from `client`. If `cap` connections are already
    /// waiting, it first evicts the oldest connection of the client that
    /// has the most waiting, counting the new one. Returns the new
    /// connection's ticket, a receiver, and true if it evicted another
    /// connection. The receiver resolves with `Ok(())` when a later call
    /// evicts this connection, and with an error once the ticket is dropped.
    pub fn admit(&self, cap: usize, client: &str) -> (Ticket, oneshot::Receiver<()>, bool) {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().unwrap();
        let mut evicted_other = false;
        // With a cap of 0 the loop would never end.
        while inner.queue.len() >= cap.max(1) {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            *counts.entry(client).or_default() += 1;
            for (_, c, _) in &inner.queue {
                *counts.entry(c.as_str()).or_default() += 1;
            }
            let most = counts.values().copied().max().unwrap_or(0);
            // The oldest connection whose client has the most waiting.
            let at = inner
                .queue
                .iter()
                .position(|(_, c, _)| counts[c.as_str()] == most)
                .unwrap_or(0);
            if let Some((_, _, evict)) = inner.queue.remove(at) {
                let _ = evict.send(());
                evicted_other = true;
            }
        }
        let id = inner.next;
        inner.next += 1;
        inner.queue.push_back((id, client.to_string(), tx));
        (
            Ticket {
                id,
                pending: self.clone(),
            },
            rx,
            evicted_other,
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
            .retain(|(id, _, _)| *id != self.id);
    }
}

/// Returns the client address of `req` from `CF-Connecting-IP`, with an
/// IPv6 address cut to its /64, because one host usually holds a whole
/// /64. It is empty when the header is missing, as under `wrangler dev`.
pub fn client_key(req: &Request) -> Result<String> {
    let ip = req.headers().get("CF-Connecting-IP")?.unwrap_or_default();
    Ok(ipv6_prefix(&ip).unwrap_or(ip))
}

/// Returns the first four groups of an IPv6 address, or None when `ip` is
/// not one.
fn ipv6_prefix(ip: &str) -> Option<String> {
    let addr: std::net::Ipv6Addr = ip.parse().ok()?;
    let s = addr.segments();
    Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
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
        let (a, mut a_rx, evicted) = pending.admit(2, "a");
        assert!(!evicted);
        assert_eq!(pending.waiting(), 1);
        drop(a);
        assert_eq!(pending.waiting(), 0);
        assert!(block_on(&mut a_rx).is_err());
    }

    #[test]
    fn pending_evicts_the_oldest_at_the_cap() {
        let pending = Pending::default();
        let (_a, a_rx, _) = pending.admit(2, "a");
        let (_b, mut b_rx, _) = pending.admit(2, "a");
        let (_c, mut c_rx, evicted) = pending.admit(2, "a");
        assert!(evicted);
        assert_eq!(pending.waiting(), 2);
        assert_eq!(block_on(a_rx), Ok(()));
        assert_eq!(b_rx.try_recv(), Ok(None));
        assert_eq!(c_rx.try_recv(), Ok(None));
    }

    #[test]
    fn pending_evicts_the_client_with_the_most() {
        let pending = Pending::default();
        let (_agent, mut agent_rx, _) = pending.admit(3, "agent");
        let (_x1, x1_rx, _) = pending.admit(3, "x");
        let (_x2, mut x2_rx, _) = pending.admit(3, "x");
        let (_x3, mut x3_rx, evicted) = pending.admit(3, "x");
        assert!(evicted);
        assert_eq!(block_on(x1_rx), Ok(()));
        assert_eq!(agent_rx.try_recv(), Ok(None));
        let (_x4, _, _) = pending.admit(3, "x");
        assert_eq!(block_on(&mut x2_rx), Ok(()));
        assert_eq!(agent_rx.try_recv(), Ok(None));
        assert_eq!(x3_rx.try_recv(), Ok(None));
    }

    #[test]
    fn parse_ack_takes_a_decimal_count() {
        assert_eq!(parse_ack("ack 0"), Some(0));
        assert_eq!(parse_ack("ack 262144"), Some(262144));
        assert_eq!(parse_ack("ack +1"), None);
        assert_eq!(parse_ack("ack -1"), None);
        assert_eq!(parse_ack("ack "), None);
        assert_eq!(parse_ack("ack 1 "), None);
        assert_eq!(parse_ack("ack 99999999999999999999"), None);
        assert_eq!(parse_ack("ACK 1"), None);
        assert_eq!(parse_ack(""), None);
    }

    #[test]
    fn ipv6_prefix_cuts_to_64() {
        assert_eq!(
            ipv6_prefix("2001:db8:1:2:3:4:5:6").as_deref(),
            Some("2001:db8:1:2::/64")
        );
        assert_eq!(ipv6_prefix("192.0.2.1"), None);
        assert_eq!(ipv6_prefix(""), None);
    }

    #[test]
    fn pending_ticket_of_an_evicted_connection_removes_nothing() {
        let pending = Pending::default();
        let (a, _a_rx, _) = pending.admit(1, "a");
        let (_b, _b_rx, _) = pending.admit(1, "a");
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
