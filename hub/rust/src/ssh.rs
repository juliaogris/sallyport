//! The reverse tunnel SSH server a stock Teleport agent connects to.
//!
//! Only agents with an `App` host certificate from the cluster host CA get
//! in. The agent opens `teleport-heartbeat` and pings on it, sends
//! `keepalive@openssh.com`, and reaches auth by opening
//! `teleport-transport` with dial address `@remote-auth-server`.

use std::collections::{HashMap, HashSet};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{select, Either};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{Certificate, PublicKey};
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::io::DuplexStream;
use worker::*;

const CHAN_HEARTBEAT: &str = "teleport-heartbeat";
pub const CHAN_TRANSPORT: &str = "teleport-transport";
const CHAN_DISCOVERY: &str = "teleport-discovery";
const REQ_DISCOVERY: &str = "discovery";
pub const REQ_DIAL: &str = "teleport-transport-dial";
const REQ_PING: &str = "ping";
const GLOBAL_KEEPALIVE: &str = "keepalive@openssh.com";
const ADDR_REMOTE_AUTH: &str = "@remote-auth-server";
const EXT_ROLE: &str = "x-teleport-role";
const EXT_AUTHORITY: &str = "x-teleport-authority";
const ROLE_APP: &str = "App";
/// The app service's process identity, used by its auth client, which
/// reaches auth through the `@remote-auth-server` passthrough.
const ROLE_INSTANCE: &str = "Instance";
/// How often the hub re-announces itself. The agent forgets a proxy
/// 3 minutes after the last announcement (lib/reversetunnel/track,
/// DefaultProxyExpiry) and then dials to find more, so this stays well
/// under that. The agent's 5-minute ping is too slow to piggyback on.
const DISCOVERY_EVERY: Duration = Duration::from_secs(30);
/// Rejected auth attempts after which the connection is dropped.
const MAX_AUTH_FAILURES: u32 = 3;
/// Channels the agent may have open on one connection. A channel counts
/// until the agent closes it, so an agent that ignores the hub's close
/// cannot open channels without limit.
const MAX_AGENT_CHANNELS: usize = 32;
/// Transport channels one connection may hold before their dial request.
const MAX_PENDING_TRANSPORTS: usize = 16;
/// How long an agent-opened transport channel may wait for its dial, and
/// how long the hub waits for the agent to open and dial a channel.
pub const DIAL_DEADLINE: Duration = Duration::from_secs(10);
/// Passthroughs to auth per connection, and across the Durable Object. Each
/// one holds an auth pipe stream, so the total stays under the pool size to
/// leave streams for the hub's own calls.
const MAX_PASSTHROUGHS_PER_CONN: usize = 2;
pub const MAX_PASSTHROUGHS_TOTAL: usize = 4;

/// The time of the last discovery request the agent took, in milliseconds
/// since the epoch, or 0 before the first one.
pub static LAST_DISCOVERY_MS: AtomicU64 = AtomicU64::new(0);
/// Counts agent connections, for [`AgentHandler::conn`].
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// An authenticated `App` connection and the agent's host ID, which is the
/// `server_id` of a dial into it.
#[derive(Clone)]
pub struct AppTunnel {
    pub handle: Handle,
    pub server_id: String,
    /// The ID of the connection, so that it clears the slot only while the
    /// slot still holds it.
    conn: u64,
}

/// State shared by every connection in the Durable Object.
#[derive(Clone)]
pub struct Shared {
    /// Passthroughs to auth open across the Durable Object.
    pub passthroughs: Arc<AtomicUsize>,
    /// Where an `App` connection registers itself after its first ping.
    pub app_tunnel: crate::app::TunnelSlot,
    /// Streams to auth that auth opened with its callout.
    pub auth_pipe: crate::authpipe::Pool,
}

/// Per-connection state for one agent SSH connection.
pub struct AgentHandler {
    /// This connection's ID.
    conn: u64,
    host_ca: PublicKey,
    cluster: String,
    shared: Shared,
    /// Set once this connection authenticates. The pre-auth deadline reads
    /// it.
    authed: Arc<AtomicBool>,
    /// This connection's place among the unauthenticated connections,
    /// dropped once it authenticates.
    ticket: Option<crate::tunnel::Ticket>,
    auth_failures: u32,
    /// Passthroughs to auth open on this connection.
    conn_passthroughs: Arc<AtomicUsize>,
    /// The authenticated agent's host ID, set by certificate auth.
    host_id: Option<String>,
    /// The authenticated certificate's system role, `App` or `Instance`.
    role: Option<String>,
    heartbeat: Option<ChannelId>,
    pinged: bool,
    /// The hub's proxy name, its host UUID, announced in discovery.
    proxy_name: String,
    /// The channels the agent opened and has not closed.
    agent_channels: HashSet<ChannelId>,
    /// Agent-opened transport channels waiting for their dial request.
    transports: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl AgentHandler {
    pub fn new(host_ca: PublicKey, cluster: String, proxy_name: String, shared: Shared, authed: Arc<AtomicBool>, ticket: crate::tunnel::Ticket) -> Self {
        Self {
            conn: CONNECTIONS.fetch_add(1, Ordering::Relaxed),
            host_ca,
            cluster,
            shared,
            authed,
            ticket: Some(ticket),
            auth_failures: 0,
            conn_passthroughs: Arc::new(AtomicUsize::new(0)),
            host_id: None,
            role: None,
            heartbeat: None,
            pinged: false,
            proxy_name,
            agent_channels: HashSet::new(),
            transports: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Rejects one auth attempt, and drops the connection after
    /// [`MAX_AUTH_FAILURES`], since russh has no attempt limit.
    fn fail_auth(&mut self) -> std::result::Result<Auth, russh::Error> {
        self.auth_failures += 1;
        if self.auth_failures >= MAX_AUTH_FAILURES {
            return Err(russh::Error::Disconnect);
        }
        Ok(Auth::reject())
    }

    /// Takes an auth pipe stream for a passthrough, if the dial request in
    /// `data` is one the hub serves and the passthrough limits allow it.
    /// The error says why the dial is refused.
    fn passthrough_stream(&self, data: &[u8]) -> std::result::Result<DuplexStream, String> {
        let req: serde_json::Value = serde_json::from_slice(data).map_err(|e| format!("bad dial request: {e}"))?;
        let addr = req.get("address").and_then(|a| a.as_str()).unwrap_or_default();
        if addr != ADDR_REMOTE_AUTH {
            return Err(format!("rejected dial to {addr:?}"));
        }
        if self.conn_passthroughs.load(Ordering::Relaxed) >= MAX_PASSTHROUGHS_PER_CONN
            || self.shared.passthroughs.load(Ordering::Relaxed) >= MAX_PASSTHROUGHS_TOTAL
        {
            return Err("passthrough limit reached".into());
        }
        self.shared
            .auth_pipe
            .take()
            .ok_or_else(|| "passthrough refused, no auth pipe stream".into())
    }
}

/// Returns why a certificate is not an acceptable agent credential for the
/// SSH user `user`, or None if it is. The certificate must be signed by
/// `host_ca` for `cluster`. russh has already checked the validity window
/// and the certificate's own signature.
fn reject_reason(host_ca: &PublicKey, cluster: &str, user: &str, cert: &Certificate) -> Option<String> {
    if cert.cert_type() != CertType::Host {
        return Some("not a host certificate".into());
    }
    // ssh-key treats an empty principal list as "any principal"; Go's
    // CertChecker requires the SSH user to be one of them.
    if !cert.valid_principals().iter().any(|p| p == user) {
        return Some("user is not a certificate principal".into());
    }
    if !cert.critical_options().is_empty() {
        return Some("unexpected critical options".into());
    }
    if cert.signature_key() != host_ca.key_data() {
        return Some("not signed by the cluster host CA".into());
    }
    let ext = cert.extensions();
    match ext.get(EXT_AUTHORITY) {
        Some(c) if c == cluster => {}
        other => return Some(format!("authority {other:?}, want {cluster:?}")),
    }
    // Go accepts any system role because proxies and nodes dial in too.
    // This hub has one legitimate client, the app service, which dials
    // with its App identity for the tunnel and its Instance identity for
    // its auth client. Accepting Proxy would let the hub's own identity
    // authenticate to itself.
    match ext.get(EXT_ROLE) {
        Some(r) if r == ROLE_APP || r == ROLE_INSTANCE => None,
        other => Some(format!("role {other:?}, want {ROLE_APP:?} or {ROLE_INSTANCE:?}")),
    }
}

/// Closes a channel the hub will not use. russh's `Channel` sends nothing
/// when it is dropped, so without this the session keeps the channel.
fn close_later(ch: Channel<Msg>) {
    wasm_bindgen_futures::spawn_local(async move {
        let _ = ch.close().await;
    });
}

/// russh drops the handler when the connection ends. If this connection is
/// the app tunnel, the slot is cleared, so app requests get "app service
/// offline" until the agent's next connection pings.
impl Drop for AgentHandler {
    fn drop(&mut self) {
        let mut slot = self.shared.app_tunnel.lock().unwrap();
        if slot.as_ref().is_some_and(|t| t.conn == self.conn) {
            console_log!("ssh: app tunnel connection ended");
            *slot = None;
        }
    }
}

impl russh::server::Handler for AgentHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, _key: &PublicKey) -> std::result::Result<Auth, Self::Error> {
        console_log!("ssh: rejected plain key for {user:?}");
        self.fail_auth()
    }

    async fn auth_openssh_certificate(&mut self, user: &str, cert: &Certificate) -> std::result::Result<Auth, Self::Error> {
        if let Some(reason) = reject_reason(&self.host_ca, &self.cluster, user, cert) {
            console_log!("ssh: rejected certificate for {user:?}: {reason}");
            return self.fail_auth();
        }
        let role = cert.extensions().get(EXT_ROLE).cloned().unwrap_or_default();
        console_log!("ssh: agent {user:?} authenticated, role {role}");
        self.host_id = Some(user.to_string());
        self.role = Some(role);
        self.authed.store(true, Ordering::Relaxed);
        self.ticket = None;
        Ok(Auth::Accept)
    }

    async fn channel_open_unknown(&mut self, typ: &str, channel: Channel<Msg>, _session: &mut Session) -> std::result::Result<bool, Self::Error> {
        if self.agent_channels.len() >= MAX_AGENT_CHANNELS {
            console_log!("ssh: rejected channel, {MAX_AGENT_CHANNELS} open");
            return Ok(false);
        }
        let id = channel.id();
        match typ {
            CHAN_HEARTBEAT if self.role.as_deref() == Some(ROLE_APP) => {
                console_log!("ssh: heartbeat channel accepted");
                self.heartbeat = Some(id);
            }
            CHAN_TRANSPORT => {
                {
                    let mut pending = self.transports.lock().unwrap();
                    if pending.len() >= MAX_PENDING_TRANSPORTS {
                        console_log!("ssh: rejected transport, {} pending", pending.len());
                        return Ok(false);
                    }
                    pending.insert(id, channel);
                }
                // Drop a transport channel whose dial request never comes.
                let pending = self.transports.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    crate::sockets::sleep(DIAL_DEADLINE).await;
                    let stale = pending.lock().unwrap().remove(&id);
                    if let Some(ch) = stale {
                        console_log!("ssh: transport channel never dialed, closing");
                        let _ = ch.close().await;
                    }
                });
            }
            other => {
                console_log!("ssh: rejected channel type {other:?}");
                return Ok(false);
            }
        }
        self.agent_channels.insert(id);
        Ok(true)
    }

    async fn channel_request_unknown(&mut self, channel: ChannelId, typ: &str, _want_reply: bool, data: &[u8], session: &mut Session) -> std::result::Result<bool, Self::Error> {
        match typ {
            REQ_PING if Some(channel) == self.heartbeat => {
                if !self.pinged {
                    self.pinged = true;
                    console_log!("ssh: first ping {:?}", String::from_utf8_lossy(data));
                    if let Some(host_id) = self.host_id.clone() {
                        // The SSH user is already `<host UUID>.<cluster>`.
                        wasm_bindgen_futures::spawn_local(probe_dial(session.handle(), host_id.clone()));
                        *self.shared.app_tunnel.lock().unwrap() = Some(AppTunnel {
                            handle: session.handle(),
                            server_id: host_id,
                            conn: self.conn,
                        });
                    }
                    wasm_bindgen_futures::spawn_local(discovery_loop(session.handle(), self.proxy_name.clone()));
                }
                Ok(true)
            }
            REQ_DIAL => {
                let Some(ch) = self.transports.lock().unwrap().remove(&channel) else {
                    return Ok(false);
                };
                let mut pipe = match self.passthrough_stream(data) {
                    Ok(pipe) => pipe,
                    Err(reason) => {
                        console_log!("ssh: {reason}");
                        close_later(ch);
                        return Ok(false);
                    }
                };
                // The bytes are the agent's own mTLS to auth. The hub only
                // copies them.
                console_log!("ssh: passthrough to auth over the callout");
                let (conn_count, total_count) = (self.conn_passthroughs.clone(), self.shared.passthroughs.clone());
                conn_count.fetch_add(1, Ordering::Relaxed);
                total_count.fetch_add(1, Ordering::Relaxed);
                wasm_bindgen_futures::spawn_local(async move {
                    let mut stream = ch.into_stream();
                    match tokio::io::copy_bidirectional(&mut stream, &mut pipe).await {
                        Ok((up, down)) => console_log!("ssh: passthrough closed, {up} up, {down} down"),
                        Err(err) => console_log!("ssh: passthrough error: {err}"),
                    }
                    conn_count.fetch_sub(1, Ordering::Relaxed);
                    total_count.fetch_sub(1, Ordering::Relaxed);
                });
                Ok(true)
            }
            other => {
                console_log!("ssh: unhandled channel request {other:?}");
                Ok(false)
            }
        }
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> std::result::Result<(), Self::Error> {
        self.transports.lock().unwrap().remove(&channel);
        self.agent_channels.remove(&channel);
        Ok(())
    }

    async fn global_request_unknown(&mut self, typ: &str, _want_reply: bool, _data: &[u8], _session: &mut Session) -> std::result::Result<bool, Self::Error> {
        Ok(typ == GLOBAL_KEEPALIVE)
    }
}

/// Opens a transport channel into the agent, asks it to dial its local
/// app service, and closes it. This checks that the agent accepts app
/// dials as soon as the tunnel is up, so a broken tunnel shows in the log
/// before a browser tries it.
async fn probe_dial(handle: Handle, server_id: String) {
    let dial = async {
        let ch = handle
            .channel_open_custom(CHAN_TRANSPORT, Vec::new())
            .await
            .map_err(|e| format!("open failed: {e}"))?;
        let req = serde_json::json!({
            "address": "@local-node",
            "server_id": server_id,
            "conn_type": "app",
        });
        let res = ch.request_custom(REQ_DIAL, true, req.to_string().into_bytes()).await;
        let _ = ch.close().await;
        res.map_err(|e| format!("request failed: {e}"))
    };
    match select(pin!(dial), pin!(crate::sockets::sleep(DIAL_DEADLINE))).await {
        Either::Left((Ok(ok), _)) => console_log!("ssh: probe dial into agent accepted: {ok}"),
        Either::Left((Err(err), _)) => console_log!("ssh: probe dial {err}"),
        Either::Right(_) => console_log!("ssh: probe dial got no answer within {DIAL_DEADLINE:?}"),
    }
}

/// Sends a discovery request every [`DISCOVERY_EVERY`] until the connection
/// closes. Each request lists this hub as the cluster's only proxy
/// (lib/reversetunnel/discovery.go).
async fn discovery_loop(handle: Handle, proxy_name: String) {
    let mut ch = match handle.channel_open_custom(CHAN_DISCOVERY, Vec::new()).await {
        Ok(ch) => ch,
        Err(err) => {
            console_log!("ssh: discovery open failed: {err}");
            return;
        }
    };
    let req = serde_json::json!({
        "proxies": [{ "version": "v2", "metadata": { "name": proxy_name } }],
    })
    .to_string();
    loop {
        if let Err(err) = ch.request_custom(REQ_DISCOVERY, false, req.clone().into_bytes()).await {
            console_log!("ssh: discovery failed: {err}");
            break;
        }
        LAST_DISCOVERY_MS.store(Date::now().as_millis(), Ordering::Relaxed);
        // Read the channel while waiting, so that anything the agent sends
        // on it does not queue in russh.
        let mut next = pin!(crate::sockets::sleep(DISCOVERY_EVERY));
        loop {
            match select(pin!(ch.wait()), next.as_mut()).await {
                Either::Left((Some(_), _)) => {}
                Either::Left((None, _)) => {
                    console_log!("ssh: discovery loop ended, channel closed");
                    return;
                }
                Either::Right(_) => break,
            }
        }
    }
    console_log!("ssh: discovery loop ended");
}
