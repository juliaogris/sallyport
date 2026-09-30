//! The reverse tunnel SSH server a stock Teleport agent connects to.
//!
//! Only agents with an `App` host certificate from the cluster host CA get
//! in. The agent opens `teleport-heartbeat` and pings on it, sends
//! `keepalive@openssh.com`, and reaches auth by opening
//! `teleport-transport` with dial address `@remote-auth-server`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{Certificate, PublicKey};
use worker::*;

const CHAN_HEARTBEAT: &str = "teleport-heartbeat";
pub const CHAN_TRANSPORT: &str = "teleport-transport";
const CHAN_DISCOVERY: &str = "teleport-discovery";
const REQ_DISCOVERY: &str = "discovery";
/// How often the hub re-announces itself. The agent forgets a proxy
/// 3 minutes after the last announcement (lib/reversetunnel/track,
/// DefaultProxyExpiry) and then dials to find more, so this stays well
/// under that. The agent's 5-minute ping is too slow to piggyback on.
const DISCOVERY_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// The time of the last discovery request the agent took, in milliseconds
/// since the epoch, or 0 before the first one.
pub static LAST_DISCOVERY_MS: AtomicU64 = AtomicU64::new(0);
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
/// Rejected auth attempts after which the connection is dropped.
const MAX_AUTH_FAILURES: u32 = 3;
/// Transport channels one connection may hold before their dial request.
const MAX_PENDING_TRANSPORTS: usize = 16;
/// How long an agent-opened transport channel may wait for its dial.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);
/// Passthroughs to auth per connection, and across the Durable Object. Each
/// one holds an auth pipe stream, so the total stays under the pool size to
/// leave streams for the hub's own calls.
const MAX_PASSTHROUGHS_PER_CONN: usize = 2;
pub const MAX_PASSTHROUGHS_TOTAL: usize = 4;

/// An authenticated `App` connection and the agent's host ID, which is the
/// `server_id` of a dial into it.
#[derive(Clone)]
pub struct AppTunnel {
    pub handle: Handle,
    pub server_id: String,
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
    passthroughs: Arc<AtomicUsize>,
    /// The authenticated agent's host ID, set by certificate auth.
    host_id: Option<String>,
    /// The authenticated certificate's system role, `App` or `Instance`.
    role: Option<String>,
    heartbeat: Option<ChannelId>,
    pinged: bool,
    /// The hub's proxy name, its host UUID, announced in discovery.
    proxy_name: String,
    /// The discovery channel into the agent, opened after the first ping.
    discovery: Arc<Mutex<Option<Channel<Msg>>>>,
    /// Agent-opened transport channels waiting for their dial request.
    transports: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl AgentHandler {
    pub fn new(host_ca: PublicKey, cluster: String, proxy_name: String, shared: Shared, authed: Arc<AtomicBool>, ticket: crate::tunnel::Ticket) -> Self {
        Self {
            shared,
            authed,
            ticket: Some(ticket),
            auth_failures: 0,
            passthroughs: Arc::new(AtomicUsize::new(0)),
            proxy_name,
            discovery: Arc::new(Mutex::new(None)),
            host_ca,
            cluster,
            host_id: None,
            role: None,
            heartbeat: None,
            pinged: false,
            transports: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns why a certificate is not an acceptable agent credential, or
    /// None if it is. russh has already checked the validity window and the
    /// certificate's own signature.
    fn reject_reason(&self, user: &str, cert: &Certificate) -> Option<String> {
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
        if cert.signature_key() != self.host_ca.key_data() {
            return Some("not signed by the cluster host CA".into());
        }
        let ext = cert.extensions();
        match ext.get(EXT_AUTHORITY) {
            Some(c) if *c == self.cluster => {}
            other => return Some(format!("authority {other:?}, want {:?}", self.cluster)),
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
}

impl AgentHandler {
    /// Rejects one auth attempt, and drops the connection after
    /// [`MAX_AUTH_FAILURES`], since russh has no attempt limit.
    fn fail_auth(&mut self) -> std::result::Result<Auth, russh::Error> {
        self.auth_failures += 1;
        if self.auth_failures >= MAX_AUTH_FAILURES {
            return Err(russh::Error::Disconnect);
        }
        Ok(Auth::reject())
    }
}

impl russh::server::Handler for AgentHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, _key: &PublicKey) -> std::result::Result<Auth, Self::Error> {
        console_log!("ssh: rejected plain key for {user:?}");
        self.fail_auth()
    }

    async fn auth_openssh_certificate(&mut self, user: &str, cert: &Certificate) -> std::result::Result<Auth, Self::Error> {
        if let Some(reason) = self.reject_reason(user, cert) {
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
        match typ {
            CHAN_HEARTBEAT if self.role.as_deref() == Some(ROLE_APP) => {
                console_log!("ssh: heartbeat channel accepted");
                self.heartbeat = Some(channel.id());
                Ok(true)
            }
            CHAN_TRANSPORT => {
                let id = channel.id();
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
                Ok(true)
            }
            other => {
                console_log!("ssh: rejected channel type {other:?}");
                Ok(false)
            }
        }
    }

    async fn channel_request_unknown(&mut self, channel: ChannelId, typ: &str, _want_reply: bool, data: &[u8], session: &mut Session) -> std::result::Result<bool, Self::Error> {
        match typ {
            REQ_PING if Some(channel) == self.heartbeat => {
                if !self.pinged {
                    self.pinged = true;
                    console_log!("ssh: first ping {:?}", String::from_utf8_lossy(data));
                    if let Some(host_id) = self.host_id.clone() {
                        // The SSH user is already `<host UUID>.<cluster>`.
                        wasm_bindgen_futures::spawn_local(test_dial(session.handle(), host_id.clone()));
                        *self.shared.app_tunnel.lock().unwrap() = Some(AppTunnel {
                            handle: session.handle(),
                            server_id: host_id,
                        });
                    }
                    wasm_bindgen_futures::spawn_local(discovery_loop(session.handle(), self.discovery.clone(), self.proxy_name.clone()));
                }
                Ok(true)
            }
            REQ_DIAL => {
                let Some(ch) = self.transports.lock().unwrap().remove(&channel) else {
                    return Ok(false);
                };
                let req: serde_json::Value = match serde_json::from_slice(data) {
                    Ok(v) => v,
                    Err(err) => {
                        console_log!("ssh: bad dial request: {err}");
                        return Ok(false);
                    }
                };
                let addr = req.get("address").and_then(|a| a.as_str()).unwrap_or_default();
                if addr != ADDR_REMOTE_AUTH {
                    console_log!("ssh: rejected dial to {addr:?}");
                    return Ok(false);
                }
                if self.passthroughs.load(Ordering::Relaxed) >= MAX_PASSTHROUGHS_PER_CONN
                    || self.shared.passthroughs.load(Ordering::Relaxed) >= MAX_PASSTHROUGHS_TOTAL
                {
                    console_log!("ssh: passthrough limit reached");
                    return Ok(false);
                }
                // The bytes are the agent's own mTLS to auth. The hub only
                // copies them.
                let Some(mut pipe) = self.shared.auth_pipe.take() else {
                    console_log!("ssh: passthrough refused, no auth pipe stream");
                    return Ok(false);
                };
                console_log!("ssh: passthrough to auth over the callout");
                let (conn_count, total_count) = (self.passthroughs.clone(), self.shared.passthroughs.clone());
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
        Ok(())
    }

    async fn global_request_unknown(&mut self, typ: &str, _want_reply: bool, _data: &[u8], _session: &mut Session) -> std::result::Result<bool, Self::Error> {
        Ok(typ == GLOBAL_KEEPALIVE)
    }
}

/// Opens a transport channel into the agent and asks it to dial its local
/// app service, which is how the hub will reach apps. S3 only checks that
/// the agent accepts the dial.
async fn test_dial(handle: Handle, server_id: String) {
    let ch = match handle.channel_open_custom(CHAN_TRANSPORT, Vec::new()).await {
        Ok(ch) => ch,
        Err(err) => {
            console_log!("ssh: test dial open failed: {err}");
            return;
        }
    };
    let req = serde_json::json!({
        "address": "@local-node",
        "server_id": server_id,
        "conn_type": "app",
    });
    match ch.request_custom(REQ_DIAL, true, req.to_string().into_bytes()).await {
        Ok(ok) => console_log!("ssh: test dial into agent accepted: {ok}"),
        Err(err) => console_log!("ssh: test dial request failed: {err}"),
    }
    let _ = ch.close().await;
}

/// Announces this hub every [`DISCOVERY_EVERY`] until the connection closes.
async fn discovery_loop(handle: Handle, slot: Arc<Mutex<Option<Channel<Msg>>>>, proxy_name: String) {
    while announce(handle.clone(), slot.clone(), proxy_name.clone()).await {
        crate::sockets::sleep(DISCOVERY_EVERY).await;
    }
    console_log!("ssh: discovery loop ended");
}

/// Sends a discovery request listing this hub as the cluster's only proxy
/// (lib/reversetunnel/discovery.go). Opens the channel on first use.
/// Returns false once the connection is gone.
async fn announce(handle: Handle, slot: Arc<Mutex<Option<Channel<Msg>>>>, proxy_name: String) -> bool {
    let existing = slot.lock().unwrap().take();
    let ch = match existing {
        Some(ch) => ch,
        None => match handle.channel_open_custom(CHAN_DISCOVERY, Vec::new()).await {
            Ok(ch) => ch,
            Err(err) => {
                console_log!("ssh: discovery open failed: {err}");
                return false;
            }
        },
    };
    let req = serde_json::json!({
        "proxies": [{ "version": "v2", "metadata": { "name": proxy_name } }],
    });
    if let Err(err) = ch.request_custom(REQ_DISCOVERY, false, req.to_string().into_bytes()).await {
        console_log!("ssh: discovery failed: {err}");
        return false;
    }
    LAST_DISCOVERY_MS.store(Date::now().as_millis(), Ordering::Relaxed);
    *slot.lock().unwrap() = Some(ch);
    true
}
