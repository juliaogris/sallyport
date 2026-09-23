//! The reverse tunnel SSH server a stock Teleport agent connects to.
//!
//! Only agents with an `App` host certificate from the cluster host CA get
//! in. The agent opens `teleport-heartbeat` and pings on it, sends
//! `keepalive@openssh.com`, and reaches auth by opening
//! `teleport-transport` with dial address `@remote-auth-server`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{Certificate, PublicKey};
use worker::*;

const CHAN_HEARTBEAT: &str = "teleport-heartbeat";
const CHAN_TRANSPORT: &str = "teleport-transport";
const CHAN_DISCOVERY: &str = "teleport-discovery";
const REQ_DISCOVERY: &str = "discovery";
const REQ_DIAL: &str = "teleport-transport-dial";
const REQ_PING: &str = "ping";
const GLOBAL_KEEPALIVE: &str = "keepalive@openssh.com";
const ADDR_REMOTE_AUTH: &str = "@remote-auth-server";
const EXT_ROLE: &str = "x-teleport-role";
const EXT_AUTHORITY: &str = "x-teleport-authority";
const ROLE_APP: &str = "App";
/// The app service's process identity, used by its auth client, which
/// reaches auth through the `@remote-auth-server` passthrough.
const ROLE_INSTANCE: &str = "Instance";

/// Where the agent-to-auth passthrough connects. This is a spike shortcut
/// that only works under `wrangler dev`; the auth callout replaces it.
#[derive(Clone)]
pub struct AuthAddr {
    pub host: String,
    pub port: u16,
}

/// Per-connection state for one agent SSH connection.
pub struct AgentHandler {
    host_ca: PublicKey,
    cluster: String,
    auth_addr: AuthAddr,
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
    pub fn new(host_ca: PublicKey, cluster: String, auth_addr: AuthAddr, proxy_name: String) -> Self {
        Self {
            proxy_name,
            discovery: Arc::new(Mutex::new(None)),
            host_ca,
            cluster,
            auth_addr,
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
    fn reject_reason(&self, cert: &Certificate) -> Option<String> {
        if cert.cert_type() != CertType::Host {
            return Some("not a host certificate".into());
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

impl russh::server::Handler for AgentHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, _key: &PublicKey) -> std::result::Result<Auth, Self::Error> {
        console_log!("ssh: rejected plain key for {user:?}");
        Ok(Auth::reject())
    }

    async fn auth_openssh_certificate(&mut self, user: &str, cert: &Certificate) -> std::result::Result<Auth, Self::Error> {
        if let Some(reason) = self.reject_reason(cert) {
            console_log!("ssh: rejected certificate for {user:?}: {reason}");
            return Ok(Auth::reject());
        }
        let role = cert.extensions().get(EXT_ROLE).cloned().unwrap_or_default();
        console_log!("ssh: agent {user:?} authenticated, role {role}");
        self.host_id = Some(user.to_string());
        self.role = Some(role);
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
                self.transports.lock().unwrap().insert(channel.id(), channel);
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
                        wasm_bindgen_futures::spawn_local(test_dial(session.handle(), host_id));
                    }
                }
                // Tell the agent this hub is the only proxy, on every ping.
                // Without it the agent pool keeps dialling for more proxies
                // and aborts each attempt with "proxy already claimed".
                wasm_bindgen_futures::spawn_local(announce(session.handle(), self.discovery.clone(), self.proxy_name.clone()));
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
                let auth = self.auth_addr.clone();
                let socket = match Socket::builder().connect(auth.host.clone(), auth.port) {
                    Ok(s) => s,
                    Err(err) => {
                        console_log!("ssh: auth connect {}:{}: {err}", auth.host, auth.port);
                        return Ok(false);
                    }
                };
                console_log!("ssh: passthrough to auth {}:{}", auth.host, auth.port);
                wasm_bindgen_futures::spawn_local(async move {
                    let mut stream = ch.into_stream();
                    let mut socket = socket;
                    match tokio::io::copy_bidirectional(&mut stream, &mut socket).await {
                        Ok((up, down)) => console_log!("ssh: passthrough closed, {up} up, {down} down"),
                        Err(err) => console_log!("ssh: passthrough error: {err}"),
                    }
                });
                Ok(true)
            }
            other => {
                console_log!("ssh: unhandled channel request {other:?}");
                Ok(false)
            }
        }
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

/// Sends a discovery request listing this hub as the cluster's only proxy
/// (lib/reversetunnel/discovery.go). Opens the channel on first use.
async fn announce(handle: Handle, slot: Arc<Mutex<Option<Channel<Msg>>>>, proxy_name: String) {
    let existing = slot.lock().unwrap().take();
    let ch = match existing {
        Some(ch) => ch,
        None => match handle.channel_open_custom(CHAN_DISCOVERY, Vec::new()).await {
            Ok(ch) => ch,
            Err(err) => {
                console_log!("ssh: discovery open failed: {err}");
                return;
            }
        },
    };
    let req = serde_json::json!({
        "proxies": [{ "version": "v2", "metadata": { "name": proxy_name } }],
    });
    match ch.request_custom(REQ_DISCOVERY, false, req.to_string().into_bytes()).await {
        Ok(_) => console_log!("ssh: discovery sent, proxy {proxy_name}"),
        Err(err) => console_log!("ssh: discovery failed: {err}"),
    }
    *slot.lock().unwrap() = Some(ch);
}
