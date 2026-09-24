//! The hub as a TLS client to the app service, over the agent's tunnel.
//!
//! The hub opens `teleport-transport` into the agent with an `@local-node`
//! dial request, then runs TLS with the user's app session certificate.
//! The app service picks the app and the session from that certificate.

use std::sync::{Arc, Mutex};

use rustls::pki_types::ServerName;
use serde_json::json;

use crate::ssh::{AppTunnel, CHAN_TRANSPORT, REQ_DIAL};

/// The SNI suffix the app service expects after the hex cluster name
/// (api/utils/cluster.go, EncodeClusterName).
const API_DOMAIN: &str = "teleport.cluster.local";

/// The authenticated `App` connection the hub dials apps through. The
/// newest connection replaces the previous one. S4 has one agent.
pub type TunnelSlot = Arc<Mutex<Option<AppTunnel>>>;

/// A TLS connection to the app service, running over one channel of the
/// agent tunnel.
pub(crate) type AppStream = tokio_rustls::client::TlsStream<russh::ChannelStream<russh::server::Msg>>;

/// Opens a transport channel into the agent, asks it to dial its local app
/// service, and runs TLS toward the app service with the given identity.
/// The SNI is the hex-encoded cluster name, as the app service expects it
/// (api/utils/cluster.go, EncodeClusterName).
pub(crate) async fn dial_app(tunnel: &AppTunnel, tls: Arc<rustls::ClientConfig>, cluster: &str) -> std::result::Result<AppStream, String> {
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

    let sni = format!("{}.{API_DOMAIN}", hex(cluster.as_bytes()));
    let name = ServerName::try_from(sni.clone()).map_err(|e| format!("sni {sni:?}: {e}"))?;
    tokio_rustls::TlsConnector::from(tls)
        .connect(name, ch.into_stream())
        .await
        .map_err(|e| format!("tls connect: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

