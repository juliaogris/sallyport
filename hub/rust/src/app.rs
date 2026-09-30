//! The hub as a TLS client to the app service, over the agent's tunnel.
//!
//! The hub opens `teleport-transport` into the agent with an `@local-node`
//! dial request, then runs TLS with the user's app session certificate.
//! The app service picks the app and the session from that certificate.

use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{select, Either};
use rustls::pki_types::ServerName;
use serde_json::json;
use worker::Delay;

use crate::ssh::{AppTunnel, CHAN_TRANSPORT, REQ_DIAL};

/// The SNI suffix the app service expects after the hex cluster name
/// (api/utils/cluster.go, EncodeClusterName).
const API_DOMAIN: &str = "teleport.cluster.local";

/// How long [`dial_app`] waits for the channel, the dial and the TLS
/// handshake together. It is the same 10 s as `DIAL_DEADLINE` in `ssh`,
/// which bounds the agent's dials.
const DIAL_APP_DEADLINE: Duration = Duration::from_secs(10);

/// The authenticated `App` connection the hub dials apps through. The
/// hub serves one agent, so the newest connection replaces the previous
/// one.
pub type TunnelSlot = Arc<Mutex<Option<AppTunnel>>>;

/// A TLS connection to the app service, running over one channel of the
/// agent tunnel.
pub(crate) type AppStream = tokio_rustls::client::TlsStream<russh::ChannelStream<russh::server::Msg>>;

/// Opens a transport channel into the agent, asks it to dial its local app
/// service, and runs TLS toward the app service with the given identity.
/// The SNI is the hex-encoded cluster name under [`API_DOMAIN`]. It returns
/// an error when the three steps take longer than [`DIAL_APP_DEADLINE`].
pub(crate) async fn dial_app(tunnel: &AppTunnel, tls: Arc<rustls::ClientConfig>, cluster: &str) -> std::result::Result<AppStream, String> {
    let mut deadline = pin!(Delay::from(DIAL_APP_DEADLINE));
    let open = tunnel.handle.channel_open_custom(CHAN_TRANSPORT, Vec::new());
    let ch = match select(pin!(open), deadline.as_mut()).await {
        Either::Left((ch, _)) => ch.map_err(|e| format!("transport open: {e}"))?,
        Either::Right(_) => return Err("transport open: timed out".into()),
    };
    let dial = json!({
        "address": "@local-node",
        "server_id": tunnel.server_id,
        "conn_type": "app",
    });
    let request = ch.request_custom(REQ_DIAL, true, dial.to_string().into_bytes());
    let accepted = match select(pin!(request), deadline.as_mut()).await {
        Either::Left((accepted, _)) => accepted.map_err(|e| format!("dial request: {e}"))?,
        Either::Right(_) => {
            // A `Channel` sends no close when it is dropped.
            let _ = ch.close().await;
            return Err("dial request: timed out".into());
        }
    };
    if !accepted {
        let _ = ch.close().await;
        return Err("dial refused by agent".into());
    }

    let sni = format!("{}.{API_DOMAIN}", hex(cluster.as_bytes()));
    let name = ServerName::try_from(sni.clone()).map_err(|e| format!("sni {sni:?}: {e}"))?;
    // Dropping the stream on a timeout closes the channel.
    let connect = tokio_rustls::TlsConnector::from(tls).connect(name, ch.into_stream());
    match select(pin!(connect), deadline).await {
        Either::Left((stream, _)) => stream.map_err(|e| format!("tls connect: {e}")),
        Either::Right(_) => Err("tls connect: timed out".into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

