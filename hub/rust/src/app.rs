//! The hub as a TLS client to the app service, over the agent's tunnel or
//! over a stream from auth's on-demand callout.
//!
//! Over the tunnel, the hub opens `teleport-transport` into the agent with
//! an `@local-node` dial request. The lazy hub asks the callout for a
//! stream instead. Then the hub runs TLS with the user's app session
//! certificate. The app service picks the app and the session from that
//! certificate.

use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::future::{select, Either};
use russh::server::Msg;
use russh::Channel;
use rustls::pki_types::ServerName;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ssh::{AppTunnel, CHAN_TRANSPORT, DIAL_DEADLINE, REQ_DIAL};

/// The SNI suffix the app service expects after the hex cluster name
/// (api/utils/cluster.go, EncodeClusterName).
const API_DOMAIN: &str = "teleport.cluster.local";

/// The authenticated `App` connection the hub dials apps through. The
/// hub serves one agent, so the newest connection replaces the previous
/// one.
pub type TunnelSlot = Arc<Mutex<Option<AppTunnel>>>;

/// Channels to the app service that one app tunnel may have open at once.
/// russh can queue up to 8 MiB on each for a slow reader.
pub const MAX_FORWARDS: usize = 16;

/// A TLS connection to the app service, over one channel of the agent
/// tunnel or over a stream from auth's on-demand callout. A tunnel
/// connection counts toward [`MAX_FORWARDS`] until it is dropped.
pub(crate) struct AppStream {
    tls: AppTls,
    /// The stream's place in the tunnel's count. The lazy hub has no tunnel.
    _forward: Option<Forward>,
}

/// The TLS connection under an [`AppStream`]: over an agent tunnel channel,
/// or over a stream from auth's on-demand callout.
enum AppTls {
    Tunnel(TlsStream),
    Lazy(tokio_rustls::client::TlsStream<tokio::io::DuplexStream>),
}

/// One stream's place in an app tunnel's count of open streams.
struct Forward(Arc<AtomicUsize>);

impl Drop for Forward {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Opens a transport channel into the agent, asks it to dial its local app
/// service, and runs TLS toward the app service with the given identity.
/// The SNI is the hex-encoded cluster name, as the app service expects it.
/// All three steps together have [`DIAL_DEADLINE`]. Returns an error when
/// the tunnel already has [`MAX_FORWARDS`] streams open.
pub(crate) async fn dial_app(
    tunnel: &AppTunnel,
    tls: Arc<rustls::ClientConfig>,
    cluster: &str,
) -> std::result::Result<AppStream, String> {
    if tunnel.forwards.fetch_add(1, Ordering::Relaxed) >= MAX_FORWARDS {
        tunnel.forwards.fetch_sub(1, Ordering::Relaxed);
        return Err(format!("{MAX_FORWARDS} app streams open"));
    }
    let forward = Forward(tunnel.forwards.clone());
    match select(
        pin!(dial_inner(tunnel, tls, cluster)),
        pin!(crate::sockets::sleep(DIAL_DEADLINE)),
    )
    .await
    {
        Either::Left((res, _)) => res.map(|tls| AppStream {
            tls: AppTls::Tunnel(tls),
            _forward: Some(forward),
        }),
        Either::Right(_) => Err(format!("dial: no answer within {DIAL_DEADLINE:?}")),
    }
}

/// Runs the three steps of [`dial_app`].
async fn dial_inner(
    tunnel: &AppTunnel,
    tls: Arc<rustls::ClientConfig>,
    cluster: &str,
) -> std::result::Result<TlsStream, String> {
    let ch = tunnel
        .handle
        .channel_open_custom(CHAN_TRANSPORT, Vec::new())
        .await
        .map_err(|e| format!("transport open: {e}"))?;
    // Closes the channel on a refusal, an error, or the deadline.
    let guard = CloseOnDrop::new(ch);
    let dial = json!({
        "address": "@local-node",
        "server_id": tunnel.server_id,
        "conn_type": "app",
    });
    let accepted = guard
        .channel()
        .request_custom(REQ_DIAL, true, dial.to_string().into_bytes())
        .await
        .map_err(|e| format!("dial request: {e}"))?;
    if !accepted {
        return Err("dial refused by agent".into());
    }

    // The stream closes the channel when it is dropped.
    connect_tls(tls, cluster, guard.into_inner().into_stream()).await
}

/// Asks auth's on-demand callout for an app stream and runs TLS toward the
/// app service over it. The wait for the stream has
/// [`crate::lazy::STREAM_WAIT`], and TLS then has [`DIAL_DEADLINE`], so the
/// dial takes at most their sum, 20 s. The error is
/// [`crate::lazy::DialError::Busy`] when the hub had no room for the dial.
pub(crate) async fn dial_app_lazy(
    lazy: &crate::lazy::Lazy,
    tls: Arc<rustls::ClientConfig>,
    cluster: &str,
) -> std::result::Result<AppStream, crate::lazy::DialError> {
    use crate::lazy::DialError;
    let stream = lazy.dial(crate::lazy::Kind::App).await?;
    let tls = match select(
        pin!(connect_tls(tls, cluster, stream)),
        pin!(crate::sockets::sleep(DIAL_DEADLINE)),
    )
    .await
    {
        Either::Left((res, _)) => res.map_err(DialError::Failed)?,
        Either::Right(_) => {
            return Err(DialError::Failed(format!(
                "tls connect: no answer within {DIAL_DEADLINE:?}"
            )))
        }
    };
    Ok(AppStream {
        tls: AppTls::Lazy(tls),
        _forward: None,
    })
}

/// Runs TLS toward the app service over `stream`, with the SNI the app
/// service expects for `cluster`.
async fn connect_tls<S>(
    tls: Arc<rustls::ClientConfig>,
    cluster: &str,
    stream: S,
) -> std::result::Result<tokio_rustls::client::TlsStream<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let sni = format!("{}.{API_DOMAIN}", hex(cluster.as_bytes()));
    let name = ServerName::try_from(sni.clone()).map_err(|e| format!("sni {sni:?}: {e}"))?;
    tokio_rustls::TlsConnector::from(tls)
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls connect: {e}"))
}

type TlsStream = tokio_rustls::client::TlsStream<russh::ChannelStream<Msg>>;

/// Closes the channel it holds when it is dropped.
pub(crate) struct CloseOnDrop(Option<Channel<Msg>>);

impl CloseOnDrop {
    pub(crate) fn new(ch: Channel<Msg>) -> Self {
        Self(Some(ch))
    }

    /// Returns the channel.
    pub(crate) fn channel(&self) -> &Channel<Msg> {
        // Only `into_inner` takes the channel out, and it consumes the guard.
        self.0.as_ref().expect("the guard holds the channel")
    }

    /// Returns the channel, which then stays open.
    pub(crate) fn into_inner(mut self) -> Channel<Msg> {
        self.0.take().expect("the guard holds the channel")
    }
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(ch) = self.0.take() {
            crate::ssh::close_later(ch);
        }
    }
}

impl AsyncRead for AppStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().tls {
            AppTls::Tunnel(t) => Pin::new(t).poll_read(cx, buf),
            AppTls::Lazy(t) => Pin::new(t).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AppStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().tls {
            AppTls::Tunnel(t) => Pin::new(t).poll_write(cx, buf),
            AppTls::Lazy(t) => Pin::new(t).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().tls {
            AppTls::Tunnel(t) => Pin::new(t).poll_flush(cx),
            AppTls::Lazy(t) => Pin::new(t).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().tls {
            AppTls::Tunnel(t) => Pin::new(t).poll_shutdown(cx),
            AppTls::Lazy(t) => Pin::new(t).poll_shutdown(cx),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
