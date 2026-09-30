//! Tests for the patched server hooks that Teleport's reverse tunnel needs.
//!
//! The russh client cannot open unknown channel types, send arbitrary
//! requests, or answer custom channel requests, so these tests drive the
//! server with a Go client built on golang.org/x/crypto/ssh, the library
//! Teleport agents use. The Go client reports what it observed on stdout.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};

use rand_core::OsRng;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};
use ssh_key::PrivateKey;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

fn goclient() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/goclient");
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("goclient");
        let status = Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&out)
            .arg(".")
            .current_dir(&dir)
            .status()
            .expect("run go build");
        assert!(status.success(), "go build failed");
        out
    })
}

#[derive(Debug, PartialEq)]
enum Event {
    ChannelOpen(String),
    ChannelRequest {
        typ: String,
        want_reply: bool,
        data: Vec<u8>,
    },
    GlobalRequest {
        typ: String,
        want_reply: bool,
        data: Vec<u8>,
    },
}

struct Handler {
    events: mpsc::UnboundedSender<Event>,
    ready: Option<oneshot::Sender<server::Handle>>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_unknown(
        &mut self,
        typ: &str,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let _ = self.events.send(Event::ChannelOpen(typ.to_owned()));
        Ok(typ == "teleport-heartbeat")
    }

    async fn channel_request_unknown(
        &mut self,
        _channel: ChannelId,
        typ: &str,
        want_reply: bool,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let _ = self.events.send(Event::ChannelRequest {
            typ: typ.to_owned(),
            want_reply,
            data: data.to_vec(),
        });
        Ok(typ == "probe-true")
    }

    async fn global_request_unknown(
        &mut self,
        typ: &str,
        want_reply: bool,
        data: &[u8],
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // The Go client sends "ready" once it can take server-opened
        // channels.
        if typ == "ready" {
            if let Some(tx) = self.ready.take() {
                let _ = tx.send(session.handle());
            }
            return Ok(true);
        }
        let _ = self.events.send(Event::GlobalRequest {
            typ: typ.to_owned(),
            want_reply,
            data: data.to_vec(),
        });
        Ok(typ == "keepalive@openssh.com")
    }
}

struct Run {
    events: Vec<Event>,
    stdout: String,
}

fn ed25519_config() -> server::Config {
    server::Config {
        keys: vec![PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()],
        ..Default::default()
    }
}

/// Runs one Go client scenario against one server session. `with_handle`
/// runs on the server side once the client sends the "ready" global
/// request.
async fn run<F, Fut>(scenario: &str, with_handle: F) -> Run
where
    F: FnOnce(server::Handle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    run_with(ed25519_config(), &[scenario], with_handle).await
}

async fn run_with<F, Fut>(config: server::Config, args: &[&str], with_handle: F) -> Run
where
    F: FnOnce(server::Handle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let bin = goclient();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let child = tokio::process::Command::new(bin)
        .arg(addr.to_string())
        .args(args)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let (stream, _) = listener.accept().await.unwrap();
    let config = Arc::new(config);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let handler = Handler {
        events: events_tx,
        ready: Some(ready_tx),
    };
    let session = server::run_stream(config, stream, handler).await.unwrap();
    let server_side = tokio::spawn(async move {
        if let Ok(handle) = ready_rx.await {
            with_handle(handle).await;
        }
    });

    let out = child.wait_with_output().await.unwrap();
    assert!(out.status.success(), "goclient {args:?} failed");
    server_side.await.unwrap();
    // The session ends with an error when the client drops the connection.
    let _ = session.await;

    let mut events = Vec::new();
    while let Ok(e) = events_rx.try_recv() {
        events.push(e);
    }
    Run {
        events,
        stdout: String::from_utf8(out.stdout).unwrap(),
    }
}

#[tokio::test]
async fn unknown_channel_open_follows_handler() {
    let r = run("open", |_| async {}).await;
    assert_eq!(r.stdout, "heartbeat=ok\nrefused=unknown channel type\n");
    assert_eq!(
        r.events,
        vec![
            Event::ChannelOpen("teleport-heartbeat".into()),
            Event::ChannelOpen("teleport-refused".into()),
        ]
    );
}

#[tokio::test]
async fn unknown_channel_request_replies_only_when_asked() {
    let r = run("chanreq", |_| async {}).await;
    // If the server had answered ping, Go would read that failure as the
    // reply to probe-true.
    assert_eq!(r.stdout, "probe-true=true\nprobe-false=false\n");
    assert_eq!(
        r.events,
        vec![
            Event::ChannelOpen("teleport-heartbeat".into()),
            Event::ChannelRequest {
                typ: "ping".into(),
                want_reply: false,
                data: vec![1, 2, 3],
            },
            Event::ChannelRequest {
                typ: "probe-true".into(),
                want_reply: true,
                data: b"t".to_vec(),
            },
            Event::ChannelRequest {
                typ: "probe-false".into(),
                want_reply: true,
                data: vec![],
            },
        ]
    );
}

#[tokio::test]
async fn unknown_global_request_replies_only_when_asked() {
    let r = run("global", |_| async {}).await;
    // If the server had answered the second keepalive, Go would read that
    // success as the reply to probe-false.
    assert_eq!(r.stdout, "keepalive-reply=true\nprobe-false=false\n");
    let keepalive = |want_reply| Event::GlobalRequest {
        typ: "keepalive@openssh.com".into(),
        want_reply,
        data: vec![],
    };
    assert_eq!(
        r.events,
        vec![
            keepalive(true),
            keepalive(false),
            Event::GlobalRequest {
                typ: "probe-false".into(),
                want_reply: true,
                data: vec![],
            },
        ]
    );
}

#[tokio::test]
async fn server_opens_custom_channel_and_sends_custom_requests() {
    let (results_tx, results_rx) = oneshot::channel();
    let r = run("transport", move |handle| async move {
        let channel = handle
            .channel_open_custom("teleport-transport", vec![0xab, 0xcd])
            .await
            .unwrap();
        let dial = channel
            .request_custom("teleport-transport-dial", true, vec![1, 2])
            .await
            .unwrap();
        let other = channel
            .request_custom("teleport-other", true, vec![])
            .await
            .unwrap();
        let no_reply = channel
            .request_custom("teleport-quiet", false, vec![3])
            .await
            .unwrap();
        channel.close().await.unwrap();
        let _ = results_tx.send((dial, other, no_reply));
    })
    .await;
    assert_eq!(
        r.stdout,
        "open-extra=abcd\n\
         request=teleport-transport-dial:0102\n\
         request=teleport-other:\n\
         request=teleport-quiet:03\n"
    );
    assert_eq!(results_rx.await.unwrap(), (true, false, true));
    assert_eq!(r.events, vec![]);
}

#[tokio::test]
async fn messages_on_unconfirmed_channel_are_ignored() {
    let (results_tx, results_rx) = oneshot::channel();
    let r = run("unconfirmed", move |handle| async move {
        let mut channel = handle
            .channel_open_custom("teleport-transport", vec![])
            .await
            .unwrap();
        let dial = channel
            .request_custom("teleport-transport-dial", true, vec![])
            .await
            .unwrap();
        channel.close().await.unwrap();
        let mut early = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                early.extend_from_slice(&data);
            }
        }
        let _ = results_tx.send((dial, early));
    })
    .await;
    assert_eq!(r.stdout, "request=teleport-transport-dial:\n");
    assert_eq!(results_rx.await.unwrap(), (true, vec![]));
    assert_eq!(r.events, vec![]);
}

#[tokio::test]
async fn request_custom_fails_when_peer_closes_first() {
    let (result_tx, result_rx) = oneshot::channel();
    let r = run("transport-close", move |handle| async move {
        let channel = handle
            .channel_open_custom("teleport-transport", vec![])
            .await
            .unwrap();
        let reply = channel
            .request_custom("teleport-transport-dial", true, vec![])
            .await;
        let _ = result_tx.send(reply);
        handle
            .disconnect(
                russh::Disconnect::ByApplication,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
    })
    .await;
    assert_eq!(r.stdout, "request=teleport-transport-dial\n");
    assert!(matches!(
        result_rx.await.unwrap(),
        Err(russh::Error::Disconnect)
    ));
}

#[tokio::test]
async fn request_custom_fails_when_server_closes_first() {
    let (result_tx, result_rx) = oneshot::channel();
    let r = run("transport-silent", move |handle| async move {
        let channel = handle
            .channel_open_custom("teleport-transport", vec![])
            .await
            .unwrap();
        // The session handles the request before the close, because both
        // go through the same queue. The timeout turns a reply that never
        // comes into a test failure.
        let (reply, _) = tokio::join!(
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                channel.request_custom("teleport-transport-dial", true, vec![]),
            ),
            channel.close(),
        );
        let _ = result_tx.send(reply);
        handle
            .disconnect(
                russh::Disconnect::ByApplication,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
    })
    .await;
    assert_eq!(r.stdout, "request=teleport-transport-dial\n");
    assert!(matches!(
        result_rx.await.unwrap(),
        Ok(Err(russh::Error::Disconnect))
    ));
}

/// Runs a scenario that sends one data packet of `size` bytes, bypassing Go's
/// packet size and window checks, and returns what the Go client printed.
async fn send_raw_data(scenario: &str, config: server::Config, size: usize) -> String {
    run_with(config, &[scenario, &size.to_string()], |_| async {})
        .await
        .stdout
}

#[tokio::test]
async fn data_over_maximum_packet_size_disconnects() {
    let max = ed25519_config().maximum_packet_size as usize;
    assert_eq!(
        send_raw_data("oversize-data", ed25519_config(), max).await,
        "after-data=true\n"
    );
    assert_eq!(
        send_raw_data("oversize-data", ed25519_config(), max + 1).await,
        "after-data=false\n"
    );
}

#[tokio::test]
async fn data_over_window_disconnects() {
    let small_window = || server::Config {
        window_size: 16384,
        ..ed25519_config()
    };
    assert_eq!(
        send_raw_data("overwindow-data", small_window(), 16384).await,
        "after-data=true\n"
    );
    assert_eq!(
        send_raw_data("overwindow-data", small_window(), 16385).await,
        "after-data=false\n"
    );
}

/// Returns a CA key and a server config whose ECDSA host key has a host
/// certificate signed by that CA.
fn host_cert_config() -> (PrivateKey, server::Config) {
    let ca = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let host = PrivateKey::random(
        &mut OsRng,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder =
        ssh_key::certificate::Builder::new([7u8; 16], host.public_key(), now - 60, now + 3600)
            .unwrap();
    builder
        .cert_type(ssh_key::certificate::CertType::Host)
        .unwrap();
    builder.key_id("hub").unwrap();
    builder.valid_principal("127.0.0.1").unwrap();
    builder.valid_principal("hub.sallyport").unwrap();
    let cert = builder.sign(&ca).unwrap();
    let config = server::Config {
        keys: vec![host],
        host_certificates: vec![cert],
        ..Default::default()
    };
    (ca, config)
}

#[tokio::test]
async fn host_certificate_passes_cert_checker() {
    let (ca, config) = host_cert_config();
    let ca_pub = ca.public_key().to_openssh().unwrap();
    let r = run_with(config, &["hostcert", &ca_pub], |_| async {}).await;
    assert_eq!(
        r.stdout,
        "handshake=ok\ncert-principals=127.0.0.1,hub.sallyport\n"
    );
}

#[tokio::test]
async fn plain_host_key_fails_cert_checker() {
    let (ca, mut config) = host_cert_config();
    config.host_certificates.clear();
    let ca_pub = ca.public_key().to_openssh().unwrap();
    let r = run_with(config, &["hostcert", &ca_pub], |_| async {}).await;
    assert!(
        r.stdout.starts_with("handshake=failed: ") && r.stdout.contains("host key"),
        "stdout: {}",
        r.stdout
    );
}

#[tokio::test]
async fn host_certificate_falls_back_to_plain_key() {
    let (_, config) = host_cert_config();
    let r = run_with(config, &["hostkey-plain"], |_| async {}).await;
    assert_eq!(r.stdout, "host-key-type=ecdsa-sha2-nistp256\n");
}
