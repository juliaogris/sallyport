//! Tests that the server sends no channel data or other non-kex messages
//! during a key exchange.
//!
//! RFC 4253 section 7.1 allows only key exchange messages between KEXINIT
//! and NEWKEYS. The russh client accepts other messages there, so this test
//! uses the Go client from `tests/goclient`, which drops the connection
//! with "unexpected message type 94" when it gets channel data during a key
//! exchange.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rand_core::OsRng;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, Limits};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn goclient() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/goclient");
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("goclient-rekey");
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

struct EchoHandler;

impl server::Handler for EchoHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_unknown(
        &mut self,
        typ: &str,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if typ != "teleport-echo" {
            return Ok(false);
        }
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(channel.into_stream());
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });
        Ok(true)
    }
}

#[tokio::test]
async fn frequent_rekeys_keep_channel_data_out_of_the_kex() {
    const CHANNELS: usize = 8;
    const SIZE: usize = 2 << 20;
    let _ = env_logger::try_init();

    let config = server::Config {
        keys: vec![PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()],
        // About 128 server-initiated rekeys over the run.
        limits: Limits::new(128 << 10, 1 << 30, Duration::from_secs(3600)),
        // Larger than a full window of small packets, so that the slow reader
        // check never closes an echo channel.
        channel_buffer_size: 4096,
        ..Default::default()
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let child = tokio::process::Command::new(goclient())
        .arg(addr.to_string())
        .args(["rekey-echo", &CHANNELS.to_string(), &SIZE.to_string()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let (stream, _) = listener.accept().await.unwrap();
    let session = server::run_stream(Arc::new(config), stream, EchoHandler)
        .await
        .unwrap();

    let out = tokio::time::timeout(Duration::from_secs(120), child.wait_with_output())
        .await
        .expect("goclient timed out")
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "goclient failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(stdout, format!("echo=ok channels={CHANNELS} size={SIZE}\n"));
    // The session ends with an error when the client drops the connection.
    let _ = session.await;
}
