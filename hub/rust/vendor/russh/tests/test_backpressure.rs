//! sallyport: a channel whose reader stops reading is closed, and the other
//! channels on the connection keep flowing. Upstream instead blocked the
//! whole connection until the slow reader caught up.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand_core::OsRng;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{client, Channel, ChannelMsg};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

const CHANNEL_BUFFER_SIZE: usize = 10;
const CHUNK: usize = 16 * 1024;

#[tokio::test]
async fn slow_reader_is_closed_and_others_flow() -> Result<(), anyhow::Error> {
    let (server, mut got_rx) = Server::start(false).await;
    let session = server.connect(client::Config::default()).await?;

    // The server never reads the first channel.
    let mut slow = session.channel_open_session().await?;
    let fast = session.channel_open_session().await?;

    let mut writer = slow.make_writer();
    let data = vec![7u8; CHUNK];
    for _ in 0..CHANNEL_BUFFER_SIZE * 2 {
        if writer.write_all(&data).await.is_err() {
            break;
        }
    }
    drop(writer);
    wait_closed(&mut slow).await;

    fast.data(&b"hello"[..]).await?;
    let got = timeout(Duration::from_secs(5), got_rx.recv()).await?;
    assert_eq!(got.as_deref(), Some(&b"hello"[..]));

    server.assert_held_reader_fails().await;
    Ok(())
}

/// The queue is full of data when the EOF arrives, so the EOF closes the
/// channel.
#[tokio::test]
async fn slow_reader_is_closed_on_eof() -> Result<(), anyhow::Error> {
    let (server, _got_rx) = Server::start(false).await;
    let session = server.connect(client::Config::default()).await?;

    let mut slow = session.channel_open_session().await?;
    let mut writer = slow.make_writer();
    let data = vec![7u8; CHUNK];
    for _ in 0..CHANNEL_BUFFER_SIZE {
        writer.write_all(&data).await?;
    }
    drop(writer);
    slow.eof().await?;
    wait_closed(&mut slow).await;

    server.assert_held_reader_fails().await;
    Ok(())
}

/// The server writes on a channel whose reader it never polls, so every
/// window adjust from the client queues a `WindowAdjusted` message there.
/// Upstream blocked the session loop once that queue filled.
#[tokio::test]
async fn unread_writer_channel_does_not_stall() -> Result<(), anyhow::Error> {
    let (server, mut got_rx) = Server::start(true).await;
    // A small client window makes the client send many window adjusts.
    let config = client::Config {
        window_size: 4 * CHUNK as u32,
        ..Default::default()
    };
    let session = server.connect(config).await?;

    let mut writer_side = session.channel_open_session().await?;
    let fast = session.channel_open_session().await?;

    let mut received = 0usize;
    let want = CHANNEL_BUFFER_SIZE * 8 * CHUNK;
    let read = timeout(Duration::from_secs(10), async {
        while received < want {
            match writer_side.wait().await {
                Some(ChannelMsg::Data { data }) => received += data.len(),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    assert!(read.is_ok(), "stalled after {received} of {want} bytes");

    fast.data(&b"hello"[..]).await?;
    let got = timeout(Duration::from_secs(5), got_rx.recv()).await?;
    assert_eq!(got.as_deref(), Some(&b"hello"[..]));
    Ok(())
}

async fn wait_closed(channel: &mut Channel<client::Msg>) {
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Close) | None => return,
                _ => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "slow channel was not closed");
}

#[derive(Clone)]
struct Server {
    addr: SocketAddr,
    opened: Arc<AtomicUsize>,
    got: mpsc::UnboundedSender<Vec<u8>>,
    /// Holds the unread channel open.
    held: Arc<Mutex<Vec<Channel<Msg>>>>,
    /// When true, the first channel writes data instead of being held.
    write_first: bool,
}

impl Server {
    /// Starts a server on a local port. The receiver gets the data of every
    /// channel after the first.
    async fn start(write_first: bool) -> (Server, mpsc::UnboundedReceiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (got, got_rx) = mpsc::unbounded_channel();
        let server = Server {
            addr: listener.local_addr().unwrap(),
            opened: Default::default(),
            got,
            held: Default::default(),
            write_first,
        };
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()],
            channel_buffer_size: CHANNEL_BUFFER_SIZE,
            ..Default::default()
        });
        let mut sh = server.clone();
        tokio::spawn(async move { sh.run_on_socket(config, &listener).await });
        (server, got_rx)
    }

    async fn connect(
        &self,
        config: client::Config,
    ) -> Result<client::Handle<Client>, anyhow::Error> {
        let key = Arc::new(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
        let mut session = client::connect(Arc::new(config), self.addr, Client).await?;
        let hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        assert!(session
            .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, hash))
            .await?
            .success());
        Ok(session)
    }

    /// Reads the held channel after the server closed it. The reader gets
    /// the full queue and then an error, not a clean end of stream.
    async fn assert_held_reader_fails(&self) {
        let mut channel = self.held.lock().unwrap().pop().unwrap();
        let mut got = Vec::new();
        let read = channel.make_reader().read_to_end(&mut got).await;
        assert!(
            read.is_err(),
            "read ended cleanly after {} bytes",
            got.len()
        );
        assert_eq!(got.len(), CHANNEL_BUFFER_SIZE * CHUNK);
    }
}

impl russh::server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        mut channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.opened.fetch_add(1, Ordering::Relaxed) == 0 {
            if self.write_first {
                // Write without ever calling `wait`, so nothing drains
                // this channel's queue.
                tokio::spawn(async move {
                    let data = vec![7u8; CHUNK];
                    for _ in 0..CHANNEL_BUFFER_SIZE * 8 {
                        if channel.data(&data[..]).await.is_err() {
                            break;
                        }
                    }
                    std::future::pending::<()>().await;
                    drop(channel);
                });
            } else {
                self.held.lock().unwrap().push(channel);
            }
            return Ok(true);
        }
        let got = self.got.clone();
        tokio::spawn(async move {
            while let Some(msg) = channel.wait().await {
                if let ChannelMsg::Data { data } = msg {
                    let _ = got.send(data.to_vec());
                }
            }
        });
        Ok(true)
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
