//! The auth pipe: WebSockets that auth opens to the hub with its callout.
//!
//! The hub sends a 32-byte nonce. Auth replies with its own nonce and an
//! Ed25519 signature over `"sallyport/authpipe/v1" || host || hub nonce ||
//! auth nonce`, where host is the host of the URL auth dialled. The hub
//! checks the signature against the pinned key in `AUTH_CALLOUT_PUBKEY` and
//! the host against `CALLOUT_HOST`. A verified WebSocket waits in the pool
//! until the hub takes it. Auth hands the stream to its listener on the
//! hub's first message.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::channel::oneshot;
use futures::future::{select, Either};
use futures::StreamExt;
use ring::signature::{UnparsedPublicKey, ED25519};
use tokio::io::DuplexStream;
use tokio::sync::Notify;
use worker::*;

use crate::tunnel::{pump, secret_bytes, Pending, Ticket, PIPE_BYTES};

pub const PATH: &str = "/tunnel/auth";
const DOMAIN: &[u8] = b"sallyport/authpipe/v1";
const NONCE: usize = 32;
const SIGNATURE: usize = 64;
/// The challenge is one round trip, so a socket that has not answered by
/// then is closed.
const CHALLENGE_DEADLINE: Duration = Duration::from_secs(3);
/// Verified WebSockets from auth, waiting or in use, that the hub keeps.
/// Auth opens 8 by default. Above this, a newly verified stream closes the
/// oldest waiting one.
const MAX_STREAMS: usize = 8;
/// Verified WebSockets the hub accepts. Only streams in use can take the
/// hub above [`MAX_STREAMS`], because [`Pool::push`] closes waiting ones.
const MAX_ACCEPTED: usize = 2 * MAX_STREAMS;
/// WebSockets in the challenge. Auth opens all its streams at once, so this
/// is [`MAX_STREAMS`]. Above it, a new socket closes the oldest one in the
/// challenge, so sockets that never answer cannot keep auth out.
const MAX_UNVERIFIED: usize = MAX_STREAMS;
/// How long [`Pool::take_wait`] waits for auth to open a stream when none
/// is waiting.
pub const TAKE_WAIT: Duration = Duration::from_secs(5);

/// One verified WebSocket from auth, as the hub end of an in-memory pipe.
/// Dropping the pipe closes the WebSocket.
struct Stream {
    pipe: DuplexStream,
    /// False once the WebSocket has closed.
    alive: Arc<AtomicBool>,
}

/// The verified streams waiting for the hub, oldest first. The Durable
/// Object is single-threaded, but russh's handler must be `Send`.
#[derive(Clone, Default)]
pub struct Pool {
    ready: Arc<Mutex<VecDeque<Stream>>>,
    /// Verified WebSockets, waiting or in use.
    open: Arc<AtomicUsize>,
    arrived: Arc<Notify>,
    /// The WebSockets in the challenge.
    unverified: Pending,
}

impl Pool {
    /// Takes the oldest open stream, or returns None if there is none.
    pub fn take(&self) -> Option<DuplexStream> {
        let mut ready = self.ready.lock().unwrap();
        while let Some(s) = ready.pop_front() {
            if s.alive.load(Ordering::Relaxed) {
                return Some(s.pipe);
            }
        }
        None
    }

    /// Takes the oldest open stream. If there is none, it waits for auth to
    /// open one until `deadline` resolves, and then returns None.
    pub async fn take_until(&self, deadline: impl Future<Output = ()>) -> Option<DuplexStream> {
        let mut deadline = pin!(deadline);
        loop {
            let mut arrived = pin!(self.arrived.notified());
            arrived.as_mut().enable();
            if let Some(s) = self.take() {
                return Some(s);
            }
            if let Either::Right(_) = select(arrived, deadline.as_mut()).await {
                return self.take();
            }
        }
    }

    /// Takes the oldest open stream, waiting up to [`TAKE_WAIT`] for one.
    pub async fn take_wait(&self) -> std::result::Result<DuplexStream, String> {
        self.take_until(crate::sockets::sleep(TAKE_WAIT))
            .await
            .ok_or_else(|| format!("no auth pipe stream within {TAKE_WAIT:?}"))
    }

    /// Adds a verified stream. When more than [`MAX_STREAMS`] WebSockets are
    /// open, it closes the oldest waiting stream, unless the new one is the
    /// only one waiting. Returns true if it closed one.
    fn push(&self, stream: Stream) -> bool {
        let evicted = {
            let mut ready = self.ready.lock().unwrap();
            ready.retain(|s| s.alive.load(Ordering::Relaxed));
            ready.push_back(stream);
            if self.open() > MAX_STREAMS && ready.len() > 1 {
                ready.pop_front()
            } else {
                None
            }
        };
        let closed = evicted.is_some();
        drop(evicted);
        self.arrived.notify_waiters();
        closed
    }

    /// Returns the number of verified streams waiting.
    pub fn ready(&self) -> usize {
        self.ready.lock().unwrap().iter().filter(|s| s.alive.load(Ordering::Relaxed)).count()
    }

    /// Returns the number of verified WebSockets from auth, waiting or in
    /// use.
    pub fn open(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    /// Returns the number of WebSockets from auth in the challenge.
    pub fn unverified(&self) -> usize {
        self.unverified.waiting()
    }
}

/// Accepts one WebSocket from auth and runs the challenge on it.
pub fn accept(req: &Request, env: &Env, pool: &Pool) -> Result<Response> {
    // Auth's callout sends no `Origin`, and a browser always sends one.
    if req.headers().get("Origin")?.is_some() {
        return Response::error("origin not allowed", 403);
    }
    if pool.open() >= MAX_ACCEPTED {
        console_log!("tunnel/auth: stream limit reached");
        return Response::error("too many streams", 503);
    }
    let key = secret_bytes(env, "AUTH_CALLOUT_PUBKEY")?;
    if key.len() != 32 {
        return Err(Error::RustError("AUTH_CALLOUT_PUBKEY is not 32 bytes".into()));
    }
    let host = env.var("CALLOUT_HOST")?.to_string();

    let pair = WebSocketPair::new()?;
    let ws = pair.server;
    // Newer compatibility dates deliver binary messages as Blob, which
    // workers-rs 0.8 reads as zero bytes. Ask for ArrayBuffer instead.
    worker::js_sys::Reflect::set(ws.as_ref(), &"binaryType".into(), &"arraybuffer".into())
        .map_err(|_| Error::RustError("setting binaryType".into()))?;
    ws.accept()?;
    console_log!("tunnel/auth: connection accepted");

    let (ticket, evicted, evicted_one) = pool.unverified.admit(MAX_UNVERIFIED);
    if evicted_one {
        console_log!("tunnel/auth: {MAX_UNVERIFIED} sockets in the challenge, closed the oldest");
    }
    let pool = pool.clone();
    wasm_bindgen_futures::spawn_local(async move {
        serve(ws.clone(), key, host, &pool, ticket, evicted).await;
        // `serve` added the WebSocket to the restart list when it started
        // listening, before the challenge.
        crate::sockets::remove(&ws);
    });
    Response::from_websocket(pair.client)
}

/// Runs the challenge on `ws`, and then adds it to `pool`. `ticket` is the
/// socket's place among the sockets in the challenge, and `evicted`
/// resolves when a newer socket takes that place.
async fn serve(ws: WebSocket, key: Vec<u8>, host: String, pool: &Pool, ticket: Ticket, mut evicted: oneshot::Receiver<()>) {
    let mut events = match crate::wsevents::events(&ws) {
        Ok(e) => e,
        Err(err) => {
            console_error!("tunnel/auth: websocket events: {err}");
            return;
        }
    };
    let mut nonce = [0u8; NONCE];
    if getrandom::getrandom(&mut nonce).is_err() || ws.send_with_bytes(nonce).is_err() {
        let _ = ws.close(Some(1011), Some("nonce"));
        return;
    }

    let deadline = pin!(crate::sockets::sleep(CHALLENGE_DEADLINE));
    let stop = select(deadline, &mut evicted);
    let reply = match select(events.next(), stop).await {
        Either::Left((Some(Ok(WebsocketEvent::Message(msg))), _)) => msg.bytes(),
        Either::Right((Either::Left(_), _)) => {
            console_log!("tunnel/auth: challenge failed, no reply within {CHALLENGE_DEADLINE:?}");
            let _ = ws.close(Some(1008), Some("challenge timeout"));
            return;
        }
        Either::Right((Either::Right(_), _)) => {
            console_log!("tunnel/auth: closed a socket in the challenge for a newer one");
            let _ = ws.close(Some(1008), Some("too many sockets in the challenge"));
            return;
        }
        _ => None,
    };
    let Some(reply) = reply.filter(|r| r.len() == NONCE + SIGNATURE) else {
        console_log!("tunnel/auth: challenge failed, bad reply");
        let _ = ws.close(Some(1008), Some("challenge"));
        return;
    };
    let (auth_nonce, sig) = reply.split_at(NONCE);
    let mut msg = Vec::with_capacity(DOMAIN.len() + host.len() + 2 * NONCE);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(host.as_bytes());
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(auth_nonce);
    if UnparsedPublicKey::new(&ED25519, &key).verify(&msg, sig).is_err() {
        console_log!("tunnel/auth: challenge failed, bad signature");
        let _ = ws.close(Some(1008), Some("challenge"));
        return;
    }
    console_log!("tunnel/auth: stream ready");
    drop(ticket);
    pool.open.fetch_add(1, Ordering::Relaxed);

    let (hub_side, pipe_side) = tokio::io::duplex(PIPE_BYTES);
    let alive = Arc::new(AtomicBool::new(true));
    let closed = pool.push(Stream {
        pipe: hub_side,
        alive: alive.clone(),
    });
    if closed {
        console_log!("tunnel/auth: {MAX_STREAMS} streams open, closed the oldest waiting one");
    }
    pump(&ws, events, pipe_side).await;
    alive.store(false, Ordering::Relaxed);
    pool.open.fetch_sub(1, Ordering::Relaxed);
    console_log!("tunnel/auth: stream closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::future::{pending, ready};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Adds a stream to `pool` as `accept` and `serve` would, and returns
    /// its far end and its liveness flag.
    fn add(pool: &Pool) -> (DuplexStream, Arc<AtomicBool>, bool) {
        let (hub_side, far) = tokio::io::duplex(64);
        let alive = Arc::new(AtomicBool::new(true));
        pool.open.fetch_add(1, Ordering::Relaxed);
        let closed = pool.push(Stream { pipe: hub_side, alive: alive.clone() });
        (far, alive, closed)
    }

    #[test]
    fn take_skips_dead_streams() {
        let pool = Pool::default();
        let (_a, a_alive, _) = add(&pool);
        let (mut b, _, _) = add(&pool);
        a_alive.store(false, Ordering::Relaxed);
        assert_eq!(pool.ready(), 1);
        let mut got = pool.take().expect("a live stream");
        block_on(async {
            got.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            b.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"x");
        });
        assert!(pool.take().is_none());
    }

    #[test]
    fn push_closes_oldest_waiting_stream_above_limit() {
        let pool = Pool::default();
        let mut fars = Vec::new();
        for _ in 0..MAX_STREAMS {
            let (far, _, closed) = add(&pool);
            assert!(!closed);
            fars.push(far);
        }
        let (_newest, _, closed) = add(&pool);
        assert!(closed);
        assert_eq!(pool.ready(), MAX_STREAMS);
        // The oldest stream's hub end was dropped, so its far end reads EOF.
        let mut buf = [0u8; 1];
        assert_eq!(block_on(fars[0].read(&mut buf)).unwrap(), 0);
    }

    #[test]
    fn push_keeps_the_only_waiting_stream() {
        let pool = Pool::default();
        pool.open.fetch_add(MAX_STREAMS, Ordering::Relaxed);
        let (_far, _, closed) = add(&pool);
        assert!(!closed);
        assert_eq!(pool.ready(), 1);
    }

    #[test]
    fn take_until_returns_none_at_deadline() {
        let pool = Pool::default();
        assert!(block_on(pool.take_until(ready(()))).is_none());
    }

    #[test]
    fn take_until_waits_for_a_stream() {
        let pool = Pool::default();
        let waiter = pool.clone();
        let (got, far) = block_on(async {
            let take = waiter.take_until(pending());
            let add = async { add(&pool).0 };
            futures::join!(take, add)
        });
        assert!(got.is_some());
        drop(far);
    }
}
