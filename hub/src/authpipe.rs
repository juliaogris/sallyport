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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{select, Either};
use futures::StreamExt;
use ring::signature::{UnparsedPublicKey, ED25519};
use tokio::io::DuplexStream;
use worker::*;

use crate::tunnel::{pump, secret_bytes, PIPE_BYTES};

pub const PATH: &str = "/tunnel/auth";
const DOMAIN: &[u8] = b"sallyport/authpipe/v1";
const NONCE: usize = 32;
const SIGNATURE: usize = 64;
const CHALLENGE_DEADLINE: Duration = Duration::from_secs(10);
/// WebSockets the hub keeps, verified or not. Auth opens 8 by default.
const MAX_STREAMS: usize = 8;

/// One verified WebSocket from auth, as the hub end of an in-memory pipe.
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
    open: Arc<AtomicUsize>,
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

    /// Returns the number of verified streams waiting.
    pub fn ready(&self) -> usize {
        self.ready.lock().unwrap().iter().filter(|s| s.alive.load(Ordering::Relaxed)).count()
    }

    /// Returns the number of open WebSockets from auth, waiting or in use.
    pub fn open(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }
}

/// Accepts one WebSocket from auth and runs the challenge on it.
pub fn accept(env: &Env, pool: &Pool) -> Result<Response> {
    if pool.open.load(Ordering::Relaxed) >= MAX_STREAMS {
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
    worker::js_sys::Reflect::set(ws.as_ref(), &"binaryType".into(), &"arraybuffer".into())
        .map_err(|_| Error::RustError("setting binaryType".into()))?;
    ws.accept()?;
    console_log!("tunnel/auth: connection accepted");

    let pool = pool.clone();
    pool.open.fetch_add(1, Ordering::Relaxed);
    wasm_bindgen_futures::spawn_local(async move {
        serve(ws, key, host, &pool).await;
        pool.open.fetch_sub(1, Ordering::Relaxed);
    });
    Response::from_websocket(pair.client)
}

async fn serve(ws: WebSocket, key: Vec<u8>, host: String, pool: &Pool) {
    let mut events = match ws.events() {
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

    let reply = match select(events.next(), Box::pin(Delay::from(CHALLENGE_DEADLINE))).await {
        Either::Left((Some(Ok(WebsocketEvent::Message(msg))), _)) => msg.bytes(),
        Either::Right(_) => {
            console_log!("tunnel/auth: challenge failed, no reply within {CHALLENGE_DEADLINE:?}");
            let _ = ws.close(Some(1008), Some("challenge timeout"));
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

    let (hub_side, pipe_side) = tokio::io::duplex(PIPE_BYTES);
    let alive = Arc::new(AtomicBool::new(true));
    pool.ready.lock().unwrap().push_back(Stream {
        pipe: hub_side,
        alive: alive.clone(),
    });
    pump(&ws, events, pipe_side).await;
    alive.store(false, Ordering::Relaxed);
    console_log!("tunnel/auth: stream closed");
}
