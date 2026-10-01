//! The lazy hub: auth's callout keeps one control socket open, and the hub
//! asks it for a stream each time it needs one, so the Durable Object can
//! hibernate while nobody uses it.
//!
//! The control socket is accepted with the hibernation API. Cloudflare
//! answers its "ping" with "pong" without waking the object. Its challenge
//! is the auth pipe's, and its state lives in the socket's attachment, so it
//! survives hibernation. The hub sends "dial auth <id>" or "dial app <id>"
//! on the one verified control socket. Auth then opens a stream with the id
//! in the `Sallyport-Stream-Id` header. The hub checks the id before the
//! upgrade, and uses each id once.
//!
//! The control upgrade's response carries `Sallyport-Control: refuse`. A
//! callout that reads it may answer a dial it will not open a stream for
//! with "refuse <id>", and the dial then fails at once instead of after
//! [`STREAM_WAIT`]. A refused id is used up.
//!
//! A callout that sets `Sallyport-Stream: ack` on a stream upgrade acks the
//! bytes it receives from the hub, as the hub acks the bytes it receives,
//! and the hub then keeps at most [`UPLOAD_WINDOW`] unacked on that stream.
//! Without the header the hub sends without waiting.
//!
//! Streams are accepted without hibernation, so the object stays awake while
//! one is open. A stream closes after [`STREAM_IDLE`] without bytes.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::pin::pin;
use std::rc::Rc;
use std::time::Duration;

use base64::Engine as _;
use futures::channel::oneshot;
use futures::future::{select, Either};
use serde::{Deserialize, Serialize};
use tokio::io::DuplexStream;
use worker::*;

use crate::tunnel::{secret_bytes, PIPE_BYTES};

/// The tag of every control socket.
const CONTROL: &str = "control";
/// The request header that carries a stream's id.
const STREAM_ID_HEADER: &str = "Sallyport-Stream-Id";
/// The request header on a stream upgrade whose value `ack` says that the
/// callout acks what it receives.
const STREAM_HEADER: &str = "Sallyport-Stream";
/// The response header on the control upgrade that lists what the hub
/// accepts on the control socket after the challenge.
const CONTROL_HEADER: &str = "Sallyport-Control";
/// A control socket that has not passed the challenge by then is closed.
const CHALLENGE_DEADLINE_MS: u64 = 10_000;
/// Control sockets in the challenge. At this many, a new socket closes the
/// oldest socket of the client address with the most in the challenge, with
/// 1013, so that one address cannot close the callout's socket.
const MAX_PENDING_CONTROL: usize = 4;
/// Dials waiting for their stream or for an app stream's place. Above this
/// a dial fails at once. Auth's callout allows a burst of 128 dials of each
/// kind, and a page load can send more than 32 app requests at once, each
/// of which is one dial.
const MAX_PENDING_DIALS: usize = 128;
/// Dials for callers that have not signed in, such as a passkey login,
/// that may wait at once. Above this such a dial fails at once, so that
/// logins cannot take the pending dials of signed-in users.
const MAX_PENDING_ANONYMOUS: usize = 8;
/// App streams open at once, waiting for their stream or paired. At this
/// many, an app dial waits for one to close, and fails when none closes
/// within [`STREAM_WAIT`]. Each stream can hold about 2.3 MiB: 1 MiB
/// queued by [`crate::wsevents`], up to 1 MiB sent and not yet acked, two
/// 64 KiB pipe halves, and TLS and HTTP buffers. 32 streams hold at most
/// about 74 MiB, which leaves room under the Durable Object's 128 MB for the
/// rest of the hub.
const MAX_APP_STREAMS: usize = 32;
/// How long a dial waits for its stream.
pub(crate) const STREAM_WAIT: Duration = Duration::from_secs(10);
/// A stream closes after this long without bytes in either direction. This
/// also closes an app response that sends nothing for that long, such as a
/// quiet server-sent events stream or a long poll.
pub const STREAM_IDLE: Duration = Duration::from_secs(30);
/// How many bytes a stream passes on between two acks. Auth's window is
/// 1 MiB, larger than this, so it can keep sending while an ack is on its
/// way. [`crate::wsevents`] closes a WebSocket that queues more than its
/// `MAX_QUEUED_BYTES`, so that limit must stay at or above auth's window.
pub(crate) const ACK_EVERY: u64 = 256 * 1024;
/// Bytes the hub sends on a stream with acks before it waits for one. The
/// callout closes a stream that has more than 8 MiB waiting for its reader.
pub(crate) const UPLOAD_WINDOW: u64 = 1024 * 1024;

thread_local! {
    /// The lazy hub of this Wasm instance, if `HUB_MODE` is `lazy`. The
    /// instance is single-threaded, so the auth client and the app proxy
    /// can reach it without the hub being `Send`.
    static LAZY: RefCell<Option<Rc<Lazy>>> = const { RefCell::new(None) };
}

/// Returns true if `env` asks for the lazy hub.
pub fn enabled(env: &Env) -> bool {
    env.var("HUB_MODE")
        .map(|v| v.to_string() == "lazy")
        .unwrap_or(false)
}

/// Removes the lazy hub of this instance, so that a new Durable Object does
/// not use the `State` of an earlier one.
pub fn clear() {
    LAZY.with(|l| *l.borrow_mut() = None);
}

/// Returns the lazy hub of this instance, if there is one.
pub fn get() -> Option<Rc<Lazy>> {
    LAZY.with(|l| l.borrow().clone())
}

/// The kind of stream a dial asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Auth,
    App,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Auth => "auth",
            Kind::App => "app",
        }
    }
}

/// Who a dial is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A signed-in user, or the hub itself.
    SignedIn,
    /// A request that has not signed in, which counts toward
    /// [`MAX_PENDING_ANONYMOUS`].
    Anonymous,
}

/// The state of a control socket, kept in its attachment.
#[derive(Serialize, Deserialize)]
struct Attachment {
    /// When the hub accepted the socket, in ms since the epoch.
    accepted_ms: u64,
    /// The hub's nonce, while the challenge runs.
    nonce: Vec<u8>,
    verified: bool,
    /// The client address, from [`crate::tunnel::client_key`]. It is empty
    /// on a socket that an older hub accepted.
    #[serde(default)]
    client: String,
}

/// Why a dial got no stream.
#[derive(Debug)]
pub enum DialError {
    /// The hub has no room for the dial, or auth's callout refused it.
    Busy(String),
    /// Auth is not connected, or no stream arrived in time.
    Failed(String),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Busy(msg) | DialError::Failed(msg) => f.write_str(msg),
        }
    }
}

/// A dial waiting for its stream.
struct PendingDial {
    kind: Kind,
    caller: Caller,
    /// Sends the stream, or None when the callout refused the dial.
    tx: oneshot::Sender<Option<DuplexStream>>,
    /// An app dial's place in [`MAX_APP_STREAMS`]. The stream's pump keeps
    /// it until the WebSocket closes, because the queue of the WebSocket's
    /// events lives as long as the WebSocket.
    slot: Option<Slot>,
}

/// The places for app streams, of which `cap` can be taken at once.
struct Slots {
    open: Cell<usize>,
    cap: usize,
    /// Wakes one waiting dial when a place is freed.
    freed: tokio::sync::Notify,
}

impl Slots {
    fn new(cap: usize) -> Rc<Self> {
        Rc::new(Self {
            open: Cell::new(0),
            cap,
            freed: tokio::sync::Notify::new(),
        })
    }
}

/// One app stream's place in [`Slots`]. Dropping it frees the place.
struct Slot(Rc<Slots>);

impl Slot {
    /// Takes a place, or returns None when all are taken.
    fn take(slots: &Rc<Slots>) -> Option<Self> {
        if slots.open.get() >= slots.cap {
            return None;
        }
        slots.open.set(slots.open.get() + 1);
        Some(Self(slots.clone()))
    }

    /// Takes a place, and waits for one to be freed when all are taken. It
    /// returns None when `deadline` completes first.
    async fn wait<D: std::future::Future + Unpin>(
        slots: &Rc<Slots>,
        deadline: &mut D,
    ) -> Option<Self> {
        loop {
            if let Some(slot) = Self::take(slots) {
                return Some(slot);
            }
            let freed = pin!(slots.freed.notified());
            if let Either::Right(_) = select(freed, &mut *deadline).await {
                return None;
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let slots = &self.0;
        slots.open.set(slots.open.get().saturating_sub(1));
        slots.freed.notify_one();
    }
}

/// Counts one dial in `waiting` while it lives.
struct Waiting<'a>(&'a Cell<usize>);

impl<'a> Waiting<'a> {
    fn new(waiting: &'a Cell<usize>) -> Self {
        waiting.set(waiting.get() + 1);
        Self(waiting)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// The lazy hub's state: the Durable Object's socket list and the dials
/// waiting for a stream.
pub struct Lazy {
    state: State,
    /// Auth's Ed25519 public key, which signs the control challenge.
    key: Vec<u8>,
    /// The host auth signs in the challenge, `CALLOUT_HOST`.
    host: String,
    /// Dials waiting for their stream, by id, for [`MAX_PENDING_DIALS`].
    dials: RefCell<HashMap<String, PendingDial>>,
    /// App streams waiting or open, for [`MAX_APP_STREAMS`].
    app_streams: Rc<Slots>,
    /// App dials waiting for a place in `app_streams`, which count toward
    /// [`MAX_PENDING_DIALS`].
    waiting: Cell<usize>,
}

impl Lazy {
    /// Builds the lazy hub, sets the ping auto-response and installs it for
    /// [`get`].
    pub fn install(state: State, env: &Env) -> Result<Rc<Self>> {
        let key = secret_bytes(env, "AUTH_CALLOUT_PUBKEY")?;
        if key.len() != 32 {
            return Err(Error::RustError(
                "AUTH_CALLOUT_PUBKEY is not 32 bytes".into(),
            ));
        }
        let host = env.var("CALLOUT_HOST")?.to_string();
        let pair = WebSocketRequestResponsePair::new("ping", "pong")?;
        state.set_websocket_auto_response(&pair);
        let lazy = Rc::new(Self {
            state,
            key,
            host,
            dials: RefCell::new(HashMap::new()),
            app_streams: Slots::new(MAX_APP_STREAMS),
            waiting: Cell::new(0),
        });
        LAZY.with(|l| *l.borrow_mut() = Some(lazy.clone()));
        console_log!("lazy: woke, {} sockets", lazy.state.get_websockets().len());
        Ok(lazy)
    }

    /// Accepts a control socket and sends it the challenge nonce.
    pub fn accept_control(&self, req: &Request) -> Result<Response> {
        // Auth's callout sends no `Origin`, and a browser always sends one.
        if req.headers().get("Origin")?.is_some() {
            return Response::error("origin not allowed", 403);
        }
        self.prune();
        let client = crate::tunnel::client_key(req)?;
        let (pending, sockets): (Vec<_>, Vec<_>) = self
            .controls()
            .into_iter()
            .filter(|(a, _)| !a.verified)
            .map(|(a, ws)| ((a.accepted_ms, a.client), ws))
            .unzip();
        if let Some(at) = evict(&pending, &client, MAX_PENDING_CONTROL) {
            console_log!("lazy: too many control sockets in the challenge, closing the oldest of the busiest client");
            let _ = sockets[at].close(Some(1013), Some("try again later"));
        }

        let pair = WebSocketPair::new()?;
        let ws = pair.server;
        self.state.accept_websocket_with_tags(&ws, &[CONTROL]);
        let mut nonce = vec![0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::RustError(format!("nonce: {e}")))?;
        ws.serialize_attachment(Attachment {
            accepted_ms: Date::now().as_millis(),
            nonce: nonce.clone(),
            verified: false,
            client,
        })?;
        ws.send_with_bytes(&nonce)?;
        let headers = Headers::new();
        headers.set(CONTROL_HEADER, "refuse")?;
        Ok(Response::from_websocket(pair.client)?.with_headers(headers))
    }

    /// Handles a message on a control socket: the challenge reply while it
    /// is pending, and "refuse <id>" after that. Any other message after the
    /// challenge closes the socket. The runtime answers "ping" itself, so it
    /// never reaches the hub.
    pub fn on_message(&self, ws: WebSocket, msg: WebSocketIncomingMessage) -> Result<()> {
        self.prune();
        // A socket that the hub has closed, for example in `prune` or for a
        // newer socket, must not verify or refuse.
        if !is_open(&ws) {
            return Ok(());
        }
        let Some(mut a) = ws.deserialize_attachment::<Attachment>()? else {
            let _ = ws.close(Some(1008), Some("unknown socket"));
            return Ok(());
        };
        // `prune` has closed this socket, so a reply must not verify it.
        if expired(&a, Date::now().as_millis()) {
            return Ok(());
        }
        if a.verified {
            if let WebSocketIncomingMessage::String(text) = &msg {
                if let Some(id) = parse_refuse(text) {
                    self.refuse(id);
                    return Ok(());
                }
            }
            console_log!("lazy: unexpected message on the control socket, closing it");
            let _ = ws.close(Some(1008), Some("unexpected message"));
            return Ok(());
        }
        let reply = match msg {
            WebSocketIncomingMessage::Binary(b) => b,
            WebSocketIncomingMessage::String(_) => Vec::new(),
        };
        let Ok(nonce) = <[u8; 32]>::try_from(a.nonce.as_slice()) else {
            let _ = ws.close(Some(1008), Some("unknown socket"));
            return Ok(());
        };
        if let Err(err) = crate::authpipe::verify_reply(&self.key, &self.host, &nonce, &reply) {
            console_log!("lazy: control challenge failed, {err}");
            let _ = ws.close(Some(1008), Some("challenge"));
            return Ok(());
        }
        // The verified control socket that the hub accepted last replaces
        // the others, also when an older one passes the challenge after it.
        for (other, old) in self.controls() {
            if !other.verified {
                continue;
            }
            console_log!("lazy: control socket replaced by a newer one");
            if other.accepted_ms > a.accepted_ms {
                let _ = ws.close(Some(1000), Some("replaced"));
                return Ok(());
            }
            let _ = old.close(Some(1000), Some("replaced"));
        }
        a.verified = true;
        a.nonce.clear();
        ws.serialize_attachment(a)?;
        console_log!("lazy: control socket verified");
        Ok(())
    }

    /// Accepts the stream for a pending dial, or answers 404.
    pub fn accept_stream(&self, req: &Request) -> Result<Response> {
        if req.headers().get("Origin")?.is_some() {
            return Response::error("origin not allowed", 403);
        }
        let id = req.headers().get(STREAM_ID_HEADER)?.unwrap_or_default();
        let window = acks(&req.headers().get(STREAM_HEADER)?.unwrap_or_default());
        let Some(dial) = self.dials.borrow_mut().remove(&id) else {
            return Response::error("unknown stream", 404);
        };
        let pair = WebSocketPair::new()?;
        let ws = pair.server;
        // Newer compatibility dates deliver binary messages as Blob, which
        // workers-rs 0.8 reads as zero bytes. Ask for ArrayBuffer instead.
        worker::js_sys::Reflect::set(ws.as_ref(), &"binaryType".into(), &"arraybuffer".into())
            .map_err(|_| Error::RustError("setting binaryType".into()))?;
        ws.accept()?;
        let events = crate::wsevents::events(&ws)?;
        let (hub_side, pipe_side) = tokio::io::duplex(PIPE_BYTES);
        let PendingDial { kind, tx, slot, .. } = dial;
        if tx.send(Some(hub_side)).is_err() {
            console_log!(
                "lazy: {} stream arrived after its dial gave up",
                kind.as_str()
            );
            let _ = ws.close(Some(1000), Some("dial gone"));
        } else {
            wasm_bindgen_futures::spawn_local(async move {
                let mode = crate::tunnel::PumpMode::Stream {
                    idle: STREAM_IDLE,
                    window,
                };
                crate::tunnel::pump(&ws, events, pipe_side, mode).await;
                drop(slot);
            });
        }
        Response::from_websocket(pair.client)
    }

    /// Asks auth's callout for a stream and waits up to [`STREAM_WAIT`]
    /// for it. When [`MAX_APP_STREAMS`] are open, an app dial first waits
    /// for one to close, within the same [`STREAM_WAIT`]. It returns
    /// [`DialError::Failed`] at once when [`MAX_PENDING_DIALS`] dials wait.
    /// It returns [`DialError::Busy`] at once for [`Caller::Anonymous`] when
    /// [`MAX_PENDING_ANONYMOUS`] such dials wait, when no app stream closes
    /// in time, and when the callout refuses the dial.
    pub async fn dial(
        &self,
        kind: Kind,
        caller: Caller,
    ) -> std::result::Result<DuplexStream, DialError> {
        let started = Date::now().as_millis();
        let not_connected = || DialError::Failed("auth is not connected".to_string());
        if !self.connected() {
            return Err(not_connected());
        }
        if self.dials.borrow().len() + self.waiting.get() >= MAX_PENDING_DIALS {
            return Err(DialError::Failed(format!(
                "{MAX_PENDING_DIALS} dials waiting"
            )));
        }
        let anonymous = |d: &&PendingDial| d.caller == Caller::Anonymous;
        if caller == Caller::Anonymous
            && self.dials.borrow().values().filter(anonymous).count() >= MAX_PENDING_ANONYMOUS
        {
            return Err(DialError::Busy(format!(
                "{MAX_PENDING_ANONYMOUS} dials waiting for callers that have not signed in"
            )));
        }
        let mut deadline = pin!(crate::sockets::sleep(STREAM_WAIT));
        let slot = match kind {
            Kind::App => {
                let _waiting = Waiting::new(&self.waiting);
                let Some(slot) = Slot::wait(&self.app_streams, &mut deadline).await else {
                    console_log!("lazy: no app stream closed within {STREAM_WAIT:?}");
                    return Err(DialError::Busy(format!(
                        "{MAX_APP_STREAMS} app streams open"
                    )));
                };
                Some(slot)
            }
            Kind::Auth => None,
        };
        // The control socket can change while an app dial waits.
        let control = self.control().ok_or_else(not_connected)?;
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| DialError::Failed(format!("stream id: {e}")))?;
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let (tx, rx) = oneshot::channel();
        self.dials.borrow_mut().insert(
            id.clone(),
            PendingDial {
                kind,
                caller,
                tx,
                slot,
            },
        );
        // Removes the id however the dial ends, also when its future is
        // dropped, so that the id does not count toward the cap.
        let _guard = DialGuard {
            dials: &self.dials,
            id: id.clone(),
        };
        if let Err(err) = control.send_with_str(format!("dial {} {id}", kind.as_str())) {
            return Err(DialError::Failed(format!("sending dial: {err}")));
        }
        let res = match select(rx, deadline).await {
            Either::Left((Ok(Some(stream)), _)) => Ok(stream),
            Either::Left((Ok(None), _)) => Err(DialError::Busy(format!(
                "auth refused the {} dial",
                kind.as_str()
            ))),
            Either::Left((Err(_), _)) => Err(DialError::Failed("dial cancelled".to_string())),
            Either::Right(_) => Err(DialError::Failed(format!(
                "no {} stream within {STREAM_WAIT:?}",
                kind.as_str()
            ))),
        };
        console_log!(
            "lazy: cold {} dial {} in {} ms",
            kind.as_str(),
            if res.is_ok() { "paired" } else { "failed" },
            Date::now().as_millis().saturating_sub(started)
        );
        res
    }

    /// Fails the pending dial `id` at once, as refused. An id that is not
    /// pending is ignored.
    fn refuse(&self, id: &str) {
        let Some(dial) = self.dials.borrow_mut().remove(id) else {
            return;
        };
        console_log!("lazy: auth refused a {} dial", dial.kind.as_str());
        let _ = dial.tx.send(None);
    }

    /// Returns true if a verified control socket is open.
    pub fn connected(&self) -> bool {
        self.control().is_some()
    }

    /// Returns the open verified control socket that the hub accepted last.
    fn control(&self) -> Option<WebSocket> {
        self.controls()
            .into_iter()
            .filter(|(a, _)| a.verified)
            .max_by_key(|(a, _)| a.accepted_ms)
            .map(|(_, ws)| ws)
    }

    /// Returns the open control sockets with their attachments. A socket
    /// that is closing is left out.
    fn controls(&self) -> Vec<(Attachment, WebSocket)> {
        self.state
            .get_websockets_with_tag(CONTROL)
            .into_iter()
            .filter(is_open)
            .filter_map(|ws| match ws.deserialize_attachment::<Attachment>() {
                Ok(Some(a)) => Some((a, ws)),
                _ => None,
            })
            .collect()
    }

    /// Closes control sockets that have not passed the challenge in time.
    fn prune(&self) {
        let now = Date::now().as_millis();
        for (a, ws) in self.controls() {
            if expired(&a, now) {
                console_log!("lazy: control challenge failed, no reply in time");
                let _ = ws.close(Some(1008), Some("challenge timeout"));
            }
        }
    }
}

/// Returns true if `ws` is open, and not closing or closed.
fn is_open(ws: &WebSocket) -> bool {
    AsRef::<web_sys::WebSocket>::as_ref(ws).ready_state() == web_sys::WebSocket::OPEN
}

/// Removes a dial's id from the pending dials when dropped.
struct DialGuard<'a> {
    dials: &'a RefCell<HashMap<String, PendingDial>>,
    id: String,
}

impl Drop for DialGuard<'_> {
    fn drop(&mut self) {
        self.dials.borrow_mut().remove(&self.id);
    }
}

/// Returns true if the `Sallyport-Stream` value `v` lists `ack`. The
/// tokens may be separated by commas, spaces or both, as the callout reads
/// `Sallyport-Control`.
fn acks(v: &str) -> bool {
    v.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .any(|t| t.eq_ignore_ascii_case("ack"))
}

/// Returns the id in a control message "refuse <id>", or None when `text`
/// is any other message. The id is 43 characters of unpadded base64url, as
/// the hub makes them.
fn parse_refuse(text: &str) -> Option<&str> {
    let id = text.strip_prefix("refuse ")?;
    let ok = id.len() == 43
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then_some(id)
}

/// Returns true if `a` is still in the challenge after its deadline, at
/// `now` in ms since the epoch.
fn expired(a: &Attachment, now: u64) -> bool {
    !a.verified && now.saturating_sub(a.accepted_ms) > CHALLENGE_DEADLINE_MS
}

/// Returns the index in `pending` of the socket to close before a socket
/// from `client` joins, or None when fewer than `cap` are pending. Each
/// pending socket is its accept time and its client. The socket is the
/// oldest of the client with the most pending, counting the new one.
fn evict(pending: &[(u64, String)], client: &str, cap: usize) -> Option<usize> {
    if pending.len() < cap.max(1) {
        return None;
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    *counts.entry(client).or_default() += 1;
    for (_, c) in pending {
        *counts.entry(c.as_str()).or_default() += 1;
    }
    let most = counts.values().copied().max().unwrap_or(0);
    pending
        .iter()
        .enumerate()
        .filter(|(_, (_, c))| counts[c.as_str()] == most)
        .min_by_key(|(_, (t, _))| *t)
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evict_picks_the_busiest_clients_oldest() {
        let p = |items: &[(u64, &str)]| -> Vec<(u64, String)> {
            items.iter().map(|(t, c)| (*t, c.to_string())).collect()
        };
        assert_eq!(evict(&p(&[(1, "x"), (2, "x")]), "x", 3), None);
        assert_eq!(
            evict(&p(&[(1, "auth"), (3, "x"), (2, "x")]), "y", 3),
            Some(2)
        );
        assert_eq!(
            evict(&p(&[(1, "auth"), (2, "x"), (3, "y")]), "x", 3),
            Some(1)
        );
        assert_eq!(evict(&p(&[(2, "a"), (1, "b"), (3, "c")]), "d", 3), Some(1));
        assert_eq!(evict(&[], "x", 0), None);
    }

    #[test]
    fn expired_only_in_the_challenge_after_the_deadline() {
        let a = |verified| Attachment {
            accepted_ms: 1_000,
            nonce: Vec::new(),
            verified,
            client: String::new(),
        };
        assert!(!expired(&a(false), 1_000 + CHALLENGE_DEADLINE_MS));
        assert!(expired(&a(false), 1_001 + CHALLENGE_DEADLINE_MS));
        assert!(!expired(&a(true), 1_001 + CHALLENGE_DEADLINE_MS));
    }

    #[test]
    fn dial_guard_removes_the_id_and_frees_its_slot() {
        let slots = Slots::new(1);
        let dials = RefCell::new(HashMap::new());
        let (tx, _rx) = oneshot::channel();
        dials.borrow_mut().insert(
            "x".to_string(),
            PendingDial {
                kind: Kind::App,
                caller: Caller::SignedIn,
                tx,
                slot: Slot::take(&slots),
            },
        );
        assert_eq!(slots.open.get(), 1);
        drop(DialGuard {
            dials: &dials,
            id: "x".to_string(),
        });
        assert!(dials.borrow().is_empty());
        assert_eq!(slots.open.get(), 0);
    }

    #[test]
    fn acks_reads_the_stream_header() {
        assert!(acks("ack"));
        assert!(acks("other, ack"));
        assert!(acks("other ack"));
        assert!(acks("other,ack"));
        assert!(!acks("other"));
        assert!(acks("ACK"));
        assert!(!acks(""));
        assert!(!acks("acks"));
    }

    #[test]
    fn parse_refuse_takes_one_id() {
        let id = "a".repeat(42) + "_";
        assert_eq!(parse_refuse(&format!("refuse {id}")), Some(id.as_str()));
        assert_eq!(parse_refuse(&format!("refuse  {id}")), None);
        assert_eq!(parse_refuse(&format!("refuse {id} ")), None);
        assert_eq!(parse_refuse(&format!("refuse {}", &id[1..])), None);
        assert_eq!(parse_refuse(&format!("refuse {}=", &id[1..])), None);
        assert_eq!(parse_refuse(&format!("dial app {id}")), None);
        assert_eq!(parse_refuse("refuse"), None);
        assert_eq!(parse_refuse(""), None);
    }

    #[test]
    fn slot_take_stops_at_the_cap() {
        let slots = Slots::new(2);
        let a = Slot::take(&slots).unwrap();
        let _b = Slot::take(&slots).unwrap();
        assert!(Slot::take(&slots).is_none());
        assert_eq!(slots.open.get(), 2);
        drop(a);
        assert_eq!(slots.open.get(), 1);
        assert!(Slot::take(&slots).is_some());
    }

    #[test]
    fn slot_wait_takes_a_freed_place_or_gives_up() {
        use futures::executor::block_on;
        use futures::future::{join, pending, ready};

        let slots = Slots::new(1);
        let held = Slot::take(&slots).unwrap();
        assert!(block_on(Slot::wait(&slots, &mut ready(()))).is_none());

        let mut never = pending::<()>();
        let (got, ()) = block_on(join(Slot::wait(&slots, &mut never), async {
            drop(held);
        }));
        assert!(got.is_some());
        assert_eq!(slots.open.get(), 1);

        let waiting = Cell::new(0);
        let w = Waiting::new(&waiting);
        assert_eq!(waiting.get(), 1);
        drop(w);
        assert_eq!(waiting.get(), 0);
    }
}
