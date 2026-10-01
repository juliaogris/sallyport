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
/// The response header on the control upgrade that lists what the hub
/// accepts on the control socket after the challenge.
const CONTROL_HEADER: &str = "Sallyport-Control";
/// A control socket that has not passed the challenge by then is closed.
const CHALLENGE_DEADLINE_MS: u64 = 10_000;
/// Control sockets in the challenge. Above this the oldest is closed.
const MAX_PENDING_CONTROL: usize = 4;
/// Dials waiting for their stream. Above this a dial fails at once.
const MAX_PENDING_DIALS: usize = 32;
/// App streams open at once, waiting for their stream or paired. Above
/// this an app dial fails at once. Each stream can hold about 2.3 MiB: 1 MiB
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

/// The state of a control socket, kept in its attachment.
#[derive(Serialize, Deserialize)]
struct Attachment {
    /// When the hub accepted the socket, in ms since the epoch.
    accepted_ms: u64,
    /// The hub's nonce, while the challenge runs.
    nonce: Vec<u8>,
    verified: bool,
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
    /// Sends the stream, or None when the callout refused the dial.
    tx: oneshot::Sender<Option<DuplexStream>>,
    /// An app dial's place in [`MAX_APP_STREAMS`]. The stream's pump keeps
    /// it until the WebSocket closes, because the queue of the WebSocket's
    /// events lives as long as the WebSocket.
    slot: Option<Slot>,
}

/// One app stream's place in [`MAX_APP_STREAMS`]. Dropping it frees the
/// place.
struct Slot(Rc<Cell<usize>>);

impl Slot {
    /// Takes a place in `open`, or returns None when `cap` are taken.
    fn take(open: &Rc<Cell<usize>>, cap: usize) -> Option<Self> {
        if open.get() >= cap {
            return None;
        }
        open.set(open.get() + 1);
        Some(Self(open.clone()))
    }
}

impl Drop for Slot {
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
    app_streams: Rc<Cell<usize>>,
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
            app_streams: Rc::new(Cell::new(0)),
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
        let pending: Vec<(u64, WebSocket)> = self
            .controls()
            .into_iter()
            .filter(|(a, _)| !a.verified)
            .map(|(a, ws)| (a.accepted_ms, ws))
            .collect();
        if pending.len() >= MAX_PENDING_CONTROL {
            if let Some((_, oldest)) = pending.into_iter().min_by_key(|(t, _)| *t) {
                let _ = oldest.close(Some(1008), Some("too many sockets in the challenge"));
            }
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
        let nonce: [u8; 32] = a.nonce.as_slice().try_into().unwrap_or([0; 32]);
        if let Err(err) = crate::authpipe::verify_reply(&self.key, &self.host, &nonce, &reply) {
            console_log!("lazy: control challenge failed, {err}");
            let _ = ws.close(Some(1008), Some("challenge"));
            return Ok(());
        }
        // A newly verified control socket replaces the older ones.
        for (other, old) in self.controls() {
            if other.verified {
                let _ = old.close(Some(1000), Some("replaced"));
            }
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
        let PendingDial { kind, tx, slot } = dial;
        if tx.send(Some(hub_side)).is_err() {
            console_log!(
                "lazy: {} stream arrived after its dial gave up",
                kind.as_str()
            );
            let _ = ws.close(Some(1000), Some("dial gone"));
        } else {
            wasm_bindgen_futures::spawn_local(async move {
                let mode = crate::tunnel::PumpMode::Stream { idle: STREAM_IDLE };
                crate::tunnel::pump(&ws, events, pipe_side, mode).await;
                drop(slot);
            });
        }
        Response::from_websocket(pair.client)
    }

    /// Asks auth's callout for a stream and waits up to [`STREAM_WAIT`]
    /// for it. It returns [`DialError::Busy`] at once when
    /// [`MAX_PENDING_DIALS`] dials wait, or for an app stream when
    /// [`MAX_APP_STREAMS`] are open.
    pub async fn dial(&self, kind: Kind) -> std::result::Result<DuplexStream, DialError> {
        let started = Date::now().as_millis();
        let control = self
            .control()
            .ok_or_else(|| DialError::Failed("auth is not connected".to_string()))?;
        if self.dials.borrow().len() >= MAX_PENDING_DIALS {
            return Err(DialError::Busy(format!(
                "{MAX_PENDING_DIALS} dials waiting"
            )));
        }
        let slot =
            match kind {
                Kind::App => Some(Slot::take(&self.app_streams, MAX_APP_STREAMS).ok_or_else(
                    || DialError::Busy(format!("{MAX_APP_STREAMS} app streams open")),
                )?),
                Kind::Auth => None,
            };
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| DialError::Failed(format!("stream id: {e}")))?;
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let (tx, rx) = oneshot::channel();
        self.dials
            .borrow_mut()
            .insert(id.clone(), PendingDial { kind, tx, slot });
        // Removes the id however the dial ends, also when its future is
        // dropped, so that the id does not count toward the cap.
        let _guard = DialGuard {
            dials: &self.dials,
            id: id.clone(),
        };
        if let Err(err) = control.send_with_str(format!("dial {} {id}", kind.as_str())) {
            return Err(DialError::Failed(format!("sending dial: {err}")));
        }
        let res = match select(rx, pin!(crate::sockets::sleep(STREAM_WAIT))).await {
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
        newest_open(self.controls().into_iter().map(|(a, ws)| {
            let open =
                AsRef::<web_sys::WebSocket>::as_ref(&ws).ready_state() == web_sys::WebSocket::OPEN;
            (a.accepted_ms, a.verified && open, ws)
        }))
    }

    /// Returns the control sockets with their attachments.
    fn controls(&self) -> Vec<(Attachment, WebSocket)> {
        self.state
            .get_websockets_with_tag(CONTROL)
            .into_iter()
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

/// Returns the item with the largest accept time among those marked usable.
/// Each item is its accept time, whether it is usable, and the item.
fn newest_open<T>(items: impl IntoIterator<Item = (u64, bool, T)>) -> Option<T> {
    items
        .into_iter()
        .filter(|(_, usable, _)| *usable)
        .max_by_key(|(t, _, _)| *t)
        .map(|(_, _, item)| item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_open_picks_the_newest_usable() {
        assert_eq!(
            newest_open([(1, true, "a"), (3, false, "b"), (2, true, "c")]),
            Some("c")
        );
        assert_eq!(newest_open([(1, false, "a")]), None);
        assert_eq!(newest_open(Vec::<(u64, bool, &str)>::new()), None);
    }

    #[test]
    fn expired_only_in_the_challenge_after_the_deadline() {
        let a = |verified| Attachment {
            accepted_ms: 1_000,
            nonce: Vec::new(),
            verified,
        };
        assert!(!expired(&a(false), 1_000 + CHALLENGE_DEADLINE_MS));
        assert!(expired(&a(false), 1_001 + CHALLENGE_DEADLINE_MS));
        assert!(!expired(&a(true), 1_001 + CHALLENGE_DEADLINE_MS));
    }

    #[test]
    fn dial_guard_removes_the_id_and_frees_its_slot() {
        let open = Rc::new(Cell::new(0));
        let dials = RefCell::new(HashMap::new());
        let (tx, _rx) = oneshot::channel();
        dials.borrow_mut().insert(
            "x".to_string(),
            PendingDial {
                kind: Kind::App,
                tx,
                slot: Slot::take(&open, 1),
            },
        );
        assert_eq!(open.get(), 1);
        drop(DialGuard {
            dials: &dials,
            id: "x".to_string(),
        });
        assert!(dials.borrow().is_empty());
        assert_eq!(open.get(), 0);
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
        let open = Rc::new(Cell::new(0));
        let a = Slot::take(&open, 2).unwrap();
        let _b = Slot::take(&open, 2).unwrap();
        assert!(Slot::take(&open, 2).is_none());
        assert_eq!(open.get(), 2);
        drop(a);
        assert_eq!(open.get(), 1);
        assert!(Slot::take(&open, 2).is_some());
    }
}
