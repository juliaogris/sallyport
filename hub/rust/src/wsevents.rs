//! The events of a WebSocket as a stream.
//!
//! `worker::WebSocket::events` panics when an event arrives after its stream
//! was dropped, and a panic restarts the Wasm instance with every tunnel and
//! auth pipe stream in it. This stream drops such an event instead.

use std::cell::Cell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::Stream;
use worker::wasm_bindgen::closure::Closure;
use worker::wasm_bindgen::JsCast;
use worker::web_sys;
use worker::{Date, Result, WebSocket, WebsocketEvent};

/// The most events queued on one stream, and the longest an event waited
/// in a queue, in ms, across all streams since the last [`take_stats`].
static MAX_DEPTH: AtomicU64 = AtomicU64::new(0);
static MAX_WAIT_MS: AtomicU64 = AtomicU64::new(0);

/// Returns and resets the most events queued on one stream and the longest
/// wait of an event in its queue, in ms, since the last call.
pub fn take_stats() -> (u64, u64) {
    (MAX_DEPTH.swap(0, Ordering::Relaxed), MAX_WAIT_MS.swap(0, Ordering::Relaxed))
}

type Item = (u64, Result<WebsocketEvent>);

/// The events of one WebSocket. Dropping it removes its listeners.
pub struct Events {
    ws: web_sys::WebSocket,
    rx: UnboundedReceiver<Item>,
    closed: bool,
    depth: Rc<Cell<usize>>,
    max_depth: usize,
    max_wait_ms: u64,
    message: Closure<dyn FnMut(web_sys::MessageEvent)>,
    close: Closure<dyn FnMut(web_sys::CloseEvent)>,
    error: Closure<dyn FnMut(web_sys::ErrorEvent)>,
}

/// Returns the events of `ws`. The stream ends after the close event.
pub fn events(ws: &WebSocket) -> Result<Events> {
    let ws: &web_sys::WebSocket = ws.as_ref();
    let (tx, rx) = unbounded::<Item>();
    let depth = Rc::new(Cell::new(0usize));
    let send = {
        let depth = depth.clone();
        move |item: Result<WebsocketEvent>| {
            if tx.unbounded_send((Date::now().as_millis(), item)).is_ok() {
                depth.set(depth.get() + 1);
            }
        }
    };
    let s = send.clone();
    let message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        s(Ok(WebsocketEvent::Message(e.into())));
    });
    let s = send.clone();
    let close = Closure::<dyn FnMut(web_sys::CloseEvent)>::new(move |e: web_sys::CloseEvent| {
        s(Ok(WebsocketEvent::Close(e.into())));
    });
    let error = Closure::<dyn FnMut(web_sys::ErrorEvent)>::new(move |e: web_sys::ErrorEvent| {
        send(Err(e.error().into()));
    });
    ws.add_event_listener_with_callback("message", message.as_ref().unchecked_ref())?;
    ws.add_event_listener_with_callback("close", close.as_ref().unchecked_ref())?;
    ws.add_event_listener_with_callback("error", error.as_ref().unchecked_ref())?;
    Ok(Events {
        ws: ws.clone(),
        rx,
        closed: false,
        depth,
        max_depth: 0,
        max_wait_ms: 0,
        message,
        close,
        error,
    })
}

impl Events {
    /// Returns the most events this stream has had queued, and the longest
    /// an event waited in the queue, in ms.
    pub fn stats(&self) -> (usize, u64) {
        (self.max_depth, self.max_wait_ms)
    }
}

impl Stream for Events {
    type Item = Result<WebsocketEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(None);
        }
        let item = futures::ready!(Pin::new(&mut this.rx).poll_next(cx));
        let item = item.map(|(queued, item)| {
            let depth = this.depth.get();
            this.depth.set(depth.saturating_sub(1));
            let wait = Date::now().as_millis().saturating_sub(queued);
            this.max_depth = this.max_depth.max(depth);
            this.max_wait_ms = this.max_wait_ms.max(wait);
            MAX_DEPTH.fetch_max(depth as u64, Ordering::Relaxed);
            MAX_WAIT_MS.fetch_max(wait, Ordering::Relaxed);
            item
        });
        if matches!(item, Some(Ok(WebsocketEvent::Close(_)))) {
            this.closed = true;
        }
        Poll::Ready(item)
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        let _ = self.ws.remove_event_listener_with_callback("message", self.message.as_ref().unchecked_ref());
        let _ = self.ws.remove_event_listener_with_callback("close", self.close.as_ref().unchecked_ref());
        let _ = self.ws.remove_event_listener_with_callback("error", self.error.as_ref().unchecked_ref());
    }
}
