//! The events of a WebSocket as a stream.
//!
//! `worker::WebSocket::events` panics when an event arrives after its stream
//! was dropped, and a panic restarts the Wasm instance with every tunnel and
//! auth pipe stream in it. This stream drops such an event instead.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::Stream;
use worker::wasm_bindgen::closure::Closure;
use worker::wasm_bindgen::JsCast;
use worker::web_sys;
use worker::{Result, WebSocket, WebsocketEvent};

/// The events of one WebSocket. Dropping it removes its listeners.
pub struct Events {
    ws: web_sys::WebSocket,
    rx: UnboundedReceiver<Result<WebsocketEvent>>,
    closed: bool,
    message: Closure<dyn FnMut(web_sys::MessageEvent)>,
    close: Closure<dyn FnMut(web_sys::CloseEvent)>,
    error: Closure<dyn FnMut(web_sys::ErrorEvent)>,
}

/// Returns the events of `ws`. The stream ends after the close event.
pub fn events(ws: &WebSocket) -> Result<Events> {
    let ws: &web_sys::WebSocket = ws.as_ref();
    let (tx, rx) = unbounded();
    let t = tx.clone();
    let message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        let _ = t.unbounded_send(Ok(WebsocketEvent::Message(e.into())));
    });
    let t = tx.clone();
    let close = Closure::<dyn FnMut(web_sys::CloseEvent)>::new(move |e: web_sys::CloseEvent| {
        let _ = t.unbounded_send(Ok(WebsocketEvent::Close(e.into())));
    });
    let error = Closure::<dyn FnMut(web_sys::ErrorEvent)>::new(move |e: web_sys::ErrorEvent| {
        let _ = tx.unbounded_send(Err(e.error().into()));
    });
    ws.add_event_listener_with_callback("message", message.as_ref().unchecked_ref())?;
    ws.add_event_listener_with_callback("close", close.as_ref().unchecked_ref())?;
    ws.add_event_listener_with_callback("error", error.as_ref().unchecked_ref())?;
    Ok(Events {
        ws: ws.clone(),
        rx,
        closed: false,
        message,
        close,
        error,
    })
}

impl Stream for Events {
    type Item = Result<WebsocketEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(None);
        }
        let item = futures::ready!(Pin::new(&mut this.rx).poll_next(cx));
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
