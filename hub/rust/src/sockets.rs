//! Lists of the hub's open WebSockets and timers that outlive the Wasm
//! instance.
//!
//! A Rust panic is a Wasm trap. workers-rs then starts a new Wasm instance in
//! the same isolate and builds a new Durable Object, but the WebSockets the
//! old instance accepted stay open with no code behind them. Auth's callout
//! and the agents see a live connection and do not redial, so the new
//! instance has no auth pipe streams and no tunnels. The lists are on the
//! global object, which the new instance can still read, so it closes those
//! WebSockets and their peers dial again.
//!
//! The old instance's event listeners and `setTimeout` callbacks are JS
//! functions that call into whichever Wasm instance is current. After a
//! restart, that is the new one, with a pointer into the old one's memory,
//! and the call traps again. So the socket list also keeps each socket's
//! listeners, which [`close_all`] removes before it closes the socket, and
//! [`sleep`] keeps its timer IDs in a list that [`clear_timers`] clears.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use worker::js_sys::{self, Array, Function, Map, Reflect, Set};
use worker::wasm_bindgen::closure::Closure;
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::web_sys::{self, WorkerGlobalScope};
use worker::WebSocket;

/// A `Map` from each open WebSocket to an `Array` of its listeners, each a
/// `[type, function]` pair.
const KEY: &str = "__sallyport_hub_sockets";
/// A `Set` of the IDs of the timers [`sleep`] started that have not fired.
const TIMERS_KEY: &str = "__sallyport_hub_timers";
const PANIC_KEY: &str = "__sallyport_hub_last_panic";
/// The close code for "service restart".
const RESTART: u16 = 1012;

fn map() -> Option<Map> {
    let global = js_sys::global();
    let key = JsValue::from_str(KEY);
    let value = Reflect::get(&global, &key).ok()?;
    if value.is_instance_of::<Map>() {
        return Some(value.unchecked_into());
    }
    let map = Map::new();
    Reflect::set(&global, &key, &map).ok()?;
    Some(map)
}

fn timers() -> Option<Set> {
    let global = js_sys::global();
    let key = JsValue::from_str(TIMERS_KEY);
    let value = Reflect::get(&global, &key).ok()?;
    if value.is_instance_of::<Set>() {
        return Some(value.unchecked_into());
    }
    let set = Set::new(&JsValue::UNDEFINED);
    Reflect::set(&global, &key, &set).ok()?;
    Some(set)
}

/// Returns the listener list of `ws`, and adds `ws` with an empty list if it
/// is not in the socket list.
fn listeners(map: &Map, ws: &web_sys::WebSocket) -> Array {
    let value = map.get(ws);
    if value.is_instance_of::<Array>() {
        return value.unchecked_into();
    }
    let list = Array::new();
    map.set(ws, &list);
    list
}

/// Adds `ws` to the socket list.
pub fn add(ws: &WebSocket) {
    if let Some(map) = map() {
        listeners(&map, ws.as_ref());
    }
}

/// Adds `ws` to the socket list, if it is not there, and records that `f`
/// listens for its `typ` events.
pub fn add_listener(ws: &web_sys::WebSocket, typ: &str, f: &Function) {
    if let Some(map) = map() {
        listeners(&map, ws).push(&Array::of2(&JsValue::from_str(typ), f));
    }
}

/// Removes `ws` from the socket list.
pub fn remove(ws: &WebSocket) {
    if let Some(map) = map() {
        let js: &web_sys::WebSocket = ws.as_ref();
        map.delete(js);
    }
}

/// Removes the listeners of every WebSocket in the socket list, closes the
/// WebSocket, empties the list, and returns how many WebSockets there were.
pub fn close_all() -> u32 {
    let Some(map) = map() else {
        return 0;
    };
    let n = map.size();
    map.for_each(&mut |list, ws| {
        let ws: web_sys::WebSocket = ws.unchecked_into();
        if let Ok(list) = list.dyn_into::<Array>() {
            for pair in list.iter() {
                let pair: Array = pair.unchecked_into();
                if let (Some(typ), Ok(f)) =
                    (pair.get(0).as_string(), pair.get(1).dyn_into::<Function>())
                {
                    let _ = ws.remove_event_listener_with_callback(&typ, &f);
                }
            }
        }
        let _ = ws.close_with_code_and_reason(RESTART, "hub restarted");
    });
    map.clear();
    n
}

/// Cancels every timer [`sleep`] started that has not fired, and returns
/// how many there were.
pub fn clear_timers() -> u32 {
    let Some(set) = timers() else {
        return 0;
    };
    let n = set.size();
    let global: WorkerGlobalScope = js_sys::global().unchecked_into();
    set.for_each(&mut |id, _, _| {
        if let Some(id) = id.as_f64() {
            global.clear_timeout_with_handle(id as i32);
        }
    });
    set.clear();
    n
}

/// Returns a future that resolves after `d`. It is `worker::Delay` with
/// its timer ID kept in the list that [`clear_timers`] clears.
pub fn sleep(d: Duration) -> Sleep {
    Sleep {
        millis: i32::try_from(d.as_millis()).unwrap_or(i32::MAX),
        state: Rc::new(TimerState::default()),
        timer: None,
    }
}

#[derive(Default)]
struct TimerState {
    fired: Cell<bool>,
    id: Cell<Option<i32>>,
    waker: RefCell<Option<Waker>>,
}

/// The future [`sleep`] returns. Dropping it cancels the timer.
pub struct Sleep {
    millis: i32,
    state: Rc<TimerState>,
    /// The timer ID and the callback it runs, once the timer has started.
    timer: Option<(i32, Closure<dyn FnMut()>)>,
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.state.fired.get() {
            return Poll::Ready(());
        }
        *this.state.waker.borrow_mut() = Some(cx.waker().clone());
        if this.timer.is_none() {
            let state = this.state.clone();
            let callback = Closure::<dyn FnMut()>::new(move || {
                state.fired.set(true);
                if let (Some(id), Some(set)) = (state.id.get(), timers()) {
                    set.delete(&JsValue::from(id));
                }
                if let Some(waker) = state.waker.borrow_mut().take() {
                    waker.wake();
                }
            });
            let global: WorkerGlobalScope = js_sys::global().unchecked_into();
            match global.set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                this.millis,
            ) {
                Ok(id) => {
                    this.state.id.set(Some(id));
                    if let Some(set) = timers() {
                        set.add(&JsValue::from(id));
                    }
                    this.timer = Some((id, callback));
                }
                // Without a timer the future would never resolve, so it
                // resolves now.
                Err(_) => return Poll::Ready(()),
            }
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some((id, _)) = self.timer.take() {
            if !self.state.fired.get() {
                let global: WorkerGlobalScope = js_sys::global().unchecked_into();
                global.clear_timeout_with_handle(id);
            }
            if let Some(set) = timers() {
                set.delete(&JsValue::from(id));
            }
        }
    }
}

/// Keeps `msg` on the global object, so that the next Wasm instance can log
/// why the previous one stopped.
pub fn set_last_panic(msg: &str) {
    let _ = Reflect::set(
        &js_sys::global(),
        &JsValue::from_str(PANIC_KEY),
        &JsValue::from_str(msg),
    );
}

/// Returns and clears the message that [`set_last_panic`] kept.
pub fn take_last_panic() -> Option<String> {
    let global = js_sys::global();
    let key = JsValue::from_str(PANIC_KEY);
    let msg = Reflect::get(&global, &key).ok()?.as_string()?;
    let _ = Reflect::set(&global, &key, &JsValue::UNDEFINED);
    Some(msg)
}
