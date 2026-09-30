//! A list of the hub's open WebSockets that outlives the Wasm instance.
//!
//! A Rust panic is a Wasm trap. workers-rs then starts a new Wasm instance in
//! the same isolate and builds a new Durable Object, but the WebSockets the
//! old instance accepted stay open with no code behind them. Auth's callout
//! and the agents see a live connection and do not redial, so the new
//! instance has no auth pipe streams and no tunnels. The list is a JS `Set`
//! on the global object, which the new instance can still read, so it
//! closes those WebSockets and their peers dial again.

use worker::js_sys::{self, Reflect, Set};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::WebSocket;

const KEY: &str = "__sallyport_hub_sockets";
const PANIC_KEY: &str = "__sallyport_hub_last_panic";
/// The close code for "service restart".
const RESTART: u16 = 1012;

fn set() -> Option<Set> {
    let global = js_sys::global();
    let key = JsValue::from_str(KEY);
    let value = Reflect::get(&global, &key).ok()?;
    if value.is_instance_of::<Set>() {
        return Some(value.unchecked_into());
    }
    let set = Set::new(&JsValue::UNDEFINED);
    Reflect::set(&global, &key, &set).ok()?;
    Some(set)
}

/// Adds `ws` to the list.
pub fn add(ws: &WebSocket) {
    if let Some(set) = set() {
        let js: &worker::web_sys::WebSocket = ws.as_ref();
        set.add(js);
    }
}

/// Removes `ws` from the list.
pub fn remove(ws: &WebSocket) {
    if let Some(set) = set() {
        let js: &worker::web_sys::WebSocket = ws.as_ref();
        set.delete(js);
    }
}

/// Closes every WebSocket in the list, empties it, and returns how many
/// there were.
pub fn close_all() -> u32 {
    let Some(set) = set() else {
        return 0;
    };
    let n = set.size();
    set.for_each(&mut |value, _, _| {
        let ws: worker::web_sys::WebSocket = value.unchecked_into();
        let _ = ws.close_with_code_and_reason(RESTART, "hub restarted");
    });
    set.clear();
    n
}

/// Keeps `msg` on the global object, so that the next Wasm instance can log
/// why the previous one stopped.
pub fn set_last_panic(msg: &str) {
    let _ = Reflect::set(&js_sys::global(), &JsValue::from_str(PANIC_KEY), &JsValue::from_str(msg));
}

/// Returns and clears the message that [`set_last_panic`] kept.
pub fn take_last_panic() -> Option<String> {
    let global = js_sys::global();
    let key = JsValue::from_str(PANIC_KEY);
    let msg = Reflect::get(&global, &key).ok()?.as_string()?;
    let _ = Reflect::set(&global, &key, &JsValue::UNDEFINED);
    Some(msg)
}
