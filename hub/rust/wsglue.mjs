// JavaScript glue for the WebSockets the Rust hub accepts, used only by the
// `rust` env. It tests whether the Rust hub's own WebSocket glue drops
// tunnels, since the Go hub, whose glue is JavaScript, drops almost none.
//
// It replaces the global WebSocketPair before the Wasm module loads. The
// server end that Rust gets is a GluedSocket: JavaScript accepts the real
// socket and listens on it, gives Rust a copy of each message, and sends a
// copy of each buffer Rust passes. workers-rs passes views of Wasm memory
// to `send`, and Rust reuses those buffers, so the copy keeps a later send
// from changing bytes already queued.
const RealPair = globalThis.WebSocketPair;

class GluedSocket {
  constructor(ws) {
    this.ws = ws;
    this.listeners = { message: [], close: [], error: [] };
    this.binaryType = 'arraybuffer';
  }

  accept() {
    this.ws.binaryType = 'arraybuffer';
    this.ws.accept();
    for (const type of ['message', 'close', 'error']) {
      this.ws.addEventListener(type, (e) => this.dispatch(type, e));
    }
  }

  dispatch(type, e) {
    let ev;
    if (type === 'message') {
      const d = e.data;
      ev = { data: typeof d === 'string' ? d : d.slice(0) };
    } else if (type === 'close') {
      ev = { code: e.code, reason: e.reason, wasClean: e.wasClean };
    } else {
      ev = { error: e.error, message: e.message };
    }
    for (const f of [...this.listeners[type]]) {
      try {
        f(ev);
      } catch (err) {
        console.error(`wsglue: ${type} listener threw: ${err}`);
      }
    }
  }

  addEventListener(type, f) {
    (this.listeners[type] ||= []).push(f);
  }

  removeEventListener(type, f) {
    const list = this.listeners[type];
    const i = list ? list.indexOf(f) : -1;
    if (i >= 0) list.splice(i, 1);
  }

  send(d) {
    this.ws.send(typeof d === 'string' ? d : d.slice());
  }

  close(code, reason) {
    if (code === undefined) this.ws.close();
    else this.ws.close(code, reason);
  }

  get readyState() {
    return this.ws.readyState;
  }
}

globalThis.WebSocketPair = function WebSocketPair() {
  const pair = new RealPair();
  return { 0: pair[0], 1: new GluedSocket(pair[1]) };
};
