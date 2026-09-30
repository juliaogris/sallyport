// The Worker entry and the Durable Object glue of the Go hub.
//
// The Worker entry is plain JavaScript: it classifies the host, answers
// /webapi/find and /webapi/ping, and forwards everything else to the one
// Durable Object. Only the Durable Object runs the Go program, so a
// stateless Worker isolate never pays for the Go runtime.
//
// Go and JavaScript share bytes through Uint8Arrays that live as long as
// their connection or stream. JavaScript copies each WebSocket message into
// the connection's in buffer and passes Go only the length, and Go fills
// the out buffer and passes JavaScript only the length. A js.Value that Go
// creates is freed only when the Go GC runs its finalizer, so a new
// Uint8Array per message keeps every byte in JavaScript memory.
import { DurableObject } from 'cloudflare:workers';
import './build/wasm_exec.js';
import mod from './build/hub.wasm';

const HUB_INSTANCE = 'hub';

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const kind = classify(env, url.hostname);
    // Every path on an app host is app traffic, so it goes to the hub.
    if (kind === 'app') return hub(env).fetch(req);
    switch (url.pathname) {
      case '/webapi/find':
      case '/webapi/ping':
        return find(env);
      case '/webapi/connectionupgrade':
      case '/tunnel/auth':
        // Reject before waking the Durable Object when the request is not a
        // WebSocket upgrade at all.
        if ((req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
          return textError('upgrade required', 426);
        }
        return hub(env).fetch(req);
    }
    if (kind === 'login') return hub(env).fetch(req);
    return textError('not found', 404);
  },
};

// Returns an error with the message as a body of bytes, so that it has no
// Content-Type, like the Rust hub's errors.
function textError(msg, status) {
  return new Response(new TextEncoder().encode(msg), { status });
}

function hub(env) {
  return env.HUB.get(env.HUB.idFromName(HUB_INSTANCE));
}

// Returns 'login' for OWNER.DOMAIN, 'app' for <app>-OWNER.DOMAIN, or null.
// App names match ^[a-z][a-z0-9]*$ and are at most 30 bytes.
function classify(env, host) {
  if (!env.OWNER || !env.DOMAIN) return null;
  const suffix = '.' + env.DOMAIN;
  if (!host.endsWith(suffix)) return null;
  const label = host.slice(0, -suffix.length);
  if (label === env.OWNER) return 'login';
  const own = '-' + env.OWNER;
  if (!label.endsWith(own)) return null;
  return /^[a-z][a-z0-9]{0,29}$/.test(label.slice(0, -own.length)) ? 'app' : null;
}

// The /webapi/find response a stock agent needs to pick TLS routing and the
// tunnel address. The keys are in the same order as the Rust hub's.
function find(env) {
  const addr = env.PUBLIC_ADDR;
  return Response.json({
    cluster_name: env.CLUSTER_NAME,
    edition: 'oss',
    min_client_version: '17.0.0-aa',
    proxy: {
      ssh: { listen_addr: addr, public_addr: addr, web_listen_addr: addr },
      tls_routing_enabled: true,
    },
    server_version: env.SERVER_VERSION,
  });
}

// Each Durable Object instance runs its own Go program. The runtime can
// build a new instance in the same isolate, for example after it upgrades
// itself, and I/O objects of the old instance cannot be used from the new
// one. So a new instance stops the old program and starts a fresh one, and
// the old program's WebSockets are closed, so that auth's callout and the
// agents dial again.
let current = null;

// program is one Go program: its instance, its open WebSockets and response
// streams by the ID Go gave them, and the requests it has not answered.
class program {
  constructor(env) {
    this.go = new globalThis.Go();
    this.inst = null;
    this.api = null;
    this.sockets = new Map();
    this.streams = new Map();
    this.pending = new Set();
    this.exited = false;
    this.ready = this.start(env);
  }

  async start(env) {
    this.inst = await WebAssembly.instantiate(mod, this.go.importObject);
    globalThis.sallyportEnv = env;
    globalThis.sallyportGlue = this.glue();
    console.log('hub: go start, linear memory ' + (this.linearMem() >> 20) + ' MiB');
    this.done = this.go.run(this.inst).then(() => this.cleanup());
    // main has set globalThis.sallyport by the time it first blocks.
    this.api = globalThis.sallyport;
  }

  linearMem() {
    return this.inst ? this.inst.exports.mem.buffer.byteLength : 0;
  }

  // Stops the program and waits for it to exit.
  async stop() {
    await this.ready.catch(() => {});
    if (this.exited || !this.api) return;
    try {
      this.api.shutdown();
    } catch {}
    await this.done;
  }

  // Closes what the exited program left open.
  cleanup() {
    this.exited = true;
    console.log('hub: go program exited');
    let closed = 0;
    let failed = '';
    for (const ws of this.sockets.values()) {
      try {
        ws.close(1012, 'service restart');
        closed++;
      } catch (e) {
        failed = ' (' + e + ')';
      }
    }
    console.log('hub: closed ' + closed + ' of ' + this.sockets.size + ' WebSockets of the exited program' + failed);
    this.sockets.clear();
    for (const s of this.streams.values()) {
      try {
        s.ctl.error(new Error('service restart'));
      } catch {}
      s.resolve();
    }
    this.streams.clear();
    for (const resolve of this.pending) resolve(new Response('service restart', { status: 503 }));
    this.pending.clear();
    if (current === this) current = null;
  }

  // Returns the functions Go calls. Go reads them once at start.
  glue() {
    const p = this;
    return {
      // Accepts a new WebSocket pair for connection id, whose incoming
      // bytes go through inBuf, and returns the client end for the 101
      // response.
      accept(id, inBuf) {
        const pair = new WebSocketPair();
        const client = pair[0];
        const ws = pair[1];
        ws.binaryType = 'arraybuffer';
        ws.accept();
        p.sockets.set(id, ws);
        ws.addEventListener('message', (e) => {
          if (typeof e.data === 'string' || p.exited) return;
          const d = new Uint8Array(e.data);
          for (let off = 0; off < d.length; off += inBuf.length) {
            const k = Math.min(d.length - off, inBuf.length);
            inBuf.set(d.subarray(off, off + k));
            p.api.push(id, k);
          }
        });
        const closed = (e) => {
          if (!p.sockets.delete(id) || p.exited) return;
          p.api.closed(id, e.code || 0);
        };
        ws.addEventListener('close', closed);
        ws.addEventListener('error', closed);
        return client;
      },
      // Sends the first n bytes of outBuf, which is Go's persistent
      // buffer, so the message is a copy.
      send(id, outBuf, n) {
        const ws = p.sockets.get(id);
        if (!ws) return false;
        try {
          ws.send(outBuf.slice(0, n));
          return true;
        } catch (e) {
          console.log('glue: websocket send: ' + e);
          return false;
        }
      },
      close(id, code, reason) {
        const ws = p.sockets.get(id);
        p.sockets.delete(id);
        try {
          ws?.close(code, reason);
        } catch {}
      },
      // Returns a ReadableStream whose chunks Go supplies through buf.
      stream(sid, buf) {
        return new ReadableStream(
          {
            pull(ctl) {
              if (p.exited) return ctl.error(new Error('service restart'));
              return new Promise((resolve) => {
                p.streams.set(sid, { ctl, buf, resolve });
                p.api.pull(sid);
              });
            },
            cancel() {
              p.streams.delete(sid);
              if (!p.exited) p.api.cancel(sid);
            },
          },
          { highWaterMark: 0 },
        );
      },
      // Delivers the answer to one pull: n >= 0 bytes in buf, then the end
      // if last is true, or -2 for an error.
      chunk(sid, n, last) {
        const s = p.streams.get(sid);
        if (!s) return;
        p.streams.delete(sid);
        try {
          if (n > 0) s.ctl.enqueue(s.buf.slice(0, n));
          if (n === -2) s.ctl.error(new Error('upstream body error'));
          else if (last) s.ctl.close();
        } catch {}
        s.resolve();
      },
      // The size of the WASM linear memory in bytes.
      linearMem() {
        return p.linearMem();
      },
      // The JavaScript values Go holds a reference to, and the bytes in the
      // typed arrays among them, as "count bytes".
      jsValues() {
        let n = 0;
        let bytes = 0;
        for (const v of p.go._values || []) {
          if (v === undefined) continue;
          n++;
          if (ArrayBuffer.isView(v)) bytes += v.byteLength;
        }
        return n + ' ' + bytes;
      },
    };
  }
}

// Returns the running program of this instance, replacing one that belongs
// to another instance or has exited.
async function programFor(owner, env) {
  if (!current || current.owner !== owner || current.exited) {
    const old = current;
    const next = new program(env);
    next.owner = owner;
    current = next;
    if (old) {
      console.log('hub: stopping the go program of a previous instance');
      await old.stop();
    }
  }
  const p = current;
  await p.ready;
  return p;
}

export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    console.log('hub: durable object started');
    this.program = programFor(this, env);
  }

  async fetch(req) {
    const p = await programFor(this, this.env);
    const url = new URL(req.url);
    let body = null;
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body) {
      body = new Uint8Array(await req.arrayBuffer());
    }
    const headers = [];
    for (const [k, v] of req.headers) headers.push(k + ': ' + v);
    const r = {
      method: req.method,
      host: url.hostname,
      path: url.pathname,
      query: url.search,
      headers: headers.join('\n'),
      body,
    };
    return new Promise((resolve) => {
      p.pending.add(resolve);
      p.api.fetch(r, (status, head, b, flags, ws, stream) => {
        p.pending.delete(resolve);
        // A throw here would come out in Go as a panic, so it stays here.
        try {
          resolve(respond(status, head, b, flags, ws, stream));
        } catch (e) {
          console.log('glue: response: ' + e);
          resolve(new Response('bad response', { status: 502 }));
        }
      });
    });
  }
}

// Builds the Response Go described. head is "name: value" lines. Bit 1 of
// flags asks for the body to go out as is, because it is already encoded.
// Bit 2 sends a string body as bytes, with no Content-Type.
function respond(status, head, body, flags, ws, stream) {
  const h = new Headers();
  if (head) {
    for (const line of head.split('\n')) {
      const i = line.indexOf(': ');
      if (i > 0) h.append(line.slice(0, i), line.slice(i + 2));
    }
  }
  const init = { status, headers: h };
  if (ws) init.webSocket = ws;
  if (flags & 1) init.encodeBody = 'manual';
  if (flags & 2) body = new TextEncoder().encode(body);
  return new Response(stream || body || null, init);
}
