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

// The most bytes a login host request body, or the body of the handoff on
// an app host, may have. A WebAuthn answer or credential is a few KB, and
// the body is held in JavaScript and in Go.
const LOGIN_BODY_LIMIT = 64 * 1024;
// The most bytes an app request body may have. The body is held in
// JavaScript and in Go before it goes to the app, and the isolate has 128
// MB for both and the Go program's linear memory, which never shrinks.
const APP_BODY_LIMIT = 8 << 20;

// The app host path of the launch handoff, and the hub's app cookies.
const AUTH_PATH = '/x-teleport-auth';
const APP_COOKIE = '__Host-sp_app';
const SUBJECT_COOKIE = '__Host-sp_subject';

// The login host paths the Go program answers, as web.go routes them. Any
// other path is 404 without waking the Durable Object.
const LOGIN_PATHS = new Set([
  '/',
  '/web/login',
  '/webapi/login/begin',
  '/webapi/login/finish',
  '/web/logout',
  '/web/passkeys',
  '/webapi/passkeys',
  '/web/add-passkey',
  '/webapi/add-passkey/begin',
  '/webapi/add-passkey/finish',
]);
const LOGIN_PREFIXES = ['/web/invite/', '/webapi/invite/', '/web/launch/', '/webapi/passkeys/'];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const kind = classify(env, url.hostname);
    if (kind === 'app') return appRequest(req, env, url);
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
    if (kind === 'login' && loginPath(url.pathname)) return hub(env).fetch(req);
    return textError('not found', 404);
  },
};

function loginPath(path) {
  return LOGIN_PATHS.has(path) || LOGIN_PREFIXES.some((p) => path.startsWith(p));
}

// Answers the app host requests that need no session as web.go does, and
// forwards the rest to the Durable Object. A request without both app
// cookies goes to the login host, so a scanner or a stray browser does not
// wake the Durable Object or have its body read.
function appRequest(req, env, url) {
  const path = url.pathname;
  if (path === AUTH_PATH) return hub(env).fetch(req);
  if (path === '/teleport-logout') return toLogin(env);
  if (path.startsWith('/x-teleport-dbsc')) return textError('not found', 404);
  switch (req.method) {
    case 'GET':
    case 'HEAD':
    case 'OPTIONS':
      break;
    default:
      if (!sameOriginFetch(req, url.hostname)) return textError('bad origin', 403);
  }
  if (!cookie(req, APP_COOKIE) || !cookie(req, SUBJECT_COOKIE)) return toLogin(env);
  return hub(env).fetch(req);
}

// Sends the browser to the login host and clears the app cookies.
function toLogin(env) {
  const h = new Headers({ location: 'https://' + env.OWNER + '.' + env.DOMAIN + '/' });
  for (const name of [APP_COOKIE, SUBJECT_COOKIE]) {
    h.append('set-cookie', name + '=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0');
  }
  return new Response(null, { status: 303, headers: h });
}

// Returns the value of the named cookie, or null.
function cookie(req, name) {
  for (const c of (req.headers.get('Cookie') || '').split(';')) {
    const i = c.indexOf('=');
    if (i > 0 && c.slice(0, i).trim() === name) return c.slice(i + 1).trim();
  }
  return null;
}

// Returns false when the browser says the request came from another
// origin. A request with neither Sec-Fetch-Site nor Origin is not from a
// browser page and passes.
function sameOriginFetch(req, host) {
  const site = req.headers.get('Sec-Fetch-Site');
  if (site !== null) return site === 'same-origin' || site === 'none';
  const origin = req.headers.get('Origin');
  return origin === null || origin === 'https://' + host;
}

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
// owner is the Durable Object instance it runs for, whose storage it uses.
class program {
  constructor(owner, env) {
    this.owner = owner;
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
          if (p.exited) return;
          // A text message is a lazy stream's ack, which Go checks.
          if (typeof e.data === 'string') return p.api.text(id, e.data);
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
      // Sends s as a text message, for a lazy stream's ack.
      sendText(id, s) {
        try {
          const ws = p.sockets.get(id);
          if (!ws) return false;
          ws.send(s);
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
      // Reports whether the privilege token id has added a passkey.
      tokenUsed(id) {
        const rows = p.owner.ctx.storage.sql.exec('SELECT 1 FROM used_tokens WHERE id = ?', id).toArray();
        return rows.length > 0;
      },
      // Records that the privilege token id added a passkey, to keep until
      // expires, and forgets the tokens that expired before now. Both are
      // Unix milliseconds.
      tokenUse(id, now, expires) {
        const sql = p.owner.ctx.storage.sql;
        sql.exec('DELETE FROM used_tokens WHERE expires <= ?', now);
        sql.exec('INSERT OR REPLACE INTO used_tokens (id, expires) VALUES (?, ?)', id, expires);
      },
      // Asks auth's callout for a stream of kind auth or app with the given
      // id, on the verified control socket. Returns false if there is none.
      // A throw here would come out in Go as a panic, so it stays here.
      dial(kind, id) {
        try {
          const c = p.owner.verifiedControl();
          if (!c) return false;
          c.ws.send('dial ' + kind + ' ' + id);
          return true;
        } catch (e) {
          console.log('lazy: sending dial: ' + e);
          return false;
        }
      },
      // Reports whether a verified control socket is open.
      connected() {
        try {
          return p.owner.verifiedControl() !== null;
        } catch (e) {
          console.log('lazy: connected: ' + e);
          return false;
        }
      },
    };
  }
}

// Returns the running program of this instance, replacing one that belongs
// to another instance or has exited.
async function programFor(owner, env) {
  if (!current || current.owner !== owner || current.exited) {
    const old = current;
    const next = new program(owner, env);
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

// The lazy hub's control socket. Auth's callout keeps one open with
// callout_mode: on_demand. The hub sends a 32-byte nonce, and auth replies
// with its own nonce and an Ed25519 signature, by AUTH_CALLOUT_PUBKEY, over
// "sallyport/authpipe/v1" || CALLOUT_HOST || hub nonce || auth nonce, as on
// the auth pipe. The socket is accepted with the hibernation API, and its
// state is in its attachment, so it survives hibernation. Go sends dials on
// it through glue.dial.
const CONTROL = 'control';
const AUTHPIPE_DOMAIN = 'sallyport/authpipe/v1';
const NONCE_BYTES = 32;
const SIGNATURE_BYTES = 64;
// A control socket that has not passed the challenge by then is closed.
const CHALLENGE_DEADLINE_MS = 10_000;
// Control sockets in the challenge. At this many, a new one closes the
// oldest of the client address with the most, counting the new one, with
// 1013, so that one address that opens many evicts its own, and auth's
// callout tries again soon.
const MAX_PENDING_CONTROL = 4;
// A verified control socket with no ping for this long is closed as dead.
// Auth's callout pings every 30 s, and the runtime answers each ping and
// notes when.
const CONTROL_STALE_MS = 90_000;
// The readyState of an open WebSocket.
const OPEN = 1;

export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    console.log('hub: durable object started');
    // The privilege tokens that have added a passkey, so that a token is
    // used once. Storage outlives a deploy, which restarts the Go program.
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS used_tokens (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
    this.lazy = env.HUB_MODE === 'lazy';
    // HUB_MODE unset or pool is the pool hub. Any other value answers every
    // request with 500, so that a typo does not run the wrong hub quietly.
    this.badMode = !['', 'pool', 'lazy'].includes(env.HUB_MODE || '');
    if (this.badMode) {
      console.log('hub: HUB_MODE ' + JSON.stringify(env.HUB_MODE) + ' is not pool or lazy');
      return;
    }
    if (this.lazy) {
      // The runtime answers "ping" without waking the object. The lazy hub
      // starts the Go program on the first request that needs it, so a
      // control socket message does not start it.
      ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
      console.log('lazy: woke, ' + ctx.getWebSockets().length + ' sockets');
      return;
    }
    this.program = programFor(this, env);
  }

  async fetch(req) {
    if (this.badMode) return textError('bad HUB_MODE', 500);
    const url = new URL(req.url);
    if (this.lazy) {
      this.prune();
      if (
        url.pathname === '/tunnel/auth' &&
        url.searchParams.get('mode') === 'control' &&
        classify(this.env, url.hostname) !== 'app'
      ) {
        return this.acceptControl(req);
      }
      // The lazy hub has no reverse tunnel and no auth pipe pool, so only a
      // stream reaches Go. A stream answers a dial, and a dial waits only
      // while this instance's program runs, so a stream for no running
      // program is 404 without starting one.
      if (classify(this.env, url.hostname) !== 'app') {
        if (url.pathname === '/webapi/connectionupgrade') return textError('not found', 404);
        if (url.pathname === '/tunnel/auth') {
          const running = current && current.owner === this && !current.exited;
          if (url.searchParams.get('mode') !== 'stream' || !running) return textError('not found', 404);
        }
      }
    }
    const p = await programFor(this, this.env);
    let body = null;
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body) {
      const app = classify(this.env, url.hostname) === 'app' && url.pathname !== AUTH_PATH;
      body = await readBody(req, app ? APP_BODY_LIMIT : LOGIN_BODY_LIMIT);
      if (body === null) return textError('request body too large', 413);
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
      // Go has copied the body, so this one can be freed.
      r.body = null;
    });
  }

  // Accepts a control socket and sends it the challenge nonce.
  async acceptControl(req) {
    // Auth's callout sends no Origin, and a browser always sends one.
    if (req.headers.has('Origin')) return textError('origin not allowed', 403);
    const key = await this.calloutKey();
    if (typeof key === 'string') {
      // The error is logged, and not sent to a caller who has not
      // authenticated.
      console.log('lazy: ' + key);
      return textError('bad AUTH_CALLOUT_PUBKEY', 500);
    }
    const client = clientKey(req.headers.get('CF-Connecting-IP'));
    const pending = this.controls().filter((c) => !c.a.verified);
    if (pending.length >= MAX_PENDING_CONTROL) {
      closeWS(busiestOldest(pending, client).ws, 1013, 'try again later');
    }
    const pair = new WebSocketPair();
    const ws = pair[1];
    this.ctx.acceptWebSocket(ws, [CONTROL]);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    ws.serializeAttachment({ acceptedMs: Date.now(), nonce: Array.from(nonce), verified: false, client });
    ws.send(nonce);
    // The header tells the callout that it may answer a dial with
    // "refuse <id>".
    return new Response(null, { status: 101, webSocket: pair[0], headers: { 'Sallyport-Control': 'refuse' } });
  }

  // Handles a message on a control socket: the challenge reply while it is
  // pending, and "refuse <id>" once it is verified. A verified socket that
  // sends anything else is closed. "ping" never arrives here.
  async webSocketMessage(ws, msg) {
    if (!this.lazy) return closeWS(ws, 1011, 'no handler');
    this.prune();
    if (ws.readyState !== OPEN) return;
    const a = ws.deserializeAttachment();
    if (!a) return closeWS(ws, 1008, 'unknown socket');
    if (a.verified) {
      const m = typeof msg === 'string' ? /^refuse ([A-Za-z0-9_-]{43})$/.exec(msg) : null;
      if (!m) {
        console.log('lazy: unexpected message on the control socket, closing it');
        return closeWS(ws, 1008, 'unexpected message');
      }
      // A dial waits only while this instance's program runs, so a refuse
      // for no running program has no dial to end.
      if (current && current.owner === this && !current.exited && current.api) {
        try {
          current.api.refuse(m[1]);
        } catch (e) {
          console.log('lazy: refuse: ' + e);
        }
      }
      return;
    }
    const reply = typeof msg === 'string' ? new Uint8Array(0) : new Uint8Array(msg);
    const err = await this.verifyReply(a.nonce, reply);
    if (err) {
      console.log('lazy: control challenge failed, ' + err);
      return closeWS(ws, 1008, 'challenge');
    }
    if (ws.readyState !== OPEN) return;
    // The verified control socket that the hub accepted last replaces the
    // others, also when an older one passes the challenge after it.
    for (const c of this.controls()) {
      if (!c.a.verified || c.ws === ws) continue;
      if (c.a.acceptedMs > a.acceptedMs) return closeWS(ws, 1000, 'replaced');
      closeWS(c.ws, 1000, 'replaced');
    }
    a.verified = true;
    a.nonce = [];
    ws.serializeAttachment(a);
    console.log('lazy: control socket verified');
  }

  // Without the auto-reply flag the runtime needs the close echoed.
  async webSocketClose(ws, code, reason) {
    console.log('lazy: control socket closed, code ' + code + ' ' + JSON.stringify(reason));
    closeWS(ws, 1000, 'closed');
  }

  async webSocketError(ws, err) {
    console.log('lazy: control socket error: ' + err);
  }

  // Returns the open control sockets with their attachments.
  controls() {
    const out = [];
    for (const ws of this.ctx.getWebSockets(CONTROL)) {
      if (ws.readyState !== OPEN) continue;
      let a = null;
      try {
        a = ws.deserializeAttachment();
      } catch {}
      if (a) out.push({ ws, a });
    }
    return out;
  }

  // Returns the open verified control socket that the hub accepted last, or
  // null. It first closes the verified ones with no ping for
  // CONTROL_STALE_MS, so that a dial on a dead socket fails at once.
  verifiedControl() {
    const now = Date.now();
    let best = null;
    for (const c of this.controls()) {
      if (!c.a.verified) continue;
      const ping = this.ctx.getWebSocketAutoResponseTimestamp(c.ws);
      if (now - Math.max(c.a.acceptedMs, ping ? ping.getTime() : 0) > CONTROL_STALE_MS) {
        console.log('lazy: no ping on the control socket for ' + CONTROL_STALE_MS / 1000 + ' s, closing it');
        closeWS(c.ws, 1001, 'no ping');
        continue;
      }
      if (!best || c.a.acceptedMs > best.a.acceptedMs) best = c;
    }
    return best;
  }

  // Closes control sockets that have not passed the challenge in time.
  prune() {
    const now = Date.now();
    for (const c of this.controls()) {
      if (!c.a.verified && now - c.a.acceptedMs > CHALLENGE_DEADLINE_MS) {
        console.log('lazy: control challenge failed, no reply in time');
        closeWS(c.ws, 1008, 'challenge timeout');
      }
    }
  }

  // Returns the callout's public key as a CryptoKey, or a string that says
  // what is wrong with AUTH_CALLOUT_PUBKEY.
  async calloutKey() {
    if (this.key) return this.key;
    let raw;
    try {
      raw = Uint8Array.from(atob((this.env.AUTH_CALLOUT_PUBKEY || '').trim()), (ch) => ch.charCodeAt(0));
    } catch (e) {
      return 'AUTH_CALLOUT_PUBKEY: ' + e;
    }
    if (raw.length !== 32) return 'AUTH_CALLOUT_PUBKEY is not 32 bytes';
    try {
      this.key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    } catch (e) {
      return 'AUTH_CALLOUT_PUBKEY: ' + e;
    }
    return this.key;
  }

  // Checks auth's reply to the challenge nonce, and returns null or what is
  // wrong with it.
  async verifyReply(nonce, reply) {
    if (reply.length !== NONCE_BYTES + SIGNATURE_BYTES) return 'bad reply length';
    if (!nonce || nonce.length !== NONCE_BYTES) return 'no nonce';
    const key = await this.calloutKey();
    if (typeof key === 'string') return key;
    const enc = new TextEncoder();
    const parts = [
      enc.encode(AUTHPIPE_DOMAIN),
      enc.encode(this.env.CALLOUT_HOST || ''),
      Uint8Array.from(nonce),
      reply.subarray(0, NONCE_BYTES),
    ];
    const msg = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
    let off = 0;
    for (const x of parts) {
      msg.set(x, off);
      off += x.length;
    }
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, reply.subarray(NONCE_BYTES), msg);
    return ok ? null : 'bad signature';
  }
}

// Returns the client address ip, from CF-Connecting-IP, with an IPv6
// address cut to its /64, because one host usually holds a whole /64. It
// is empty when the header is missing, as under wrangler dev.
function clientKey(ip) {
  ip = (ip || '').split('%')[0];
  if (!ip.includes(':') || ip.includes('.')) return ip;
  const [head, tail] = ip.split('::');
  let groups = head ? head.split(':') : [];
  if (tail !== undefined) {
    const t = tail ? tail.split(':') : [];
    groups = [...groups, ...Array(Math.max(8 - groups.length - t.length, 0)).fill('0'), ...t];
  }
  return groups.slice(0, 4).map((g) => parseInt(g || '0', 16).toString(16)).join(':') + '::/64';
}

// Returns the oldest of the pending control sockets whose client address
// has the most pending, counting a new one from client.
function busiestOldest(pending, client) {
  const counts = new Map([[client, 1]]);
  for (const c of pending) counts.set(c.a.client || '', (counts.get(c.a.client || '') || 0) + 1);
  const most = Math.max(...counts.values());
  let best = null;
  for (const c of pending) {
    if (counts.get(c.a.client || '') !== most) continue;
    if (!best || c.a.acceptedMs < best.a.acceptedMs) best = c;
  }
  return best;
}

function closeWS(ws, code, reason) {
  try {
    ws.close(code, reason);
  } catch {}
}

// Reads the whole body of req into one Uint8Array, or returns null when it
// is longer than limit bytes. The rest of a long body is read and dropped,
// because a response before the body is read closes the connection.
async function readBody(req, limit) {
  const reader = req.body.getReader();
  const chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n <= limit) chunks.push(value);
  }
  if (n > limit) return null;
  const body = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    body.set(c, off);
    off += c.byteLength;
  }
  return body;
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
