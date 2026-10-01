// A plain JavaScript Worker entry for the Rust hub, used by every env that
// sets `main = "front.mjs"` in wrangler.toml. It routes like the Rust entry
// in src/lib.rs, and the Durable Object is still the Rust `Hub`.
//
// The free plan allows 10 ms of CPU per Worker request, and the Rust entry
// peaks at about 21 ms because every request runs the hub's Wasm. This
// entry peaks at about 3 ms, as the Go hub's does.
export { Hub } from './build/worker/shim.mjs';

const HUB_INSTANCE = 'hub';

// The app host path of the launch handoff, and the hub's app cookies.
const AUTH_PATH = '/x-teleport-auth';
const APP_COOKIE = '__Host-sp_app';
const SUBJECT_COOKIE = '__Host-sp_subject';

// The login host paths the hub routes, as src/web.rs has them in
// LOGIN_PATHS and LOGIN_PREFIXES. Any other path is 404 without waking the
// Durable Object.
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

// The same JSON as src/ping.rs.
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

// Returns an error with the message as a body of bytes, so that it has no
// Content-Type, like the Rust entry's errors.
function textError(msg, status) {
  return new Response(new TextEncoder().encode(msg), { status });
}

// Answers the app host requests that need no session as src/web.rs does,
// and forwards the rest to the Durable Object. A request without both app
// cookies goes to the login host, so a scanner or a stray browser does not
// wake the Durable Object.
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

function loginPath(path) {
  return LOGIN_PATHS.has(path) || LOGIN_PREFIXES.some((p) => path.startsWith(p));
}

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
        // Agents and auth dial the login host. A hub without OWNER and
        // DOMAIN names no host, so it takes them on any host.
        if (!kind && env.OWNER && env.DOMAIN) return textError('not found', 404);
        // The lazy hub takes only a control socket or a stream on
        // /tunnel/auth. It has no reverse tunnel and no auth pipe pool, and a
        // peer that dials one anyway retries, so it must not wake the Durable
        // Object each time.
        if (env.HUB_MODE === 'lazy') {
          const mode = url.searchParams.get('mode');
          if (url.pathname !== '/tunnel/auth' || (mode !== 'control' && mode !== 'stream')) {
            return textError('not found', 404);
          }
        }
        return hub(env).fetch(req);
    }
    if (kind === 'login' && loginPath(url.pathname)) return hub(env).fetch(req);
    return textError('not found', 404);
  },
};
