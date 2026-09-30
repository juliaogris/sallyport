// A plain JavaScript Worker entry for the Rust hub, used only by the `rust`
// env. It routes like the Rust entry in src/lib.rs, and the Durable Object
// is still the Rust `Hub`.
//
// It tests whether the Rust Worker entry drops tunnels. Every agent tunnel
// passes through the Worker that accepted it, and with the Rust entry that
// Worker runs the hub's Wasm. The Go hub has a plain JavaScript entry and
// drops almost no tunnels under the same traffic.
export { Hub } from './build/worker/shim.mjs';

const HUB_INSTANCE = 'hub';

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
