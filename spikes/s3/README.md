# S3 - tunnel terminator in WASM

Can a Durable Object accept a stock Teleport v18.10.0 agent over
`/webapi/connectionupgrade`: WebSocket with `alpn-ping`, then a rustls
server with the hub's Host-CA-signed TLS cert, then an SSH server with the
hub's Host-CA-signed SSH host cert?

## Setup

- `cluster/auth.yaml`: a local v18.10.0 auth on `127.0.0.1:3025`, cluster
  `sallyport`. Binaries and data live in `../../.local/`, which is not
  committed.
- Hub identity minted with `proxymint` from the core branch
  `julia/sallyport/auth-callout`, under a 5-minute `proxy` token that is
  deleted afterwards. The TLS cert carries `O=Proxy` and SAN `localhost`;
  the SSH host cert is signed by the cluster host CA.

```
tctl --config=auth.yaml tokens add --type=proxy --ttl=5m
proxymint -token <token> -host-uuid <uuid> -principal localhost -out <dir>
tctl --config=auth.yaml tokens rm <token>
```

## Findings

### 1. The crypto crates compile for `wasm32-unknown-unknown`

`rustls` 0.23 with `ring` and `russh` 0.54 with `ring` build once two
feature flags are set:

- `ring` with `wasm32_unknown_unknown_js`, for its RNG.
- `rustls-pki-types` with `web`, for `UnixTime::now`.
- `getrandom` 0.2 `js` and 0.3 `wasm_js`, with
  `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`.

### 2. `russh`'s server does not run on wasm without patches

`russh` supports wasm for its client. Its server code calls tokio's time
directly, bypassing the wasm `Instant` in `russh-util`:

- `tokio::time::Instant::now()` on every encrypted packet
  (`server/encrypted.rs` `process_packet`). On `wasm32-unknown-unknown`
  this panics, because std `Instant` is not implemented there.
- `tokio::time::sleep`, `sleep_until` and `timeout` for keepalive,
  inactivity and auth rejection. These need a tokio runtime, which a
  Durable Object does not have.

About 13 call sites outside the client.

### 3. `russh`'s server cannot speak Teleport's reverse tunnel protocol

- **Unknown channel types are rejected with no hook.** `teleport-heartbeat`
  and `teleport-transport` opened by the agent get `unknown channel type`.
- **The server cannot open a custom channel type.** The hub must open
  `teleport-transport` to the agent to dial the app service.
- **Unknown channel requests get `CHANNEL_FAILURE` even when no reply was
  asked for.** The agent's heartbeat `ping` has `want_reply = false`, so
  it would receive an unexpected failure. `teleport-transport-dial` needs
  a real `true` reply.
- **Unknown global requests get `REQUEST_FAILURE` regardless of
  `want_reply`.** `keepalive@openssh.com` wants a reply, so a failure is
  tolerated by the agent. Replying when no reply was asked for is still a
  protocol error.

### Decision

Vendor `russh` 0.54.5 into `vendor/russh` and patch it:

1. A time shim: `web-time` `Instant` and JS-timer sleeps on wasm, tokio
   on native.
2. `Handler::channel_open_unknown(type, channel, session) -> bool`.
3. `Handler::channel_request_unknown(channel, type, want_reply, data)`,
   replying only when asked.
4. `Handler::global_request_unknown(type, want_reply, data)`, replying
   only when asked.
5. Server-side `Handle::channel_open_custom(type)` and a way to send a
   channel request with a reply.

The patch is the S3 result as much as the handshake is. It is small enough
to carry, and a candidate for upstreaming to `russh`.
