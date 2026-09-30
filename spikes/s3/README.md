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
- **Unknown channel requests always fail.** `teleport-transport-dial`
  needs a real `true` reply. (Corrected: stock russh already sends no
  reply when `want_reply` is false, so the heartbeat `ping` was safe.)
- **Unknown global requests get `REQUEST_FAILURE` regardless of
  `want_reply`.** `keepalive@openssh.com` wants a reply, so a failure is
  tolerated by the agent. Replying when no reply was asked for is still a
  protocol error.

### Decision

Vendor `russh` 0.54.5 into `rust/vendor/russh` and patch it:

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

## Result so far, 2026-09-24: TLS layer passes

A stock v18.10.0 app service, joined once through the reference proxy
and then pointed at the hub, completed the WebSocket upgrade with
`alpn-ping` and the inner TLS handshake with ALPN
`teleport-reversetunnel`, then sent its SSH identification:

```
tunnel: tls established, alpn "teleport-reversetunnel"
tunnel: agent ssh id "SSH-2.0-Go"
```

The agent verifies the hub's TLS cert against the cluster host CA before
it sends anything, so this also proves the minted identity. SSH is next.

Two fixes it took:

- **`binaryType` must be `arraybuffer`.** With compatibility date
  2026-09-01, workerd delivers binary WebSocket messages as `Blob`, and
  `workers-rs` 0.8.6 `MessageEvent::bytes()` reads a `Blob` as zero
  bytes. The hub sets `binaryType` before `accept()`.
- **Auth must run with `proxy_listener_mode: multiplex`.** Otherwise the
  reference proxy runs in separate mode and the agent dials port 3024.

The reference proxy run is the oracle: `Connected to Auth Server through
tunnel.`, then `Agent state updated ... current_state:connected`.

The newer join client also tries a WebSocket upgrade with a subprotocol
other than `alpn-ping` before it falls back to `/webapi/host/credentials`.
The hub returns 400 for it. Phase 1 has to handle both.

## russh patch, 2026-09-24

`rust/vendor/russh` is patched and committed; `rust/vendor/russh/PATCHES.md` lists
every change. Native tests: 48 pass, including 4 new hook tests driven by
a Go client on `golang.org/x/crypto/ssh`. It builds for wasm32 at
457 KB gzipped. The wasm timer code has not yet run under workerd.

### 4. The agent requires an SSH host certificate

The agent verifies the hub with `NewHostKeyCallback`, which accepts only
a host certificate signed by the host CA and has no plain-key fallback
(`lib/reversetunnel/agent_dialer.go:78-105`). russh's server can present
only plain host keys. One more patch is needed: advertise the
`*-cert-v01@openssh.com` host key algorithms and send the certificate as
the host key blob in the key exchange reply, signing with the underlying
key.

## Result, 2026-09-24: SSH layer passes

With the host-certificate patch and two more fixes, a stock v18.10.0 app
service runs its whole reverse tunnel through the hub:

```
ssh: agent "<host>.sallyport" authenticated, role Instance
ssh: passthrough to auth 127.0.0.1:3025
ssh: agent "<host>.sallyport" authenticated, role App
ssh: heartbeat channel accepted
ssh: first ping "2026-09-23T21:44:34.713547Z"
ssh: discovery sent, proxy b4d32df5-3eff-45ae-84ac-e69f9eca18f4
ssh: test dial into agent accepted: true
```

and the agent logs `Connected to Auth Server through tunnel.` and
`Agent state updated ... current_state:connected`.

### 5. ssh-key cannot parse Teleport host certificates

Teleport host certs have `valid_before = u64::MAX`, OpenSSH's "forever".
The forked `ssh-key` caps timestamps at `i64::MAX` and rejects the cert.
`rust/vendor/ssh-key` keeps the raw value, so a re-encoded cert keeps its CA
signature, and only saturates the `SystemTime` view.

### 6. The agent dials with two identities

The auth client dials with the process's `Instance` certificate and the
tunnel pool with `App`. The hub admits exactly those two. `Proxy` and
every other role are still rejected, so the hub's own identity cannot
authenticate to itself. The heartbeat channel requires `App`.

### 7. Discovery is required, not optional

Without a `discovery` request naming the hub as the only proxy, the agent
pool dials a new connection about every two seconds and aborts each one
with `proxy already claimed`. Every attempt costs a full WebSocket, TLS
and SSH handshake on the Durable Object. The hub now sends discovery on
every ping. The plan listed discovery as cut; this reverses that.

### Smaller fixes

- Go's PEM encoder wraps OpenSSH private keys at 64 columns; `ssh-key`
  accepts only 70. The hub re-wraps before parsing.
- The SSH user is already `<host UUID>.<cluster>`; that is the dial
  `server_id` as is.

### Still to check

- Keepalive reply at the agent's 5-minute interval, and the tunnel still
  up after two intervals.
- Agent behaviour across a hub restart.
- Size budget: see below.

## Progress, 2026-09-24

- **`ring` needs LLVM clang for wasm32.** Its C code is not built by
  Apple clang, so the link fails with undefined `ring_core_*` symbols.
  `rust/hub/wrangler.toml` sets `CC_wasm32_unknown_unknown` to Homebrew LLVM.
- **Hub skeleton builds and runs** under `wrangler dev` over HTTPS with a
  `mkcert` cert: `/webapi/find` answers, and the Durable Object bridges
  the WebSocket to a rustls server with the hub TLS identity. Until the
  patched `russh` lands it logs the agent's SSH banner. Not yet run
  against an agent. Size 1.45 MB uncompressed.
- **App service joins only through a proxy.** v18.10.0 refuses
  `auth_server` when `app_service` is enabled, so the first join went
  through the reference Go proxy (`cluster/proxy.yaml`) and succeeded:
  `Successfully obtained credentials to connect to the cluster.` The
  identity is in the app data dir for reuse against the hub.
- **Reference proxy ran in separate mode.** The agent then dialled
  `[::1]:3024`, so the cluster networking config is not `multiplex`.
  Set `proxy_listener_mode: multiplex` explicitly before the next run.
- **`rust/vendor/russh` is partial and uncommitted.** The patch agent was
  stopped mid-way. Re-check it against the patch list above before use.

Next: finish the `russh` patch, wire `run_stream` into `rust/hub/src/tunnel.rs`,
point `cluster/app-tunnel.yaml` at the hub, and check the S3 exit criteria.
