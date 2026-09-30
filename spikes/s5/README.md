# S5 - gRPC over rustls over the auth pipe

Can the hub call auth over gRPC from WASM, through WebSockets that auth
opens itself? Auth runs the auth callout from the core branch
`julia/sallyport/auth-callout`. The hub runs rustls with ALPN `h2` and SNI
`teleport.cluster.local`, then HTTP/2 and gRPC.

## Setup

The cluster, hub, agent and bench app are the S3 and S4 setup. S5 adds:

- `cluster/auth.yaml`: the S3 auth config plus `callout_to` and
  `callout_key_file`. Auth runs the branch build, on the same data dir.
- An Ed25519 key for the challenge. The hub pins the raw public key.
- `rust/hub/.dev.vars`: `AUTH_CALLOUT_PUBKEY`, `S5_USER_CERT` and
  `S5_USER_KEY` (the S4 `tctl auth sign` cert for `s4user`), and
  `DEV_S5=1`.

```
openssl genpkey -algorithm ed25519 -out .local/callout.pem
openssl pkey -in .local/callout.pem -pubout -outform DER | tail -c 32 | base64
go build -o .local/teleport-callout ./tool/teleport    # in the core worktree
cd spikes/s5/cluster && ../../../.local/teleport-callout start --config=auth.yaml
```

`/spike/s5` takes two streams from the pool and makes these calls:

1. With the hub TLS identity: `Ping` and `GetClusterName`.
2. With the user's cert: `CreateAppSession` for `bench`.
3. With the hub TLS identity: `GetAppSession` for that session.

## Result, 2026-09-24: pass, with gaps

```
$ curl https://localhost:8787/spike/s5
{"app_session":{"has_tls_private_key":true,"id_len":64,"tls_cert_bytes":1549,"user":"s4user"},
 "cluster_name":"sallyport","connect_ms":9,"ping":{"cluster_name":"sallyport","server_version":"18.10.0"},
 "ping_ms":8,"streams_ready_after":6,"streams_ready_before":8,"total_ms":23}
```

- **The callout works.** Auth opens 8 WebSockets. The hub logs
  `tunnel/auth: stream ready` 8 times, and auth logs `challenge signed`
  and, on use, `stream handed to listener`.
- **gRPC works from WASM.** `h2` 0.4 and `prost` 0.13 build for
  `wasm32-unknown-unknown` with no changes. The gRPC framing is about 60
  lines by hand. Auth accepts ALPN `h2` from rustls.
- **Both TLS roles work.** With the hub identity, `Ping`,
  `GetClusterName` and `GetAppSession` succeed. With the user cert,
  `CreateAppSession` succeeds. `GetAppSession` returns the session cert
  and its TLS key.
- **Streams refill.** A used stream closes when the hub drops its
  HTTP/2 connection, and auth opens a new WebSocket. The pool is back at
  8 by the next run.
- **Hub restarts recover.** A `wrangler dev` reload closes all 8
  WebSockets with 1006. Auth backs off and redials.
- **The stream bound works.** A ninth pool gets 503. Auth backs off and
  logs `dial rate limit reached`.
- **Latency:** TLS and HTTP/2 setup 5 to 9 ms, `Ping` 5 to 8 ms, all
  four calls in 12 to 23 ms.
- **Size:** 2.4 MB raw, 817 KB gzipped, against the 10 MB budget.

### Passwordless login, 2026-09-24: pass

`/spike/s5/login` is a page with one button. It runs the login the plan
describes for Phase 3, with a passkey registered for `s4user` through the
reference proxy's reset page:

1. `CreateAuthenticateChallenge` with the hub identity and scope
   `PASSWORDLESS_LOGIN`. The hub gives the challenge to
   `navigator.credentials.get`.
2. `AuthenticateWebUser` with the hub identity and the browser's
   assertion unchanged, as `{"username": "", "webauthn": ...}`.
3. `GetWebSession` with the hub identity. It returns the user's TLS cert
   and key.
4. `CreateAppSession` with that cert, then `GetAppSession` with the hub
   identity.

```
200
{"app_session":{"has_tls_private_key":true,"tls_cert_bytes":1549,"user":"s4user"},
 "web_session":{"has_key":true,"tls_cert_bytes":1326,"user":"s4user"}}
```

### Findings

- **`AuthenticateWebUser` is HTTP/1.1, not gRPC.** It is the legacy
  route `POST /v2/users//web/authenticate`, with an empty user segment for
  a passwordless login. Auth's TLS offers only ALPN `h2`, and `h2` goes to
  the gRPC server, which answers 415. The hub sends this call on its own
  stream, with TLS and no ALPN, as HTTP/1.1.

- **`tonic` was not tried.** The plan's fallback, `prost` with gRPC
  framing by hand over `h2`, was small enough to be the first choice.
  Unary calls are all the hub needs.
- **The app session's TLS key is `TLSPriv`, field 15.** `Priv`, field 3,
  is empty for app sessions. Go's `GetTLSPriv` reads `TLSPriv`.
- **Gorilla, not gobwas.** The callout uses gorilla/websocket with a
  128 KiB read limit and no compression. The Go proxy's upgrade path uses
  gobwas because gorilla caches read errors. For the callout a read
  error ends the stream anyway.

### Agent passthrough on the pool, 2026-09-24

The agent's `@remote-auth-server` dial now takes a stream from the pool,
and the S3 direct TCP shortcut to `127.0.0.1:3025` is gone. After a hub
reload the agent's `Instance` connection logs `passthrough to auth over
the callout`, and S4 and S5 still pass. With no stream in the pool the
dial is refused and the agent retries.

### Not done

- **`ws://`.** Only `wss://localhost:8787` ran, because `wrangler dev`
  serves HTTPS here. The Go side's URL check has a unit test for `ws://`.
- **A bad signature, live.** The stream bound refused the wrong-key pool
  before its challenge. The Go unit test covers a rejected signature.
- **The process-level test** from the plan, a `TeleportProcess` with the
  callout set, is not written. The pool, listener and config tests are.
