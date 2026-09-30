# Go hub

This is a Go version of the sallyport hub, with the same behavior as the
Rust hub. It runs on Cloudflare Workers as `GOOS=js` WebAssembly inside one
Durable Object. It serves `go.example.com`, so that `rust.example.com` (Rust hub)
and `go.example.com` (Go hub) can be compared on two identical clusters.

## Layout

- `worker.mjs` is the Worker entry and the Durable Object class `Hub`. The
  Worker entry is JavaScript: it classifies the host, answers
  `/webapi/find` and `/webapi/ping`, rejects a non-upgrade request to the
  upgrade paths, and forwards everything else to the Durable Object. Only
  the Durable Object starts the Go program, so a stateless Worker isolate
  never pays the Go runtime's startup CPU and 38 MiB of memory.
- `js.go` and `wsconn.go` are the Go side of the glue. `wsconn.go` is a
  `net.Conn` over a Workers WebSocket and a response body stream.
- `tunnel.go` is the reverse tunnel: TLS with `crypto/tls` and the SSH
  server with `golang.org/x/crypto/ssh`.
- `authpipe.go` is the `/tunnel/auth` WebSocket with the Ed25519
  challenge, and `authpool.go` is the pool of verified streams, which
  also builds natively for its tests. `authrpc.go` is gRPC and the
  legacy HTTP API to auth, with
  `authmsg.go` and `proto.go` for the few protobuf fields the hub uses.
- `web.go` and `pages.go` are the login host and the app host pages.
  `passkeys.go` is the passkeys page and its JSON routes, which call auth
  as the user to list, add and remove passkeys, and the routes for adding
  a passkey from another device: `/webapi/passkeys/link` makes a link
  with a privilege token, and `/web/add-passkey/<token>` with its `begin`
  and `finish` routes uses it without a session, as the invite does. The
  passkeys page draws the QR code of the link with an encoder in its own
  script block, which `qr_test.go` runs under node and decodes.
  `appproxy.go` forwards app requests through the tunnel.
- `devtools/` holds two test commands with their own module, for testing
  a hub that the real agent and auth do not use. See "Testing on the dev
  Worker".

## Build and deploy

```
./build.sh                          # build/hub.wasm, about 11.8 MB
npx wrangler@4 deploy               # the dev Worker, see below
npx wrangler@4 deploy --env go      # go.example.com
```

`wrangler deploy` runs `build.sh` itself. `NO_OPT=1 ./build.sh` skips
`wasm-opt`.

The `go` env is the Rust hub's `go` env: the Worker `sallyport-hub-go`,
the same routes, vars, secret names and Durable Object class `Hub`. The go
test cluster on homesrv needs no change when the Worker changes language.

### Rollback to the Rust hub

Deploy the Rust hub's `go` env again from the Rust hub's directory:

```
cd hub/rust && npx wrangler@4 deploy --env go
```

The secrets stay, because they belong to the Worker, not to the code. A
deploy drops every tunnel, and the agent redials within about a minute.

## Testing on the dev Worker

`wrangler deploy` with no env deploys `julia-sallyport-gohub-dev` on
workers.dev, with no routes. It has the go cluster's secrets, and its own
host is its login host and its `CALLOUT_HOST`. The real agent cannot use
it, because the hub's SSH host certificate names `go.example.com` and the
agent checks that, and auth only calls out to `go.example.com`. The two
devtools stand in for them, on homesrv:

- `devtools/callout` keeps streams open to `/tunnel/auth`, signs the
  challenge with `~/sallyport-go/callout.pem`, and copies each stream to
  auth on `127.0.0.1:3226` once the hub uses it. This is what auth's own
  callout does.
- `devtools/agent` dials the tunnel with the identity from a copy of the
  app service's proc database (`/ids/app/current` or
  `/ids/instance/current`). With `-role app` it pings, takes discovery
  requests and the hub's test dial. With `-role instance` it opens the
  `@remote-auth-server` passthrough and calls auth's `Ping` through it.
  With `-plain` it must be rejected.

Build them with `GOOS=linux GOARCH=amd64 go build ./agent ./callout` in
`devtools/`.

## Status on 2026-09-30

- **Running on go.example.com** since 00:37 UTC, with fixes deployed until
  01:27. The six stages of parity with the Rust hub are in: the Worker
  entry, the tunnel, the auth pipe, gRPC and HTTP to auth, the browser
  pages and the app proxy. The passkey invite and login were not tried
  with a real passkey yet.
- **Size.** `build/hub.wasm` is 11.84 MB after `wasm-opt -Oz` (3.29 MB
  gzip). Wrangler uploads 11.4 MiB (3.2 MiB gzip), with a startup time
  of 11 to 22 ms. The Rust hub is about 0.7 MB gzip. The passkey routes
  and page added 62 KB (20 KB gzip), and the link, the token routes and
  the QR encoder in the page another 36 KB (2 KB gzip).
- **Memory.** The heartbeat logs linear memory, the Go heap after a GC,
  the memory Go has mapped (`sys`), goroutines and the js.Values Go
  holds. Linear memory starts at 38 MiB before any Go code runs, while
  Go's `sys` is about 4 MiB, so the baseline is the module's initial
  memory. With one agent and the probe every minute, linear memory
  settled at 55.5 MiB with a heap of 1.1 to 1.3 MiB and 40 to 56
  goroutines. The soft memory limit is 48 MiB of Go memory.
- **Side by side.** The same requests to both hubs give the same status,
  headers and body, except that a handoff POST with a bad JSON body
  gets 400 from the Go hub and 500 from the Rust hub.

Bugs found on the way, fixed in the commits after the first deploy:

- **App connections left open.** The runtime stops pulling a response
  body once it has Content-Length bytes, and does not always cancel a
  stream when the browser goes away. The heap grew 4.6 MiB a minute until
  the GC thrashed. The last chunk now carries the end, and a body that is
  not pulled for 30 s is closed.
- **A new Durable Object instance in the same isolate.** After a runtime
  upgrade the new instance used the old Go program, whose WebSockets
  belong to the old instance. Each instance now runs its own program.
