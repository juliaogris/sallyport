# Go hub

The sallyport hub runs on Cloudflare Workers as `GOOS=js` WebAssembly
inside one Durable Object. It serves `julia.example.com` and
`julia.example.net`.

## Layout

- `worker.mjs` is the Worker entry and the Durable Object class `Hub`. The
  Worker entry is JavaScript: it classifies the host, answers
  `/webapi/find` and `/webapi/ping`, rejects a non-upgrade request to the
  upgrade paths, and forwards the rest to the Durable Object, except for
  these. A login host path that `web.go` does not route gets 404. On an
  app host, `/teleport-logout` and a request without both app cookies go
  to the login host, `/x-teleport-dbsc` paths get 404, and a request that
  can change state or a WebSocket handshake from another origin gets 403.
  Only the Durable Object starts the Go program, so a stateless Worker
  isolate never pays the Go runtime's startup CPU and 38 MiB of memory.
  The Durable Object passes an app request body to Go as Go reads it. It
  reads any other request body before Go runs, and answers 413 for one
  over 64 KiB. It also owns the SQLite table of used privilege tokens,
  which Go reads and writes through the glue.
- `js.go` and `wsconn.go` are the Go side of the glue. `wsconn.go` is a
  `net.Conn` over a Workers WebSocket and a response body stream.
- `appproxy.go` forwards an app request to the app service over TLS with
  the user's certificate. `appws.go` forwards a WebSocket to an app. The
  runtime hands the Durable Object whole messages and not the upgraded
  bytes, so the hub opens its own WebSocket to the app and copies each
  message across with its type.
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
  a passkey from another device. `POST /webapi/passkeys/link` makes a
  privilege token and returns `/web/add-passkey#<token>`, with the token
  in the fragment so that it stays out of logs and the Referer. That page
  needs no session. It takes the token out of the address bar and sends
  it in the body of `POST /webapi/add-passkey/begin` (`{"token"}`) and
  `POST /webapi/add-passkey/finish` (`{"token", "name", "credential"}`).
  A token adds one passkey: after a finish that worked, the hub keeps the
  token ID in Durable Object storage until the token has expired, and
  both routes answer 403 `invalid token` for it, as they do for a token
  auth does not know. The passkeys page draws the QR code of the link
  with an encoder in its own script block, which `qr_test.go` runs under
  node and decodes. The decoder is checked against codes from qrencode
  under `testdata/qrencode`, and against fresh ones when qrencode is
  installed. `appproxy.go` forwards app requests through the tunnel.

## Build and deploy

```
./build.sh                          # build/hub.wasm, about 11.85 MB
npx wrangler@4 deploy --env edge    # julia.example.com
npx wrangler@4 deploy --env party   # julia.example.net
```

`wrangler deploy` runs `build.sh` itself. `NO_OPT=1 ./build.sh` skips
`wasm-opt`. The secrets belong to each Worker, so a deploy keeps them. A
deploy drops every connection, and the cluster redials within about a
minute.

## Size and memory

- **Size.** `build/hub.wasm` is about 11.85 MB after `wasm-opt -Oz`
  (3.29 MB gzip), with a startup time of 11 to 22 ms.
- **Memory.** The heartbeat logs linear memory, the Go heap after a GC,
  the memory Go has mapped (`sys`), goroutines and the js.Values Go
  holds. Linear memory starts at 38 MiB before any Go code runs, while
  Go's `sys` is about 4 MiB, so the baseline is the module's initial
  memory. The soft memory limit is 48 MiB of Go memory.
