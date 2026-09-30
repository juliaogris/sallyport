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
- `authpipe.go` is the `/tunnel/auth` stream pool with the Ed25519
  challenge. `authrpc.go` is gRPC and the legacy HTTP API to auth, with
  `authmsg.go` and `proto.go` for the few protobuf fields the hub uses.
- `web.go` and `pages.go` are the login host and the app host pages.
  `appproxy.go` forwards app requests through the tunnel.
- `devtools/` holds two test commands with their own module, for testing
  a hub that the real agent and auth do not use. See "Testing on the dev
  Worker".

## Build and deploy

```
./build.sh                          # build/hub.wasm, about 11.7 MB
npx wrangler@4 deploy               # the dev Worker, see below
npx wrangler@4 deploy --env go      # go.example.com
```

`wrangler deploy` runs `build.sh` itself. `NO_OPT=1 ./build.sh` skips
`wasm-opt`.

The `go` env is the Rust hub's `go` env: the Worker `sallyport-hub-go`,
the same routes, vars, secret names and Durable Object class `Hub`. The go
test cluster on homesrv needs no change when the Worker changes language.

### Rollback to the Rust hub

Deploy the Rust hub's `go` env again from the Rust hub's directory (`hub/`
today, `rust/hub/` after the move):

```
cd hub && npx wrangler@4 deploy --env go
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
