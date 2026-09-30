# Conformance tests

The conformance tests run the same black-box tests against the Go hub and
the Rust hub. Each hub runs locally under `wrangler dev`. The tests need no
Teleport cluster and no deploy.

```
./run.sh              # build both hubs, test both, print one table
./run.sh go           # one hub
NO_BUILD=1 ./run.sh   # use the hubs as last built
SP_HUB=rust go test -run TestTunnelAuth -v .
SP_HUB=go go test -run TestRekey -long -v .   # 2 GiB through one tunnel
```

`run.sh` needs `npx`, Go, `worker-build` and Homebrew's LLVM for the Rust
hub. `go test` alone needs the hub to be built already.

## What a run does

- `NewPKI` generates a test cluster: an SSH and a TLS host CA, the hub's
  TLS certificate and SSH host certificate, and the callout key.
- `StartHub` writes a `wrangler.toml` and a `.dev.vars` with the test vars
  and those secrets to a temporary directory, and starts `wrangler dev` on
  a free port. The hub's own `wrangler.toml` is not used.
- Requests go to `127.0.0.1:<port>` with the host in the Host header. The
  login host is `hub.test` and app hosts are `<app>-hub.test`.
- `wrangler dev` serves HTTPS with a self-signed certificate, which the
  tests do not check. Over plain HTTP it rewrites the Origin header to
  `http://`, so no POST would pass the hub's Origin check.
- A fake agent dials the tunnel with host certificates from the test CA. A
  fake callout answers the `/tunnel/auth` challenge with the test callout
  key.
- `FakeAuth` keeps 4 callout streams open and serves auth on each stream
  the hub uses: the unary gRPC calls on h2 and the passwordless login on
  the legacy HTTP API. Alice has a passkey and Bob has an invite. WebAuthn
  is not checked. A credential ID of `cred-alice` or `cred-bob` passes.
- `Agent.ServeApp` makes the fake agent serve a test app on each dial the
  hub makes into it, with TLS that requires the user's certificate.

Most tests share one hub. A test that needs an empty callout pool or its
own fake auth starts its own hub with `freshHub` or `newStack`.

With `-keep`, the temporary directory stays, with the `wrangler dev` log of
each hub.

## What is not tested

- An `http://` Origin, because `wrangler dev` rewrites it.
- A real browser's WebAuthn and a stock Teleport app service.
- Durable Object restarts, CPU time and memory. `wrangler dev` does not
  enforce the Workers limits, so these need a live env.
