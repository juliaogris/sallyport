# The live deploy, 2026-09-24

The hub runs on Cloudflare at `julia.example.com`. Auth and the app service
run on the Mac and dial out to it; nothing on the Mac listens inbound.
Three users log in with passkeys: Julia, alice and `julia-teleport`.

## What runs where

- **Cloudflare:** `cd hub && npx wrangler@4 deploy --env edge`. The `edge`
  env serves `julia.example.com` (login host) and the app hosts
  `bench-julia.example.com`, `octo-julia.example.com` and
  `octocam-julia.example.com`. The edge build leaves out the `spikes` Cargo
  feature, so `/spike/*` answers 404. Live log:
  `npx wrangler@4 tail --env edge --format pretty`. The hub logs a
  heartbeat line every minute.
- **Auth:** `deploy/auth.yaml`, built from the public fork branch
  `sallyport/auth-callout-v18.11.1`. It dials the callout to
  `wss://julia.example.com/tunnel/auth` and sets `keep_alive_interval: 30s`.
- **App service:** stock 18.11.1 with `deploy/app.yaml`, which points at
  `julia.example.com:443`. Run it with
  `TELEPORT_TLS_ROUTING_CONN_UPGRADE=yes`.

A deploy restarts the Durable Object and drops the agent's tunnel. With
the 30 s keepalive the agent's watchdog is 90 s. The app service reads
the keepalive when it starts, so restart it after changing auth's value.

## Results

- **S2 answered by octocam.** An MJPEG stream from `~/bin/octocam` plays
  through the Durable Object.
- **Flat per-user hosts.** `<owner>.example.com` is the login host, and
  `<app>-<owner>.example.com` is an app host.
- **Rebased to 18.11.1.** Public `v18.11.1` is a different commit from
  core's, so never push core history to the fork.
- **`base64ct` 1.6.0 bug.** It rejects some valid OpenSSH private keys
  with `InvalidLength`. The hub identity minted for `julia.example.com` hit
  it. See `vendor/russh/PATCHES.md`.
- **Stall at 14:09.** Discovery to the agent and auth passthroughs stopped
  while pages still loaded, until a redeploy. russh adjusts the window
  when data arrives and then waits for the channel's queue, so a reader
  that stops reading blocks the session loop and every other channel.
  The patched russh closes that channel instead, and
  `vendor/russh/tests/test_backpressure.rs` fails on the old code and
  passes on the new. The hub queues up to 256 messages per channel.
- **OctoPrint.** `octo` is back on the dashboard without WebSocket
  forwarding. OctoPrint asks for its own login. Its SockJS client should
  fall back to HTTP polling; not yet confirmed through the hub.
- **Security review** of the web route: `security-review.md`.

## Gotchas

- `wrangler dev` does not reload `.dev.vars` on a code reload. Restart it
  after changing secrets.
- `Response::redirect` has immutable headers in workers-rs, so it cannot
  set cookies. Use a 303 built with `Response::empty()`.
- `AuthenticateWebUser` is HTTP/1.1 on the legacy route
  `/v2/users//web/authenticate`, sent with TLS and no ALPN. Auth offers
  only `h2`, and `h2` goes to gRPC, which answers 415.
- The app session TLS key is `TLSPriv`, field 15, not `Priv`.
- The first deploy needed a `workers.dev` subdomain. Opening the Workers
  page in the dashboard once created it.
- The app service log can contain null bytes after a restart, so use
  `grep -a` or `tr -d '\000'`.
