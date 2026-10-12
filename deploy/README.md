# The live deploy

Two clusters run on `homesrv`, each behind its own hub on Cloudflare. Nothing
on homesrv listens on the internet: each cluster's auth calls out to its hub.

| Cluster | Hub | Cloudflare account | homesrv config |
|---|---|---|---|
| julia | `julia.example.com` | gmail, paid Workers plan | `deploy/homesrv/` |
| party | `julia.example.net` | juliaogris.com, free Workers plan | `deploy/homesrv-party/` |

Each hub has a login host, `julia.<domain>`, and app hosts
`<app>-julia.<domain>` for `bench`, `octo` and `octocam`.

## Cloudflare

Deploy from `hub/go`:

```
npx wrangler@4 deploy --env edge    # julia.example.com
npx wrangler@4 deploy --env party   # julia.example.net
npx wrangler@4 tail --env edge --format pretty
```

Both envs set `HUB_MODE = "lazy"`: the hub's Durable Object sleeps while
nobody uses the cluster. The hub logs a heartbeat line every minute while
it is awake. A deploy restarts the Durable Object and drops the callout,
which auth redials within about a minute.

The free plan allows 100,000 requests and 13,000 GB-s of Durable Object
time a day, and resets at 00:00 UTC. One hub fits. Three hubs on that
account used about 14,400 GB-s a day and ran out each evening, which is
why the party account has one hub.

## homesrv

Each cluster is one process of the Teleport fork with auth and the app
service, run by a systemd user unit: `sallyport-auth` for julia and
`sallyport-party` for party. Auth's callout has `callout_mode: on_demand`.
The app service starts no reverse tunnel and serves the streams the
callout opens. The other units are `sallyport-bench` and
`sallyport-party-bench` (static bench servers), `sallyport-octocam` (the
webcam relay) and `sallyport-proxy` (the LAN web UI). Lingering is on, so
they start at boot. Over ssh, set `XDG_RUNTIME_DIR=/run/user/$(id -u)`
before `systemctl --user` or `journalctl --user`.

- **Binary.** The fork with on-demand mode is built on homesrv from
  `~/src/teleport-fork-coder`, branch `sallyport/lazy`, into
  `~/sallyport-lazy/bin/` (`teleport`, `tctl`, `proxymint`,
  `appsessmint`). Both clusters run that binary. Older `tctl` builds
  reject `callout_mode`, so use
  `~/sallyport-lazy/bin/tctl --config <cluster>/deploy/teleport.yaml`.
- **Admin web UI.** `sallyport-proxy`, a stock 18.11.1 proxy, serves
  Teleport's web UI at `https://teleport.julia.example.com:3080`. The DNS
  record points at homesrv's LAN address, 192.168.1.200, and is not proxied
  by Cloudflare, so the UI works only at home. It cannot reach the apps,
  since there is no reverse tunnel. The cert is from Let's Encrypt,
  issued by `lego` with a DNS-01 challenge and the Cloudflare token in
  `~/sallyport/cf-token`. `sallyport-cert.timer` renews it daily when 30
  days or fewer are left, and the proxy reloads the files every 12 hours.
- **Probe.** `deploy/probe` probes julia every minute and party every 10
  minutes, and writes one CSV row per cluster and run to
  `~/sallyport-probe/data/`. `summary.py` prints the success rates.
- **Nightly conformance.** See `deploy/homesrv-conformance/README.md`.

## Gotchas

- `wrangler dev` does not reload `.dev.vars` on a code reload. Restart it
  after changing secrets.
- `AuthenticateWebUser` is HTTP/1.1 on the legacy route
  `/v2/users//web/authenticate`, sent with TLS and no ALPN. Auth offers
  only `h2`, and `h2` goes to gRPC, which answers 415.
- The app session TLS key is `TLSPriv`, field 15, not `Priv`.
- Auth rate-limits `CreateAuthenticateChallenge` per client address to a
  burst of 40 calls, then 20 a minute. Every login on a hub reaches auth
  from the same stream, so they share one limit. The hub answers 429 when
  it is reached.
- Public `v18.11.1` is a different commit from core's, so never push core
  history to the public fork.
- The app service log can contain null bytes after a restart, so use
  `grep -a` or `tr -d '\000'`.
- The hub does not forward WebSockets, so OctoPrint's web UI cannot
  connect through it. The webcam and OctoPrint's API work.
