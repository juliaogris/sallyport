# S1 - edge ALPN probe

Does a stock Teleport v18.10.0 agent decide on its own to use the
WebSocket connection upgrade when its proxy address is a Cloudflare
Worker?

## How

- `worker/` is a bare Worker that answers every request with 200.
- `probe/` calls `client.IsALPNConnUpgradeRequired` from Teleport's api
  module exactly as tagged v18.10.0, with
  `TELEPORT_TLS_ROUTING_CONN_UPGRADE` unset. It also prints the raw TLS
  handshake result with ALPN `teleport-reversetunnel`, which is what the
  probe bases its decision on.

```
cd worker && npx wrangler@4 deploy
cd ../probe && ./run.sh <worker-host>:443
```

`run.sh` extracts the v18.10.0 api module from a local core checkout
(`CORE`, default `~/teleport/core/_master`). A Go proxy lookup returned a
newer api version whose probe offers `teleport-reversetunnelv2` as well,
so the tag is pinned by source, not by module version.

## Result, 2026-09-23

| Host | Upgrade required | Raw handshake |
|---|---|---|
| `sallyport-s0.radial-ghost-980.workers.dev` | `true` | ok, negotiated ALPN `""`, TLS 1.3 |

Cloudflare completes the handshake and ignores the ALPN offer. The probe
reads the empty negotiated protocol as "ALPN stripped" and returns
`true`, so a stock agent upgrades without the env var.

Still to run: the same probe against `teleport.jul.run` once the zone is
on Cloudflare. A custom domain goes through the same edge, so the result
is expected to match.

S1 gates nothing. The plan sets `TELEPORT_TLS_ROUTING_CONN_UPGRADE=yes`
on the agent either way; this result says the variable is a safety net,
not a requirement.
