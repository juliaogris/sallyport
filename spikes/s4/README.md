# S4 - TLS client to the app service

Can the hub reach an app through the agent's tunnel? The hub opens
`teleport-transport` into the agent with an `@local-node` dial request,
then runs a rustls client with the user's app session certificate, SNI
`EncodeClusterName("sallyport")` and the cluster host CA as root.

## Setup

The cluster, the hub and the agent are the S3 setup. S4 adds:

- `role.yaml`: role `s4-apps`, which allows apps labelled
  `sallyport-spike: s4`.
- A second app `bench` in `../s3/cluster/app-tunnel.yaml`, a Python
  static server on `127.0.0.1:18080` with `index.html` and a 10 MB random
  file. Both apps have the spike label.
- User `s4user` with role `s4-apps`.
- `appsessmint` from the core branch `julia/sallyport/auth-callout`. It
  calls `CreateAppSession` as the user, then `GetAppSession` with the hub
  proxy identity, because the first response has no private key. This is
  the same pair of calls the Go proxy makes, without a passkey.

```
cd .local
python3 -m http.server 18080 --bind 127.0.0.1 --directory bench
tctl --config=auth.yaml create -f spikes/s4/role.yaml
tctl --config=auth.yaml users add s4user --roles=s4-apps --ttl=48h
tctl --config=auth.yaml auth sign --user=s4user --format=tls --out=s4user --ttl=8h
appsessmint -user-identity s4user -proxy-identity hub-identity \
  -user s4user -app bench -public-addr bench-julia.example.com -cluster sallyport \
  -out s4-appsession
```

`hub/.dev.vars` gets `S4_APP_CERT` and `S4_APP_KEY` (base64 of
`app.crt` and `app.key`) and `DEV_S4=1`. `/spike/s4?path=<path>` then sends
one `GET` through the tunnel and returns the status and the timing. The
endpoint is off without `DEV_S4`.

## Result, 2026-09-24: pass

```
$ curl https://localhost:8787/spike/s4?path=/
{"body_bytes":28,"dial_ms":1,"mb_per_s":0.0,"status":"HTTP/1.1 200 OK","tls_ms":5,"transfer_ms":7}
$ curl https://localhost:8787/spike/s4?path=/10mb.bin
{"body_bytes":10485760,"dial_ms":1,"mb_per_s":22.88,"status":"HTTP/1.1 200 OK","tls_ms":2,"transfer_ms":437}
```

- **`GET /` returns 200** with the bench page.
- **10 MB at 22.7 to 23.0 MB/s** over four runs, against a floor of
  1 MB/s. The bytes cross the agent's TLS, SSH and the app TLS inside the
  Durable Object.
- **No CPU-limit line** in the hub log. `wrangler dev` may not enforce the
  Workers CPU limit, so this does not show the edge limit is met. Phase 4
  measures it on the edge.
- **Size:** 2.1 MB raw, 720 KB gzipped, against the 10 MB budget.
- **The dial and the TLS handshake** take 1 ms and 2 to 5 ms.

The kill condition in the plan does not apply. Item (c), SSH without the
agent's inner TLS, is not needed for throughput.

## Not measured

- **The body is read inside the Durable Object** and dropped. Streaming it
  on to a browser adds the Worker response path, which Phase 4 measures.
- **OctoPrint.** `GET /` on `octo.local` answers 302 to its login page, so
  the 200 check used the bench app.
- **Failure signals** from the plan (bad dial request, wrong SNI, no
  session ID) were not provoked.
