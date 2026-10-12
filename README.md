# <img src="logo.svg" alt="" height="32"> sallyport

A Teleport proxy in Go, compiled to WebAssembly, running on Cloudflare
Workers with one Durable Object as the stateful hub. It fronts a Teleport
auth and app service that run on a home server with no inbound ports. The
first app is OctoPrint.

A sallyport is a fortified entry with two gates where only one opens at
a time.

## Status

The hub serves two clusters on the home server `homesrv`: `julia.example.com`
on a paid Workers plan, and `julia.example.net` on the free plan. Users
log in with passkeys and open the apps from the dashboard. The hub
forwards an app's WebSockets, which OctoPrint's web UI uses, and streams
a long-held response to the browser as the app sends it.

## Layout

- `hub/go/` - the Worker and the Durable Object in Go (js/wasm).
- `conformance/` - a black-box suite that runs against the hub under
  `wrangler dev`.
- `deploy/` - the configs and systemd units for homesrv, the probe, the live
  deploy notes and the web route security review.

The spikes S1 to S5 and their results were removed after the tag
`spikes-final`.

## Home side

Each cluster is one process of a Teleport fork that runs auth and the app
service. The fork adds an on-demand callout: auth dials out to the hub
when a user needs it, so nothing on the home server listens on the
internet. See `deploy/README.md`.

## Rust and Go

The project started with two hubs, one in Rust and one in Go, and settled
on Go. The Rust hub is on the branch
[`with-rust`](https://github.com/juliaogris/sallyport/tree/with-rust).

The Rust hub used `workers-rs` compiled to wasm. It had about 7,900 lines
of Rust, with its inline tests, and about 160 lines of JavaScript. It
needed patched copies of `russh` and `ssh-key`, about 31,000 lines. The
Go hub is Go compiled to js/wasm, with about 4,700 lines of Go and about
860 lines of JavaScript in `worker.mjs`.

Both hubs passed the same conformance suite: 246 pass, 0 fail and 2 skip.
Then both ran for 7 days on homesrv, with a probe every minute. The numbers
are from the last 139.5 hours, after the last fix to a Rust crash. In that
crash, `h2` 0.4.19 called `Instant::now` when a stream was reset, which
panics on wasm32.

| | Rust | Go |
|---|---|---|
| Complete 10 MB downloads | 95.4% | 100% |
| 10 MB download, median | 1.90 s | 1.80 s |
| Small request, median | 164 ms | 76 ms |
| Time to first byte, median | 182 ms | 96 ms |
| 8 parallel 1 MB downloads, free plan | about 50% | about 100% |

Go was more reliable, with no short downloads, and it was faster for
small requests. Its code is smaller, with no patched libraries to keep.
The short Rust downloads remained after several fixes.

## License

sallyport is licensed under the GNU Affero General Public License v3.0 or
later, the license of Teleport, which it adapts. See `LICENSE`.
