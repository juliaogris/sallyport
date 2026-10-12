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
log in with passkeys and open the apps from the dashboard. The hub does
not forward WebSockets yet, so OctoPrint's web UI cannot connect. The
webcam and OctoPrint's API work.

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

## License

sallyport is licensed under the GNU Affero General Public License v3.0 or
later, the license of Teleport, which it adapts. See `LICENSE`.
