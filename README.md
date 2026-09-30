# sallyport

A Teleport proxy in Rust, compiled to WebAssembly, running on Cloudflare
Workers with one Durable Object as the stateful hub. It fronts a Teleport
auth and app service that sit on a Raspberry Pi at home with no inbound
ports. The first app is OctoPrint.

A sallyport is a fortified entry with two gates where only one opens at
a time.

## Status

Feasibility and planning. No code yet. Spikes S1 to S5 come first, in that order.

## Layout

- `hub/rust/` - the Worker and the Durable Object in Rust (`workers-rs`),
  with the patched `russh` and `ssh-key` in `vendor/`.
- `hub/go/` - the same Worker and Durable Object in Go (js/wasm).
- `conformance/` - a black-box suite that runs the same tests against
  either hub.
- `deploy/` - the configs and systemd units for homesrv, the probe, the live
  deploy notes and the web route security review.
- `devtools/` - stand-ins for the agent and auth's callout, for testing a
  hub that the real agent and auth cannot reach.

The spikes S1 to S5 and their results were removed after the tag
`spikes-final`.

## Pi side

Stock Teleport v18.10.0 app service. Auth built from a Teleport branch
that adds auth dial-out (`callout_to`), so that auth opens the pipe to the
hub itself.

## License

sallyport is licensed under the GNU Affero General Public License v3.0 or
later, the license of Teleport, which it adapts. See `LICENSE`. The
vendored crates in `hub/rust/vendor/` keep their own licenses: `russh` is
Apache-2.0 and `ssh-key` is Apache-2.0 or MIT.
