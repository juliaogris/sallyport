# sallyport

A Teleport proxy in Rust, compiled to WebAssembly, running on Cloudflare
Workers with one Durable Object as the stateful hub. It fronts a Teleport
auth and app service that sit on a Raspberry Pi at home with no inbound
ports. The first app is OctoPrint.

A sallyport is a fortified entry with two gates where only one opens at
a time.

## Status

Feasibility and planning. No code yet. Spikes S0 to S5 come first.

## Layout

- `hub/` - the Worker and the Durable Object (Rust, `workers-rs`).
- `authtun/` - Phase 0 scaffold: the auth pipe as a standalone Go
  program, retired once auth dial-out lands in Teleport.
- `mint/` - one-shot Go tool that joins the hub as a proxy and writes its
  identity files.
- `spikes/` - one directory per spike with its result.

## Pi side

Stock Teleport v18.10.0 app service. Auth built from a Teleport branch
that adds auth dial-out (`tunnel_to`), so that auth opens the pipe to the
hub itself.
