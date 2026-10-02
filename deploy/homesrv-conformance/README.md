# Nightly conformance on homesrv

`nightly.sh` runs the conformance suite against the Go and Rust hubs from
the latest `main`, under `wrangler dev` on homesrv, where the Mac's sleep
cannot cut a run. `sallyport-conformance.timer` starts it at 02:00.

Each run writes `~/sallyport-conformance/<date>/`:

- `summary.txt`: the commit, the minutes, and pass, fail and skip per hub,
  with each failing test.
- `log.txt`: the build and test output.
- `go.json` and `rust.json`: the `go test -json` output.

## Install

The suite needs, on homesrv and without sudo:

- Go from `~/.local/go`, with `GOTOOLCHAIN=auto` to fetch the version in
  `go.mod`
- rustup with the `wasm32-unknown-unknown` target, and `worker-build`
  0.8.6 from `cargo install`
- node in `~/.local/node`, for `npx wrangler@4`
- `clang` and `llvm-ar` for the Rust hub, from `sudo apt install clang
  llvm`. Without them only the Go hub is tested.
- a clone of the repo at `~/sallyport-conformance/repo` that can fetch
  `main`

```
mkdir -p ~/sallyport-conformance/bin
cp nightly.sh ~/sallyport-conformance/bin/
cp sallyport-conformance.service sallyport-conformance.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now sallyport-conformance.timer
```

To run once by hand: `systemctl --user start sallyport-conformance.service`.

The timer stays disabled during a measurement run of the clusters, because
the suite adds about 45 minutes of load next to them.
