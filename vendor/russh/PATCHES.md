# Patches to russh 0.54.5

This is russh 0.54.5 from crates.io, patched so that its SSH server runs on
`wasm32-unknown-unknown` in a Cloudflare Durable Object and can speak
Teleport's reverse tunnel protocol. The crate name and version are unchanged
so that `[patch.crates-io]` can point at this directory.

## Packaging

- `Cargo.toml`: Removed the cargo-generated header, the example and bench
  targets, and the dev-dependencies that only the examples used (`clap`,
  `ratatui`, `shell-escape`, `termion`, `tokio-fd`, `russh-sftp`).
- `Cargo.toml`: Added an empty `[workspace]` table so that `cargo test` works
  in this directory when the parent repository has its own workspace.
- `Cargo.toml`: Added the wasm-only dependencies `web-time`, `gloo-timers`
  (with `futures`) and `wasm-bindgen-futures`.
- `Cargo.toml`: Added the `teleport_hooks` test target.
- `examples/`, `benches/`: Removed.
- `LICENSE.txt`: Added from the upstream `v0.54.5` tag, because the published
  crate does not include it.
- `src/keys/mod.rs`: Marked the `load_public_key` doctest `no_run`, because
  it reads `../files/id_ed25519.pub`, which the published crate does not ship.

## Time shim

- `src/rt.rs`: New private module with `Instant`, `sleep`, `sleep_until`,
  `timeout`, `Elapsed` and `system_now`. On native targets these are tokio's
  and `std::time::SystemTime::now`. On `wasm32` they use `web_time` and a JS
  `setTimeout` timer that runs in a `spawn_local` task and signals over a
  `futures` oneshot, so the sleep future stays `Send`. `Sleep::reset` keeps
  one JS timer per sleep.
- `src/lib_inner.rs`: Declared `mod rt`. `Error::Elapsed` now wraps
  `crate::rt::Elapsed`, which is tokio's type on native targets.
- `src/server/session.rs`: The keepalive and inactivity timers use
  `crate::rt::sleep` and reset with `crate::rt::Instant`.
- `src/server/encrypted.rs`: Auth rejection deadlines use `crate::rt::Instant`
  and `crate::rt::sleep_until`.
- `src/server/encrypted.rs`: The certificate validity check uses
  `crate::rt::system_now` instead of `SystemTime::now`, which panics on
  `wasm32-unknown-unknown`.
- `src/server/mod.rs`: The SSH identification read timeout uses
  `crate::rt::timeout`.
- `src/keys/agent/server.rs`, `src/keys/agent/client.rs`: Replaced
  `tokio::time::sleep` with `crate::rt::sleep`.
- `src/session.rs`, `src/server/mod.rs`, `src/client/mod.rs`: `last_rekey`
  is a `crate::rt::Instant` instead of a `russh_util::time::Instant`, and
  the rekey check uses `saturating_duration_since`. On `wasm32`,
  `russh_util` reads the clock with `chrono::Utc::now`, and its
  `duration_since` panics with "Duration is negative" when the clock goes
  back. The Workers clock can go back between events. The panic trapped the
  hub's Wasm instance, which dropped every tunnel and auth pipe stream,
  several times an hour.

## Building the server on wasm

- `src/lib_inner.rs`: The `server` module is no longer gated off on `wasm32`.
- `src/server/mod.rs`: `Server::run_on_socket`, `Server::run_on_address` and
  the `tokio::net` import are gated off on `wasm32`. `run_stream` is the wasm
  entry point.
- `src/msg.rs`, `src/cert.rs`, `src/negotiation.rs`: Removed the
  `not(wasm32)` gates on server-only message constants,
  `PublicKeyOrCertificate::decode` and `server::Config`, and removed the
  wasm-only `Config` stub.

## Handler hooks

- `src/server/mod.rs`, `src/server/encrypted.rs`: New
  `Handler::channel_open_unknown(typ, channel, session)`. `true` confirms the
  channel and `false` sends the existing "unknown channel type" failure. The
  default returns `false`.
- `src/server/mod.rs`, `src/server/encrypted.rs`: New
  `Handler::channel_request_unknown(channel, typ, want_reply, data, session)`.
  `data` is the bytes after the want-reply byte. The reply is sent only if the
  client asked for one. The default returns `false`.
- `src/server/mod.rs`, `src/server/encrypted.rs`: New
  `Handler::global_request_unknown(typ, want_reply, data, session)`. The reply
  is sent only if the client asked for one. Before this patch, an unknown
  global request always got `SSH_MSG_REQUEST_FAILURE`. The default returns
  `false`.

## Server-initiated channels and requests

- `src/server/session.rs`: New `Handle::channel_open_custom(typ, extra)` and
  `Session::channel_open_custom(typ, extra)` that open a channel of any type.
  New `Msg::ChannelOpenCustom` variant.
- `src/server/session.rs`: New `Channel<server::Msg>::request_custom(typ,
  want_reply, data)` and `Session::channel_request_custom`. With
  `want_reply`, it waits for the reply and returns `true` or `false`. New
  `Msg::ChannelRequestCustom` variant and `Session::pending_channel_requests`
  queue.
- `src/server/encrypted.rs`: The server now handles incoming
  `SSH_MSG_CHANNEL_SUCCESS` and `SSH_MSG_CHANNEL_FAILURE` by answering the
  oldest pending request on that channel. Pending requests are dropped when
  the channel closes.

## Host certificates

- `src/server/mod.rs`: New `Config::host_certificates`, matched to `keys` by
  public key. The default is empty, which keeps the old behavior.
- `src/negotiation.rs`: New `Names::key_is_cert`. When a host key has a
  certificate, the server advertises the `*-cert-v01@openssh.com` name right
  before the plain name, and `read_kex` records which of the two the client
  chose. `read_kex` and `possible_host_key_algos_for_keys` now take the
  server `Config` instead of the key list.
- `src/server/kex.rs`: When the certificate algorithm is chosen, the
  certificate is used as the host key blob in both the exchange hash and the
  `KEX_ECDH_REPLY` or `KEX_DH_GEX_REPLY` packet. The signature is still made
  by the underlying private key.

## Tests

- `tests/teleport_hooks.rs`, `tests/goclient/`: Tests for the hooks, the
  server-initiated channel and host certificates, driven by a Go client on golang.org/x/crypto/ssh,
  because the russh client cannot open unknown channel types, send arbitrary
  requests or answer custom channel requests.

- **ssh-key `UnixTime`** (`vendor/ssh-key/src/certificate/unix_time.rs`): accept `valid_before = u64::MAX`, which OpenSSH and Teleport use for "forever". The raw value is kept so a re-encoded certificate keeps its CA signature; only the `SystemTime` view saturates.

- **`base64ct` requirement** (`Cargo.toml`): `~1.6` relaxed to `1.6`, so the lockfile can use 1.8.3. `base64ct` 1.6.0 rejects some valid OpenSSH private keys with `InvalidLength`, depending on the key's encoded length. A hub identity minted for `julia.example.com` hit it; 1.8.3 parses the same key.

- **Slow channel readers** (`src/server/encrypted.rs`): incoming channel data is queued with `try_send` instead of `send().await`. russh adjusts the window when data arrives, not when it is read, so a reader that stopped reading blocked the session loop and every other channel on the connection. On 2026-09-24 this stalled the live hub: discovery and auth passthroughs stopped while octocam MJPEG streams were open. A full queue now closes that one channel; its reader sees end of stream after draining what is queued. `tests/test_backpressure.rs` is rewritten to test this, because upstream's version asserted the old connection-wide blocking.

- **Window adjust and EOF sends** (`src/server/encrypted.rs`): `ChannelMsg::WindowAdjusted` is queued with `try_send` and dropped when the queue is full, because `window_size().update` already wakes writers and the message only informs the reader. Upstream's blocking send froze the whole connection when a channel was written but never read, after the queue filled with window adjusts; a go-do spike run stopped at 27.75 of 32 MiB this way. `ChannelMsg::Eof` also uses `try_send`, and a full queue closes the channel as for data. `tests/test_backpressure.rs` has `unread_writer_channel_does_not_stall`, which fails on the old code.

- **Messages during a rekey** (`src/server/session.rs`, `src/server/encrypted.rs`, `src/session.rs`): the server no longer sends channel data or any other non-kex message between its `KEXINIT` and the end of the key exchange. RFC 4253 section 7.1 does not allow them, and the Go client drops the connection with "unexpected message type 94 (expected one of [31])". russh rekeys after every 1 GiB it writes, and a go-do spike run with 8 downloads dropped this way at 2 GiB every time. Upstream only stopped taking new messages from `Handle` during a key exchange. A `CHANNEL_WINDOW_ADJUST` from the client still flushed the channel's queued data, a `CHANNEL_DATA` still sent a window adjust back, and handler replies and keepalives went out too. `Session::flush` now keeps everything in `enc.write` while a key exchange is active, except after a disconnect. `Session::flush_pending` does nothing during a key exchange, because the exchange ends with `flush_all_pending`. `Encrypted::data` and `extended_data` queue during a key exchange even when the queue is empty, where upstream's `&&` wrote the data out. `flush_all_pending` now sends a pending EOF or close, which it dropped before, and a flushed queue clears its pending EOF so that later flushes do not send it again. The client side has the same window adjust path but is not patched, because the hub only runs the server. `tests/test_rekey_channel_data.rs` echoes 2 MiB both ways on 8 channels through a Go client with a 128 KiB rekey limit, about 126 rekeys, and fails on the old code.
