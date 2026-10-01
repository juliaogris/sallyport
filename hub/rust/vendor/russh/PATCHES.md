# Patches to russh 0.54.5

This is russh 0.54.5 from crates.io, patched so that its SSH server runs on
`wasm32-unknown-unknown` in a Cloudflare Durable Object and can speak
Teleport's reverse tunnel protocol. The crate name and version are unchanged
so that `[patch.crates-io]` can point at this directory. The last section
lists the changes to the vendored ssh-key crate in `../ssh-key`.

## Packaging

- `Cargo.toml`: Removed the cargo-generated header, the example and bench
  targets, the `autoexamples = false` and `autobenches = false` settings,
  and the dev-dependencies that only the examples used (`clap`, `ratatui`,
  `shell-escape`, `termion`, `tokio-fd`, `russh-sftp`).
- `Cargo.toml`: Added an empty `[workspace]` table so that `cargo test` works
  in this directory when the parent repository has its own workspace.
- `Cargo.toml`: Added the wasm-only dependencies `web-time`, `gloo-timers`
  (with `futures`) and `wasm-bindgen-futures`.
- `Cargo.toml`: Added the `teleport_hooks` and `test_rekey_channel_data`
  test targets.
- `Cargo.toml`: Relaxed the `base64ct` requirement from `~1.6` to `1.6`, so
  the lockfile can use 1.8.3. `base64ct` 1.6.0 rejects some valid OpenSSH
  private keys with `InvalidLength`, depending on the key's encoded length.
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
  one JS timer per sleep. The timer delay is at most `i32::MAX` ms, because
  gloo-timers passes it to JS as an `i32` and a negative delay fires at
  once. A longer sleep re-arms when the timer fires.
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
  hub's Wasm instance, which dropped every tunnel and auth pipe stream.

## Building the server on wasm

- `src/lib_inner.rs`: The `server` module is no longer gated off on `wasm32`.
- `src/server/mod.rs`: `Server::run_on_socket`, `Server::run_on_address` and
  the `tokio::net` import are gated off on `wasm32`. `run_stream` is the wasm
  entry point. Two imports that only those functions use have
  `#[cfg_attr(target_arch = "wasm32", allow(unused_imports))]`.
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
  client asked for one. The default returns `false`. The "unknown channel
  request" log line is `debug!` instead of `warn!`, because the hub gets
  one for every heartbeat ping.
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
  the peer closes the channel or when `Session::close` closes it, and
  `request_custom` then returns `Error::Disconnect`.
- `src/session.rs`, `src/server/encrypted.rs`: New
  `CommonSession::is_established_channel`, from upstream v0.63.3. The
  `CHANNEL_CLOSE`, `CHANNEL_EOF`, `CHANNEL_DATA`, `CHANNEL_EXTENDED_DATA`,
  `CHANNEL_WINDOW_ADJUST` and `CHANNEL_REQUEST` arms ignore a message for a
  channel that the peer has not confirmed. Without this, a peer that
  answers the server's `CHANNEL_OPEN` with a `CHANNEL_REQUEST` reaches
  `assert!(channel.confirmed)` in `Session::channel_failure`. The other
  arms also ignore a message for a channel this side has already closed.
- `src/session.rs`, `src/server/encrypted.rs`: New
  `CommonSession::is_unconfirmed_channel`. The `CHANNEL_CLOSE` arm uses it
  instead of `is_established_channel`, so it ignores a close only for a
  channel this side opened and the peer has not confirmed. When this side
  closes first, the peer's close is the reply, and it still reaches
  `Handler::channel_close`. Upstream v0.63.3 drops that reply, so a handler
  that frees state in `channel_close` never frees it for channels the
  server closed.
- `src/server/encrypted.rs`: A `CHANNEL_OPEN_CONFIRMATION` or
  `CHANNEL_OPEN_FAILURE` for a channel that is already confirmed ends the
  connection with `Error::Inconsistent`, as x/crypto does.
- `src/server/encrypted.rs`: A `CHANNEL_OPEN_CONFIRMATION` for a channel
  whose opener stopped waiting, for example at a deadline, closes the
  channel. Upstream ignores the failed send, and the channel stays open
  until the connection ends.

## Incoming channel data

- `src/server/encrypted.rs`: `CHANNEL_DATA` and `CHANNEL_EXTENDED_DATA`
  longer than the channel's advertised maximum packet size end the
  connection with `Error::PacketSize`. Data longer than the channel's
  remaining window ends it with `Error::Inconsistent`. Go's x/crypto does
  the same. Before this, russh ignored data past the window and checked no
  length except the 256 KiB transport packet limit, so a channel queue of
  256 messages could hold about 64 MiB. It now holds at most
  `channel_buffer_size * maximum_packet_size` bytes when the maximum packet
  size is a power of two. `CryptoVec` rounds each message's capacity up to
  a power of two, so another size can take up to about twice that.
- `src/server/encrypted.rs`: `CHANNEL_DATA`, `CHANNEL_EXTENDED_DATA` and
  `CHANNEL_EOF` are queued on the channel with `try_send` instead of
  `send().await`. russh adjusts the window when data arrives, not when it is
  read, so a reader that stopped reading blocked the session loop and every
  other channel on the connection. A full queue now closes that one channel.
  Its reader gets what is queued, and then `wait` returns `None` and the
  `AsyncRead` readers (`make_reader`, `into_stream`) return an error, so a
  reader does not take the lost data for a clean end of stream.
- `src/channels/channel_ref.rs`, `src/channels/mod.rs`,
  `src/channels/io/rx.rs`, `src/server/session.rs`, `src/client/mod.rs`:
  `ChannelRef` and `ChannelReadHalf` share a `reader_too_slow` flag, which
  the server sets before it closes a slow channel.
- `src/server/encrypted.rs`: `ChannelMsg::WindowAdjusted` is queued with
  `try_send` and dropped when the queue is full, because
  `window_size().update` already wakes writers and the message only informs
  the reader. Upstream's blocking send froze the whole connection when a
  channel was written but never read, after the queue filled with window
  adjusts.

## Messages during a rekey

RFC 4253 section 7.1 allows only key exchange messages between `KEXINIT`
and `NEWKEYS`, and the Go client drops the connection with "unexpected
message type 94 (expected one of [31])". russh rekeys after every 1 GiB it
writes. Upstream only stopped taking new messages from `Handle` during a
key exchange. A `CHANNEL_WINDOW_ADJUST` from the client still flushed the
channel's queued data, a `CHANNEL_DATA` still sent a window adjust back,
and handler replies and keepalives went out too.

- `src/server/session.rs`, `src/server/mod.rs`: `Session::flush` keeps
  everything in `enc.write` while a key exchange is active, except after a
  disconnect. If `enc.write` passes the new `Config::max_write_during_kex`,
  4 MiB by default, during a key exchange, `flush` ends the connection with
  `Error::Kex`, because a peer that never finishes the exchange could
  otherwise grow it without limit with requests that want a reply.
- `src/server/session.rs`: `Session::flush_pending` does nothing during a
  key exchange, because the exchange ends with `flush_all_pending`.
- `src/session.rs`: `Encrypted::data` and `extended_data` queue during a key
  exchange even when the queue is empty, where upstream's `&&` wrote the
  data out.
- `src/session.rs`: `flush_all_pending` sends a pending EOF or close, which
  it dropped before, and a flushed queue clears its pending EOF so that
  later flushes do not send it again.
- The client side has the same window adjust path but is not patched,
  because the hub only runs the server.

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
  server-initiated channel and requests, the unconfirmed-channel checks,
  the close of a channel confirmed after its opener left, the packet size
  and window checks, the key exchange limit and host certificates. A Go
  client on golang.org/x/crypto/ssh drives them, because the russh client
  cannot open unknown channel types, send arbitrary requests or answer
  custom channel requests. The Go client sends
  out-of-order messages through x/crypto's unexported packet writers, which
  it reaches with `go:linkname`.
- `tests/test_backpressure.rs`: Rewritten for the slow reader close on data
  and on EOF and for `unread_writer_channel_does_not_stall`, because
  upstream's version asserted the old connection-wide blocking.
- `tests/test_rekey_channel_data.rs`: Echoes 2 MiB both ways on 8 channels
  through the Go client with a 128 KiB rekey limit, about 126 rekeys.
- `src/rt.rs`: A unit test for the wasm timer delay.

## ssh-key

- `Cargo.toml`: Added an empty `[workspace]` table so that `cargo test`
  works in that directory, as for russh.
- `src/certificate/unix_time.rs`: `UnixTime::new` accepts
  `valid_before = u64::MAX`, which OpenSSH and Teleport use for "forever".
  The raw value is kept so that a re-encoded certificate keeps its CA
  signature. Only the `SystemTime` value saturates. Two unit tests cover
  the raw value and the `SystemTime`.
