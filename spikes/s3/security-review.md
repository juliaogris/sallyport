# S3 security review, 2026-09-24

Reviewer: security-auditor agent (Opus 5.5), read-only, on sallyport at
7e11164 plus the discovery-loop change. Findings and fix status below.

## Correctly enforced

- Nothing before auth: channel opens, channel requests, global requests
  and the passthrough are unreachable until `auth_openssh_certificate`
  accepts (`vendor/russh/src/server/encrypted.rs:135`).
- russh checks the cert validity window, its own signature and proof of
  possession before the handler; `signature_key() == host_ca.key_data()`
  is then sufficient.
- User certs, plain keys, password, none and keyboard-interactive are
  rejected. Authority must equal the cluster. Roles App and Instance only,
  so the hub's own Proxy identity is rejected.
- Heartbeat is App-only; only `@remote-auth-server` dials are served.
- Host certificate presentation matches cert to key and signs with the
  matching private key.
- The ssh-key `u64::MAX` change does not weaken validity checks.

## Findings

| ID | Severity | Finding | Fix |
|---|---|---|---|
| H1 | High | No pre-auth deadline, no connection cap; `inactivity_timeout: None` also disables the SSH id read timeout; `auth_rejection_time: 0` | 30 s deadline over TLS accept plus SSH auth; cap connections per DO; non-zero rejection time; drop after repeated auth failures |
| H2 | High | SSH user not checked against `valid_principals`; empty principals means any | Reject unless principals contain the user; reject empty principals |
| M1 | Medium | Undialed transport channels leak and can stall the session loop | Cap transports per connection; remove on close and after a dial deadline |
| M2 | Medium | Passthrough sockets unbounded; Instance is held by every agent type | Cap passthroughs per connection and in total |
| M3 | Medium | `AUTH_HOST`/`AUTH_PORT` silent port fallback; relay risk if shipped | Fail on bad port; passthrough only with `DEV_PASSTHROUGH=1`; replace with the callout before deploy |
| L1 | Low | ssh-key accepts any value above `i64::MAX`; upstream test fails | Accept only `u64::MAX`; update test |
| L2 | Low | Per-frame logging controllable by unauthenticated clients | Remove per-frame logs |
| L3 | Low | One pinned host CA key; fails during CA rotation | Accept a CA list (functional, not security) |
| L4 | Low | Unknown critical options not rejected | Reject non-empty critical options |
