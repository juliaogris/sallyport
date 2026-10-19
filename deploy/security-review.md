# Web route security review, 2026-09-24

This review read the Rust hub, which is on the `with-rust` branch. The Go
hub has the same web routes and the same fixes, but the open items were
not checked against it again.

Reviewer: Claude (Opus 5.5), reading `rust/hub/src/web.rs` and
`rust/hub/src/appproxy.rs` at `54981b3`. No live attacks were run. Findings and
fix status below.

## Correctly enforced

- Cookies are `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`
  and `Path=/`, so they are host-only and no sibling host can set them.
- Every `POST` on the login host needs `Origin` equal to the login host.
  The handoff `POST` on an app host needs `Origin` equal to that app host.
- Every app host request asks auth with `GetAppSession`, and any error
  denies. The subject cookie is compared with the session's bearer token
  with `ct_eq`, which leaks only the length.
- The bearer token travels in the URL fragment, which the browser never
  sends to a server. The handoff page removes it from history with
  `replaceState`, and both the redirect and the page set
  `no-referrer`.
- The hub's own `__Host-sp_*` cookies are stripped from the `Cookie`
  header before a request goes to the app service.
- Requests with no app cookies are redirected to login without a call to
  auth.
- The login host serves only its own paths, and `/x-teleport-dbsc` is
  refused.

## Findings

| ID | Severity | Finding | Fix | Status |
|---|---|---|---|---|
| M1 | Medium | Every `<app>-<owner>.example.com` is the same site, and so will be other users' hosts such as `alice.example.com`. `SameSite=Lax` sends the app cookies on a `POST` from a sibling host, and non-GET requests to app hosts were forwarded with no origin check. A sibling page can also set a `Domain=example.com` cookie that defeats an app's double-submit CSRF token, such as OctoPrint's. | Refuse non-GET, non-HEAD, non-OPTIONS requests on app hosts when `Sec-Fetch-Site` is not `same-origin`, or, without that header, when `Origin` is not the app host | fixed in `web.rs`, `same_origin_fetch` |
| M2 | Medium | Unauthenticated `POST /webapi/login/finish` takes one auth pipe stream each. A script that sets `Origin` can empty the pool of 8 and block every login, launch and app request until auth opens new streams. `/webapi/login/begin` and `/webapi/invite/*` reach auth the same way. | Cloudflare rate limit rule on `/webapi/*` per IP; consider sending `AuthenticateWebUser` over the shared `HubAuth` connection instead of a fresh stream | open |
| L1 | Low | Login CSRF on app hosts: a link to `https://<app>-<owner>.example.com/x-teleport-auth#<sid>.<bearer>` with the attacker's own app session signs the victim in as the attacker, because the page posts the fragment from the right origin. Teleport binds the handoff to a state cookie set at launch. | The app host sets a random state cookie before it sends the browser to the launch, and the handoff takes only the state of that cookie, as in Teleport. A cookie on the login host would never reach the app host. | fixed |
| L2 | Low | The handoff page accepted a start path of `/\evil.example`, which browsers read as `//evil.example`, an open redirect. Reachable through L1. | Also reject a backslash in the start path | fixed in `HANDOFF_PAGE` |
| L3 | Low | An app response could send `Set-Cookie: __Host-sp_app=...` and replace or clear the hub's session cookies. | Drop upstream `Set-Cookie` headers for `__Host-sp_*` names | fixed in `appproxy.rs` |
| L4 | Low | Any request with junk app cookies makes one `GetAppSession` call to auth, so auth load follows request rate. | Same rate limit rule as M2, on app hosts | open |
| I1 | Info | Headers named in a `Connection` header are forwarded; RFC 9110 says they are hop-by-hop too. Not checked: whether the app service overwrites a browser's `X-Forwarded-*` and `Teleport-Jwt-Assertion` headers. | Also drop the headers `Connection` names | open |
| I2 | Info | `GET /teleport-logout` on an app host clears the app cookies with no origin check, so any page can log a user out of an app. | None needed for now | accepted |

## Addendum, 2026-10-16: apps under the login host

An app in `SUB_APPS` is served at `<app>.<owner>.example.com`, under the
login host, so that a web UI there can log in with a passkey. This review
read the Go hub.

| ID | Severity | Finding | Fix | Status |
|---|---|---|---|---|
| S1 | High | A page on a `SUB_APPS` host can ask for a passkey answer for the login host, because the WebAuthn relying party ID is a suffix of its host. A server can post that answer to `/webapi/login/finish` or the passkey routes with any `Origin`, and auth accepts an answer from a page on any host under the relying party ID. One passkey tap gives the page's author a hub web session, and a second one can add their own passkey. | Before the hub sends an answer to auth, require its `clientDataJSON` to have the expected `type`, `origin` equal to the login host, and no `crossOrigin` | fixed in `request.go`, `checkClientData` |
| S2 | Low | The hub's pages could be framed by any page, such as one on a `SUB_APPS` host, which could put the hub's buttons and passkey prompts under its own. | Send `frame-ancestors 'none'` and `X-Frame-Options: DENY` with every hub page | fixed in `request.go`, `html` |
| S3 | Low | The Worker and the Go hub read `SUB_APPS` differently: the Worker kept an empty name and names that are not app names, so it sent hosts such as `.<owner>.example.com` to the Durable Object. | Drop the same names in the Worker as in Go | fixed in `worker.mjs`, `subApps` |
| S4 | Info | A page on a `SUB_APPS` host can still use the user's passkeys with its own upstream, which is what the Teleport web UI needs. A cookie it sets with `Domain=<owner>.example.com` reaches the login host and the other app hosts, as one with `Domain=example.com` from any app host already did (M1). | List only apps whose pages are trusted with passkey prompts | accepted |
| S5 | Info | With an app in `WEB_UI_APPS`, the handoff sets the Teleport web UI's `__Host-session` cookie to the user's hub web session, a full Teleport login. Only an app in both `SUB_APPS` and `WEB_UI_APPS` gets it, only within 60 s of its launch, once, and only after the launch state and app session checks pass. After the UI renews its session, hub logout does not end the renewed session, and a launch after that overwrites it, so it stays valid until it expires. | Accepted. The UI's own logout ends its session | accepted |
