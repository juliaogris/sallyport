# Web route security review, 2026-09-24

Reviewer: Claude (Opus 5.5), reading `hub/src/web.rs` and
`hub/src/appproxy.rs` at `54981b3`. No live attacks were run. Findings and
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
| L1 | Low | Login CSRF on app hosts: a link to `https://<app>-julia.example.com/x-teleport-auth#<sid>.<bearer>` with the attacker's own app session signs the victim in as the attacker, because the page posts the fragment from the right origin. Teleport binds the handoff to a state cookie set at launch. | Set a random state cookie on the login host at launch and require it back through the handoff | open |
| L2 | Low | The handoff page accepted a start path of `/\evil.example`, which browsers read as `//evil.example`, an open redirect. Reachable through L1. | Also reject a backslash in the start path | fixed in `HANDOFF_PAGE` |
| L3 | Low | An app response could send `Set-Cookie: __Host-sp_app=...` and replace or clear the hub's session cookies. | Drop upstream `Set-Cookie` headers for `__Host-sp_*` names | fixed in `appproxy.rs` |
| L4 | Low | Any request with junk app cookies makes one `GetAppSession` call to auth, so auth load follows request rate. | Same rate limit rule as M2, on app hosts | open |
| I1 | Info | Headers named in a `Connection` header are forwarded; RFC 9110 says they are hop-by-hop too. Not checked: whether the app service overwrites a browser's `X-Forwarded-*` and `Teleport-Jwt-Assertion` headers. | Also drop the headers `Connection` names | open |
| I2 | Info | `GET /teleport-logout` on an app host clears the app cookies with no origin check, so any page can log a user out of an app. | None needed for now | accepted |
