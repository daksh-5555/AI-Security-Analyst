# ADR-0019: Browser refresh-cookie flow (HttpOnly refresh + in-memory access token)

Status: accepted. Date: 2026-11-19.

## Context

The backend authenticates with `Authorization: Bearer` access tokens and returns
an opaque refresh token in the login/refresh JSON body; only the refresh token's
hash is persisted and it is rotated on every use. This is correct for API
clients, but the frontend (Stage 1 complete) needs a browser-safe story. Holding
the refresh token in `localStorage` or any JavaScript-readable store exposes it
to XSS exfiltration. The owner's direction for Stage 2: keep the access token in
memory only, and deliver the refresh token as an **HttpOnly, Secure, SameSite**
cookie that JavaScript can never read. The change had to be additive — the
existing header/body contract and the full test suite must stay intact — and
introduce no database migration.

## Decision

1. **Additive cookie delivery, body contract preserved.** On login and refresh,
   when `AUTH_REFRESH_COOKIE_ENABLED` is true (default), the rotated refresh token
   is also set as an HttpOnly cookie (`aisa_refresh`), scoped to `Path=/api/v1/auth`
   so it is only ever attached to the three auth endpoints that read it. The body
   still carries the refresh token by default (`AUTH_REFRESH_IN_RESPONSE_BODY`),
   which keeps every existing API client and test unchanged. A browser deployment
   sets that flag false so the refresh token is never placed where JavaScript can
   read it; the access token continues to travel in the body and is held in memory
   by the SPA.

2. **Refresh accepts the token from body or cookie; body wins.** `/auth/refresh`
   reads an explicit body token first and falls back to the cookie. The request
   body became optional (`RefreshRequest.refresh_token` is now nullable) so a
   browser can refresh with no body at all.

3. **CSRF only on the cookie path, via stateless double-submit.** The header/body
   API is immune to CSRF because a cross-site page cannot make the browser send a
   custom `Authorization` header. The one new CSRF surface is a cookie-sourced
   refresh. It is guarded by a double-submit check: a readable `aisa_csrf` cookie
   is set alongside the refresh cookie — scoped to `Path=/` (not the auth prefix),
   because a single-page app served at `/` must be able to read it (cookie reads
   honour path) to echo it, and it carries no secret, only the double-submit value.
   The client must echo its value in an
   `X-CSRF-Token` header; the server requires header and cookie to match
   (constant-time). A cross-site attacker can neither read the cookie (same-origin
   policy) nor set the custom header (no CORS permits it). A **body**-sourced
   refresh skips the check, because an attacker who cannot read the token cannot
   place it in the body — that path is not a CSRF vector. The check runs before
   any rotation work. Logout already requires the Bearer access token, so it is
   inherently CSRF-safe and only needs to clear the cookies.

4. **Secure required off localhost.** `AUTH_COOKIE_SECURE` defaults true and
   `validate_security_configuration` fails closed if the cookie feature is enabled
   with Secure off in staging/production. It may be set false only for a local
   same-origin http dev proxy, where a browser would otherwise refuse to return a
   Secure cookie. `AUTH_COOKIE_SAMESITE` defaults `strict`; `none` is not permitted.

5. **No persistence change.** Cookies are pure transport. The refresh token's hash
   remains the only server-side record and rotation/reuse-detection/session-family
   revocation are unchanged. No migration.

## Consequences

- The browser keeps the access token in memory and silently re-authenticates on
  load and on expiry via `POST /auth/refresh` (empty body, cookie + CSRF header),
  with no refresh token ever reachable by JavaScript.
- Two cookies are added to login/refresh responses when the feature is on. No
  existing test asserts cookie absence, and the body contract is unchanged, so the
  suite stays green by default.
- The CSRF defense is stateless (no server-side token store) and scoped to exactly
  one endpoint; the rest of the API surface keeps its header-bearer CSRF immunity.
- Alternatives rejected: refresh token in `localStorage` (XSS-exfiltratable);
  SameSite alone without double-submit (weaker, and Lax permits some cross-site
  POST contexts); a server-side CSRF token table (needless state for a
  double-submit-adequate, single-endpoint surface).
