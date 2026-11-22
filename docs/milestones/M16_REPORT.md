# M16 — Browser refresh-cookie flow (backend auth change)

Status: complete, pending owner approval. Date: 2026-11-19.
ADR: [0019-browser-refresh-cookie-flow.md](../adr/0019-browser-refresh-cookie-flow.md)

## Scope

The owner approved the plan to add an HttpOnly refresh cookie + in-memory access
token model so the Stage 2 frontend never exposes the refresh token to
JavaScript. This was implemented as an additive, backward-compatible backend
change with no database migration. The header/body API contract is unchanged by
default, so the full suite stays green.

## What changed (6 files)

**Modified**
- `app/core/config.py` — seven settings (`auth_refresh_cookie_enabled`,
  `auth_refresh_in_response_body`, `auth_cookie_secure`, `auth_cookie_samesite`,
  `auth_cookie_domain`, `auth_refresh_cookie_name`, `auth_csrf_cookie_name`) and a
  fail-closed guard: Secure cookies are required when the feature is on in
  staging/production.
- `app/schemas/auth.py` — `RefreshRequest.refresh_token` is now optional, so a
  browser can refresh with no body and present the cookie instead.
- `app/api/auth.py` — login and refresh set the HttpOnly refresh cookie + readable
  CSRF cookie; refresh reads body-or-cookie (body wins) and enforces double-submit
  CSRF only on the cookie path; logout clears both cookies.

**New**
- `app/api/auth_cookies.py` — cookie set/clear/read helpers and the stateless
  double-submit CSRF check (`require_csrf`), all pure transport, no DB state.
- `tests/test_auth_refresh_cookie.py` — 10 offline tests: cookie attributes
  (HttpOnly/Secure/SameSite=strict/Path), cookie refresh with CSRF, missing/wrong
  CSRF → 403, body precedence skips CSRF, no-token → generic 401, cookie rotation,
  logout clears cookies, feature-disabled sets no cookies, body-token suppression.
- `tests/test_security_config.py` — 2 tests for the Secure fail-closed guard
  (rejected when enabled + insecure; allowed when feature disabled).

## Security properties

- Refresh token is HttpOnly + Secure + SameSite=strict, scoped to `/api/v1/auth`;
  XSS cannot read it and it is only ever sent to the three auth endpoints.
- Access token stays in the body for the SPA to hold in memory (never in storage).
- The one cookie-bearing CSRF surface (cookie refresh) is guarded by double-submit;
  the rest of the API keeps its header-bearer CSRF immunity. Logout is CSRF-safe
  via its required Bearer token.
- `AUTH_REFRESH_IN_RESPONSE_BODY=false` lets a browser deployment drop the refresh
  token from the body entirely, so JavaScript never receives it.

## Tests

- Full suite: **1699 passed, 11 skipped** (was 1687; +12 new tests). The 11 skips
  are the unchanged opt-in/Windows/PostgreSQL skips. Run under `APP_ENV=test`.
- No existing test was modified except the additive `test_security_config.py` cases.

## Backup & diff

- Current-state backup: `AI_Security_Analyst_backups/auth_cookie_20261119_202546/current/`.
- Note: the intended pre-change backup was silently skipped by a shell glob error;
  the exact pre-change baseline was reconstructed by reverse-applying this session's
  edits, and the change diff (6 files only) is at `docs/milestones/M16_backup_diff.patch`.

## Correction (2026-11-20, from live frontend testing)

A live browser test of the cookie flow caught a path bug: the readable `aisa_csrf`
cookie had been scoped to `Path=/api/v1/auth`, so a single-page app served at `/`
could not read it to echo in the `X-CSRF-Token` header, and silent refresh on page
reload failed (redirect to login). Fixed by scoping the CSRF cookie to `Path=/`
(`CSRF_COOKIE_PATH` in `app/api/auth_cookies.py`); the HttpOnly `aisa_refresh`
cookie stays `Path=/api/v1/auth`. The CSRF cookie carries no secret, so a site-wide
path is safe. Test updated; auth suite green (165 passed in the affected subset).

## Not done / follow-ups

- No commit/push (no git repo), per standing instruction.
- Frontend Stage 2 (consume the cookie: in-memory access token, silent refresh on
  load/expiry, `X-CSRF-Token` echo, logout) is the next step, pending approval.
- Live browser end-to-end verification against a running backend is not part of the
  offline suite.
