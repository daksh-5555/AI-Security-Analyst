# M15 / D14 — Authenticated Local Lab Targets (DVWA)

Status: **complete, awaiting owner review.** Delivers D14: a safe, end-to-end
authenticated assessment of a local DVWA-style lab.

## Your three decisions, as built

- **Lab runtime: code + opt-in test now.** No install was needed. An offline
  DVWA-like loopback fixture covers the behaviour; `tests/test_dvwa_integration.py`
  runs the real end-to-end flow only when `DVWA_URL` is set (it skips otherwise,
  like the PostgreSQL tests). `docs/lab/dvwa.md` has the `docker run` recipe.
- **Separate `lab-credentials` endpoint.** Lab credentials never share a schema
  with routine target fields.
- **Login-only, no guessing.** Exactly one login attempt is made (asserted). No
  retry, enumeration, or brute force exists anywhere in the code.

## Safety-design decision for your review

The endpoint logs in once and **persists only the resulting session cookie; the
password is used once and never stored**, logged, returned, or placed in
evidence/reports. This avoids storing a reusable password and needs no
encryption dependency. The stored cookie is still sensitive, so the whole
feature is off by default and **forbidden in staging/production**. If you would
rather persist nothing and supply credentials per run, that is a small change.

## What was added

| Area | Files |
| --- | --- |
| Migration | `0022_create_web_target_lab_sessions.py`: one lab session per assessment; lab-session audit actions; downgrade guard |
| Model/schema | `app/models/web_target_lab_session.py`, `app/schemas/lab_credentials.py` |
| Login flow | `app/services/net/lab_session.py`: one scripted login (GET token → single POST), local-only guard, sanitized errors |
| Guarded client | optional `default_headers` on `GuardedHttpClient` (binds the lab cookie to the single allowed host); threaded through `build_target_client` |
| Service/API | `app/services/lab_credentials.py`; `app/api/lab_credentials.py` (POST/GET/DELETE); wired into `run_web_tools` |
| Settings | `WEB_AUTH_LAB_ENABLED` (default false; prod-forbidden) and the `WEB_AUTH_LAB_*` form-shape settings (DVWA defaults) |
| Tests | `tests/dvwa_fixtures.py`, `tests/test_lab_credentials.py` (10), `tests/test_migration_0022.py` (3), `tests/test_dvwa_integration.py` (opt-in, skipped) |
| Docs | ADR-0018, `docs/lab/dvwa.md`, README, `.env.example` |

No new dependency (stdlib `http.cookies` only). No API change beyond the new
endpoint; OpenAPI diff is additive (1 path, 2 schemas, 2 audit-action values).

## Constraints honoured

| Constraint | How |
| --- | --- |
| DVWA runs locally in an isolated lab | Target host must be a literal address in the configured local networks; loopback-bound `docker run` documented |
| No unrestricted public-target scanning | Feature off by default, local-only, forbidden outside development; registration + owner authorization (M4) still required |
| All HTTP via the guarded client | Login and authenticated crawl/probe use `build_target_client` only; the new cookie travels solely to the one allowed host |
| No destructive probes / credential attacks / data extraction / DoS | One login with known creds (no guessing); probes stay GET-only, inert-marker and boolean-only, unchanged |
| Preserve existing functionality and tests | Only migration head-pins bumped to `0022`; no assertion weakened |

## Tests (offline)

- Login stores only the cookie, never the password; audit context carries no
  secret; exactly one login attempt (`test_login_stores_only_the_cookie_never_the_password`).
- Wrong credentials establish nothing; disabled feature contacts nothing;
  delete clears; GET never exposes the cookie.
- **An authenticated run reaches a reflected-XSS page that an anonymous run
  cannot** (anonymous run finds nothing — every page redirects to login);
  the session cookie never appears in persisted findings
  (`test_authenticated_run_reaches_the_protected_surface`).
- Cookie/password never logged; non-local target refused; production
  configuration fails closed.

## Verification

| Check | Result |
| --- | --- |
| `pytest` full | **1687 passed, 0 failed, 11 skipped** (7 Windows-only, 3 PostgreSQL-only, 1 DVWA-only), 0 warnings |
| Lab-auth / migration tests | 10 + 3 passed; DVWA integration test skipped (no `DVWA_URL`) |
| Coverage | 89% overall; lab service 100%, login flow 85%, API 92% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0022`; no drift; round trip; downgrade guard |
| OpenAPI | additive (1 path, 2 schemas, 2 audit-action enum values) |
| Dependencies | unchanged (stdlib only) |

## Known gaps and risks

- The stored lab session cookie is sensitive at rest; mitigated by off-by-default
  + production-forbidden + never exposed. (Design decision above.)
- Lab sessions expire; re-POST to re-establish.
- Verified against the offline fixture; the real-DVWA path is covered by the
  opt-in test, which has not been run here (no lab provisioned).
- The authenticated surface is still assessed with the existing GET-only,
  non-destructive probes; POST-form and stored-XSS testing remain out of scope.
- Windows suite still not run.
