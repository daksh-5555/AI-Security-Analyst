# ADR-0018: Authenticated local lab targets (DVWA)

Status: accepted (M15 / D14). Date: 2026-11-17.

## Context

Most of a deliberately-vulnerable lab such as DVWA sits behind a form login with
a per-session anti-CSRF token. The M5 crawler and M6 probes are GET-only and
unauthenticated, so they never reach that surface. D14 asks for a safe,
end-to-end DVWA assessment with hard constraints: isolated local lab only, no
unrestricted public scanning, all egress through the guarded client, and no
destructive probes, credential attacks, data extraction, or DoS.

The owner chose: build it now with an offline DVWA-like fixture plus an opt-in
integration test; store credentials behind a dedicated endpoint; and treat
"log in with known credentials" as in scope and "credential guessing/brute
force" as permanently out of scope.

## Decision

1. **Lab-credential login, not credential discovery.** A new service performs a
   single scripted login with operator-supplied *known* credentials: GET the
   login page, read the anti-CSRF token, POST the form once. There is no retry,
   no guessing, and no enumeration. The fixture asserts exactly one login
   attempt.
2. **Off by default, local only, forbidden in production.** `WEB_AUTH_LAB_ENABLED`
   gates the whole feature and is false by default; `validate_security_configuration`
   refuses to start with it enabled in staging/production. The target host must
   be a literal address inside the configured local test networks (loopback for
   DVWA); a hostname that cannot be proven local is refused.
3. **Store only the session cookie, never the password.** `POST
   .../web-target/lab-credentials` logs in and persists only the resulting
   session cookie (`web_target_lab_sessions`, migration 0022, one per
   assessment). The password is used once and discarded. The cookie is never
   returned by the API, logged, or placed in evidence or reports; `GET` reports
   only `configured`, `username`, and `login_path`; `DELETE` clears it. Both
   establish and clear are audited.
4. **Reuse the guarded client unchanged.** The login and the subsequent
   authenticated crawl/probe use the existing `build_target_client`, which is
   host-bound and SSRF-safe. The only new primitive is an optional
   `default_headers` on `GuardedHttpClient`, used to bind the lab cookie; it
   travels only to the single allowed host and is overridden by per-request
   headers. The probe engine stays GET-only and never receives credentials; its
   inert-marker and boolean-only rules are unchanged, so there is no destructive
   request, data extraction, or DoS.
5. **Offline tests plus an opt-in live test.** A loopback DVWA-like fixture
   (session cookie, per-session CSRF token, reflected-XSS page reachable only
   after login) covers login success/failure, the local-only and
   fail-closed guards, cookie non-exposure, and an authenticated run reaching a
   surface an anonymous run cannot. `tests/test_dvwa_integration.py` runs the
   full flow against a real DVWA only when `DVWA_URL` is set, mirroring the
   opt-in PostgreSQL tests; otherwise it skips.

## Consequences

- A genuine authenticated assessment of a local DVWA works end-to-end, within
  every stated constraint, with no new runtime dependency.
- The stored artifact is a lab session cookie, not a reusable password. It is
  still sensitive at rest; the feature is therefore dev/lab-only and
  production-forbidden, and the cookie is kept out of all outputs. This is the
  deliberate trade-off (documented for owner review) versus storing the password
  or adding an encryption dependency.
- Lab sessions expire; re-running `POST .../lab-credentials` re-establishes one.
- Inside a workflow, runtime probes against the authenticated surface still
  require the M10 human-approval gate.
- The feature never creates or authorizes a target: registration and
  owner-confirmed authorization (M4) are unchanged and still required first.
