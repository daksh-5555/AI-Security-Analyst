# AI Security Analyst Backend — Final Project Release Report

| | |
| --- | --- |
| Date | 2026-11-16 |
| Repository | `~/Desktop/Vulnerability_backend-main` (no Git repository) |
| Original snapshot | `~/Desktop/AI_Security_Analyst_backups/20261116-165001/original` (167 files, SHA-256 inventory alongside, read-only) |
| Unified diff | `~/Desktop/AI_Security_Analyst_backups/20261116-165001/changes.diff` |
| Verification host | macOS, Python 3.12.15 in an isolated virtual environment outside the project |
| Verdict | **READY WITH DOCUMENTED LIMITATIONS** |

## 1. Executive summary

The backend is a well-engineered, security-focused FastAPI service that implements
the identity, authorization, auditing, and static repository-analysis foundation of
the AI Security Analyst platform. Before this release it had one failing test, caused
by a confirmed absolute-path disclosure, plus several confirmed hardening gaps.

This release fixed nine findings (B1–B9) with regression tests, including both
information-disclosure defects, the event-loop blocking in authentication routes,
unbounded unauthenticated audit writes, weak production configuration validation,
missing failed-login throttling, broad integrity-error handling, validation-error
echoing, and unbounded rate-limiter memory. The full suite now passes (1,138 passed,
0 failed, 7 Windows-only skips); lint, formatting, and migration drift checks are
clean.

The project is presentable as a **secure backend and static-analysis foundation**.
It is not the complete platform described in the academic synopsis: runtime
testing, AI/LLM features, RAG, reporting, a frontend, and deployment tooling are not
implemented, and four security findings remain as documented, accepted limitations.

## 2. Requirements baseline and resources

| Resource | Status |
| --- | --- |
| `AI_Security_Analyst_Project_Context.md` | Not found in the project or anywhere under the user's home directory |
| `AI_Security_Analyst_Project_Plan.docx` | Not found |
| Previous audit `Pasted text (20261107-082719).txt` | Not found; the Phase 5.2.4 audit in the working conversation was used |
| `~/Downloads/AI_Security_Analyst_Academic_Project_Synopsis.pdf` | Found and used as the long-term scope baseline |
| README and source | Inspected in full before any change |

No content was invented for the missing documents.

## 3. Verified project architecture

- **API layer** (`app/api`): auth, assessments, analysis runs, attack-surface
  summary, admin audit, and admin security monitoring routers. Dependencies resolve a
  database-backed principal and apply role and ownership checks.
- **Core** (`app/core`): settings with fail-closed validation, security primitives
  (Argon2id, HS256 JWT, opaque tokens), mailer, rate limiting, role identifiers.
- **Services** (`app/services`): identity lifecycle, sessions and refresh rotation,
  authorization, audit, assessment lifecycle, repository targets, findings, analysis
  execution (heartbeat lease, cooperative deadline, admission), and nine static
  analyzers chained by `attack_surface_reporting`.
- **Persistence**: SQLAlchemy 2 on SQLite, 14 linear Alembic migrations.

A Mermaid architecture diagram is in `README.md` §3.

## 4. Implemented functionality

| Area | Status |
| --- | --- |
| Registration, verification, reset, login, refresh rotation with replay detection, logout, `/me` | Implemented and tested |
| Role- and ownership-based authorization on all assessment routes; admin APIs | Implemented and tested |
| Audited assessment lifecycle; durable audit events; denial-pattern monitoring | Implemented and tested |
| Local repository targets with containment checks | Implemented and tested |
| Discovery, technology detection, route extraction, auth-control/input/sensitive-operation detection, correlation, call graph, input-to-operation flow | Implemented and tested (JavaScript/TypeScript support is partial) |
| Analysis runs with atomic completion, heartbeat, deadline, admission control | Implemented and tested |
| Conservative finding generation (`informational` / `not_tested`) | Implemented and tested |
| Git/archive ingestion, secret scanning, dependency CVE lookup | Not implemented |
| Crawler, runtime XSS/SQLi testing, DVWA lab, HTTP evidence | Not implemented |
| LLM, LangChain/LangGraph, RAG/FAISS | Not implemented |
| HTML reports, retesting, React dashboard, Docker | Not implemented |

Against the synopsis phases: Phase 1 complete; Phase 2 partial (no secrets or
dependency checks, local ingestion only); Phases 3–4 static halves complete, runtime
halves absent; Phases 5–7 absent; Phase 8 has strong unit and integration tests but
no end-to-end tests or containers.

## 5. Security findings and their disposition

| ID | Finding | Stage A classification | Disposition |
| --- | --- | --- | --- |
| S-1 | Absolute repository path in summary `issues[].source_file` | Confirmed and reproducible (failing test) | **Fixed (B1)** |
| S-2 | Unauthenticated requests force one audit row each | Confirmed and reproducible (200 requests → 200 rows) | **Fixed (B4)** — bounded per client and globally |
| S-3 | Blocking Argon2/DB work inside `async def` auth routes | Confirmed by code inspection; measurement consistent | **Fixed (B3)** |
| S-4 | Repository-location errors reveal path existence and type | Confirmed and reproducible | **Fixed (B2)** |
| S-5 | Process-local IP limiting; no per-account throttle | Confirmed by code inspection | **Partially fixed (B6)** — per-(account, address) throttle, account alert, proxy guidance; distributed limiting remains a limitation |
| S-6 | Production configuration not fully fail-closed | Confirmed by code inspection | **Fixed (B5)** |
| S-7 | Repository targets have no owner | Confirmed by code inspection | **Accepted limitation** |
| S-8 | Enumeration timing (reset/resend) | Reproduced in-process (2.0 ms vs 1.1 ms) | **Accepted limitation** |
| S-9 | Broad `IntegrityError` handling | Confirmed by code inspection | **Fixed (B7)** |
| S-10 | Default-role check-then-insert race | Confirmed by code; not exploitable today | **Accepted limitation** |
| S-11 | Validation errors echo submitted values | Reproduced | **Fixed (B8)** |
| S-12 | Logging and sensitive data | Confirmed (low): no secrets logged; tracebacks may contain paths | **Accepted limitation** (new log events avoid raw identifiers) |
| S-13 | Rate-limiter memory growth | Confirmed by code inspection | **Fixed (B9)** |

### Fix details

- **B1 (S-1).** `app/services/input_operation_flow.py` labels repository-wide issues
  with `"."` (`_REPOSITORY_ROOT_LABEL`) at all three former `inventory.root` sites.
  New `tests/disclosure_helpers.py` decodes JSON and checks native and POSIX spellings,
  so the regression test also works on Windows, where JSON-escaped backslashes made the
  old `str(path) in response.text` assertion ineffective.
- **B2 (S-4).** `app/api/v1.py` maps every `InvalidRepositoryLocationError` to the
  single `REPOSITORY_LOCATION_INVALID_DETAIL`. Specific reasons stay internal for
  service callers. API change: the 422 detail text changed; the status code did not.
- **B3 (S-3).** All `app/api/auth.py` handlers are plain `def`, so FastAPI runs them
  in its threadpool. A behavioural test blocks the login service in a worker thread
  and proves the event loop keeps serving requests; it fails against the old handler.
- **B4 (S-2).** `app/api/dependencies.py` records an unauthenticated denial only
  within `AUDIT_UNAUTHENTICATED_DENIALS_PER_CLIENT` (20) per address and
  `AUDIT_UNAUTHENTICATED_DENIALS_GLOBAL` (600) overall per 60 s. Responses are
  unchanged (`401`).
- **B5 (S-6).** `app/core/config.py` now requires explicit `DATABASE_URL`,
  `SMTP_HOST`, `EMAIL_FROM`, and `REPOSITORY_ALLOWED_ROOTS` in staging/production,
  rejects `localhost` sender domains and relative roots, and still accepts an explicit
  loopback SMTP relay. `app/main.py` validates at import (covering
  `--lifespan off`) and disables `/docs`, `/redoc`, `/openapi.json` in production
  unless `API_DOCS_ENABLED=true`. Stale descriptions of the deadline, heartbeat, and
  stale threshold were corrected.
- **B6 (S-5).** Login throttles failures per (SHA-256 of normalized email, client
  address), returns `429` even for a correct password while throttled, behaves
  identically for unknown accounts, and clears on success. Because the key includes
  the address, a third party cannot lock out a user's own address. Account-wide
  failures only emit one `login_failure_threshold` warning (alert, never block).
  Forwarded headers are never read; the README documents Uvicorn
  `--forwarded-allow-ips`.
- **B7 (S-9).** New `app/db/integrity.py` identifies the violated constraint by name
  (PostgreSQL) or exact SQLite message. Only the expected races (duplicate email,
  active action token, duplicate role assignment) are treated as benign. Others are
  logged as `unexpected_integrity_error` without driver text or values. The default
  role assignment now re-raises unexpected violations instead of reporting success.
  Generic `202` responses are unchanged, so no enumeration channel was added.
- **B8 (S-11).** `app/main.py` strips `input` from every 422, keeping `loc`, `msg`,
  and `type`.
- **B9 (S-13).** `app/core/rate_limit.py` caps tracked identities per limiter. Stale
  keys (judged against each key's own window) are pruned first. Active keys are never
  evicted. When full, new identities share a per-scope overflow bucket, so floods make
  limiting stricter, not weaker.

## 6. Changes made

Source (12 files): `app/api/auth.py`, `app/api/constants.py`,
`app/api/dependencies.py`, `app/api/v1.py`, `app/core/config.py`,
`app/core/rate_limit.py`, `app/db/integrity.py` (new), `app/main.py`,
`app/services/identity.py`, `app/services/input_operation_flow.py`,
`app/services/roles.py`, `app/services/user_action_tokens.py`.

Tests (11 files): `tests/conftest.py` (resets the new limiters),
`tests/disclosure_helpers.py` (new), `tests/test_auth_event_loop.py` (new),
`tests/test_integrity_classification.py` (new), `tests/test_rate_limit_hardening.py`
(new), `tests/test_validation_error_sanitization.py` (new),
`tests/test_analysis_runs_api.py`, `tests/test_input_operation_flow.py`,
`tests/test_repository_security.py`, `tests/test_repository_targets.py`,
`tests/test_security_config.py`.

Existing assertions that changed, and why:

- `test_repository_targets.py`: the three distinct location messages became the single
  generic detail. This is the intended B2 behaviour change; every case is still
  asserted to be `422`, and a new test asserts that all rejections are byte-identical.
- `test_security_config.py`: `test_valid_production_configuration_passes` now supplies
  the explicit deployment settings that B5 requires.
- Path-disclosure assertions in `test_repository_security.py` and
  `test_analysis_runs_api.py` were strengthened, not weakened (decoded-JSON and
  platform-independent).

Documentation and configuration: `README.md` (rewritten into 17 sections with a
Mermaid diagram and status tables), `docs/TECHNICAL_REFERENCE.md` (new; preserves
the previous detailed reference with stale statements corrected), `.env.example`
(new settings, placeholders only), and this report.

No migration was added or changed. No database schema or data was touched.

## 7. Test results

All runs used a scratch virtual environment, `APP_ENV=test`, temporary per-test
SQLite databases, `PYTHONDONTWRITEBYTECODE=1`, and caches redirected outside the
project.

| Check | Before (Stage A) | After |
| --- | --- | --- |
| `pytest` (full suite) | 1084 passed, **1 failed**, 7 skipped | **1138 passed, 0 failed, 7 skipped** (63.9 s) |
| Coverage (`app`) | 86% | 86% (`rate_limit` 95%, `integrity` 100%, `dependencies` 99%, `config` 96%, `auth` API 93%) |
| `ruff check .` | All checks passed | All checks passed |
| `ruff format --check .` | 161 files formatted | 168 files formatted |
| Type checking | Not configured | Not configured (not run) |

The 7 skips are Windows-only path-semantics tests (case-insensitivity, drive letters,
UNC, reparse points); they were not executed on this macOS host.

New regression tests: 53 (collected tests rose from 1,092 to 1,145). Breakdown: B1: 2,
plus strengthened assertions in three existing tests; B2: 1; B3: 2; B4: 3; B5: 21
parametrized cases including two subprocess import tests; B6: 7; B7: 7; B8: 4; B9: 6.
For B3, B7, and B8, the new tests were run against the original code and failed as
expected (B3: 2 of 2 with the original `app/api/auth.py`; B7: 3 of 7, the other 4
assert preserved behaviour; B8: 3 of 4, the fourth covers the auth routes that were
already sanitized), then passed against the fix. The Stage A probe scripts were rerun independently after the fixes:

| Probe | Before | After |
| --- | --- | --- |
| Absolute path in summary response | leaked in `issues[0..1].source_file` | no occurrence |
| Location oracle (outside dir / outside file / missing) | 3 distinct messages | 1 identical message |
| Audit rows after 200 unauthenticated requests | 200 | 20 |
| 422 echoes a submitted value | yes | no |
| Reset/resend timing, existing vs unknown | 2.0 / 1.1 ms | 2.0 / 1.2 ms (accepted, S-8) |

Security regression areas exercised by the suite: authentication and session
lifecycle, refresh replay and revocation, authorization and ownership, path
containment and disclosure, error sanitization, audit logging, rate limiting and
throttling, production configuration, token handling, log redaction of new events,
and concurrency (threaded file-backed SQLite for login/reset, refresh/logout, reset
races, and single active analysis run).

Not tested: PostgreSQL behaviour, multi-process or multi-instance limits, real SMTP
delivery and TLS handshakes (only mocked), Windows hosts, load and performance, and
end-to-end flows through a deployed server.

## 8. Database and migration verification

On a scratch SQLite database outside the project:

- 14 revisions in a single linear chain (`0001` → `0014`), one head, one base.
- `alembic upgrade head`: OK.
- `alembic check`: "No new upgrade operations detected" (models match migrations).
- `alembic downgrade base` then `alembic upgrade head`: OK.
- Data-preservation and round-trip tests for `0010`–`0014` plus concurrency suites:
  77 passed.

No project database existed in the repository, and none was created or modified.

## 9. Remaining security limitations

See `README.md` §16 for impact, rationale, and the path to resolution. In summary:

- **S-7** No repository-target ownership. Analysts can read analysis output for any
  directory under shared allowed roots.
- **S-8** Measurable timing difference for existing accounts on reset/resend.
- **S-10** Check-then-insert default-role assignment (latent until role management
  exists).
- **S-12** Exception tracebacks may contain server paths; no logging configuration or
  redaction filter.
- All rate limits, throttles, the audit budget, and analysis admission are
  process-local. Distributed credential stuffing is alerted on, not blocked.
- No retention for audit, session, refresh-token, and action-token tables.
- Synchronous in-request analysis with stage-boundary deadlines; no cancellation
  workflow or stale-run recovery.
- SQLite only; PostgreSQL is unverified.
- No admin bootstrap; `Viewer` has no sharing model.

## 10. Known missing functionality

Runtime vulnerability testing (crawler, XSS/SQLi, DVWA), HTTP evidence, secret and
dependency scanning, Git/archive ingestion, LLM explanations, LangChain/LangGraph,
RAG/FAISS, HTML reporting, retesting, the React dashboard, Docker/Compose, background
workers, distributed rate limiting, and PostgreSQL support.

## 11. Deployment readiness

- **Local and academic demonstration:** ready. Install, migrate, and run steps are
  documented, and the console mailer makes the full identity flow demonstrable offline.
- **Single-instance internal deployment:** possible with care. Use explicit
  settings, TLS termination, a single worker or awareness of per-worker limits,
  `--forwarded-allow-ips` behind a proxy, one allowed root per trust boundary (S-7),
  and operator procedures for stale runs.
- **Multi-tenant or internet-facing production:** not ready. It needs
  repository-target ownership, shared rate limiting, a background worker, retention,
  logging hygiene, and PostgreSQL verification.

## 12. Portfolio presentation recommendations

- Present it as a "secure backend and static-analysis foundation for an AI-assisted
  security platform", not as a working AI scanner.
- Lead with the engineering highlights: fail-closed configuration; database-bound
  sessions with refresh replay detection and atomic revocation; a documented lock
  order with concurrency tests; ownership enforced in queries; audit-in-transaction
  design; disclosure-safe errors; and conservative, evidence-labelled findings.
- Show the audit trail: this report's before/after table demonstrates the security
  review and regression-testing process.
- Demo script: register, verify (console token), log in, create an assessment,
  register a sample Flask/FastAPI repository, run analysis, then show findings, the
  attack-surface summary, and admin audit events.
- Be explicit about the roadmap and the limitations in README §16–17; reviewers value
  honest scoping.
- Before publishing, initialise Git yourself and commit the backup snapshot as the
  first commit and this release as the second, so the history shows the hardening
  diff.

## 13. Final release-readiness verdict

**READY WITH DOCUMENTED LIMITATIONS.**

All confirmed high-priority defects found in the audit are fixed and covered by
regression tests. The complete suite, lint, formatting, and migration checks pass.
Documentation now matches the code. The verdict is not "READY FOR PORTFOLIO
PRESENTATION" without qualification because four security findings (S-7, S-8, S-10,
S-12) and several infrastructure limitations remain, and most of the
synopsis-level functionality (runtime testing, AI, RAG, reporting, frontend,
deployment) is not implemented. These are documented accurately rather than claimed.
