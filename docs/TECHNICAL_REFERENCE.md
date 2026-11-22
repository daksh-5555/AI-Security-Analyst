# AI Security Analyst — Technical Reference

This document holds the detailed behaviour of each backend subsystem. The
[README](../README.md) gives the overview, setup, and limitations; this file is the
reference for exact API contracts, error behaviour, concurrency rules, and analyzer
internals. Everything here describes code that exists in this repository.

All `curl` examples for protected routes assume `ACCESS_TOKEN` holds an access token
obtained from `POST /api/v1/auth/login`.

## Contents

- [Authorization](#authorization)
- [Audit events and administrative APIs](#audit-events-and-administrative-apis)
- [Deployment configuration validation](#deployment-configuration-validation)
- [Identity schema, lifecycle, login, and sessions](#identity-schema)
- [Assessment lifecycle](#assessment-lifecycle)
- [Repository targets](#repository-targets)
- [Finding persistence](#finding-persistence)
- [Analysis runs](#analysis-runs)
- [Repository discovery](#repository-discovery)
- [Technology detection](#technology-detection)
- [Attack surface analysis](#attack-surface-analysis)
- [Attack surface summary reporting](#attack-surface-summary-reporting)
- [Analysis tool extension seam](#analysis-tool-extension-seam)
- [Secret scanning](#secret-scanning)
- [Guarded egress client](#guarded-egress-client)
- [Dependency advisory analysis](#dependency-advisory-analysis)
- [Target authorization](#target-authorization)
- [Web crawling](#web-crawling)
- [Runtime probes](#runtime-probes)
- [Normalized evidence and retest](#normalized-evidence-and-retest)
- [Background execution and recovery](#background-execution-and-recovery)
- [Advisory LLM explanations](#advisory-llm-explanations)
- [Assessment workflows](#assessment-workflows)
- [Knowledge retrieval](#knowledge-retrieval)
- [Assessment reports](#assessment-reports)
- [PostgreSQL](#postgresql)

## Authorization

Implemented in `app/services/authorization.py` and enforced through FastAPI
dependencies in `app/api/dependencies.py`.

Every request to `/api/v1/assessments*` and `/api/v1/admin/*` must carry exactly one
`Authorization: Bearer <access token>` header. The token is validated (HS256, issuer,
audience, type, lifetime) and then bound to a live `user_sessions` row: the session
must belong to the token subject, be unrevoked, and be within its idle and absolute
expiry. The user must be active and email-verified. Roles are read from the database
on every request; the JWT carries no role claims, so role changes and revocations take
effect immediately.

| Role | Read assessments | Create / mutate / execute | Visibility |
| ---- | ---------------- | ------------------------- | ---------- |
| `Admin` | yes | yes | all assessments, including legacy rows with no owner |
| `Security Analyst` | yes | yes | only assessments they own |
| `Viewer` | yes | no | only assessments they own (see limitation below) |

- Ownership is enforced inside the database query (`owner_id = principal.user_id`),
  never by trusting a client-supplied owner or identifier secrecy.
- An assessment the caller cannot see returns `404 Assessment not found`, exactly like
  a nonexistent one, so identifiers cannot be probed.
- A caller without a sufficient role receives `403`.
- A missing or invalid token receives the generic `401` with `WWW-Authenticate: Bearer`.
- Admin endpoints require the `Admin` role.

Known gaps: there is no role-management API and no administrator bootstrap command,
so the first `Admin` must be assigned directly in the database. A `Viewer` cannot
create assessments and there is no sharing model, so in practice a Viewer can see
nothing until a sharing or assignment feature exists.

## Audit events and administrative APIs

`audit_events` (migration `0012`) records security-relevant operations. Actions:
`assessment.created`, `assessment.access_denied`, `assessment.lifecycle_changed`,
`assessment.lifecycle_denied`, `repository_target.created`, `analysis_run.started`,
`analysis_run.completed`, and `analysis_run.failed`. Outcomes are `success`,
`failure`, and `denied`.

- Successful mutations write their audit row in the same transaction as the change,
  so a mutation and its audit record cannot diverge.
- Denials (401, 403, not-visible 404, rejected lifecycle transitions) are committed
  independently after the business transaction is rolled back.
- Unauthenticated denials on assessment routes are recorded with a null actor, but
  only up to `AUDIT_UNAUTHENTICATED_DENIALS_PER_CLIENT` per client address and
  `AUDIT_UNAUTHENTICATED_DENIALS_GLOBAL` overall per
  `AUDIT_UNAUTHENTICATED_DENIAL_WINDOW_SECONDS` (defaults 20, 600, 60 s). Requests over
  the budget still receive the same `401`; only the audit write is skipped. This
  prevents unauthenticated callers from forcing unbounded database writes. The budget
  is process-local.
- Audit `context` is bounded operational metadata and is never returned by the API.
- There is no retention or archival policy; the table grows without bound.

Administrative endpoints (Admin role only, `Cache-Control: no-store`):

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/api/v1/admin/audit-events` | Filter by `action`, `outcome`, `actor_user_id`, `assessment_id`, `resource_id`, `from_time` (inclusive), `to_time` (exclusive); `limit` 1–100 (default 50) and `offset`. Ordered by `occurred_at` then `id`, newest first. |
| `GET` | `/api/v1/admin/security-monitoring/denial-patterns` | Aggregates `denied` events between required `from_time` and `to_time` (window at most 30 days) by actor, resource type, resource, and action; reports groups with at least `min_attempts` (2–1000, default 5). |

## Deployment configuration validation

`validate_security_configuration` (`app/core/config.py`) runs when `app.main` is
imported and again at application startup, so hosts that skip lifespan events still
fail closed. In every environment it rejects enabling both `SMTP_SSL` and
`SMTP_STARTTLS`, and an `SMTP_USERNAME` without `SMTP_PASSWORD`. In `staging` and
`production` it additionally requires:

- `JWT_SECRET` of at least 32 UTF-8 bytes.
- `EMAIL_BACKEND=smtp` (the console backend prints tokens and is refused) with
  `SMTP_SSL` or `SMTP_STARTTLS` enabled. TLS uses the system trust store with
  certificate and hostname verification (`ssl.create_default_context()`).
- `DATABASE_URL`, `SMTP_HOST`, `EMAIL_FROM`, and `REPOSITORY_ALLOWED_ROOTS` to be set
  explicitly instead of inheriting development defaults. A loopback `SMTP_HOST` is
  accepted when set explicitly, because a local mail relay is a legitimate setup.
- An `EMAIL_FROM` whose domain is not `localhost` or `*.localhost`.
- Only absolute paths in `REPOSITORY_ALLOWED_ROOTS`.

`/docs`, `/redoc`, and `/openapi.json` are disabled in `production` unless
`API_DOCS_ENABLED=true`, and enabled elsewhere unless `API_DOCS_ENABLED=false`.

## Identity schema

Migration `0008` creates the normalized identity tables:

- `users` — UUID primary key, unique normalized email, password hash, activation
  and email-verification flags, and UTC timestamps.
- `roles` — UUID primary key and a unique canonical role name.
- `user_roles` — composite `(user_id, role_id)` primary key with a cascading user
  foreign key and a restricted role foreign key.

The migration seeds exactly three canonical roles: `Admin`, `Security Analyst`, and
`Viewer`. It does not create users or assign roles to any user.

Phase 5.2.3 adds the identity lifecycle endpoints on top of this schema, and Phase
5.2.4 adds login, persisted sessions, database-backed access authentication, and
refresh-token rotation, logout, assessment ownership, and role-based authorization.
Role-management endpoints remain unimplemented. The approved role policy is:

- Public registration accepts no role ID, role name, or role list from the client.
- Registration creates no role assignment.
- Successful email verification grants the `Security Analyst` default role only when
  the user has no existing role assignment.
- Existing explicit `Viewer` or `Admin` assignments remain unchanged.
- `Viewer` is available only through explicit authorized assignment workflows.
- `Admin` is never assigned through public registration or automatic verification.
- Assignment decisions use deterministic seeded role identifiers, not mutable names.

Downgrading migration `0008` drops only `user_roles`, `users`, and `roles`; it does
not alter assessment, finding, repository, or analysis-run data.

### Identity lifecycle

Migration `0009` creates `user_action_tokens`:

- UUID primary key and a cascading user foreign key.
- `purpose` restricted to `email_verification` or `password_reset`.
- Unique SHA-256 `token_hash`; raw tokens are never persisted.
- `created_at`, `expires_at`, and nullable `consumed_at`.
- A partial unique index on `(user_id, purpose)` where `consumed_at IS NULL`, so at
  most one unconsumed token exists per user and purpose. This is enforced on SQLite
  and PostgreSQL; other dialects are rejected at migration time.

| Method | Path | Success |
| ------ | ---- | ------- |
| `POST` | `/api/v1/auth/register` | `202` generic message |
| `POST` | `/api/v1/auth/resend-verification` | `202` generic message |
| `POST` | `/api/v1/auth/verify-email` | `204` |
| `POST` | `/api/v1/auth/password-reset/request` | `202` generic message |
| `POST` | `/api/v1/auth/password-reset/confirm` | `204` |
| `POST` | `/api/v1/auth/login` | `200` access and refresh tokens |
| `POST` | `/api/v1/auth/refresh` | `200` rotated access and refresh tokens |
| `POST` | `/api/v1/auth/logout` | `204` current session and refresh family revoked |
| `GET` | `/api/v1/auth/me` | `200` current identity and roles |

Registration, resend, and reset request always return the same generic status and
body regardless of account existence or eligibility. Unknown, expired, consumed,
inactive-user, and wrong-purpose tokens return a generic `400`. Invalid requests
return `422` without echoing submitted values (this applies to every route, not only auth). Auth responses are marked
`Cache-Control: no-store`.

Passwords must contain at least 12 characters and at most 1024 UTF-8 bytes. Tokens
are cryptographically secure, prefixed (`verify_` or `reset_`), single-use, bound to
one purpose, and time-limited. Verification of an already-verified user is
idempotent and never grants a second role.

A successful password reset leaves `is_email_verified` unchanged and commits the new
password hash, consumption of the presented reset token, invalidation of every other
outstanding reset token, and revocation of every active session and its active refresh
tokens in one transaction. All of that user's sessions are revoked with reason
`password_reset`; other users are untouched. Already-consumed or already-revoked
refresh tokens keep their existing history, including `consumed_at` and
`replaced_by_id`. Previously issued access tokens fail `/me` because the persisted
session is revoked, and previously issued refresh tokens fail because their rows are
revoked. A persistence failure rolls the password, reset token, session, and refresh
token changes back together; a genuine persistence failure returns a generic `500`,
while unusable reset tokens keep the generic `400`.

Email delivery uses a small abstraction:

- `EMAIL_BACKEND` defaults to `smtp`. The `console` backend must be requested
  explicitly and prints plain-text messages to standard output; it is restricted to
  `development` and `test`.
- `EMAIL_BACKEND=smtp` uses the Python standard library with optional STARTTLS or
  implicit TLS, optional credentials, and a configurable timeout.
- `staging` and `production` reject the console backend and require SMTP or implicit
  TLS. SMTP credentials are stored as secrets and never logged.

### Login and access authentication

`POST /api/v1/auth/login` accepts `email` and `password` only. Malformed email,
unknown account, wrong password, inactive account, and unverified account all return
the same `401` body, `{"detail": "Invalid email or password"}`. Password verification
runs before account-state checks, and unusable or unknown identities still perform a
cached dummy Argon2id verification so they are not distinguishable by that work.
Successful login optionally rehashes a legacy password in the same transaction that
creates the session and its initial refresh token. Login never grants a role.

Login and password reset serialize on the `users` row. Login reads and verifies the
password optimistically, closes that advisory read before the slow Argon2 work, then
locks the user row and revalidates the hash before creating the session. If a reset
committed in the meantime, the old password fails at revalidation; if login acquired the
lock first, a concurrent reset waits and then revokes the session the login created.
Under PostgreSQL the lock is `SELECT ... FOR UPDATE`; SQLite has no row locks, so login
takes its database write lock with a no-op `UPDATE` before reading the row. The no-op
leaves `updated_at` unchanged.

The response contains `access_token`, `token_type` (`bearer`), `expires_in`,
`refresh_token`, `refresh_expires_in`, and `session_id`. The access token is a signed
HS256 JWT whose `sub` is the user ID and whose `sid` is the persisted session ID; it
carries no role or permission claims. The opaque refresh token is returned once and
only its SHA-256 hash is stored. Its expiry equals the session's idle expiry.

`GET /api/v1/auth/me` requires exactly one `Authorization: Bearer <access token>`
header. Every request re-validates the JWT and loads the persisted session, checking
that it belongs to the token subject, is not revoked, and has not passed its idle or
absolute expiry. The user must still be active and verified, and role names are
resolved from the database on every request rather than from JWT claims. The response
contains only `id`, `email`, `is_active`, `is_email_verified`, and `roles`. Client
authentication failures share one generic `401` with `WWW-Authenticate: Bearer`; a
missing or invalid server signing secret surfaces as an internal server error, not a
client error.

Session timing is:

- `absolute_expires_at = now + ABSOLUTE_SESSION_TTL_SECONDS`
- `idle_expires_at = min(now + REFRESH_TOKEN_TTL_SECONDS, absolute_expires_at)`
- the initial refresh token's `expires_at` equals `idle_expires_at`

`POST /api/v1/auth/refresh` accepts only `refresh_token`. A valid rotation consumes the
presented token exactly once, keeps `sid` unchanged, issues a new access token, and
persists one replacement refresh token (only its SHA-256 hash is stored). The old row
records `consumed_at` and `replaced_by_id`. Idle expiry slides to
`min(now + REFRESH_TOKEN_TTL_SECONDS, absolute_expires_at)` and the absolute expiry is
never extended. The replacement refresh token's expiry equals the updated idle expiry.

Presenting a previously consumed token is treated as reuse: the entire session family
is revoked with reason `refresh_reuse`, every refresh token in the family is revoked,
and a structured warning (`security_event=refresh_token_reuse`) records only
identifiers. Existing access tokens for that session then fail persisted-session
validation. Unknown tokens, expired tokens, and revoked or expired sessions return the
same generic `401` as reuse; an unknown token is not confirmed as reuse and does not
revoke anything. Rotation consumes the token with a conditional `UPDATE` (unconsumed,
unrevoked, unexpired) and requires an affected row count of one, so two concurrent
requests using the same token cannot both succeed; the loser observes a consumed token
and is treated as reuse.

`POST /api/v1/auth/logout` requires the same Bearer access token as `GET /me` and
takes no request body. The session ID comes only from the verified token claims bound
to a live database session; callers cannot select another session. Logout revokes the
authenticated `user_sessions` row with reason `logout` and revokes every refresh token
in that session family in the same transaction. Other sessions belonging to the same
user are untouched, and a failure rolls back both the session and token updates.

Refresh rotation and logout both update the session row before the refresh-token rows,
so they serialize on that row. If refresh commits first, logout's later token update
sees and revokes the replacement token; if logout commits first, refresh's conditional
session update matches zero rows and is rejected. A refresh therefore cannot leave a
usable refresh token or active session behind. This relies on row-level write
serialization: SQLite serializes writers with its database write lock, and PostgreSQL
row locks under READ COMMITTED make the blocked conditional update re-evaluate against
the committed row. Concurrent behavior is tested against file-backed SQLite only;
PostgreSQL contention is not executed in this test suite.

A repeated logout cannot authenticate with the now-revoked access token and returns the
same generic `401` as any other unusable token.

Refresh rotation, logout, reuse revocation, password reset, and login share one lock
order: action token (password reset only), user row (password reset and login),
`user_sessions` in ascending identifier order, then that session's `refresh_tokens`.
Password reset consumes the reset token first, which serializes concurrent reset
attempts, locks the user row, and then locks each session before its tokens. Login takes
the user-row lock and only inserts a new session and refresh token; it never locks an
existing session, so it cannot form a cycle with logout or refresh. Refresh, logout, and
reuse already lock session before token, so the previous token-then-session cycle is
gone. Password reset revokes only active tokens so consumed/replaced history is
preserved. Concurrent reset-versus-refresh and reset-versus-logout serialize on the
session row; if reset commits first, the other operation sees the revoked session, and
if the other commits first, reset's later update sees and revokes any replacement token.
This relies on row-level write serialization: SQLite serializes writers with its
database write lock, and PostgreSQL row locks under READ COMMITTED make blocked
conditional updates re-evaluate against the committed row. Real contention is tested
against file-backed SQLite only; PostgreSQL contention is reasoned about, not executed
here.

A login that wins the user-row race commits its session first, so reset then revokes it.
A login that loses the race re-reads the committed hash and rejects the old password. A
legacy rehash therefore cannot overwrite a reset that won the race. Under extreme SQLite
write contention one side may surface a generic `500` after the busy timeout, but it can
never commit an old-password session that survives a committed reset. Logout-all-devices
as a separate endpoint is not implemented. All auth endpoints are marked
`Cache-Control: no-store` and `Pragma: no-cache`. Assessment, repository, finding,
attack-surface, and analysis-run APIs require a Bearer access token and enforce the
role and ownership policy described in [Authorization](#authorization).

### Session persistence schema

Migration `0010` creates the persistence foundation for authenticated sessions:

- `user_sessions` — UUID primary key used as the JWT `sid`; cascading `user_id`
  foreign key; `created_at`, `last_refreshed_at`, `absolute_expires_at`,
  `idle_expires_at`; nullable `revoked_at` and `revocation_reason`.
- `refresh_tokens` — UUID primary key; cascading `session_id` foreign key; unique
  SHA-256 `token_hash`; `created_at`, `expires_at`; nullable `consumed_at`,
  `revoked_at`, and self-referencing `replaced_by_id` with `ON DELETE SET NULL`.
- Revocation reasons are `logout`, `password_reset`, `refresh_reuse`, `expired`,
  `user_deactivated`, and `admin`.
- A partial unique index on `session_id` where
  `consumed_at IS NULL AND revoked_at IS NULL` allows at most one active refresh
  token per session. This is enforced on SQLite and PostgreSQL; other dialects are
  rejected at migration time.
- Session and expiry indexes support lookup and cleanup.

This schema now backs login, `GET /me`, refresh rotation with replay detection,
current-session logout, and all-session revocation on password reset. General
revocation endpoints beyond logout and password reset, and protected assessment APIs,
are not implemented yet.

Auth rate limiting is an in-memory sliding window scoped by endpoint and direct
client address. **It is process-local and not distributed.** Multiple workers or
instances each keep independent counters, so production deployments must add a
shared limiter or gateway-level protection. Per-account token-request cooldowns are
enforced against the database and do apply across processes.

Login additionally throttles repeated failures for one account from one client
address (`AUTH_LOGIN_FAILURE_MAX_ATTEMPTS` per `AUTH_LOGIN_FAILURE_WINDOW_SECONDS`,
default 5 per 15 minutes). While throttled, even a correct password receives `429`, so
throttled guesses reveal nothing. The throttle is keyed by a SHA-256 of the normalized
submitted email plus the client address, identically for existing and unknown
accounts, so it does not enumerate accounts and raw addresses are not kept in memory.
Because the key includes the client address, an attacker elsewhere cannot lock a user
out. Failures for one account across all addresses only raise a single
`security_event=login_failure_threshold` warning at `AUTH_LOGIN_ACCOUNT_ALERT_THRESHOLD`;
they never block. A successful login clears that address's failure count.

The application never reads `X-Forwarded-For` or `Forwarded`. Behind a reverse proxy,
start Uvicorn with `--forwarded-allow-ips=<proxy address>` so that only the trusted
proxy can set the client address. Without that, every client behind the proxy shares
the proxy's address and therefore one rate-limit bucket.

Limiter memory is bounded (10,000 identities per limiter). Expired identities are
pruned first; identities with events still inside their window are never evicted,
because eviction would let a client reset its own counter. When the table is still
full, new identities share one overflow bucket per scope, so a key flood makes the
limiter stricter, not more permissive.

Downgrading migration `0009` drops only `user_action_tokens`; it does not modify

## Assessment lifecycle

Only these transitions are accepted:

| Current status | Allowed next status      |
| -------------- | ------------------------ |
| `queued`       | `running`                |
| `running`      | `completed`, `failed`    |
| `completed`    | none (terminal)          |
| `failed`       | none (terminal)          |

Every other transition, including a transition to the same status or any transition
out of a terminal status, is rejected with `422`. An accepted transition updates the
assessment and writes an immutable history record in the same database transaction.
Assessment creation is not recorded as a history entry.

Create an assessment:

```bash
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{"assessment_type": "repository"}'
```

Response (`201 Created`):

```json
{
  "id": "4b2f1f6c-9c5a-4db1-bb18-14acf2f2c8f7",
  "assessment_type": "repository",
  "status": "queued",
  "created_at": "2026-10-26T12:00:00Z",
  "updated_at": "2026-10-26T12:00:00Z"
}
```

Transition an assessment:

```bash
curl -X PATCH -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/status \
  -H "Content-Type: application/json" \
  -d '{"status": "running", "reason": "Worker claimed the job."}'
```

The response uses the assessment representation with the new status and `updated_at`
(`200 OK`). Only `status` and an optional `reason` are accepted; request fields such as
timestamps are rejected. `reason` is limited to 500 characters.

Read its history:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/history
```

Response (`200 OK`):

```json
[
  {
    "id": "a2e7b9d3-5db6-44a4-b885-ff9b1f53262e",
    "assessment_id": "4b2f1f6c-9c5a-4db1-bb18-14acf2f2c8f7",
    "previous_status": "queued",
    "new_status": "running",
    "changed_at": "2026-10-26T12:01:00Z",
    "reason": "Worker claimed the job."
  }
]
```

History is returned in chronological order and is not paginated.

Unknown identifiers return `404 Not Found` with `{"detail": "Assessment not found"}`.
Invalid assessment types, unknown request fields such as `target_url`, invalid
pagination values, and rejected status transitions return `422 Unprocessable Entity`.

## Repository targets

A repository assessment can have at most one registered repository target. Only
`local_path` sources are supported; `git_url` is not accepted yet. Registration is
allowed only while the assessment is `queued`, and the assessment must have type
`repository`.

Register a target:

```bash
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/repository \
  -H "Content-Type: application/json" \
  -d '{"source_kind": "local_path", "location": "/srv/repositories/project"}'
```

Response (`201 Created`):

```json
{
  "id": "c3f0d7e2-8a4b-4f1e-9c2d-6b7a8e9f0a1b",
  "assessment_id": "4b2f1f6c-9c5a-4db1-bb18-14acf2f2c8f7",
  "source_kind": "local_path",
  "location": "project",
  "created_at": "2026-11-02T12:00:00Z",
  "updated_at": "2026-11-02T12:00:00Z"
}
```

Retrieve it:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/repository
```

The location is resolved to an absolute, symlink-free path before it is stored. It
must already exist, must be a directory, and must be inside one of the configured
`REPOSITORY_ALLOWED_ROOTS`. Path traversal and symlink escapes are rejected. The API
does not traverse repository contents, run Git commands, or execute repository code.

The stored absolute path is internal. API responses return `location` as a path
relative to the matching allowed root (for example, `project`). If the stored target
is no longer under any configured root, responses use the generic identifier
`repository`. Absolute host paths, usernames, and profile directories are never
returned.

Path validation resolves the candidate before checking containment, so `..`
segments, symbolic links, junctions, and other reparse points are canonicalized
first. Containment is component-based rather than a string-prefix check; on Windows
it is case-insensitive. Sibling directories such as `C:\projects-evil` are rejected
for an allowed root of `C:\projects`. Windows UNC, device, and extended-length paths
are rejected before resolution unless an allowed root is itself configured as such a
path.

Error behavior:

- Unknown assessment or unregistered target: `404 Not Found`.
- Non-repository assessment, non-queued assessment, or duplicate registration:
  `409 Conflict`.
- Missing, invalid, nonexistent, non-directory, or out-of-root location:
  `422 Unprocessable Entity` with the single detail
  `{"detail": "Repository location is not a permitted directory"}`. Every rejection
  uses the same body, so responses cannot be used to probe whether arbitrary server
  paths exist or whether they are files or directories. The specific reason is kept
  internally for service callers and tests.

## Finding persistence

Findings are stored in a normalized structure. One assessment has many findings and
one finding has many evidence records. Persistence uses the existing `Finding` and
`Evidence` schemas. The read schema additionally exposes the persisted finding `id`
and its optional `analysis_run_id`; both are additive and existing fields are
unchanged. Evidence `details` is stored as JSON and returned unchanged.

Read persisted findings:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/findings
```

Response (`200 OK`):

```json
[
  {
    "id": "5f0d7f3e-3f3e-4f8a-9f0b-2c0a1d6f9a11",
    "analysis_run_id": null,
    "title": "SQL injection in search endpoint",
    "category": "SQL injection",
    "severity": "high",
    "status": "inconclusive",
    "confidence": 0.6,
    "summary": "User input reaches a query without parameterization.",
    "affected_component": "app/search.py:42",
    "remediation": "Use parameterized queries.",
    "evidence": [
      {
        "description": "Request input is concatenated into a SQL query.",
        "source": "static-analysis",
        "details": {"rule_id": "sql-injection"}
      }
    ]
  }
]
```

Findings are returned in persistence order, and evidence is returned in the order it
was supplied. An assessment with no findings returns `200 OK` with `[]`. An unknown
assessment returns `404 Not Found` with `{"detail": "Assessment not found"}`.

Pass the optional `analysis_run_id` query parameter to scope the response to one
analysis run:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" "http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/findings?analysis_run_id={run_id}"
```

Without the parameter, assessment-wide behavior is preserved, including findings
persisted before run association existed (`analysis_run_id` is `null` for those
rows). With the parameter, only findings produced by that run are returned. An
unknown run, or a run owned by a different assessment, returns `404 Not Found` with
`{"detail": "Analysis run not found"}` rather than an empty list.

Only reading is exposed. There is no public endpoint for submitting findings, and a
`POST` to the findings path returns `405 Method Not Allowed`. Findings are written
through the service layer (`app/services/findings.py`), which verifies the assessment,
persists findings and nested evidence in one transaction, and rolls back on database
errors. Deleting an assessment cascades to its findings and evidence.

## Analysis runs

`POST /api/v1/assessments/{assessment_id}/analysis-runs` executes the analysis
pipeline and returns after it finishes (201, final run state). With
`?mode=async` (when `ANALYSIS_ASYNC_ENABLED=true`) it instead queues the run for the
background worker and returns 202; see
[Background execution and recovery](#background-execution-and-recovery). The run,
its findings, and the `COMPLETED` status are persisted atomically in both modes.

Each run starts in `running`. It becomes `completed` only when the analysis pipeline
and its findings commit together, and only while the run is still `running`. A
completion transition that loses a concurrent terminal-state race writes no
completion audit event and rolls its findings back. If analysis, finding
persistence, or completion fails, the findings are rolled back and the run is
marked `failed` with a sanitized `error_message`. A failure that also prevents the
FAILED state and its failure audit event from committing leaves the run `running`.

Because the terminal state and its audit event are committed atomically, a
failure-audit persistence error or a process exit can leave a run `running`
rather than `failed` without a matching audit record. While the stale run remains
`running`, a new analysis for the same assessment returns `409 Conflict`. Since M8,
the worker's recovery sweep (`python -m app.worker`, or `--recover-only` on a
schedule) marks such a run `failed` with `error_code=lease_expired` and records the
`analysis_run.failed` event once its lease expires. Do not mark runs terminal by
hand: a terminal run without matching audit history breaks the lifecycle
invariant. Runs can be cancelled through
`POST …/analysis-runs/{run_id}/cancel`.

Findings produced by a run come from the conservative static finding policy. Only
relationships that are `resolved` and contain source-backed propagation steps are
represented. Each generated finding is `informational` with status `not_tested`,
states that runtime execution and exploitability were not verified, and points at
repository-relative source locations. Eligible relationships that cannot be
represented are skipped and recorded as bounded limitations in
`analysis_metadata.finding_policy.limitations`; no severity, confidence, or
remediation value is invented. These findings are static evidence, not confirmed
vulnerabilities.

```bash
curl -i -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8000/api/v1/assessments/{assessment_id}/analysis-runs
```

Response (`201 Created`, with `Location` pointing at the run resource; metadata is
abridged here):

```json
{
  "id": "8b7f5c66-0c2b-4f1a-b5b5-6d1a8e2f0c33",
  "assessment_id": "0d3c8f2e-8a44-4d5f-9a9e-6f0b7d1c2e44",
  "status": "completed",
  "created_at": "2026-11-07T12:00:00Z",
  "started_at": "2026-11-07T12:00:00Z",
  "completed_at": "2026-11-07T12:00:03Z",
  "error_message": null,
  "findings_count": 4,
  "analysis_metadata": {
    "analyzer": {"name": "AI Security Analyst", "version": "0.1.0"},
    "finding_count": 4,
    "analysis_issue_count": 0,
    "completeness": {"is_complete": true},
    "finding_policy": {"generated_finding_count": 4}
  }
}
```

`GET /api/v1/assessments/{assessment_id}/analysis-runs` returns runs owned by the
assessment, newest first, with descending run ID as the deterministic tie-breaker.
History items contain bounded run fields and `findings_count`, but never the findings
collection. `GET /api/v1/assessments/{assessment_id}/analysis-runs/{run_id}` returns
one run with its compact `analysis_metadata` and `findings_count`; a run that is
unknown or owned by another assessment returns `404`.

A missing assessment returns `404` with `{"detail": "Assessment not found"}`, and an
assessment without a registered repository target returns `404` with
`{"detail": "Repository target not found"}`. An execution failure returns `500` with
`{"detail": "Analysis run failed"}` while retaining the run in `failed` state with a
sanitized `error_message`; internal exception details and filesystem paths are not
exposed.

At most one analysis run may be `running` for an assessment at a time. This is
enforced by a partial unique database index on `analysis_runs.assessment_id` for
rows whose status is `running`, not only by application checks. A second `POST`
while a run is active returns `409 Conflict` with
`{"detail": "Analysis run already in progress"}`. Completed and failed runs do not
block new runs, and separate assessments may each have their own active run.

Admission control is best-effort and process-local. Run creation and the
attack-surface summary share one process-local global semaphore
(`ANALYSIS_MAX_CONCURRENT_JOBS`); only run creation also consumes a per-user
in-flight slot (`ANALYSIS_MAX_CONCURRENT_JOBS_PER_USER`). Each endpoint has its
own per-user sliding-window request limit (`analysis.run` and `analysis.summary`,
`ANALYSIS_RATE_LIMIT_MAX_REQUESTS` per `ANALYSIS_RATE_LIMIT_WINDOW_SECONDS`).
Exceeding a rate limit or the concurrent-run quota returns `429`; failing to
acquire global capacity within `ANALYSIS_QUEUE_WAIT_SECONDS` returns `503`. Both
responses include `Retry-After`. A concurrent same-user request may receive
`429` before the active-run `409` is evaluated; sequential duplicates still
return `409`. Admission rejections create no analysis run, heartbeat, or
lifecycle audit event.

Because the routes are synchronous, waiting for global capacity blocks a worker
thread. The wait happens before the execution deadline is created, so
`ANALYSIS_EXECUTION_TIMEOUT_SECONDS` measures pipeline work only; the worst-case
request duration is approximately `ANALYSIS_QUEUE_WAIT_SECONDS` plus the
execution timeout.

These controls are process-local: each Uvicorn worker keeps independent
rate-limit counters, per-user counters, and semaphore capacity, so with `N`
workers the effective limits are approximately `N` times the configured values.
Multiple application instances multiply capacity further. There is no
deployment-wide enforcement, distributed queue, distributed lock, or guaranteed
FIFO ordering, and no strict starvation prevention.

Concurrency enforcement was implemented and tested on SQLite, the database dialect
the project configures and tests. The migration also emits an equivalent PostgreSQL
partial-index predicate, but PostgreSQL is not a configured or tested dialect here
(no driver dependency); do not assume it has been validated.

Upgrading an existing database to migration `0007` requires at most one `running`
row per assessment. A database that already contains duplicate `running` rows for
one assessment (possible under earlier code that had no such constraint) must have
those rows resolved manually before the upgrade, because creating the unique partial
index will otherwise fail. The migration does not choose or modify a run
automatically.

A stale `running` run can also remain if the process exits after committing the
start record. The heartbeat extends `lease_expires_at` by
`ANALYSIS_STALE_AFTER_SECONDS` (which is validated to exceed the execution
deadline plus two heartbeat intervals). A run whose lease is past is therefore no
longer being worked on, and the recovery sweep reclaims it as described in
[Background execution and recovery](#background-execution-and-recovery).

Terminal lifecycle auditing (`analysis_run.completed` and `analysis_run.failed`)
was introduced with migration `0013` (M6). Runs that reached a terminal state
before that cutover have no terminal audit event; they are not backfilled.

Audit attribution uses `ON DELETE SET NULL` for the actor. No user hard-delete API
exists; if a user row is hard-deleted directly while an analysis is executing, the
terminal audit insert can fail and the run remains `running`. Raw execution
exceptions are written to application logs; log hygiene is tracked separately and
is outside the audit trail, which records only bounded fields such as the failure
stage and finding count.

Production readiness: analysis runs execute inside the request, so a long analysis
occupies a worker thread. Cooperative deadlines and heartbeats bound pipeline
work, and process-local admission control bounds concurrent pipelines and
per-user request rates (see above). Asynchronous mode moves execution to the
worker, adds a database-wide per-user quota and running cap, progress (`stage`,
`attempts`), cancellation, and stale-lease recovery. Run responses are not
paginated.

Every assessment, repository, finding, attack-surface, and analysis-run endpoint
requires a Bearer access token bound to a live database session. See
[Authorization](#authorization) for the role and ownership policy.

## Repository discovery

`app/services/repository_discovery.py` builds a deterministic, read-only inventory of
regular files below a registered repository root. It is a service boundary for later
orchestration; it is not exposed as an API route and does not persist the inventory.

Use `discover_repository(root)` with a validated root, or
`discover_registered_repository(db, assessment_id)` to load a registered
`RepositoryTarget` and discover its stored location. The stored location is
revalidated against `REPOSITORY_ALLOWED_ROOTS` before traversal.

Discovery:

- Traverses directories recursively and records POSIX-style relative paths,
  lowercase extensions, and file sizes.
- Returns files and skipped items in deterministic sorted order.
- Excludes `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.pytest_cache`,
  `.ruff_cache`, `.next`, `dist`, and `build` directories.
- Keeps configuration files such as `package.json`, `requirements.txt`,
  `pyproject.toml`, `Dockerfile`, and `.env.example`.
- Never opens file contents, including `.env`; metadata is inspected with `stat`
  only.
- Skips symbolic links and does not execute repository code, Git commands, shell
  commands, or network requests.
- Applies `REPOSITORY_MAX_FILE_COUNT`, `REPOSITORY_MAX_DEPTH`, and
  `REPOSITORY_MAX_TOTAL_SIZE_BYTES`. When a limit is reached, traversal stops or
  skips the remaining work and the result reports `is_complete: false` plus the
  truncation reason.
- Records permission errors, inaccessible entries, and files that disappear during
  traversal as skipped items rather than failing the whole inventory.

Example result (abridged):

```json
{
  "root": "/srv/repositories/project",
  "files": [
    {
      "relative_path": "src/main.py",
      "extension": "py",
      "size_bytes": 128
    }
  ],
  "skipped": [
    {
      "relative_path": "node_modules",
      "kind": "directory",
      "reason": "excluded_directory",
      "detail": null
    }
  ],
  "summary": {
    "directory_count": 1,
    "file_count": 1,
    "total_size_bytes": 128,
    "skipped_count": 1,
    "is_complete": true,
    "truncation_reasons": [],
    "limits": {
      "max_file_count": 10000,
      "max_depth": 50,
      "max_total_size_bytes": 536870912
    }
  }
}
```

Excluded directories, symbolic links, and non-regular files are intentional
exclusions and do not make the inventory incomplete. Permission errors, disappeared
entries, and paths outside the root do.

TOCTOU limitation: the filesystem can change between validation and traversal.
Discovery re-checks entries without following symlinks and verifies that child paths
resolve inside the root, but a path could still be replaced by a symlink or moved
outside the root after those checks. File sizes are snapshots, and fully race-free
traversal would require platform-specific directory-handle operations. Windows
junctions and other reparse-point directories are skipped with the symlink reason.

## Technology detection

`app/services/technology_detector.py` consumes a `RepositoryDiscoveryResult` and
returns a deterministic `TechnologyDetectionResult`. It is a service boundary for
later orchestration; it is not exposed as an API route and does not persist results.

```python
result = detect_technologies(root, inventory)
```

The detector revalidates `root` against `REPOSITORY_ALLOWED_ROOTS`, requires the
inventory root to match, and inspects only files already present in the inventory.
It does not traverse the filesystem, read source files, execute repository code,
invoke Git or shell commands, install dependencies, or make network requests.

### Language detection

Languages come only from inventoried file extensions. The mapping is explicit:

| Language   | Extensions |
| ---------- | ---------- |
| Python     | `py`, `pyi` |
| JavaScript | `js`, `mjs`, `cjs`, `jsx` |
| TypeScript | `ts`, `mts`, `cts`, `tsx` |
| Java       | `java` |
| C          | `c`, `h` |
| C++        | `cpp`, `cc`, `cxx`, `hpp`, `hh`, `hxx` |
| C#         | `cs` |
| Go         | `go` |
| Rust       | `rs` |
| PHP        | `php` |
| Ruby       | `rb` |
| Kotlin     | `kt`, `kts` |
| Swift      | `swift` |
| HTML       | `html`, `htm` |
| CSS        | `css`, `scss`, `sass` |
| SQL        | `sql` |

Every matching file contributes an evidence path, and `file_count` is the number of
matching files. Directory names and manifest presence never create a language
detection. The result does not claim a primary language because no deterministic
primary-language rule is defined in this phase.

### Manifest detection

Only these basenames are read, at any depth, and only when they appear in the
discovery inventory:

- `package.json`
- `pyproject.toml`
- `requirements.txt`
- `go.mod`
- `Cargo.toml`
- `pom.xml`
- `Dockerfile`

| Manifest | Detection |
| -------- | --------- |
| `package.json` | React, Next.js, Express, NestJS, Vue, Angular, Fastify, selected database drivers and ORMs |
| `pyproject.toml` | FastAPI, Django, Flask, SQLAlchemy, LangChain, pytest from PEP 621, Poetry, PDM, and dependency groups |
| `requirements.txt` | FastAPI, Django, Flask, SQLAlchemy, LangChain, pytest, selected database drivers |
| `go.mod` | Go Modules build tool plus recognized Go modules such as Gin, Echo, Fiber, Chi, gRPC, GORM, and database drivers |
| `Cargo.toml` | Cargo build tool plus recognized crates such as Axum, Actix Web, Rocket, Tokio, Serde, SQLx, and database drivers |
| `pom.xml` | Maven build tool plus recognized Maven artifacts such as Spring Boot, Spring Framework, Hibernate, JUnit, and database drivers |
| `Dockerfile` | Docker infrastructure marker |

Manifests are parsed with `json`, `tomllib`, `re`, and
`xml.etree.ElementTree`. A dependency is reported as *declared*, not installed or
operational. Unknown dependencies are ignored rather than reported as arbitrary
libraries. `Dockerfile` is detected by filename and its contents are not read.

### Evidence and confidence

Each detection includes one or more `TechnologyEvidence` records and an explicit
detection method. Confidence values are fixed rules:

| Rule | Confidence | Method |
| ---- | ---------: | ------ |
| Exact language extension mapping | `0.95` | `file_extension` |
| Exact recognized dependency in a manifest | `0.95` | `manifest_dependency` |
| Manifest content marker, such as a Go module or Maven project | `0.85` | `manifest_marker` |
| Infrastructure filename marker, such as `Dockerfile` | `0.60` | `filename_marker` |

When the same technology is declared more than once, detections are aggregated by
name and category. Evidence is deduplicated and sorted, and `file_count` counts
distinct supporting files.

### Limits and failures

- `TECHNOLOGY_MANIFEST_MAX_SIZE_BYTES` caps each manifest read. Files larger than
  the limit are reported with reason `too_large` and are not parsed.
- `TECHNOLOGY_MAX_MANIFEST_FILES` caps how many allowlisted manifests are inspected.
  Additional candidates are reported with reason `max_manifest_files`.
- Malformed JSON, TOML, and XML, invalid UTF-8, permission errors, disappeared
  files, symlink manifests, non-regular files, and paths outside the root are
  recorded as `TechnologyDetectionIssue` records instead of aborting detection.
- Discovery completeness is preserved in `summary.discovery_is_complete` and
  `summary.discovery_truncation_reasons`. A truncated inventory is never presented
  as a complete technology inventory.

Example result (abridged):

```json
{
  "root": "/srv/repositories/project",
  "detections": [
    {
      "name": "Python",
      "category": "language",
      "confidence": 0.95,
      "method": "file_extension",
      "file_count": 2,
      "evidence": [
        {"path": "src/main.py", "detail": "File extension '.py' maps to Python."},
        {"path": "src/utils.py", "detail": "File extension '.py' maps to Python."}
      ]
    },
    {
      "name": "FastAPI",
      "category": "framework",
      "confidence": 0.95,
      "method": "manifest_dependency",
      "file_count": 1,
      "evidence": [
        {"path": "pyproject.toml", "detail": "Declared in project.dependencies as 'fastapi'."}
      ]
    },
    {
      "name": "Docker",
      "category": "infrastructure",
      "confidence": 0.6,
      "method": "filename_marker",
      "file_count": 1,
      "evidence": [
        {"path": "Dockerfile", "detail": "Dockerfile is present."}
      ]
    }
  ],
  "issues": [],
  "summary": {
    "detection_count": 3,
    "language_count": 1,
    "framework_count": 1,
    "library_count": 0,
    "database_count": 0,
    "infrastructure_count": 1,
    "build_tool_count": 0,
    "manifest_files_read": 1,
    "issue_count": 0,
    "discovery_is_complete": true,
    "discovery_truncation_reasons": []
  }
}
```

TOCTOU limitation: a manifest path is checked for relative containment, symlink
status, regular-file status, and size immediately before it is opened, but the
filesystem can change between those checks and the read. A path could be replaced
by a symlink or moved outside the root after validation. Reads are size-capped and
failures become structured issues, but fully race-free operation would require
platform-specific directory handles.

## Attack surface analysis

`app/services/attack_surface.py` consumes a `RepositoryDiscoveryResult` and a
`TechnologyDetectionResult` and returns a deterministic `AttackSurfaceResult`. It
is a service boundary for later orchestration; it is not exposed as an API route
and does not persist results.

```python
result = identify_attack_surface(root, inventory, technologies)
```

The analyzer revalidates `root` against `REPOSITORY_ALLOWED_ROOTS`, requires both
the inventory root and the technology result root to match, and inspects only
Python and JavaScript/TypeScript files already present in the inventory. It never
executes or imports repository code, runs Git or shell commands, invokes
subprocesses, or makes network requests.

### Supported framework patterns

Python, parsed with `ast`:

| Framework | Pattern |
| --------- | ------- |
| FastAPI | `@app.get(...)`, `@router.post(...)`, and the other standard HTTP decorators (`put`, `patch`, `delete`, `head`, `options`, `trace`) |
| FastAPI prefixes | `APIRouter(prefix="/api")` and `app.include_router(router, prefix="/v1")` |
| Flask | `@app.route(...)`, `@blueprint.route(...)`, and Flask 2.x shortcut decorators such as `@app.get(...)` |
| Flask prefixes | `Blueprint(..., url_prefix="/api")` and `app.register_blueprint(bp, url_prefix="/v1")` |
| Django | `path(...)` and `re_path(...)` in `urls.py` or a module that assigns `urlpatterns` |

JavaScript/TypeScript, scanned with a scoped token scanner:

| Framework | Pattern |
| --------- | ------- |
| Express | `app.get(...)`, `router.post(...)`, and the other standard HTTP methods, plus `app.all(...)` |
| Express `use` | `app.use("/metrics", handler)` when the first argument is a concrete path and a handler is present |
| Express prefixes | `app.use("/api", router)` where the second argument is a statically recognizable router |
| NestJS | `@Controller(...)`, `@Get(...)`, `@Post(...)`, `@Put(...)`, `@Patch(...)`, `@Delete(...)` |

Django route declarations are reported with `http_method="ANY"` because Django URL
patterns are method-agnostic. Express `app.use(...)` route declarations and Flask
routes whose `methods` list cannot be resolved are also reported with `ANY`.

### Python AST versus JavaScript/TypeScript extraction

Python files are parsed with the standard-library `ast` module. Module-level string
constants are folded deterministically, so `BASE = "/api"` followed by
`@app.get(BASE + "/items")` resolves to `/api/items`. Decorator line numbers and
handler names come from the AST. Invalid Python syntax is reported as
`invalid_syntax`.

JavaScript and TypeScript are not parsed as a full language. The analyzer uses a
small token scanner that understands line and block comments, single-quoted,
double-quoted, and template strings, escaped characters, regular-expression
literals in common positions, simple string concatenation, call arguments, and
NestJS decorators. This is intentionally incomplete: it does not implement
JavaScript semantics, TypeScript types, JSX, arbitrary regular-expression
analysis, or control flow. Comments and string contents are tokenized safely, so
route-like text inside them is not reported as a route. Unsupported or ambiguous
declarations become unresolved candidates or `unsupported_syntax` issues.

### Route resolution and confidence

A candidate is `resolved` only when its path and every statically applied prefix
are known. Otherwise it is `unresolved`, and `path` contains the source expression
or best-known fragment rather than an invented concrete path. For example,
`@app.get(get_path())` becomes an unresolved candidate with path `get_path()`, and
`app.get(BASE_PATH + "/users", handler)` becomes an unresolved candidate containing
`BASE_PATH`.

| Rule | Confidence |
| ---- | ---------: |
| Python AST literal path and statically resolved prefixes | `0.95` |
| Python path or prefix that cannot be resolved | `0.50` |
| JavaScript/TypeScript literal path and statically resolved prefixes | `0.85` |
| JavaScript/TypeScript path or prefix that cannot be resolved | `0.40` |

Paths for FastAPI, Flask, Express, and NestJS are normalized to a leading `/`.
Django paths are preserved as declared because Django URL patterns are relative and
`re_path` values are regular expressions. Exact duplicate candidates are removed;
the same route declared on different lines or in different files is preserved.

### Source inspection security controls

Before reading a source file, the analyzer:

- Revalidates the repository root against `REPOSITORY_ALLOWED_ROOTS`.
- Requires the inventory root and technology result root to match.
- Inspects only files present in `RepositoryDiscoveryResult`.
- Rejects absolute paths, Windows drive paths, and `..` traversal.
- Resolves the path and verifies containment inside the repository root.
- Rejects symlinks, Windows reparse points, and non-regular files without following
  them.
- Rejects paths containing excluded dependency or cache directories such as
  `node_modules`, `.git`, `.venv`, `dist`, and `build`.
- Rejects `.env` files, credential-like filenames, and private-key suffixes before
  opening them.
- Applies `ATTACK_SURFACE_SOURCE_MAX_SIZE_BYTES` to each read and
  `ATTACK_SURFACE_MAX_SOURCE_FILES` to the number of inspected files.
- Records invalid UTF-8, invalid syntax, permission errors, disappeared files, and
  inaccessible paths as structured `AnalysisIssue` records instead of aborting.

Discovery completeness is preserved in `summary.discovery_is_complete` and
`summary.discovery_truncation_reasons`. `summary.is_complete` is `True` only when
discovery was complete and no analysis issue was recorded. Unresolved route
candidates do not by themselves make the analysis incomplete.

### Limits and failures

- `ATTACK_SURFACE_SOURCE_MAX_SIZE_BYTES` caps each source-file read.
- `ATTACK_SURFACE_MAX_SOURCE_FILES` caps how many eligible source files are
  inspected. Additional candidates produce one `max_source_files` issue.
- Invalid paths, outside-root paths, symlinks, reparse points, non-regular files,
  oversized files, invalid encodings, invalid syntax, permission errors,
  disappeared files, excluded paths, and sensitive files become structured issues.
- Files skipped by discovery with a source extension are reported as issues, while
  discovery truncation reasons are preserved separately.

### Unsupported syntax and limitations

- JavaScript/TypeScript extraction is a scoped scanner, not a parser.
- Dynamic paths and prefixes are reported as unresolved; they are not evaluated.
- NestJS object-form decorator arguments such as
  `@Controller({ path: "users" })` are reported as `unsupported_syntax`.
- NestJS decorators on properties and complex TypeScript decorator combinations may
  not be associated with the intended method.
- Django `include(...)` prefixes and nested URL configuration are not resolved.
- Python constants inside classes or functions are not folded into module-level
  route expressions.
- Flask `methods` values must be a literal list, tuple, or set to be expanded.
- Source files are assumed to be UTF-8 (with an optional BOM). Other declared
  Python encodings are reported as `invalid_encoding`.
- Only Python and JavaScript/TypeScript are inspected; other detected languages are
  ignored by this milestone.
- This route-extraction stage does not perform authentication analysis, form
  extraction, injection detection, finding generation, or persistence. Those
  analyses are separate services or remain out of scope.

TOCTOU limitation: each source path is checked for relative containment,
symlink/reparse-point status, regular-file status, and size immediately before it is
opened, but the filesystem can change between those checks and the read. A path
could be replaced by a symlink or moved outside the root after validation. Reads
are size-capped and failures become structured issues, but fully race-free
operation would require platform-specific directory handles.

Example result (abridged):

```json
{
  "root": "/srv/repositories/project",
  "routes": [
    {
      "path": "/api/v1/items",
      "http_method": "POST",
      "framework": "fastapi",
      "source_file": "main.py",
      "line_number": 10,
      "handler_name": "create_item",
      "detection_confidence": 0.95,
      "resolution_status": "resolved"
    },
    {
      "path": "/api/users",
      "http_method": "POST",
      "framework": "express",
      "source_file": "server.js",
      "line_number": 5,
      "handler_name": "createUser",
      "detection_confidence": 0.85,
      "resolution_status": "resolved"
    },
    {
      "path": "/users/:id",
      "http_method": "GET",
      "framework": "nestjs",
      "source_file": "users.controller.ts",
      "line_number": 5,
      "handler_name": "findOne",
      "detection_confidence": 0.85,
      "resolution_status": "resolved"
    },
    {
      "path": "get_path()",
      "http_method": "GET",
      "framework": "fastapi",
      "source_file": "dynamic.py",
      "line_number": 4,
      "handler_name": "dynamic",
      "detection_confidence": 0.5,
      "resolution_status": "unresolved"
    }
  ],
  "issues": [],
  "summary": {
    "source_files_inspected": 4,
    "route_count": 4,
    "resolved_route_count": 3,
    "unresolved_route_count": 1,
    "issue_count": 0,
    "is_complete": true,
    "discovery_is_complete": true,
    "discovery_truncation_reasons": []
  }
}
```

## Attack surface summary reporting

```http
GET /api/v1/assessments/{assessment_id}/attack-surface/summary
```

The endpoint resolves the repository target registered for the assessment, runs the
existing deterministic discovery, technology, route, authentication, input,
sensitive-operation, correlation, handler/call, and input-to-operation flow analyses,
and returns the consolidated attack-surface summary directly. The HTTP response uses
`AttackSurfaceSummaryResponse`; the internal `AttackSurfaceSummaryResult` is not
returned because it carries the absolute repository root.

The response has five top-level fields:

- `repository` — the repository path relative to its configured allowed root.
- `routes` — one entry per route, containing the original authentication,
  authorization, input, sensitive-operation, correlation, handler, definition, call,
  and flow evidence associated with that route.
- `global_evidence` — handler, definition, call, and flow evidence that could not be
  associated with a summarized route.
- `issues` — deduplicated issues with their original categories, identifiers, source
  locations, explanations, and origins.
- `summary` — aggregate counts, resolution totals, issue totals, and per-source
  completeness/truncation metadata.

The result is recalculated on every request. It is not cached, stored, or exposed as
an immutable snapshot, so repository changes between requests are reflected in the
next response. The endpoint performs no database writes and does not persist analysis
results.

Error behavior:

- Unknown assessment: `404 Not Found` with `{"detail": "Assessment not found"}`.
- Assessment without a registered repository target: `404 Not Found` with
  `{"detail": "Repository target not found"}`.
- Registered target that no longer exists, is no longer a directory, or is outside
  the configured allowed roots: `422 Unprocessable Entity` with
  `{"detail": "Registered repository target is no longer valid"}`. The same response
  is returned when analysis execution revalidates the target immediately before
  creating an analysis run, or when a later analysis stage detects that the
  repository root has become invalid.
- Invalid assessment UUID: `422 Unprocessable Entity` from request validation.
- Unexpected analysis failure: `500 Internal Server Error` with a generic detail
  message. No stack trace or internal filesystem detail is returned.

The endpoint sets `Cache-Control: no-store` on successful responses, error responses,
and request-validation errors because a repository can change between requests. This
header is scoped to the summary endpoint and does not change caching for other routes.
The OpenAPI schema documents the `200`, `404`, `422`, and `500` responses.

Filesystem disclosure: the response never includes an absolute server-side path.
`repository` is relative to the configured allowed root, and source evidence uses
repository-relative paths. Raw filesystem exception messages are not included in
issues or API errors; failed inspections use generic details while preserving the
reason category and repository-relative source location.

Analysis execution revalidates the registered target immediately before creating a
run and each analysis stage revalidates the root before reading files. This reduces
the time between validation and use, but it does not make traversal race-free; see
the repository discovery TOCTOU limitation above.

Current limitations:

- Analysis runs synchronously inside the request and can be expensive for large
  repositories. There is no background worker or progress reporting. Cooperative
  execution deadlines and heartbeats bound pipeline work, and process-local
  admission control bounds concurrency and per-user request rates; those limits
  are not deployment-wide and provide no guaranteed fair ordering.
- Each request re-reads and re-parses the same source files across several analysis
  stages. This repeated parsing cost remains a known performance limitation; the
  database read transaction is ended after discovery so its connection is released
  before the analysis pipeline runs.
- Responses include full nested evidence and are not paginated or field-filtered, so
  they can be large.
- Assessment APIs require authentication and enforce the role and ownership policy
  described above. Repository responses and attack-surface summaries use
  repository-relative paths; the absolute stored repository path is not exposed.
  The service should still be restricted to trusted deployments and placed behind an
  authenticating gateway where appropriate.

## Analysis tool extension seam

Added in M1 (see `docs/adr/0001`–`0004`). Since M2, analysis runs execute the
registry built in `app/services/analysis_tools.py` (currently the secret scanner)
after the static pipeline. The static pipeline itself still runs directly.

- `app/schemas/tooling.py`: `ToolResult`, `EvidenceRecord`, `EvidenceLocation`,
  `EvidenceProvenance`, `ToolStatus` (`completed`, `partial`, `failed`, `skipped`,
  `cancelled`), and `SafeErrorCode`. Validators reject absolute host paths and `..`,
  bound excerpts to 240 characters, require an error code for
  failed/skipped/cancelled results (and forbid one for completed results), and
  require a partial result to state its limitations.
- `app/services/tooling/protocol.py`: the `AnalysisTool` protocol and the immutable
  `ToolContext`.
- `app/services/tooling/registry.py`: `StageRegistry` (ordered, duplicate-free) and
  `PipelineConfig` (enabled stages, per-stage `ToolBudget`, read-only options).
- `app/services/tooling/executor.py`: `run_stages`. Every registered stage is
  reported. Disabled or inapplicable stages are `skipped`, exceptions are `failed`
  (`tool_error`, with no exception text), cancellation or run timeout is
  `cancelled` for the remaining stages, and a stage budget overrun is `failed`
  (`budget_exhausted`). `PipelineOutcome.is_clean` is true only when every stage
  completed without evidence.
- `app/services/tooling/redaction.py`: fixed-width masking, excerpt, header, and URL
  redaction, content hashes, HMAC fingerprints, and deterministic evidence keys.
- `app/services/tooling/target_policy.py`: `TargetAuthorizationPolicy`
  (`DenyAllTargetPolicy` by default) and `NetworkSafetyPolicy` with conservative
  defaults and special-purpose address blocking. Enforcement arrives in M4.
- `app/services/tooling/adapters.py`: `StaticAttackSurfaceTool` exposes the
  existing pipeline (via `analyze_discovered_repository`) as one tool, mapping
  resolved input-to-operation relationships to repository evidence and
  incompleteness to `partial`.

## Secret scanning

Added in M2 (ADR-0005). The scanner is `SecretScannerTool` (stage `secret_scan`,
tool version `1.0.0`, rule set `secret-rules-2026.11.1`).

| Rule ID | Detects | Severity | Base confidence |
| --- | --- | --- | --- |
| `secret.private_key_block` | `-----BEGIN … PRIVATE KEY-----` | high | 0.95 |
| `secret.aws_access_key_id` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 | high | 0.90 |
| `secret.aws_secret_access_key` | 40-character value assigned to `aws_secret_access_key` | critical | 0.90 |
| `secret.github_token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` tokens | high | 0.95 |
| `secret.github_fine_grained_token` | `github_pat_…` | high | 0.95 |
| `secret.gitlab_token` | `glpat-…` | high | 0.90 |
| `secret.slack_token` | `xox[abprs]-…` | high | 0.85 |
| `secret.stripe_live_key` | `sk_live_`/`rk_live_` | critical | 0.90 |
| `secret.google_api_key` | `AIza` + 35 | medium | 0.85 |
| `secret.connection_string_password` | password in `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis://`, `amqp://`, … URLs | high | 0.85 |
| `secret.jwt` | `eyJ….eyJ….…` | medium | 0.70 |
| `secret.dotenv_assignment` | non-placeholder value for a secret-like name in `.env`-style files | high | 0.60 |
| `secret.generic_assignment` | quoted value ≥ 16 characters with ≥ 3.5 bits/character entropy assigned to a secret-like name | medium | 0.40 |
| `custom.*` | operator-defined (`SECRET_SCAN_CUSTOM_RULES`) | configured | 0.70 |

Confidence is halved in test-fixture and example paths. Run results appear in
`analysis_metadata.tools[]` as `stage`, `tool`, `version`, `rule_set_version`,
`status`, `error_code`, `counts` (`files_scanned`, `bytes_scanned`, `matches`,
`placeholders_ignored`, `allowlisted`, `long_lines_truncated`, `skipped_<reason>`),
`evidence_count`, and `limitations`. `analysis_metadata.completeness` adds
`static_analysis_is_complete`, `tools_are_complete`, and `incomplete_tools`;
`is_complete` is true only when both parts are complete.

Each secret finding's evidence `details` contains `evidence_key`, `rule_id`,
`rule_set_version`, `path`, `line`, `redacted_excerpt`, `fingerprint`,
`file_context` (`source`, `test_fixture`, `example`), and `limitations`.

## Guarded egress client

`app/services/net/guarded_client.py` (ADR-0006). `GuardedHttpClient(policy,
allowed_hosts=…)` supports GET, HEAD, and POST and raises `EgressError(code)` with
codes `scheme_not_allowed`, `host_not_allowed`, `credentials_in_url`,
`invalid_url`, `dns_failure`, `blocked_address`, `redirect_limit`,
`redirect_loop`, `bad_redirect`, `timeout`, `response_too_large`,
`decompression_limit`, `content_type_not_allowed`, `connection_failed`, and
`request_budget_exhausted`. `GuardedResponse` exposes `status`, `headers`, `body`,
`final_url` (redacted), `redirect_chain` (redacted), `elapsed_seconds`, and
`redacted_headers()`.

## Dependency advisory analysis

Stage `dependency_audit`, tool `dependency_auditor` 1.0.0, rule
`dependency.osv_advisory` (ADR-0007).

| File | Ecosystem | Exact versions from | Relationship |
| --- | --- | --- | --- |
| `requirements*.txt` | PyPI | `==` pins | direct |
| `pyproject.toml` | PyPI | `==` pins (PEP 621), exact Poetry strings | direct |
| `poetry.lock` | PyPI | all entries | direct if declared in the sibling `pyproject.toml`, otherwise transitive |
| `Pipfile.lock` | PyPI | `==` versions | unknown |
| `package.json` | npm | exact `x.y.z` | direct |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | all entries (v1–v3) | direct if declared by the root package |

Tool counts: `manifests_parsed`, `dependencies`, `resolved_versions`,
`unresolved_versions`, `direct_dependencies`, `packages_checked`,
`packages_unchecked`, `stale_package_results`, `advisory_matches`,
`provider_requests`, `file_issues`. Limitation codes: `unresolved_versions`,
`advisory_data_unavailable`, `stale_advisory_data`, `max_packages`,
`file.<reason>` (`malformed`, `oversize`, `symlink`, `unsupported_lock_format`, …),
`range_check_unsupported`, `range_check_disagreement`.

Dependency finding evidence `details` contains `evidence_key`, `rule_id`, `path`,
`ecosystem`, `package`, `version`, `relationship`, `dependency_source`, `dev`,
`advisory_id`, `aliases`, `cve_ids`, `range_check`, `match_explanation`,
`fixed_versions`, `published`, `modified`, `source`, `source_url`, `fetched_at`,
`freshness`, `provider_severity`, and `limitations`.

Run completeness: a tool that is `skipped` with `not_applicable` (for example no
dependency files) does not make `completeness.is_complete` false; a disabled,
failed, cancelled, or partial tool does.

## Target authorization

Added in M4 (ADR-0004).

| Method | Path | Role | Success | Errors |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/assessments/{id}/web-target` | owner/Admin (manage) | `201` target | `422` invalid URL / host not allowlisted / missing confirmation or statement; `409` not a web assessment, not queued, already registered |
| `GET` | `/api/v1/assessments/{id}/targets` | any role (visible) | `200` list | `404` |
| `POST` | `/api/v1/assessments/{id}/targets/{target_id}/authorize` | owner/Admin | `200` target | `409` already authorized; `404`; `422` |
| `POST` | `/api/v1/assessments/{id}/targets/{target_id}/revoke` | owner/Admin | `200` target | `409` already revoked; `404` |

Request body for `web-target`: `base_url`, `authorization_statement`
(20–1000 characters), `confirm_authorized: true`. Body for `authorize`:
`authorization_statement`, `confirm_authorized: true`. Response fields: `id`,
`assessment_id`, `target_type`, `target` (repository path relative to its root, or
canonical URL), `status`, `authorization_basis`, `authorization_statement`,
`created_by_user_id`, `authorized_by_user_id`, `authorized_at`,
`revoked_by_user_id`, `revoked_at`, `policy_snapshot`, `created_at`, `updated_at`.

`POST …/analysis-runs` and `GET …/attack-surface/summary` return
`409 {"detail": "Target authorization is required before analysis"}` when the
repository target's record is missing, pending, or revoked. With
`REPOSITORY_ISOLATION=per_user`, a target outside the owner's sub-root returns the
generic `422` at registration and `422 Registered repository target is no longer
valid` at analysis time.

## Web crawling

Added in M5 (ADR-0008). `POST /api/v1/assessments/{id}/analysis-runs` on a
`web_security` assessment:

- `404 {"detail": "Web target not found"}` when no web target is registered;
- `409 {"detail": "Target authorization is required before analysis"}` when the
  target is pending, revoked, or its host is no longer allowlisted (no run record
  is created);
- otherwise `201` with the run. A crawl failure does not fail the run; the tool
  status records it.

Web run `analysis_metadata`: `analyzer`, `target` (`type`, `url`),
`finding_count`, `completeness` (`is_complete`, `tools_are_complete`,
`incomplete_tools`), `tools[]` (stage `web_crawl`, tool `web_crawler` 1.0.0), and
`crawl_inventory` with at most 200 entries each in:

- `pages[]`: `path`, `status`, `content_type`, `depth`, `title`, `parameters`;
- `forms[]`: `page`, `method`, `action`, `classification`, `fields[]`
  (`name`, `type`, `required`), `submitted` (always false);
- `auth_boundaries[]`: `path`, `signal`.

Crawler counts: `pages_fetched`, `requests_made`, `forms_recorded`,
`evidence_records`, `request_errors`, `skipped_<reason>` (`unsafe_link`,
`out_of_scope`, `robots_disallowed`, `variant_limit`, `depth_limit`,
`redirected_out_of_scope`). Limitation codes: `truncated.max_pages`,
`truncated.max_requests`, `truncated.max_forms_recorded`,
`request_failed.<egress code>`, `skipped.<reason>`, `parse_truncated`.

## Runtime probes

Added in M6 (ADR-0009). Stage `runtime_probes`, tool `runtime_prober` 1.0.0,
rule set `probe-policy-1`. It runs after `web_crawl` when
`RUNTIME_PROBES_ENABLED=true`.

| Rule | Verdicts → finding status | Category / severity |
| --- | --- | --- |
| `runtime.xss_reflection` | `potential` → potential; `inconclusive` → inconclusive | `xss` / medium |
| `runtime.sqli_boolean` | `confirmed` → confirmed; `inconclusive` → inconclusive | `sqli` / high |
| `runtime.sqli_error_signal` | `potential` → potential | `sqli` / medium |

Evidence `details` include `rule_id`, `url_path` (path and parameter name),
`parameter`, `verdict`, `request_summary`, `response_summary` (status and length,
plus content type for XSS), and either `reflection_context` and `reproduced`
(XSS) or `sql_context`, `observations` (similarities), and `thresholds` (SQLi),
plus `cwe_ids` and `limitations`.

Counts: `candidate_parameters`, `probe_requests`, `xss_not_reflected`,
`xss_reflected_encoded`, `xss_potential`, `xss_inconclusive`,
`sqli_confirmed`, `sqli_inconclusive`, `sqli_error_signal`, `sqli_no_signal`,
`sqli_unstable_baseline`, and `skipped_<reason>` (`sensitive_parameter`,
`unsafe_endpoint`, `post_or_external_form`, `parameter_budget`, `out_of_scope`).

## Normalized evidence and retest

Added in M7 (ADR-0010).

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/assessments/{id}/evidence` | Query: `analysis_run_id` (404 if not this assessment's run), `limit` 1–200 (default 100), `offset`. Oldest first. |
| `GET` | `/api/v1/assessments/{id}/evidence/{evidence_id}` | 404 when the item belongs to another assessment. |

Evidence item fields: `id`, `analysis_run_id`, `evidence_key`, `source_type`,
`tool_name`, `tool_version`, `rule_set_version`, `rule_id`, `method`,
`location_path`, `location_line`, `url_path`, `parameter`, `summary`,
`redacted_excerpt`, `content_hash`, `fingerprint`, `request_summary`,
`response_summary`, `limitations`, `details`, `observed_at`.

New `FindingRead` fields (null or empty for pre-0017 findings): `rule_id`,
`source_stage`, `verification_method`, `status_rationale`, `cwe_ids`, `cve_ids`,
`first_seen_at`, `last_seen_at`, `previous_status`, `evidence_ids`.

Run metadata adds `retest`: `previous_run_id`, `new`, `recurring`,
`not_reproduced`, `evidence_items`. `finding_count` includes `not_reproduced`
findings.

## Background execution and recovery

Added in M8 (ADR-0011, migration `0018`).

Run states: `queued` → `running` → `completed` | `failed` | `cancelled`. A
`running` run may also go back to `queued` when a retry is due. At most one
`queued` or `running` run exists per assessment; the partial unique index
`uq_analysis_runs_active_assessment` enforces this.

| Endpoint | Behaviour |
| --- | --- |
| `POST …/analysis-runs?mode=async` | 400 unless `ANALYSIS_ASYNC_ENABLED`; validates the target; commits a `queued` run with an `analysis_run.queued` event; 202 with `Location`. 409 when the assessment already has an active run; 429 when the user's queued and running runs on other assessments reach `ANALYSIS_MAX_CONCURRENT_JOBS_PER_USER` (counted in the database). |
| `POST …/analysis-runs/{run_id}/cancel` | Queued run: `cancelled` now, with an `analysis_run.cancelled` event. Running run: sets `cancel_requested_at` (repeatable); the run stops at its next heartbeat or stage check and ends `cancelled`. Terminal run: 409. Other assessment's run: 404. |
| `GET …/attack-surface/summary?source=persisted` | Summary stored by the newest `completed` repository run; 404 if none. The default `source=live` recalculates as before. |

New run fields (all runs): `stage`, `attempts`, `error_code`, `cancel_requested_at`.
`started_at` holds the creation time while a run is queued, and the claim time
afterwards.

Worker (`python -m app.worker [--once | --recover-only]`). It validates the
deployment configuration like the API, then loops:

1. **Recover.** A running run is stale when its lease has expired, or, for rows
   without a lease, when its heartbeat (or start) is older than
   `ANALYSIS_STALE_AFTER_SECONDS`. A stale run with a cancellation request
   becomes `cancelled`. A stale worker run with attempts left is requeued
   (`error_code=lease_expired_retry`). Anything else becomes `failed` with
   `lease_expired`; this includes synchronous runs, whose caller is gone.
2. **Claim.** One conditional UPDATE claims the oldest `queued` run, provided
   fewer than `ANALYSIS_WORKER_MAX_RUNNING` worker runs are running. It sets the
   lease owner, the lease expiry, `attempts + 1`, and `started_at`. The
   `analysis_run.started` event (context: attempt) commits with the claim.
3. **Execute.** The worker validates the target again; a failure here is
   permanent (`target_validation_failed`). It then runs the shared pipeline. The
   heartbeat renews only while the worker still owns the lease and no
   cancellation was requested; it records `stage`. Completion and failure are
   conditional on the lease, so a worker whose lease was taken over writes
   nothing.
4. **Retry.** A database `OperationalError` requeues the run
   (`transient_retry`) while `attempts < ANALYSIS_WORKER_MAX_ATTEMPTS`; otherwise
   the run fails. All other errors are permanent, with sanitized messages and
   `error_code` set to `<stage>_failed` or `deadline_exceeded`.

Findings and evidence are written only in the completion transaction, so an
abandoned attempt leaves nothing behind and a retry cannot duplicate findings.

Error codes: `cancelled`, `deadline_exceeded`, `lease_expired`,
`lease_expired_retry`, `transient_retry`, `transient_retries_exhausted`,
`target_validation_failed`, `analysis_failed`, `finding_generation_failed`,
`finding_persistence_failed`, `completion_failed`.

Limitations:
- The queue is the database; there is no broker and no push notification.
- Cancellation is cooperative.
- The running cap is exact on both SQLite and PostgreSQL (advisory lock plus
  `FOR UPDATE SKIP LOCKED` on PostgreSQL; see ADR-0016).
- The migration 0018 downgrade refuses while queued or cancelled runs, or
  queue/cancel audit events, exist.

## Advisory LLM explanations

Added in M9 (ADR-0012, migration `0019`). Off unless `LLM_EXPLANATIONS_ENABLED=true`;
requires the optional `[ai]` extra.

| Endpoint | Behaviour |
| --- | --- |
| `POST …/findings/{finding_id}/explanations` | Analyst/Admin. 400 when disabled; 404 for an unknown finding or one in another assessment; 429 on rate limit (scope `analysis.explanation`) or when the assessment's token budget is used up. Otherwise 201 with the stored attempt, whether `available` or `unavailable`. |
| `GET …/findings/{finding_id}/explanations` | Any role. Attempts, newest first. |

Response fields: `status`, `error_code`, `explanation` (`summary`,
`technical_explanation`, `impact`, `affected_component`, `evidence_references`,
`claims[{statement, evidence_ids}]`, `remediation_steps`, `validation_guidance`,
`uncertainty`), `provider`, `model`, `prompt_template_version`,
`supplied_evidence_ids`, `input_tokens`, `output_tokens`, `created_at`, and a fixed
`advisory_notice`.

Error codes:
- provider: `provider_not_configured`, `provider_not_installed`,
  `provider_timeout`, `provider_rate_limited`, `provider_unavailable`,
  `provider_refused`, `provider_output_truncated`, `provider_bad_request`,
  `provider_error`;
- output validation: `empty_output`, `output_too_large`, `invalid_json`,
  `schema_validation_failed` (including any attempt to return status or
  severity), `ungrounded_output` (an ID that was not supplied).

What is sent:
- the finding's id, title, category, rule, stage, status, severity, confidence,
  summary, affected component, verification method, status rationale, CWE, and
  CVE;
- up to `LLM_MAX_EVIDENCE_ITEMS` evidence items, each with id, source type,
  tool, rule, method, relative location, URL path, parameter, summary, an
  excerpt of at most 600 characters, request/response summary keys
  (`method`, `parameter`, `probe_kind`, `status_code`, `length`, `status`), and
  limitations;
- for findings without normalized evidence, their legacy evidence descriptions.

Every string is scrubbed. Fingerprints, hashes, bodies, cookies, and host paths
are never sent. The finding and its evidence are never modified.

## Assessment workflows

Added in M10 (ADR-0013, migration `0020`). Graph `assessment-workflow/1`:
`load_assessment → validate_authorization → plan_enabled_checks → approval_gate →
run_analysis → explain_findings → generate_report → finalize_run`.

| Endpoint | Behaviour |
| --- | --- |
| `POST …/workflows` `{"explain_findings": bool}` | Analyst/Admin; uses the `analysis.run` rate limit. Runs nodes until the workflow completes, fails, pauses for approval, or hits a retryable error, then returns 201 with the workflow and its events. 409 if the assessment already has an active workflow. |
| `GET …/workflows`, `GET …/workflows/{id}` | Any role. Status, current node, step count and budget, plan (checks with risk, decision, and reason, plus the config snapshot), approvals, pending approvals, linked run, error code, and the event log. |
| `POST …/workflows/{id}/approvals` `{"check": "runtime_probes", "decision": "approve"\|"deny", "reason": "..."}` | Only while `awaiting_approval` and only for a pending check (otherwise 409); any other check name is 422. Records who decided and why, then continues the workflow. |
| `POST …/workflows/{id}/resume` | Only while `running`, after a retryable error or an interruption. 409 while another request is executing a step, unless that step's marker is older than `ANALYSIS_STALE_AFTER_SECONDS`. |
| `POST …/workflows/{id}/cancel` | Cancels a running or awaiting-approval workflow, and requests cancellation of its analysis run if one is in progress. |

Plan decisions:
- **Repository targets:** static analysis, secret scan, and dependency audit
  run unless configuration disables them.
- **Web targets:** the crawl runs. `runtime_probes` is `needs_approval` when
  `RUNTIME_PROBES_ENABLED=true`, and is skipped otherwise.
- **`explain_findings`:** runs only when requested, enabled, and the limit is
  above zero.
- **`generate_report`:** builds the report (M12) and records its content hash.

Unapproved or denied tool checks are passed to the analysis as excluded stages,
which can only remove configured stages.

**Orchestration engine (M14, ADR-0017).** `WORKFLOW_ENGINE` selects `builtin`
(default) or `langgraph`. The LangGraph engine compiles a `StateGraph` with one
node per stage in the fixed `NODE_SEQUENCE` and only conditional edges; each node
runs the same `run_step_for_node` the built-in engine runs, so the claim,
budgets, approval gate, persistence, audit, and recovery are identical.
LangGraph drives traversal only and makes no LLM, tool, or network call;
traversal is bounded by `WORKFLOW_MAX_STEPS` and, as a backstop, LangGraph's
recursion limit. `langgraph` needs the `[orchestration]` extra, and the app
refuses to start if it is selected but not installed.

Event outcomes: `completed`, `skipped`, `paused`, `failed`, `error` (retryable),
`approval_recorded`, `cancelled`, `discarded` (a node finished after the
workflow was cancelled; its result was not applied).

Error codes: `assessment_not_found`, `target_not_authorized`, `analysis_failed`,
`analysis_cancelled`, `analysis_in_progress`, `capacity_unavailable`,
`active_run_conflict`, `<node>_error`, `node_attempts_exhausted`,
`step_budget_exhausted`, `cancelled`.

## Knowledge retrieval

Added in M11 (ADR-0014, migration `0021`).

**Corpus.** `app/knowledge/manifest.json` and its Markdown documents. An
optional `RAG_CORPUS_DIR` uses the same format. Each document entry has:
- `id`, `file` (a relative `.md` path), `title`, `version`, `updated_at`,
  `review_interval_days`;
- `source_type`: `project_guidance`, `owasp`, `cwe`, or `advisory`;
- `license`;
- `categories`: finding categories, with `*` wildcards; `*` alone means
  general guidance;
- `cwe_ids`, and `references` (https URLs only).

Documents larger than 50 000 characters, or containing secret-like or personal
data, are rejected, and the whole corpus is then unavailable. Chunks are cut on
`##` sections and paragraphs, with IDs `kb:<document>#<n>`. The version string
is `name@version(+operator@version)+<16 hex of SHA-256 over documents and chunks>`.

**Retrieval** (`RAG_BACKEND`).
- `lexical` is BM25 with light stemming.
- `vector` is cosine similarity over a local 512-dimension hashing embedder; on
  error it falls back to `lexical` with `fallback_reason=embedding_unavailable`.
- Stale documents are excluded unless `RAG_INCLUDE_STALE`, in which case results
  carry `stale: true`.
- Documents matching the finding's category or CWE rank first, then general
  guidance. If nothing matches, the whole corpus is searched (`filtered: false`).
- At most `RAG_MAX_CHUNKS` results.

**In explanations.** Retrieved chunks are sent in a `<reference_material>`
block of escaped JSON, before `<finding_data>`. The prompt template is
`finding-explanation/2`. Output rules:
- `source_references` must be a subset of the supplied `kb:` IDs, otherwise
  `ungrounded_sources`;
- if any were supplied, at least one must be cited, otherwise `uncited_sources`;
- `evidence_references` may not contain `kb:` IDs (`ungrounded_output`);
- claims may cite `kb:` IDs for remediation.

The explanation's `retrieval` field records:
- `status`: `used`, `none_relevant`, `unavailable`, or `disabled`;
- `backend` and `fallback_reason`;
- `filtered`;
- `knowledge_base_version`;
- `source_ids`, and `sources` with license and references.

**API.**

| Endpoint | Behaviour |
| --- | --- |
| `GET /api/v1/knowledge` | Any authenticated role. Name, version, content hash, backend, and per-document metadata with `stale` and `chunk_count` (no file paths). 404 when RAG is disabled; 503 when the corpus is invalid. |
| `GET /api/v1/knowledge/search` | `q` (2–200 characters), optional `category`, optional `cwe` (`CWE-<n>`), and `limit` (1–10). Returns attributed chunks with scores. |

## Assessment reports

Added in M12 (ADR-0015). No migration.

| Endpoint | Behaviour |
| --- | --- |
| `GET …/reports/json` | Any role that can read the assessment (others get 404). Optional `analysis_run_id`; an unknown run, or a run of another assessment, is 404. Otherwise the latest completed run is used, then the latest failed or cancelled one, then none. |
| `GET …/reports/html` | The same report, rendered as self-contained HTML. |

Headers on both: `Content-Disposition: attachment;
filename="assessment-<id>-report.<ext>"`, `Cache-Control: no-store`, and
`X-Content-Type-Options: nosniff`. The HTML response also carries
`Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; img-src
'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. The same
policy, minus `frame-ancestors`, is embedded as a meta tag. A report over
`REPORT_MAX_BYTES` returns 413.

JSON fields (schema `assessment-report/1`, sorted keys):
- `schema_version`, `generator`, `generated_at`, and `content_hash` (SHA-256
  over everything except `generated_at`);
- `assessment`, `target` (relative or redacted display and authorization), `run`;
- `scope`: `tools` with versions and statuses, `completeness`, and `workflow`
  (plan checks, configuration snapshot, approvals);
- `executive_summary` and `counts`;
- `findings[]`: classification, locations, `evidence[]`, `evidence_omitted`,
  `ai_explanation` (labelled; latest available only);
- `findings_omitted`, `checks_not_run[]`, `limitations[]`, `advisories[]`
  (advisory ID, package, version, aliases, CVEs, OSV reference), `retest`.

Every string is scrubbed again. Fingerprints, hashes, bodies, cookies, and
absolute paths are never included.

## PostgreSQL

Added in M13 (ADR-0016). Use `DATABASE_URL=postgresql+psycopg://…` with the
`[postgres]` extra.

- **Migrations.** The whole chain (`0001`–`0021`) upgrades, passes
  `alembic check`, downgrades to base, and re-upgrades on PostgreSQL 16. The
  partial unique indexes (`uq_analysis_runs_active_assessment`,
  `uq_assessment_workflows_active_assessment`) and named CHECK constraints
  exist with the same predicates as on SQLite.
- **Worker claim.** A transaction-scoped `pg_advisory_xact_lock` serializes the
  cap check and the claim; the candidate is selected with
  `FOR UPDATE SKIP LOCKED`. `ANALYSIS_WORKER_MAX_RUNNING` is exact.
- **Tests.** `TEST_POSTGRES_URL` switches the `db_engine` fixture to one fresh
  schema per test. `tests/test_postgres_migrations.py` runs only in that mode.
