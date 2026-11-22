# AI Security Analyst — Frontend

React + TypeScript + Vite single-page app for the AI Security Analyst backend.
Dark-first security-operations UI. The backend is the authoritative security
boundary; this app only reflects capabilities that real APIs support.

## Stack

React 18 · TypeScript · Vite · Tailwind CSS · shadcn/ui-style components (Radix)
· TanStack Query · React Router · Lucide. Types are generated from the backend's
OpenAPI spec (`openapi-typescript`).

## Develop

```bash
npm install
npm run gen:api     # regenerate src/lib/api/schema.d.ts from src/lib/api/openapi.json
npm run dev         # http://localhost:5173 (proxies /api and /health to the backend)
```

Run the backend separately (default `http://127.0.0.1:8000`); override with
`VITE_PROXY_TARGET`. There is no CORS middleware by design — dev uses the Vite
proxy and production is served same-origin behind a reverse proxy.

### Authentication (Stage 2)

The access token is held **in memory only** (never in `localStorage`); the
refresh token lives in an HttpOnly, Secure, SameSite cookie set by the backend
and is never readable by JavaScript. On load and on expiry the app silently calls
`POST /api/v1/auth/refresh` (no body — the cookie carries the token, echoed with a
double-submit `X-CSRF-Token` header read from the readable `aisa_csrf` cookie).
Unauthenticated visitors are routed to `/login`; the rest of the app is gated by
`RequireAuth`. The backend remains the authoritative boundary — route/role gating
here is UX only.

To exercise the cookie flow against a **local dev** backend over http, start the
backend with `AUTH_COOKIE_SECURE=false` (the Vite proxy is same-origin http, and a
browser refuses to return a Secure cookie over http). In staging/production the
backend requires Secure cookies and fails closed otherwise.

### Assessments (Stage 3)

`features/assessments/` wires the first real vertical to the backend: list
(`GET /assessments`, offset paging), create (`POST /assessments`), detail
(`GET /assessments/{id}` + `/history`), repository source config
(`POST /assessments/{id}/repository`, `local_path`), and the analysis-run
lifecycle. Runs are started with `mode=async` and **polled** (every 4s while any
run is `queued`/`running`) — so the backend **background worker** must be running
for queued runs to progress (`python -m app.worker`), and async analysis must be
enabled; otherwise `Start run` returns a clear "asynchronous analysis is not
enabled" message. Web-target (web_security) configuration is intentionally
deferred to the Attack Surface stage, where the authorization flow lives.

### Findings (Stage 4)

`features/findings/` reviews findings per assessment (`GET /assessments/{id}/findings`,
optional `analysis_run_id` filter — there is no global findings endpoint, so the
top-level **Findings** nav is an assessment picker). Severity, status and
confidence come from deterministic analysis and are authoritative; the page sorts
by severity, summarizes counts, filters by run/status, and expands each finding to
its detail and embedded evidence. Each finding can show **advisory AI explanations**
(`GET`/`POST …/findings/{id}/explanations`) — the "Generate" action costs LLM
tokens and needs LLM explanations enabled on the backend (otherwise it returns
`unavailable`). Explanations are clearly labeled advisory and never change a
finding's status, severity, or confidence.

### Attack Surface (Stage 5)

`features/attack-surface/` manages authorized **targets** and the per-assessment
**attack-surface summary** (top-level **Attack Surface** nav is an assessment
picker). For `web_security` assessments it completes the deferred Stage 3 path:
register a web target (`POST …/web-target`) with a base URL, an authorization
statement, and an explicit confirmation checkbox (the backend's required
`confirm_authorized: true`), then authorize/revoke targets (`…/targets/{id}/
authorize` · `/revoke`). The summary (`GET …/attack-surface/summary?source=live|
persisted`) shows curated metrics, a routes table, and an issues list; deep
per-route internals (call graph) are deferred. The optional DVWA lab-credentials
flow is deferred (off by default on the backend). **Only register targets you are
authorized to assess** — the UI never sends an authorization you did not make, and
the backend remains the authoritative boundary.

### Reports (Stage 6)

`features/reports/` presents the per-assessment report (top-level **Reports** nav
is an assessment picker), with an optional run filter. It renders an in-app summary
from the **JSON report** (`GET …/reports/json`) — executive summary, severity/status
counts, findings, and the backend's honest caveats (omitted findings, limitations).
The JSON report is free-form in the OpenAPI spec, so every field is read
defensively. The **HTML report** (`GET …/reports/html`, fetched as raw text via the
client's `responseType: "text"`) is shown in a **sandboxed `<iframe>`** (no scripts)
and can be downloaded or opened in a new tab; JSON is downloadable too. Downloads
are client-side blobs of already-fetched content.

### Workflows (Stage 7)

`features/workflows/` drives the bounded workflow engine per assessment (linked
from the Assessment Detail page; there is no top-level Workflows nav slot). You can
start a workflow (`POST …/workflows`, with an optional AI-explanations toggle), and
each workflow detail shows progress (current node, step N/max, graph version),
**polled** every 4s while `running`/`awaiting_approval`, plus an events timeline.
The **approval gate** (`POST …/approvals`) records an explicit approve/deny with a
required reason for a pending check (e.g. `runtime_probes`); **cancel**
(`…/cancel`) and **resume** (`…/resume`) are shown by status. Every action is a
user-initiated state change; the backend stays authoritative.

### Evidence (Stage 8)

`features/evidence/` browses the evidence an assessment's analysis collected
(top-level **Evidence** nav is an assessment picker). `GET …/evidence` supports a
run filter and limit/offset pagination and returns full, already-redacted items;
each row expands inline to its detail — tool, rule, location, observed time,
redacted excerpt, and allowlisted request/response summaries — with no separate
fetch. The backend redacts bodies and secrets before the data ever leaves it.

### Audit Logs (Stage 9)

`features/audit/` is a top-level **admin-only** page (`/audit`) over
`GET /admin/audit-events`, which returns a paginated `AuditEventPage` (items +
total), so paging shows real totals. The table lists each event's time, action,
outcome (`success`/`failure`/`denied`), resource type, actor, and a link to the
assessment when present, with filters for outcome, action, and assessment id. It
is gated by the backend: a non-admin gets `403`, rendered as an access-denied
state. The sidebar also hides the link for non-admins (convenience only).

### Overview dashboard (Stage 10)

`features/overview/` is the landing page. It shows live backend connectivity
(`/health`) and an assessment breakdown by status and type — **derived
client-side** from the latest N assessments (`GET /assessments`) and clearly
labelled as a local rollup, because the backend exposes no aggregate-statistics
endpoint and nothing here is fabricated. It also lists recent assessments and
quick links. The earlier placeholder "Recent findings" rollup was dropped (findings
are per-assessment with no global endpoint, so a global rollup would be invented).

### Administration (Stage 11)

`features/administration/` is an admin-only page (`/administration`) over
`GET /admin/security-monitoring/denial-patterns`, surfacing actor/resource/action
combinations repeatedly denied authorization. It has a look-back **window**
selector (the endpoint requires explicit `from_time`/`to_time`) and a
**min-attempts** threshold, and a table of patterns with attempt counts and
first/last seen. Admin-gated by the backend (403 → access-denied state).

## Quality

```bash
npm run typecheck   # tsc, no emit
npm run lint        # eslint
npm run test        # vitest (jsdom, mocked APIs)
npm run build       # production build (tsc -b + vite build)
```

## Structure

```
src/
  lib/api/      typed fetch client + generated OpenAPI types + /health hook
  lib/auth/     in-memory token store, CSRF helper, auth API, AuthProvider/context
  lib/query/    TanStack Query client and keys
  lib/theme/    dark-first theme provider
  components/ui/       shadcn-style primitives (Radix)
  components/auth/     RequireAuth route guard
  components/layout/   AppShell, Sidebar, Topbar, Breadcrumbs, nav model
  components/states/   Loading / Empty / Error / stage placeholders
  components/common/   SeverityBadge, StatusPill
  features/auth/       LoginPage
  features/<area>/     one page per backed capability
  routes/       React Router configuration
  test/         Vitest setup
```

## Regenerating the API contract

The committed `src/lib/api/openapi.json` is a snapshot of the backend spec. To
refresh it, dump `app.openapi()` from the backend into that file, then run
`npm run gen:api`.
