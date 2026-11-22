# M0 — Repository Re-audit and Extension Plan

Blueprint: `implementaion project.md` (Advanced Security Engine Implementation
Blueprint). Status: **awaiting owner approval. No code was changed in M0.**

Inputs read: the blueprint, `README.md`, `FINAL_PROJECT_RELEASE_REPORT.md`,
`docs/TECHNICAL_REFERENCE.md`, all models, services, APIs, and migrations, and the
test suite. `implementaion.md` is empty. The project context document and the
original plan `.docx` are still not available; the academic synopsis PDF remains the
scope baseline.

## 1. Current architecture and feature inventory

| Area | What exists (verified in code) |
| --- | --- |
| API | `app/api/auth.py`, `v1.py` (assessments, repository target, findings), `analysis_runs.py`, `attack_surface.py`, `admin_audit.py`, `admin_security_monitoring.py`; dependencies resolve a database-bound principal and enforce role + ownership |
| Identity | Registration, verification, reset, login, refresh rotation with replay detection, logout; Argon2id, HS256 JWT, hashed opaque tokens; failed-login throttle |
| Persistence | SQLite, SQLAlchemy 2, Alembic head `0014` (linear chain `0001`–`0014`) |
| Assessment | `assessment_jobs` (owner, type `repository`/`web_security`/`performance`, status lifecycle), `assessment_status_history` |
| Targets | `repository_targets` (one per assessment, `local_path` only, **no owner or authorization metadata**) |
| Static pipeline | `attack_surface_reporting.collect_assessment_analysis` hard-codes nine stages: discovery → technology → routes → auth controls → inputs → sensitive operations → correlation → handler/calls → input-to-operation flow, then summary. Cooperative `execution_context.check()` between stages |
| Runs | `analysis_runs`: status `running/completed/failed`, `created_at`, `started_at`, `completed_at`, `heartbeat_at`, `cancel_requested_at`, `cancel_requested_by_user_id`, sanitized `error_message`, JSON `analysis_metadata`. Partial unique index allows one `running` run per assessment. Execution is synchronous inside `POST …/analysis-runs` |
| Findings | `assessment_findings` (title, category, severity, status, confidence, summary, affected_component, remediation, position, optional run) + `finding_evidence` (description, source, JSON details, position) |
| Finding policy | `finding_policy.generate_findings`: resolved input→operation flows only, always `informational` / `not_tested` |
| Audit | `audit_events` with actions for assessments, targets, and run lifecycle; admin query + denial-pattern APIs |
| Controls | Process-local auth rate limits, login throttle, audit budget, analysis admission (per-user and global) |
| Reusable parsers | `technology_detector.py` already parses `package.json`, `pyproject.toml` (PEP 621, Poetry, PDM), `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml` — but only to detect technologies, not to record versions |
| Not present | Secret scanning, dependency/CVE analysis, any outbound HTTP client, crawler, runtime probes, LLM, LangChain/LangGraph, RAG, HTML reports, background worker, PostgreSQL driver |

Environment facts relevant to planning (this machine):

- PyPI and `api.osv.dev` are reachable over HTTPS (OSV returns `400` for an empty
  query, so the endpoint answers).
- **No Docker, no PostgreSQL server, no Node.js.** DVWA integration and PostgreSQL
  verification (M6 opt-in, M13) cannot run here until one of these is installed.
- Python 3.12 is available; the project targets 3.11+.
- No LLM provider credentials are configured (and none should be committed).

## 2. Mapping existing code to the blueprint contracts

| Contract field (blueprint §4) | Existing equivalent | Gap |
| --- | --- | --- |
| **4.1 Assessment target** | | |
| `id`, `assessment_id`, `created_at` | `repository_targets` | — |
| `target_type` | `assessment_jobs.assessment_type` + `source_kind=local_path` | No `web_application` target table |
| `canonical_target` | `location` (resolved absolute path) | OK for repositories; URL canonical form needed for web |
| `authorization_record`, `created_by`, `policy_snapshot`, `status` | none | **Missing**. This is also open finding S-7 |
| **4.2 Analysis run** | | |
| `id`, `assessment_id`, `status`, `heartbeat_at`, `cancel_requested_at` | `analysis_runs` | No `queued` or `cancelled` statuses |
| `started_at`, `finished_at` | `started_at`, `completed_at` | Naming only; keep existing |
| `lease_owner`, `lease_expires_at` | none | Needed in M8 |
| `stage`, `progress` | none (stage exists only in code and in failure audit context) | Needed in M7/M8 |
| `error_code` | `error_message` (sanitized text) + audit `failure_stage` | Add a safe enum code |
| `configuration_snapshot`, `tool_versions` | `analysis_metadata.analyzer` (app name/version) | Partial; per-tool versions missing |
| **4.3 Evidence** | | |
| `id` | `finding_evidence.id` | Evidence exists only *inside* a finding; it cannot be shared by several findings or exist without one |
| `source_type`, `tool_name`, `rule_id`, `location`, `metadata` | `source` (free text) + `details` JSON | Untyped; must be normalized |
| `observed_at`, `request_summary`, `response_summary`, `redacted_excerpt`, `content_hash`, `provenance`, `limitations` | none | **Missing**; a redaction layer is also missing |
| **4.4 Finding** | | |
| `id`, `assessment_id`, `analysis_run_id`, `title`, `category`, `severity`, `status`, `confidence`, `affected_component` | `assessment_findings` | — |
| `description`, `recommendation` | `summary`, `remediation` | Naming only; keep existing columns |
| `rule_id`, `cwe_ids`, `cve_ids`, `verification_method`, `false_positive_reason`, `first_seen_at`, `last_seen_at`, `evidence_ids` | none | Needed in M7. Without a stable rule/location identity, retests and deduplication are impossible |
| status values | `confirmed`, `not_reproduced`, `inconclusive`, `not_tested` | **`potential` missing**. The column is a non-native enum with a CHECK constraint, so adding it needs a migration (SQLite batch rebuild of `assessment_findings`) |
| **4.5 Tool result** | Each analyzer returns its own Pydantic result with `issues` and `summary.is_complete` / truncation reasons | No common envelope (identity, version, timing, status `completed/partial/failed/skipped/cancelled`, counts, safe error code). **M1 creates this.** |

Duplicate or overlapping concepts to reuse, not re-create:

- Analyzer completeness and truncation (`summary.is_complete`,
  `*_truncation_reasons`) map onto tool status `partial` plus limitations.
- `AnalysisExecutionContext` (deadline + abort event) is the cancellation token to
  pass to tools; do not introduce a second one.
- `analysis_admission` is the per-process concurrency budget; M8 must replace or
  extend it, not add a parallel limiter.
- Repository path safety (`validate_repository_location`, the per-analyzer
  `_validate_source_path` / sensitive-path checks) must be shared by the new secret
  and dependency tools rather than reimplemented.
- `technology_detector` manifest parsers are the starting point for the M3
  dependency inventory. It must be extended to keep versions and lock files, without
  forking the parsing logic.

## 3. Gaps and design decisions

Decisions marked **Owner decision** need your choice before or during the milestone
named. The recommendation is listed first.

| # | Decision | Recommendation | When |
| --- | --- | --- | --- |
| D1 | Where shared contracts live | New `app/schemas/tooling.py` (typed results and evidence) and `app/services/tooling/` (registry, executor, redaction, target-policy interfaces). This fits the existing `schemas` / `services` split. | M1 |
| D2 | Wire the registry into the production pipeline in M1? | **No.** M1 adds the seam plus an adapter proving that existing analyzers fit it. `execute_assessment_analysis` stays unchanged until M2, when the first new tool needs it. This keeps API behaviour bit-for-bit compatible. | M1 |
| D3 | Evidence storage | Keep `finding_evidence` for API compatibility. In M7, add a normalized `evidence_items` table plus a finding↔evidence link table. M1 defines only the Pydantic contract. | M7 (schema) |
| D4 | `potential` status | Add it with the first producer that needs it (M2 entropy candidates), through one migration that rebuilds the CHECK constraint. Status, severity, and confidence stay separate fields. | M2 |
| D5 | **Owner decision:** may the secret scanner read `.env`, key, and credential files that every other analyzer refuses to open? | **Yes, the secret scanner only.** Committed `.env` files and private keys are exactly what secret scanning must catch. It persists only the rule ID, relative path, line, a redacted excerpt, and a keyed fingerprint, never the value. Alternative: report such files by name only, without reading them. | M2 |
| D6 | **Owner decision:** secret-detection engine | **Small in-house rule engine** with documented, versioned regex rules (AWS, GitHub/GitLab, private-key blocks, connection strings, JWT, Slack, and so on). Entropy is only a secondary, low-confidence `potential` signal. No new dependency, deterministic output, and full control over redaction. Alternative: Yelp `detect-secrets` (maintained, Apache-2.0), a heavier dependency with its own output model. | M2 |
| D7 | Secret fingerprint | HMAC-SHA-256 with a dedicated `EVIDENCE_FINGERPRINT_KEY` setting, required in staging/production. A plain hash would let anyone holding the database confirm guessed low-entropy secrets offline. | M2 |
| D8 | Advisory source | OSV.dev `querybatch` API through the M4 guarded client, plus a database or file cache with fetched-at/expiry metadata and an explicit offline mode. Results are labelled `unavailable` when the provider fails. M3 needs outbound network access, so it needs M4's client. **Proposed order change: build the HTTP-client part of M4 before M3**, or give M3 a minimal advisory-only client that M4 then absorbs. | M3/M4 |
| D9 | Target ownership and authorization (fixes S-7) | New `assessment_targets` record covering repository and web targets: `created_by`, `authorization_confirmed_by/at`, an authorization statement, a canonical target, and a policy snapshot. Existing `repository_targets` rows are migrated or kept read-compatible. Web targets require an explicit allowlist entry in configuration *and* per-target confirmation. | M4 |
| D10 | Worker model | Database-backed queue. `analysis_runs` gains `queued` and `cancelled` statuses, `lease_owner`, `lease_expires_at`, `stage`, `progress`, and `error_code`; claims use a conditional `UPDATE`. A separate `python -m app.worker` process. No Redis or Celery. | M8 |
| D11 | **Owner decision:** API change for asynchronous runs | `POST …/analysis-runs` currently returns `201` with the final state. Asynchronous runs need `202` + a `queued` run. **Recommend a version switch:** keep the synchronous endpoint behaviour behind a setting during transition, add `?mode=async` or a `/api/v2` route, and make `GET …/attack-surface/summary` read persisted results (the blueprint requires that GETs stop re-running scans). | M8 |
| D12 | LLM provider | Provider-neutral abstraction with an Anthropic Claude adapter as the default implementation (official SDK), plus a mock provider for all tests. LangChain only where it removes code (structured output, retrieval glue). | M9 |
| D13 | HTML reports | Jinja2 with autoescape and a strict Content-Security-Policy; no remote assets. | M12 |
| D14 | **Owner decision:** PostgreSQL and DVWA infrastructure | Neither Docker nor PostgreSQL is installed here. Choose one: install Docker Desktop (enables DVWA + PostgreSQL Compose), install PostgreSQL locally (Homebrew), or run those checks in GitHub Actions CI. Until then M6 DVWA tests and M13 stay "not executed", not "passed". | before M6/M13 |
| D15 | Version control | The project still has no Git history. Every milestone touches many files; reviewing them by diff against folder backups is error-prone. **Recommend that you run `git init` and commit the current state** before M1 (your action or explicit approval). Otherwise a timestamped backup + diff will be made before each milestone, as in the release work. | before M1 |

## 4. File-level change plan for M1 (shared tool and evidence contracts)

No scanners, no migrations, no new dependencies, no API changes.

| File | Change |
| --- | --- |
| `app/schemas/tooling.py` (new) | Pydantic models: `ToolIdentity` (name, version, rule-set version); `ToolStatus` (`completed`, `partial`, `failed`, `skipped`, `cancelled`); `SafeErrorCode` enum; `ResourceUsage` (wall time, files/bytes read, requests made); `ToolLimitation`; `EvidenceSourceType` (`repository`, `dependency`, `http`, `crawler`, `runtime_probe`, `ai_reference`); `EvidenceLocation` (relative path + line, or URL path + parameter, validated to never be absolute); `EvidenceRecord` (blueprint §4.3, with `redacted_excerpt`, `content_hash`, `provenance`, `limitations`, `metadata`); `ToolResult` (identity, timestamps, status, counts, evidence, warnings, limitations, usage, error code). Validators enforce: no absolute paths, bounded excerpt length, status/error-code consistency (for example, `failed` requires an error code; `completed` forbids one). |
| `app/services/tooling/__init__.py` (new) | Package exports. |
| `app/services/tooling/protocol.py` (new) | `AnalysisTool` Protocol (`identity`, `applies_to(context)`, `run(context) -> ToolResult`) and a frozen `ToolContext` (assessment ID, run ID, validated repository root, discovery inventory, `AnalysisExecutionContext`, config snapshot). |
| `app/services/tooling/registry.py` (new) | `StageRegistry`: register tools by stage name and order, reject duplicates, produce a deterministic plan; `PipelineConfig` (enabled stages, per-tool budgets). |
| `app/services/tooling/executor.py` (new) | `run_stages(registry, context, config)`: runs each enabled tool, converts exceptions into `failed` results with a safe error code (no exception text), marks disabled or unavailable tools `skipped`, propagates cancellation as `cancelled`, enforces per-tool time budgets cooperatively, and returns an aggregate whose `is_clean` can never be true when any tool was `failed`/`skipped`/`cancelled`/`partial` (blueprint §7 "no silent empty clean result"). |
| `app/services/tooling/redaction.py` (new) | `redact_excerpt` (masks all but a short prefix/suffix, enforces max length), `redact_headers` (cookies, authorization, set-cookie, proxy-authorization, API-key headers), `redact_url` (credentials and secret-looking query values), `content_hash` (SHA-256 over normalized content), `keyed_fingerprint` (HMAC; key injection only, setting added in M2), plus provenance builder. Pure functions, no I/O. |
| `app/services/tooling/target_policy.py` (new) | Interfaces only: `TargetAuthorizationPolicy` Protocol, `TargetDecision` (allowed/denied + reason code), and `NetworkSafetyPolicy` frozen dataclass with safe defaults (schemes, max redirects, timeouts, byte limits, blocked ranges). No network code; the guarded client is M4. |
| `app/services/tooling/adapters.py` (new) | `StaticAttackSurfaceTool` wrapping the existing analyzers into one `ToolResult`, mapping completeness and truncation to `partial` + limitations. Used by tests only in M1 (decision D2). |
| `docs/adr/0001-tool-and-evidence-contracts.md` (new) | The seam, status semantics, "no silent clean" rule. |
| `docs/adr/0002-evidence-redaction-and-provenance.md` (new) | What may be stored or sent anywhere; fingerprinting; excerpt limits. |
| `docs/adr/0003-finding-status-dimensions.md` (new) | Status vs severity vs confidence; `potential`; proof rules for `confirmed`. |
| `docs/adr/0004-target-authorization-and-network-policy.md` (new, status *proposed*) | D9 + network policy defaults, finalized in M4. |
| `tests/test_tooling_contracts.py` (new) | Schema validation: absolute-path rejection (POSIX and Windows forms), status/error-code consistency, excerpt bounds, serialization determinism. |
| `tests/test_tooling_registry.py` (new) | Register fake tools, ordering, duplicates, disabled stages → `skipped`, exceptions → `failed` without leaking the message, cancellation → `cancelled`, aggregate never "clean" with a non-completed tool, executor never imports concrete tools. |
| `tests/test_tooling_redaction.py` (new) | Synthetic secrets never appear in redacted output, header/URL redaction, hash stability, fingerprint keyed. |
| `tests/test_tooling_adapters.py` (new) | Adapter over a temporary repository equals the existing pipeline's completeness and contains no absolute paths. |
| `README.md`, `docs/TECHNICAL_REFERENCE.md` | Short "extension seam" section; no capability claims. |

## 5. Migration and API compatibility risks

| Risk | Milestone | Mitigation |
| --- | --- | --- |
| Adding `potential` rebuilds `assessment_findings` on SQLite (CHECK constraint change) | M2 | Batch migration under the existing foreign-key-off `env.py` handling; data-preservation round-trip test like `0010`–`0014` |
| New run statuses `queued`/`cancelled` change the partial-unique-index semantics (one *active* run) | M8 | Index predicate becomes `status IN ('queued','running')`; recreate it around the batch rebuild as `0014` does; migration test |
| Synchronous `POST` returning final state is relied on by clients/tests | M8 | Versioned or mode-switched endpoint (D11); keep the current contract until removed deliberately |
| Summary GET stops recomputing | M8 | Return the last persisted summary plus its run ID and timestamp; document it |
| `repository_targets` → `assessment_targets` | M4 | Additive table plus backfill with `created_by = assessment owner`; legacy null owners flagged as "authorization unknown" and blocked from new runs until confirmed |
| New dependencies (`httpx` moved from dev to runtime, `jinja2`, LLM SDK, `langgraph`, `faiss-cpu`, PostgreSQL driver) | M3–M13 | One dependency per milestone with a stated reason; optional extras (`[ai]`, `[rag]`, `[postgres]`) so the deterministic core installs without AI packages |
| Windows paths | all | Location validators tested with both forms; the Windows suite still cannot run on this Mac |

## 6. Security risks and test plan

| Risk | Control | Test |
| --- | --- | --- |
| Secret values leaking into the DB, logs, API responses, test failure output, or prompts | Redaction before any record is constructed; `EvidenceRecord` never has a raw-value field; keyed fingerprints | Synthetic secrets searched for in persisted rows, captured logs, responses, and exception text |
| SSRF / DNS rebinding / redirect abuse (M3–M6) | Single guarded client; resolve-then-connect to the vetted IP; per-hop revalidation; blocked ranges (loopback, RFC 1918, link-local, metadata, IPv6 ULA/link-local, IPv4-mapped forms) unless explicitly allowlisted | Local mock servers, stubbed resolver for rebinding, redirect chains, IPv6/IPv4-mapped edge cases, decompression bomb |
| Unauthorized targets | Config allowlist and per-target owner confirmation; audited | Authorization tests per role/owner; LLM/graph cannot add targets (M10) |
| Destructive probes | Read-only methods by default; form submission policy denylists state-changing actions; harmless markers only; no time-based SQLi | Fixture apps that record every request; assert no destructive verbs or paths |
| Over-claiming findings | Deterministic proof rules (ADR-0003); reflection alone ≠ XSS; SQL error alone ≠ SQLi; AI cannot change status | Policy unit tests per rule, including negative fixtures |
| Prompt injection from repository/HTTP/advisory content (M9–M11) | Content passed as quoted data, structured output, evidence-ID validation, no tool invocation from model output | Injection strings in fixtures; hallucinated IDs rejected |
| HTML report XSS (M12) | Autoescaping templates, CSP, no remote assets | Malicious titles/paths/evidence render inert |
| Tool failure shown as "clean" | Aggregate status rule in M1 executor | Executor tests (M1) and run-summary tests (M7) |

All unit tests stay offline. Runtime tests use local fixture servers on loopback,
explicitly allowlisted per test. DVWA and PostgreSQL tests are opt-in markers that
are skipped (reported as *not executed*) when the infrastructure is absent.

## 7. Acceptance criteria for M1

1. The full existing suite passes unchanged (currently 1,138 passed, 7 Windows-only
   skips); `ruff check` and `ruff format --check` are clean.
2. No migration added; `alembic check` reports no drift; no new runtime dependency.
3. No API path, request, or response schema changes (OpenAPI document identical
   to before M1, verified by diffing the generated `openapi.json`).
4. `ToolResult`/`EvidenceRecord` validators reject absolute POSIX and Windows paths,
   inconsistent status/error-code pairs, and over-long excerpts.
5. A test registers two fake tools in the `StageRegistry` and runs them through the
   executor, which consumes their typed results without importing either tool's
   module.
6. Exceptions raised by a tool become `failed` results with a safe error code; the
   exception message does not appear in the result or logs.
7. Disabled tools become `skipped`, cancellation becomes `cancelled`, and the
   aggregate is never reported clean when any tool did not complete.
8. Redaction tests prove that synthetic secrets, cookies, authorization headers,
   and URL credentials never appear in redacted output.
9. The static-pipeline adapter produces a `ToolResult` whose completeness matches the
   existing analyzer summary and contains no absolute paths.
10. No scanner, network client, or LLM code exists yet. ADRs 0001–0004 are written;
    0004 is marked *proposed*.

## 8. Before M1 starts, please confirm

1. **Approve M0** and the M1 scope above (contracts only, not wired into production).
2. **D15:** initialise Git yourself, or approve backup + diff per milestone.
3. **D5/D6:** secret scanner may read `.env`/key files (recommended), and use an
   in-house rule engine (recommended) vs `detect-secrets`.
4. **D8:** accept moving the guarded-HTTP-client portion of M4 ahead of M3.
5. **D14:** how PostgreSQL and DVWA will be provided (Docker Desktop, local install,
   or CI).

Decisions D11 (asynchronous API shape) and D12 (LLM provider) can wait until their
milestones.
