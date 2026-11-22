# M1 — Shared Tool and Evidence Contracts

Status: **complete, awaiting owner review before M2.**
Scope approved in M0: contracts only. Nothing is wired into production runs, and
there are no scanners, migrations, new dependencies, or API changes.

## What was added

| File | Purpose |
| --- | --- |
| `app/schemas/tooling.py` | `ToolResult`, `EvidenceRecord`, `EvidenceLocation`, `EvidenceProvenance`, `ToolIdentity`, `ToolLimitation`, `ResourceUsage`, `ToolStatus`, `SafeErrorCode`, `EvidenceSourceType` with safety validators |
| `app/services/tooling/protocol.py` | `AnalysisTool` protocol, immutable `ToolContext` |
| `app/services/tooling/registry.py` | `StageRegistry`, `StageRegistration`, `PipelineConfig`, `ToolBudget` |
| `app/services/tooling/executor.py` | `run_stages`, `PipelineOutcome` (no-silent-clean rule) |
| `app/services/tooling/redaction.py` | Masking, excerpt, header, and URL redaction; content hash; HMAC fingerprint; evidence keys |
| `app/services/tooling/target_policy.py` | `TargetAuthorizationPolicy`, `DenyAllTargetPolicy`, `TargetDecision`, `NetworkSafetyPolicy` |
| `app/services/tooling/adapters.py` | `StaticAttackSurfaceTool` (existing pipeline as one tool) |
| `app/services/tooling/__init__.py` | Package exports |
| `docs/adr/0001`–`0004` | Contracts; redaction and provenance; status dimensions; target and network policy (*proposed*) |
| `tests/test_tooling_{contracts,registry,redaction,target_policy,adapters}.py` | 116 new tests |

Existing files changed:

- `app/services/attack_surface_reporting.py`: the post-discovery stages were
  extracted from `collect_assessment_analysis` into `analyze_discovered_repository`
  without changing behaviour, so the adapter and the production path share one stage
  order.
- `app/services/analysis_execution_context.py`: added `remaining_seconds()` and
  `child(max_seconds)`. A child shares the clock and abort event and cannot outlive
  its parent; these are used for per-stage budgets.
- `README.md`, `docs/TECHNICAL_REFERENCE.md`: a description of the seam, with no new
  capability claims.

## Acceptance criteria (from M0)

| # | Criterion | Result |
| --- | --- | --- |
| 1 | Existing suite passes; ruff clean | 1254 passed (1138 existing + 116 new), 7 Windows-only skips; `ruff check` and `ruff format --check` clean |
| 2 | No migration, no drift, no new runtime dependency | 14 migrations unchanged; `alembic check` reports no drift; upgrade → downgrade base → upgrade OK; `pyproject.toml` identical |
| 3 | No API change | The generated OpenAPI document is byte-identical before and after |
| 4 | Validators reject absolute paths, bad status/error pairs, long excerpts | `test_tooling_contracts.py`: POSIX, Windows-drive, drive-relative, UNC, `//`, `~`, and `..` cases |
| 5 | Executor consumes two fake tools without importing them | `test_executor_consumes_two_tools_through_typed_results`; an AST test confirms the executor imports no concrete tool |
| 6 | Exceptions become `failed` with a safe code; the message never appears in results or logs | `test_tool_exception_becomes_failed_without_leaking_its_message` |
| 7 | Disabled → `skipped`; cancellation → `cancelled`; never clean when incomplete | Registry tests for disabled, inapplicable, abort, run deadline, stage budget, empty registry |
| 8 | Redaction hides synthetic secrets, cookies, auth headers, URL credentials | `test_tooling_redaction.py` |
| 9 | Adapter completeness matches the pipeline; no absolute paths | `test_tooling_adapters.py` (including a truncated-discovery `partial` case) |
| 10 | No scanner, network, or LLM code; ADRs written | No new network/LLM imports in `app/`; ADR-0004 marked *proposed* |

Coverage of the new modules ranges from 93% to 100%; overall coverage is 87%.

## Known gaps and risks

- Cancellation and budgets are cooperative: a tool that never calls
  `context.execution.check()` can overrun. Each new tool must check between bounded
  units of work.
- `_SENSITIVE_NAME` in redaction intentionally over-redacts (for example a `code`
  or `author*` parameter). Accepted per ADR-0002.
- `NetworkSafetyPolicy` is not enforced anywhere yet. It becomes effective only
  with the M4 guarded client.
- The registry is not used by `execute_assessment_analysis`. M2 makes the first
  production change, routing the existing pipeline and the secret scanner through
  the registry.
- The Windows test suite still cannot run on this host.

## Proposed next milestone (M2: secret scanning)

Per the approved recommendations (D5, D6, D7): an in-house, versioned rule engine;
the secret scanner may read `.env` and key files; `EVIDENCE_FINGERPRINT_KEY` setting;
`potential` status migration; findings created from secret evidence; production runs
routed through the registry. Infrastructure decision D14 (PostgreSQL/DVWA) is still
open and is needed before M6 and M13.
