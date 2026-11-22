# M10 — Bounded, Approval-Gated Assessment Workflows

Status: **complete, awaiting owner review before M11.**

## Key decision: no LangGraph dependency (please review)

The blueprint names LangGraph, and it also says: "Do not start M10 just to claim
that LangGraph is used." I built the bounded graph in-house (ADR-0013), for two
reasons:

- LangGraph is not installed. Adding it needs a download and your approval.
- No step in this workflow needs a model to decide anything. Which checks run
  follows from the assessment type, configuration, and human approvals. An
  LLM-driven planner would add prompt-injection risk (content steering test
  selection) and no capability.

Every Phase 10 acceptance criterion is met and tested without it. If you still
want LangGraph, for example for a future LLM-assisted triage step, it can run
inside one node behind the same allowlist, approvals, and budgets. That needs
your go-ahead to add the dependency.

## What was added

| Area | Files |
| --- | --- |
| Migration | `0020_create_assessment_workflows.py`: `assessment_workflows` (one active per assessment), `workflow_events` (ordered, unique sequence), workflow audit actions and resource type, downgrade guard |
| Models | `app/models/workflow.py` |
| Graph and planner | `app/services/workflow/plan.py`: fixed node sequence, pure `plan_checks`, approval and exclusion helpers |
| Engine | `app/services/workflow/engine.py`: claim → run → persist steps, in-progress marker, step and attempt budgets, approvals, resume, cancel, adoption of an interrupted run |
| Pipeline | `excluded_stages` threaded through `execute_assessment_analysis`, `run_web_tools`, and `run_supplementary_tools`; it only narrows the configured stages. `validate_analysis_target` is now public |
| API | `app/api/workflows.py` (5 endpoints); `app/schemas/workflow.py` |
| Settings | `WORKFLOW_MAX_STEPS` (20), `WORKFLOW_MAX_NODE_ATTEMPTS` (2), `WORKFLOW_MAX_EXPLANATIONS` (5) |
| Tests | `tests/test_workflows.py` (17), `tests/test_migration_0020.py` (4) |
| Docs | ADR-0013, README, technical reference, `.env.example` |

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Bounded | Step budget (`test_step_budget_is_enforced`), per-node attempts (`test_node_attempts_are_bounded`), explanation cap (`test_explanations_are_bounded_and_advisory`); analysis deadlines and the token budget still apply |
| Replayable | The planner is a pure function, and its config snapshot is stored with the plan (`test_graph_is_a_fixed_allowlist`); the ordered event log records every node outcome and decision |
| State persisted and recoverable | Retryable error then `resume` (`test_retryable_error_then_resume`); an interrupted analysis is adopted, not repeated, so exactly one run exists (`test_interrupted_analysis_is_adopted_not_repeated`); a stale step marker allows recovery while a live one blocks it (`test_stale_step_marker_allows_recovery`) |
| Tool invocation authorized and auditable | Target re-validated as a node; analysis re-checks authorization; an invalid target fails before any run (`test_invalid_target_fails_before_any_analysis`); audit events for start, approval, and finish; per-stage results in events |
| Decisions cannot bypass target policy or budgets | Fixed node allowlist; approval endpoint accepts only allowlisted check names, so a URL gives 422; approval never enables a configuration-disabled check (`test_exclusions_only_narrow_configuration`, `test_configuration_disabled_checks_need_no_approval_and_stay_off`) |
| Human approval for higher-risk tests | Probes enabled: the workflow pauses with no run created and zero requests to the target, then approve leads to probes running (`test_high_risk_check_waits_for_approval_then_runs`); deny leads to a crawl without a single probe request, and the run is honestly incomplete (`test_denied_check_is_never_executed`) |
| No concurrent double execution | A second `advance` during a running step is refused; one analysis run, one `run_analysis` event (`test_a_running_step_cannot_be_advanced_twice`) |
| Deterministic pipeline works with AI disabled | Repository workflow completes with no provider calls; explanations requested while AI is off are skipped with `disabled_by_configuration`; explanation outages never fail a workflow |

## Defects found and fixed during M10

- **Stale reads in the engine.** I found these while writing the tests. A
  `rollback()` outside a transaction does not expire cached objects, so step
  results were discarded and attempt counts were lost. The engine now always
  re-reads the row before conditional writes.

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1616 passed, 0 failed, 7 skipped** (Windows-only), no warnings; threaded tests repeated 4× green |
| Coverage | 89% overall; planner 98%, API 95%, engine 86% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0020`; `alembic check` reports no drift; full downgrade and re-upgrade OK |
| OpenAPI | 5 new paths, 6 new schemas; `AuditAction` and `AuditResourceType` gained values; no existing path changed |
| Dependencies | unchanged (`pyproject.toml` identical to M9) |

Existing tests changed: only the head pins (`0019` → `0020`) and the rename of
the 0019 "is head" test. No assertion was weakened.

## Known gaps and risks

- Workflows run inside the request, like synchronous analysis. An interrupted
  workflow continues only when someone calls `resume`; the background worker
  does not advance workflows.
- Adopting an interrupted run is based on time: a run for the same assessment
  started after the workflow's run step is treated as the workflow's run.
- `generate_report` is a skip until M12. Approval does not require a second
  person (the requester can approve); a four-eyes rule would be a small,
  separate change.
- The Windows test suite has still not been run. D14 (Docker, PostgreSQL, DVWA)
  remains open.

## Next milestone

M11: curated security RAG. Versioned, attributed OWASP/CWE guidance used to
ground explanations, with graceful fallback when retrieval or embeddings are
unavailable. This likely needs an owner decision on the embedding and vector
library, because `faiss-cpu` is a new dependency.
