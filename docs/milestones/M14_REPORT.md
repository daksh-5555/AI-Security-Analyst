# M14 — LangGraph Orchestration Engine (owner-requested)

Status: **complete, awaiting owner review.** Reverses the "no LangGraph"
decision of M10/ADR-0013 at the owner's request; the in-house engine remains the
default and LangGraph is an opt-in second engine.

## What was added

| Area | Change |
| --- | --- |
| Shared step | `engine.run_step_for_node` extracted from the M10 loop: one unit of work (claim, budgets, running-step guard, node execution, persistence, approval pause, audit). Both engines call it, so behaviour is identical |
| LangGraph driver | `app/services/workflow/langgraph_engine.py`: a real compiled `StateGraph` with one node per stage of the fixed `NODE_SEQUENCE` and only conditional edges; drives traversal, owns no state |
| Engine selection | `WORKFLOW_ENGINE` setting (`builtin` default, `langgraph`); `engine.advance` dispatches. Config validation fails closed if `langgraph` is selected but not installed |
| Packaging | optional extra `orchestration = ["langgraph>=0.2,<0.3"]`; default install unchanged |
| Tests | `tests/test_langgraph_engine.py` (7); the whole workflow suite runs under both engines via `TEST_WORKFLOW_ENGINE` |
| Docs | ADR-0017; README, technical reference, `.env.example` |

No migration, no API change (OpenAPI byte-identical to M13).

## How the safety guarantees are preserved

LangGraph drives traversal between the fixed, allowlisted nodes and nothing
else. It owns no security-critical state: the authoritative workflow row, the
conditional-UPDATE claim, the step/attempt budgets, the human-approval gate,
crash recovery, the resume/cancel APIs, and every audit event stay in
`engine.run_step_for_node`, which both engines call. Therefore:

- the graph cannot reach a node outside the allowlist, create a target or URL,
  or run a tool/shell;
- it makes no LLM, tool, or network call (proven by the offline guard: a
  repository workflow completes having opened no socket, even though LangGraph
  pulls in `requests`/`urllib3`);
- traversal is bounded twice: our `WORKFLOW_MAX_STEPS` budget fails first, and
  LangGraph's `recursion_limit` is a hard backstop;
- the approval gate still pauses before any runtime probe, and denied checks are
  still excluded — verified under LangGraph, not just asserted.

Parity is not assumed: the entire M10 workflow suite (and the report and
knowledge suites that drive workflows) pass unchanged under
`WORKFLOW_ENGINE=langgraph`.

## Acceptance criteria (Phase 10)

| Criterion | Evidence |
| --- | --- |
| Workflow bounded and replayable | Step/attempt budgets + LangGraph recursion limit; deterministic planner unchanged; 17 workflow tests green under both engines |
| State persisted and recoverable | DB remains authoritative (not LangGraph's checkpointer); resume/adoption/stale-marker tests pass under LangGraph |
| Tool invocation authorized and auditable | Same `run_step_for_node`; target re-validated; audit events unchanged |
| Agent decisions cannot bypass policy or budgets | Fixed node allowlist; approval gate pauses under LangGraph (`test_approval_gate_still_pauses_under_langgraph`); excluded checks only narrow config |
| Deterministic pipeline works with AI disabled | Builtin is the default and needs none of these packages; config fails closed if langgraph is selected but absent |

## Issue resolved during implementation

LangChain runs `surface_langchain_deprecation_warnings()` at import, inserting
its own filter ahead of ours, so its upstream pending-deprecation notice evaded
every message/category/`-W` filter. Fixed by importing `langchain_core` first,
then re-asserting an ignore filter at the front before the warning fires, scoped
to the one-time build/compile. The application process and the test suite both
emit zero warnings.

## Verification

| Check | Result |
| --- | --- |
| `pytest` full (builtin, default) | **1674 passed, 0 failed, 10 skipped** (7 Windows-only, 3 PostgreSQL-only), 0 warnings; 89% coverage |
| `pytest` full (`WORKFLOW_ENGINE=langgraph`) | **1674 passed, 0 failed, 10 skipped**, 0 warnings — full parity with builtin |
| LangGraph-specific tests | 7 passed |
| `ruff check` / `ruff format --check` | clean |
| OpenAPI | byte-identical to M13 |
| Alembic | head `0021`, no change |
| Dependencies | core unchanged; optional `[orchestration]` extra added (langgraph 0.2.76, ~22 transitive packages) |

## Known gaps and risks

- LangGraph pins `<0.3`; 0.2.76 is verified. A 0.3 upgrade would touch only
  `langgraph_engine.py`.
- The dependency pulls in `requests`/`urllib3`, which bypass the guarded client.
  The orchestration layer never makes network calls, and the offline guard
  enforces this in tests; operators should still restrict egress at the network
  layer.
- LangGraph is verified on one local environment; not in CI.
- D14 (DVWA) is unaffected and remains planned, pending the three decisions in
  the architecture assessment (lab runtime, credential surface, scope
  confirmation).
