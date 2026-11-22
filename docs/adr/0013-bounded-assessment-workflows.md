# ADR-0013: Bounded, approval-gated assessment workflows (no LangGraph dependency yet)

Status: accepted (M10). Date: 2026-11-16.

## Context

Phase 10 asks for an orchestrated workflow over the existing tools. The
workflow must be bounded and replayable; its state must be persisted and
recoverable; tool use must be authorized and audited; and it needs human
approval for new targets and higher-risk test categories. Agent decisions must
not bypass target policy or budgets, and the deterministic pipeline must keep
working without AI. The blueprint names LangGraph, but also says: "Do not start
M10 just to claim that LangGraph is used."

Two facts shaped the decision:

- LangGraph is not installed. Adding it means downloading a new dependency
  tree, which needs the owner's approval.
- The workflow has no decision that needs a model. Which checks run follows
  from the assessment type, configuration, and human approvals. An LLM planner
  would add risk (prompt injection steering test selection) and no capability.

## Decision

1. **In-house graph engine, no new dependency.** `app/services/workflow/` holds
   a fixed graph (`assessment-workflow/1`) of eight allowlisted nodes:

   `load_assessment → validate_authorization → plan_enabled_checks →
   approval_gate → run_analysis → explain_findings → generate_report →
   finalize_run`

   The blueprint's node list maps onto this graph. Repository checks,
   dependency checks, crawling, runtime checks, evidence normalization, and the
   deterministic finding policy run inside `run_analysis`, as stages of the
   existing transactional pipeline. They are not split into separate persisted
   nodes, because that would break the "findings commit only with a completed
   run" guarantee. Their per-stage results are recorded in the node's event.
   `generate_report` is a skip until M12.
2. **Deterministic planner.** `plan_checks` is a pure function of the
   assessment type, the options, and a configuration snapshot that is stored
   with the plan, so the plan can be replayed and explained. It only selects
   among registered stages for the already-authorized target. It cannot add a
   target, URL, tool, or shell command, and no LLM takes part.
3. **Approval gates.** `runtime_probes` (active test traffic) needs a recorded
   human decision in every workflow, even when configuration allows it.
   - The workflow pauses in `awaiting_approval` before anything touches the
     target.
   - `POST …/workflows/{id}/approvals` takes the decision (`approve` or `deny`)
     with a reason. It is restricted to an allowlisted check name, attributed,
     and audited.
   - A denied check is excluded from the run. Exclusion can only narrow
     configuration (`excluded_stages`): approval never enables a check that
     configuration disables.
   - New targets are out of the workflow's reach entirely. They still require
     the owner-confirmed target registration from M4.
4. **Bounded execution.**
   - `WORKFLOW_MAX_STEPS` caps node executions, retries included.
   - `WORKFLOW_MAX_NODE_ATTEMPTS` caps retries per node.
   - `WORKFLOW_MAX_EXPLANATIONS` caps LLM calls.
   - Analysis keeps its deadline, admission control, and tool budgets.
   - Explanations keep the M9 token budget.
5. **Persisted and recoverable.**
   - `assessment_workflows` (migration 0020) stores status, current node, step
     count, options, plan, approvals and node attempts, the linked analysis
     run, and the error code.
   - `workflow_events` is an append-only, ordered log of every node outcome
     and approval decision.
   - Each step is claimed with a conditional UPDATE and marked in progress. A
     second `advance` is refused while a step runs. A marker older than
     `ANALYSIS_STALE_AFTER_SECONDS` belongs to a dead process and can be
     resumed.
   - A node exception is a retryable `error`; `POST …/resume` continues the
     workflow.
   - `run_analysis` records when it started, and on resume it adopts the run
     it already began instead of starting another.
   - At most one active workflow per assessment (partial unique index).
6. **Audit.** `workflow.started`, `workflow.approval_recorded`, and
   `workflow.finished` events, plus the existing analysis-run and explanation
   events.

## Consequences

- No new dependency, and every acceptance criterion is testable offline.
- If LangGraph is wanted later (for example, for an LLM-assisted triage loop),
  it can run inside one node behind the same allowlist and budgets. That needs
  the owner's approval to add the `langgraph` dependency.
- Workflows run synchronously in the request, like synchronous analysis runs.
  A workflow interrupted by a crash continues only when someone calls `resume`;
  the background worker does not advance workflows yet.
- The time-based adoption of an interrupted run assumes one workflow per
  assessment at a time, which the unique index enforces. A manual run started
  in the same window could be adopted; it would be the same assessment's
  analysis.
