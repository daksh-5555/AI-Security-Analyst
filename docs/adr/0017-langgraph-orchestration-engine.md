# ADR-0017: LangGraph orchestration engine (opt-in)

Status: accepted (M14). Date: 2026-11-17. Supersedes the "no LangGraph
dependency" stance of ADR-0013 by making LangGraph an optional, opt-in
orchestration engine while keeping the in-house engine as the default.

## Context

ADR-0013 built the bounded assessment workflow in-house and deliberately did
not add LangGraph, because no step needed a model to decide anything and the
library is a heavy dependency. The owner has since asked for real LangGraph as
a first-class orchestration engine.

The blueprint's Phase 10 acceptance criteria must still hold: the workflow must
be bounded and replayable, state must be persisted and recoverable, tool use
must be authorized and auditable, and agent decisions must not bypass target
policy or budgets. The deterministic pipeline must keep working without the AI
packages.

## Decision

1. **Two interchangeable engines, builtin by default.** `WORKFLOW_ENGINE` selects
   `builtin` (the ADR-0013 in-process loop) or `langgraph`. LangGraph is an
   optional extra (`pip install ".[orchestration]"`); the default install and
   the deterministic core need none of it. `validate_security_configuration`
   fails closed at startup if `langgraph` is selected but not installed.
2. **One shared unit of work.** Both engines call
   `engine.run_step_for_node`, which performs the single, security-critical
   step: the conditional-UPDATE claim, the step and per-node budgets, the
   running-step guard, the node execution, persistence, the approval pause, and
   the audit event. The two engines differ only in how they loop, so they are
   behaviourally identical and neither can skip a control. Parity is enforced by
   running the entire workflow test suite under both engines.
3. **LangGraph owns traversal only, never state or security.** The
   `StateGraph` has one node per workflow stage (the fixed, allowlisted
   `NODE_SEQUENCE`) and only conditional edges: each node runs one shared step,
   then routes to the node the step advanced to, or to `END`. The graph cannot
   reach any node outside the allowlist, cannot create a target or URL, and
   makes no LLM, tool, shell, or network call. The authoritative workflow row
   in the database, not LangGraph's checkpointer, remains the source of truth,
   so crash recovery, the resume/approve APIs, and the concurrency guarantees
   are unchanged.
4. **Double-bounded traversal.** Our `WORKFLOW_MAX_STEPS` budget fails the run
   first; LangGraph's `recursion_limit` is a hard backstop above it.
5. **Offline and quiet.** LangSmith tracing/telemetry env vars are disabled, and
   the runtime objects (database session, ids, provider factory) travel in the
   invoke config, never in serialized graph state. The offline test guard proves
   no network is opened. LangChain's import-time filter-surfacing side effect is
   neutralized so the library's upstream pending-deprecation notice is
   suppressed at the one-time build/compile site.

## Consequences

- LangGraph is genuinely the orchestrator when selected (a real compiled
  `StateGraph` of the eight named nodes), satisfying the Phase 10 "LangGraph
  orchestration" item, while every security and persistence guarantee is
  identical to the built-in engine.
- The dependency is heavy (~22 transitive packages, including `requests`/
  `urllib3`, which bypass the guarded client). It is therefore optional, off by
  default, and constrained to pure orchestration; the offline guard is the
  safety net.
- A future LLM-assisted step (for example triage) can be added as one more
  node behind the same allowlist, budgets, and approval gate, on either engine.
- If LangGraph's API changes across a major version, only
  `app/services/workflow/langgraph_engine.py` is affected; the builtin engine
  and all workflow semantics are unaffected.
