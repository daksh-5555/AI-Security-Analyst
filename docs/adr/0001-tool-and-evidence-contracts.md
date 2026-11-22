# ADR-0001: Tool and evidence contracts

- Status: Accepted (M1)
- Date: 2026-11-16

## Context

The static pipeline in `app/services/attack_surface_reporting.py` calls nine
analyzers in a hard-coded order, and each returns its own result type. The
blueprint adds secret scanning, dependency analysis, crawling, and runtime probes.
Adding each of these by editing the orchestrator and the run-metadata builder would
couple every new tool to the HTTP request path and make missing checks easy to
hide.

## Decision

1. Every tool returns a `ToolResult` (`app/schemas/tooling.py`) with its identity
   and version, the stage, a status (`completed`, `partial`, `failed`, `skipped`,
   `cancelled`), a safe error code, counts, `EvidenceRecord`s, warnings,
   limitations, and resource usage.
2. Tools implement the `AnalysisTool` protocol (`identity`, `applies_to`, `run`)
   and receive an immutable `ToolContext`: the existing `AnalysisExecutionContext`
   for deadline and cancellation, the validated repository root and discovery
   inventory, stage options, and the typed results of earlier stages.
3. A `StageRegistry` maps stage names to tools in a deterministic order.
   `run_stages` executes the plan and consumes only typed results. It never imports
   a concrete tool.
4. **No silent clean result.** Every registered stage appears in the outcome.
   Disabled or inapplicable stages are `skipped`. Exceptions become `failed` with
   `tool_error`; exception text is neither stored nor logged. Cancellation and
   run-deadline expiry mark the current and remaining stages `cancelled`. A
   per-stage budget overrun fails only that stage (`budget_exhausted`). An outcome
   is clean only if at least one stage ran and every stage completed with no
   evidence.
5. Per-stage budgets use `AnalysisExecutionContext.child()`, which shares the
   parent's clock and abort event and can never outlive the parent. There is no
   second cancellation mechanism.
6. Tools do not write to the database, touch request objects, or open network
   connections except through the M4 guarded client. Persistence stays in
   services that own transactions.

## Consequences

- New scanners (M2+) are added by registration. The run-metadata and finding
  layers consume one contract.
- In M1 the registry is not yet used by `execute_assessment_analysis` (M0 decision
  D2). `StaticAttackSurfaceTool` proves that the existing analyzers fit the
  contract. It reuses `analyze_discovered_repository`, which was extracted from
  `collect_assessment_analysis` so the stage order stays defined in one place.
- Cancellation is cooperative: a tool that never calls `context.execution.check()`
  can still overrun its budget. Tools must check between bounded units of work.
