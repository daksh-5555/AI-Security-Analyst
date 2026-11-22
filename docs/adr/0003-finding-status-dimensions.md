# ADR-0003: Finding status, severity, and confidence are separate

- Status: Accepted (M1); schema change scheduled for M2
- Date: 2026-11-16

## Context

`assessment_findings` already stores `severity`, `status`, and `confidence`
separately. The existing static policy emits only `informational` / `not_tested`.
Runtime checks will produce signals of very different strength, and the blueprint
requires a `potential` status that does not exist yet.

## Decision

- **Status** answers "how far was this verified?":
  - `confirmed`: a documented, deterministic proof rule for that check was met
    and repeated.
  - `potential`: a signal exists but does not meet the proof rule.
  - `inconclusive`: the evidence is ambiguous, unstable, or incomplete.
  - `not_reproduced`: a previous signal could not be reproduced.
  - `not_tested`: the relevant check did not run.
- **Severity** answers "how bad would it be if real?" and is assigned by
  deterministic per-rule policy, never by an LLM.
- **Confidence** (0–1) answers "how reliable is the detection technique?".
- Proof rules that are fixed now:
  - Reflection of a marker is never by itself confirmed XSS.
  - A generic SQL error, a status-code change, or a response-length change is never
    by itself confirmed SQL injection.
  - A failed, skipped, cancelled, or partial tool never produces an empty clean
    result (ADR-0001).
  - AI output and retrieved knowledge never change status or severity.
- `potential` is added to the `finding_status` enum in M2, together with its first
  producer, via a migration that rebuilds the CHECK constraint (SQLite batch mode
  under the existing foreign-key-off migration handling) and a data-preservation
  test.

## Consequences

Each new rule must document its proof rule and its status/severity mapping
alongside its tests.
