# M7 — Evidence Normalization, Finding Identity, and Retest

Status: **complete, awaiting owner review before M8.**

## What was added

| Area | Files |
| --- | --- |
| Migration | `migrations/versions/0017_normalize_evidence.py`: `evidence_items`, `finding_evidence_links`, eleven nullable finding columns, `first_seen_at`/`last_seen_at` backfill, downgrade guard |
| Models | `app/models/evidence_item.py` (`EvidenceItem`, `FindingEvidenceLink`); `AssessmentFinding` new columns, `evidence_links`, `evidence_ids` |
| Contract | `app/services/finding_normalization.py`: `NormalizedFinding` (≥1 evidence enforced, `identity_key`), `static_normalized` |
| Producers | `app/services/analysis_tools.py`: `secret_`, `dependency_`, `runtime_normalized_findings`, `normalized_findings_from_outcome` (the old `*_findings_from_result` functions remain as wrappers); `finding_policy.py` keeps each finding's source relationship; `tooling/adapters.py` exposes `flow_evidence_record` |
| Persistence | `app/services/findings.py`: `add_normalized_findings` (within-run merge, evidence items and links, first/last seen, previous status, `not_reproduced`, `RetestSummary`), `list_evidence`, `get_evidence` |
| Runs | `app/services/analysis_execution.py`: normalized persistence; completed-stage tracking; `retest` in run metadata; `finding_count` includes `not_reproduced` |
| API | `app/api/evidence.py` (2 GET endpoints); `FindingRead` additive fields; `EvidenceItemRead` |
| Tests | `test_evidence_normalization.py` (8), `test_migration_0017.py` (4) |
| Docs | ADR-0010, README, technical reference |

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Every finding has one or more traceable evidence references | `NormalizedFinding` refuses empty evidence; persistence refuses findings without links; every finding in a real run has `evidence_ids` resolvable via the API (`test_every_new_finding_references_normalized_evidence`) |
| Findings explain why status and severity were assigned | `status_rationale` and `verification_method` on every new finding, per producer |
| Missing or failed checks visible in the run summary | Already in `tools[]` and `completeness`; `retest` added; `not_reproduced` only when the check completed (`test_no_not_reproduced_when_the_check_did_not_complete`) |
| Static suspicion and runtime verification distinguishable | `source_stage`, `rule_id` prefix, evidence `source_type`, verification method; static stays `not_tested`/`informational` |
| Deduplicate by stable identity; provenance and tool versions preserved | `identity_key`; within-run merge (`test_same_identity_within_a_run_is_merged`); evidence items store tool name, version, rule-set version, method, and observed time |
| First seen, last seen, retest history | `test_recurring_findings_keep_first_seen_and_previous_status`, `test_fixed_issue_is_reported_not_reproduced_with_earlier_evidence` |
| A failed or skipped tool never yields an empty "clean" result | Unchanged executor rules, plus the retest gate on completed stages |
| Existing finding API contracts compatible | OpenAPI diff: no existing path changed; `FindingRead` gained only optional fields; legacy findings return them as null or empty (asserted in `test_findings.py`) |

## Existing tests changed (intended)

- `test_findings.py`: the head-schema column set includes the 0017 columns. Three
  whole-response comparisons now exclude the new additive fields and separately
  assert that they are empty for legacy findings.
- Migration tests `0010`–`0016`: head pin `0016` → `0017`; the 0016 "is head" test
  was renamed.
- Analysis tests that stub the whole pipeline: stand-ins gained a realistic
  `summary`; the hand-built generation gained its source relationship (now required,
  since every finding needs evidence); one patch target was renamed
  `add_findings` → `add_normalized_findings`. No assertion was weakened.

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1520 passed, 0 failed, 7 skipped** (Windows-only), no warnings |
| Coverage | 88% overall; new modules 97–100% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0017`; `alembic check` reports no drift; round trip OK; preservation, backfill, and downgrade-guard tests |
| OpenAPI | 2 new paths, 1 new schema, 10 optional `FindingRead` fields; nothing else changed |
| Dependencies | unchanged |

Defect fixed during M7: the migration used the deprecated `Column.copy()` (66
warnings per affected test file); it now builds fresh columns.

## Not done (documented in ADR-0010)

- Static ↔ runtime correlation, which needs an owner-declared link between a
  repository assessment and a web assessment.
- Routing the static pipeline through the registry (static findings are fully
  normalized anyway).
- The summary endpoint reading persisted results, which moves to M8.

## Next milestone

M8: durable background execution. That covers queued runs claimed by a worker
with a lease, heartbeats with progress, persisted cancellation, stale-lease
recovery, idempotent retries, and the summary endpoint reading persisted results.
It will need a migration (run statuses, lease fields) and an API decision (D11)
on asynchronous `POST …/analysis-runs`.
