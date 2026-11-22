# ADR-0010: Normalized evidence, finding identity, and retest

- Status: Accepted (M7)
- Date: 2026-11-16

## Decision

1. **One producer contract.** Every finding producer emits a `NormalizedFinding`:
   the existing `Finding`, plus `rule_id`, `source_stage`, a producer-specific
   identity, one or more `EvidenceRecord`s (enforced: never zero), a
   `verification_method`, a `status_rationale`, and CWE/CVE identifiers. The
   producers are the static flow policy, the secret scanner, the dependency
   auditor, and the runtime probes.
2. **Storage (migration 0017).**
   - `evidence_items` holds each redacted record per run, unique on
     (run, evidence key).
   - `finding_evidence_links` (finding ↔ item, ordered) lets one item support
     several findings, and lets a later run reference an earlier run's evidence.
   - `assessment_findings` gains `rule_id`, `source_stage`, `identity_key`,
     `verification_method`, `status_rationale`, `cwe_ids`, `cve_ids`,
     `first_seen_at`, `last_seen_at`, `previous_status`, and
     `previous_finding_id`.
   - The legacy per-finding `finding_evidence` rows are still written, so the
     existing finding API is unchanged.
3. **Identity.** `identity_key` = SHA-256 of `category | rule_id | identity`, where
   the identity is the input→operation source positions (static), the keyed secret
   fingerprint, `ecosystem|package|version|advisory`, or `url path|parameter`
   (runtime). Within a run, findings with the same identity are merged (evidence
   unioned).
4. **Retest.** For each run, the previous *completed* run of the same assessment is
   the comparison point:
   - matching identities are *recurring*: `previous_status` is set and
     `first_seen_at` is carried over;
   - new identities start with `first_seen_at = last_seen_at = now`;
   - a previous `confirmed`, `potential`, or `inconclusive` finding that is absent
     now becomes a `not_reproduced` finding in this run, but **only if its
     producing stage completed** in this run. A partial, failed, skipped, or
     disabled check never produces `not_reproduced`. Such a finding links to the
     earlier run's evidence and keeps its first and last seen times. It is not
     re-reported in later runs.
   - Run metadata records `retest` (`previous_run_id`, `new`, `recurring`,
     `not_reproduced`, `evidence_items`).
5. **Distinguishing static from runtime.** `source_stage`
   (`static_attack_surface`, `secret_scan`, `dependency_audit`, `runtime_probes`),
   `rule_id` prefixes (`static.`, `secret.`, `dependency.`, `runtime.`), the
   evidence `source_type`, and the verification method keep static suspicion and
   runtime verification apart. Static flow findings stay `not_tested` and
   `informational`.
6. **API (additive).** `FindingRead` gains `rule_id`, `source_stage`,
   `verification_method`, `status_rationale`, `cwe_ids`, `cve_ids`,
   `first_seen_at`, `last_seen_at`, `previous_status`, and `evidence_ids`. New
   endpoints `GET /assessments/{id}/evidence` (optional `analysis_run_id`,
   `limit` ≤ 200, `offset`) and `GET /assessments/{id}/evidence/{evidence_id}`
   use the existing read authorization.

## Not done in M7 (deliberately)

- **Static ↔ runtime correlation** across assessments. Repository and web targets
  live in different assessments, and nothing links them yet. Correlating them
  heuristically could produce false links. This requires an owner-declared link
  between a repository assessment and a web assessment.
- **Routing the static pipeline through the registry.** Its intermediate results
  still feed run metadata directly. Static findings are nevertheless fully
  normalized.
- **Summary endpoint reading persisted results.** This moves to M8, together with
  background execution.
