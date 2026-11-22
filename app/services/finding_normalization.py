"""Normalized findings: one contract for every finding producer (M7, ADR-0010).

A ``NormalizedFinding`` pairs the existing ``Finding`` API contract with:

- the rule and pipeline stage that produced it;
- a stable identity (used to recognise the same issue across runs: first seen,
  last seen, previous status, not reproduced);
- one or more redacted ``EvidenceRecord`` references (never zero);
- the verification method and a plain-language rationale for its status and
  severity;
- CWE and CVE identifiers when known.

Static and runtime evidence stay distinguishable through ``source_stage``,
``rule_id``, the evidence ``source_type``, and the verification method.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from app.schemas.finding import Finding
from app.schemas.tooling import EvidenceRecord
from app.services.finding_policy import FindingGenerationResult
from app.services.tooling.adapters import STATIC_STAGE, flow_evidence_record

STATIC_VERIFICATION: Final[str] = (
    "Static AST data-flow analysis: a resolved, source-backed propagation path from a "
    "request input to a sensitive operation."
)
STATIC_RATIONALE: Final[str] = (
    "Status not_tested and severity informational because only static evidence exists; "
    "no runtime check exercised this flow."
)


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    finding: Finding
    rule_id: str
    source_stage: str
    identity: str
    evidence: tuple[EvidenceRecord, ...]
    verification_method: str
    status_rationale: str
    cwe_ids: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("a normalized finding requires at least one evidence record")

    @property
    def identity_key(self) -> str:
        """Stable across runs: category, rule, and producer-specific identity."""
        material = f"{self.finding.category}|{self.rule_id}|{self.identity}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def static_normalized(
    generation: FindingGenerationResult, observed_at: datetime
) -> list[NormalizedFinding]:
    """Normalized static flow findings with their evidence records."""
    normalized: list[NormalizedFinding] = []
    for finding, relationship in zip(generation.findings, generation.relationships, strict=True):
        record = flow_evidence_record(relationship, observed_at)
        normalized.append(
            NormalizedFinding(
                finding=finding,
                rule_id=record.provenance.rule_id,
                source_stage=STATIC_STAGE,
                identity=(
                    f"{relationship.input_source_file}:{relationship.input_line_number}->"
                    f"{relationship.operation_source_file}:{relationship.operation_line_number}"
                ),
                evidence=(record,),
                verification_method=STATIC_VERIFICATION,
                status_rationale=STATIC_RATIONALE,
            )
        )
    return normalized


__all__ = ["NormalizedFinding", "STATIC_RATIONALE", "STATIC_VERIFICATION", "static_normalized"]
