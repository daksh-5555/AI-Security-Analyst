"""Conservative conversion of static flow evidence into findings."""

import math
from dataclasses import dataclass, field
from typing import Any

from app.schemas.enums import FindingSeverity, FindingStatus
from app.schemas.finding import Evidence, Finding
from app.schemas.input_operation_flow import (
    FlowResolutionStatus,
    InputOperationFlowResult,
    InputOperationRelationship,
)

EVIDENCE_SOURCE = "input_operation_flow"


@dataclass(frozen=True, slots=True)
class FindingGenerationResult:
    """Findings produced from one flow result and the policy limitations."""

    findings: list[Finding]
    eligible_relationship_count: int
    skipped_relationship_count: int
    limitations: list[str]
    # Source relationship of each finding, in the same order (used for evidence
    # normalization; additive, defaults to empty for direct constructions).
    relationships: list[InputOperationRelationship] = field(default_factory=list)


def generate_findings(flow: InputOperationFlowResult) -> FindingGenerationResult:
    """Convert eligible resolved flow relationships into informational findings.

    Only resolved relationships that contain a source-backed propagation path
    are represented. Ambiguous, unresolved, unsupported, and co-location-only
    evidence is intentionally excluded. Skipped eligible relationships are
    recorded as limitations rather than assigned invented values.
    """
    findings: list[Finding] = []
    represented: list[InputOperationRelationship] = []
    limitations: list[str] = []
    eligible_count = 0
    skipped_count = 0

    for relationship in flow.relationships:
        if relationship.resolution_status is not FlowResolutionStatus.RESOLVED:
            continue

        eligible_count += 1
        problem = _representation_problem(relationship)
        if problem is not None:
            skipped_count += 1
            limitations.append(
                f"Relationship '{relationship.relationship_id}' was skipped: {problem}"
            )
            continue

        findings.append(_build_finding(relationship))
        represented.append(relationship)

    return FindingGenerationResult(
        findings=findings,
        eligible_relationship_count=eligible_count,
        skipped_relationship_count=skipped_count,
        limitations=limitations,
        relationships=represented,
    )


def _representation_problem(relationship: InputOperationRelationship) -> str | None:
    """Return why a resolved relationship cannot be represented, if it cannot."""
    required_text = (
        relationship.relationship_id,
        relationship.input_id,
        relationship.operation_id,
        relationship.input_source_file,
        relationship.operation_source_file,
        relationship.input_declaration,
        relationship.operation_declaration,
        relationship.explanation,
    )
    if any(not isinstance(value, str) or not value.strip() for value in required_text):
        return "required relationship evidence is missing"

    if not relationship.propagation_steps:
        return "no source-backed propagation steps were recorded"

    if (
        relationship.input_line_number < 1
        or relationship.operation_line_number < 1
        or relationship.input_index < 0
        or relationship.operation_index < 0
    ):
        return "relationship source positions are invalid"

    confidence = relationship.detection_confidence
    if not isinstance(confidence, int | float) or not math.isfinite(confidence):
        return "detector confidence is not a finite number"
    if not 0.0 <= confidence <= 1.0:
        return "detector confidence is outside [0.0, 1.0]"

    return None


def _build_finding(relationship: InputOperationRelationship) -> Finding:
    input_label = relationship.input_type.value.replace("_", " ")
    operation_label = relationship.operation_category.value.replace("_", " ")

    return Finding(
        title=(
            f"Static input-to-operation flow: {input_label} input to {operation_label} operation"
        ),
        category=f"input_to_{relationship.operation_category.value}",
        severity=FindingSeverity.INFORMATIONAL,
        status=FindingStatus.NOT_TESTED,
        confidence=relationship.detection_confidence,
        summary=(
            f"Static analysis recorded a data-propagation relationship from "
            f"{input_label} input '{relationship.input_id}' at "
            f"{relationship.input_source_file}:{relationship.input_line_number} to "
            f"{operation_label} operation '{relationship.operation_id}' at "
            f"{relationship.operation_source_file}:{relationship.operation_line_number}. "
            "This is static evidence only; runtime execution, validation, "
            "exploitability, and vulnerability impact were not verified."
        ),
        affected_component=(
            f"{relationship.operation_source_file}:{relationship.operation_line_number}"
        ),
        remediation=None,
        evidence=[
            Evidence(
                description=(
                    "Deterministic static input-to-operation propagation evidence "
                    f"for relationship '{relationship.relationship_id}'."
                ),
                source=EVIDENCE_SOURCE,
                details=_evidence_details(relationship),
            )
        ],
    )


def _evidence_details(relationship: InputOperationRelationship) -> dict[str, Any]:
    return {
        "relationship_id": relationship.relationship_id,
        "input": {
            "id": relationship.input_id,
            "index": relationship.input_index,
            "type": relationship.input_type.value,
            "file": relationship.input_source_file,
            "line": relationship.input_line_number,
            "declaration": relationship.input_declaration,
            "resolution_status": relationship.input_resolution_status.value,
            "detection_confidence": relationship.input_detection_confidence,
        },
        "operation": {
            "id": relationship.operation_id,
            "index": relationship.operation_index,
            "category": relationship.operation_category.value,
            "file": relationship.operation_source_file,
            "line": relationship.operation_line_number,
            "declaration": relationship.operation_declaration,
            "resolution_status": relationship.operation_resolution_status.value,
            "detection_confidence": relationship.operation_detection_confidence,
        },
        "resolution_status": relationship.resolution_status.value,
        "detection_confidence": relationship.detection_confidence,
        "route_ids": list(relationship.route_ids),
        "handler_references": [
            reference.model_dump(mode="json") for reference in relationship.handler_references
        ],
        "propagation_steps": [
            step.model_dump(mode="json") for step in relationship.propagation_steps
        ],
        "intermediate_definition_ids": list(relationship.intermediate_definition_ids),
        "intermediate_call_ids": list(relationship.intermediate_call_ids),
        "ambiguous_definition_ids": list(relationship.ambiguous_definition_ids),
        "explanation": relationship.explanation,
        "limitations": list(relationship.limitations),
    }


__all__ = ["FindingGenerationResult", "generate_findings"]
