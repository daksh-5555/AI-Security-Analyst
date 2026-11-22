"""Adapters that expose existing analyzers through the tool contract.

``StaticAttackSurfaceTool`` wraps the existing deterministic pipeline (technology
detection through input-to-operation flow) without changing it. In M1 the adapter
is exercised by tests only; ``execute_assessment_analysis`` is not yet routed
through the registry (M0 decision D2).

Mapping rules:

- analyzer completeness → ``completed``; any incomplete source or truncation →
  ``partial`` with one limitation per cause;
- every *resolved* input-to-operation relationship → one ``repository``
  ``EvidenceRecord`` located at the input's repository-relative source line;
- unresolved or ambiguous relationships are counted, not turned into evidence.
"""

from __future__ import annotations

from datetime import datetime

from app.core.config import settings
from app.schemas.input_operation_flow import FlowResolutionStatus, InputOperationRelationship
from app.schemas.tooling import (
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSourceType,
    ToolIdentity,
    ToolLimitation,
    ToolResult,
    ToolStatus,
)
from app.services.attack_surface_reporting import (
    AssessmentAnalysisResults,
    analyze_discovered_repository,
)
from app.services.tooling.protocol import ToolContext
from app.services.tooling.redaction import content_hash, evidence_key

STATIC_STAGE = "static_attack_surface"
_RULE_PREFIX = "static.input_to_"


class StaticAttackSurfaceTool:
    """The existing static analysis pipeline as one registered tool."""

    def __init__(self) -> None:
        self._identity = ToolIdentity(
            name=STATIC_STAGE,
            version=settings.app_version,
            rule_set_version="flow-policy-1",
        )

    @property
    def identity(self) -> ToolIdentity:
        return self._identity

    def applies_to(self, context: ToolContext) -> bool:
        return context.discovery is not None

    def run(self, context: ToolContext) -> ToolResult:
        if context.discovery is None:  # guarded by applies_to; defensive
            raise ValueError("discovery inventory is required")
        started_at = context.clock()
        results = analyze_discovered_repository(
            context.discovery,
            execution_context=context.execution,
        )
        metrics = results.summary.summary
        observed_at = context.clock()

        limitations = self._limitations(results)
        relationships = results.input_operation_flow.relationships
        evidence = [
            self._evidence(relationship, observed_at)
            for relationship in relationships
            if relationship.resolution_status is FlowResolutionStatus.RESOLVED
        ]
        unique = {record.evidence_key: record for record in evidence}

        return ToolResult(
            tool=self._identity,
            stage=STATIC_STAGE,
            status=ToolStatus.COMPLETED if metrics.is_complete else ToolStatus.PARTIAL,
            started_at=started_at,
            finished_at=context.clock(),
            counts={
                "files_inventoried": context.discovery.summary.file_count,
                "routes": metrics.route_count,
                "issues": metrics.issue_count,
                "flow_relationships": len(relationships),
                "resolved_flow_relationships": len(unique),
            },
            evidence=sorted(unique.values(), key=lambda record: record.evidence_key),
            limitations=limitations,
        )

    @staticmethod
    def _limitations(results: AssessmentAnalysisResults) -> list[ToolLimitation]:
        metrics = results.summary.summary
        limitations: list[ToolLimitation] = []
        for reason in metrics.discovery_truncation_reasons:
            limitations.append(
                ToolLimitation(
                    code=f"discovery_truncated.{reason.value}",
                    detail="Repository discovery stopped early; later stages saw part of it.",
                )
            )
        for reason in metrics.route_analysis_truncation_reasons:
            limitations.append(
                ToolLimitation(
                    code=f"route_analysis_truncated.{reason.value}",
                    detail="Route analysis inspected only part of the inventory.",
                )
            )
        for status in metrics.source_statuses:
            if not status.is_complete:
                limitations.append(
                    ToolLimitation(
                        code=f"incomplete_source.{status.source.value}",
                        detail=(
                            f"The {status.source.value} analysis reported "
                            f"{status.issue_count} issue(s) and is incomplete."
                        ),
                    )
                )
        if not metrics.is_complete and not limitations:
            limitations.append(
                ToolLimitation(
                    code="analysis_incomplete",
                    detail="The static analysis summary reported incomplete coverage.",
                )
            )
        unique = {item.code: item for item in limitations}
        return [unique[code] for code in sorted(unique)]

    def _evidence(
        self,
        relationship: InputOperationRelationship,
        observed_at: datetime,
    ) -> EvidenceRecord:
        return flow_evidence_record(relationship, observed_at, identity=self._identity)


_STATIC_IDENTITY = ToolIdentity(
    name=STATIC_STAGE, version=settings.app_version, rule_set_version="flow-policy-1"
)


def flow_evidence_record(
    relationship: InputOperationRelationship,
    observed_at: datetime,
    *,
    identity: ToolIdentity = _STATIC_IDENTITY,
) -> EvidenceRecord:
    """Repository evidence for one resolved input-to-operation relationship."""
    rule_id = f"{_RULE_PREFIX}{relationship.operation_category.value}"
    location = EvidenceLocation(
        path=relationship.input_source_file,
        line=relationship.input_line_number,
    )
    digest = content_hash(
        "\n".join(
            (
                relationship.input_source_file,
                str(relationship.input_line_number),
                relationship.operation_source_file,
                str(relationship.operation_line_number),
            )
        )
    )
    return EvidenceRecord(
        evidence_key=evidence_key(identity.name, rule_id, location, digest),
        source_type=EvidenceSourceType.REPOSITORY,
        provenance=EvidenceProvenance(
            tool=identity,
            rule_id=rule_id,
            observed_at=observed_at,
            method="static input-to-operation propagation (resolved)",
        ),
        location=location,
        summary=(
            f"Input reaches a {relationship.operation_category.value} operation at "
            f"{relationship.operation_source_file}:{relationship.operation_line_number}."
        )[:1000],
        content_hash=digest,
        limitations=["Static evidence only; runtime execution and exploitability not verified."],
        metadata={
            "operation_path": relationship.operation_source_file,
            "operation_line": relationship.operation_line_number,
            "detection_confidence": relationship.detection_confidence,
        },
    )


__all__ = ["STATIC_STAGE", "StaticAttackSurfaceTool", "flow_evidence_record"]
