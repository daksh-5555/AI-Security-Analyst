import json

import pytest

from app.schemas.attack_surface import HttpMethod, RouteFramework
from app.schemas.enums import FindingSeverity, FindingStatus
from app.schemas.input_operation_flow import (
    FlowPropagationKind,
    FlowResolutionStatus,
    HandlerReference,
    InputOperationFlowResult,
    InputOperationFlowSummary,
    InputOperationRelationship,
    PropagationStep,
)
from app.schemas.input_sources import (
    InputResolutionStatus,
    InputType,
)
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
)
from app.services.finding_policy import generate_findings


def make_relationship(
    *,
    resolution_status: FlowResolutionStatus = FlowResolutionStatus.RESOLVED,
    detection_confidence: float = 0.72,
) -> InputOperationRelationship:
    return InputOperationRelationship(
        relationship_id="inputs[0]->operations[0]",
        input_id="inputs[0]",
        input_index=0,
        input_type=InputType.QUERY,
        input_source_file="app.py",
        input_line_number=20,
        input_declaration="request.args.get('q')",
        input_resolution_status=InputResolutionStatus.RESOLVED,
        input_detection_confidence=0.8,
        operation_id="operations[0]",
        operation_index=0,
        operation_category=OperationCategory.DATABASE_READ,
        operation_source_file="app.py",
        operation_line_number=30,
        operation_declaration="cursor.execute(q)",
        operation_resolution_status=OperationResolutionStatus.RESOLVED,
        operation_detection_confidence=0.9,
        resolution_status=resolution_status,
        detection_confidence=detection_confidence,
        route_ids=["route-1"],
        handler_references=[
            HandlerReference(
                handler_id="handler-1",
                route_id="route-1",
                handler_name="handler",
                source_file="app.py",
                line_number=18,
                route_path="/direct",
                http_method=HttpMethod.GET,
                framework=RouteFramework.FLASK,
            )
        ],
        intermediate_definition_ids=["definition-1"],
        intermediate_call_ids=["call-1"],
        propagation_steps=[
            PropagationStep(
                step_index=0,
                kind=FlowPropagationKind.INPUT_ACCESS,
                source_file="app.py",
                line_number=20,
                definition_id="definition-1",
                definition_name="handler",
                expression="request.args.get('q')",
                explanation="The input access was observed.",
            ),
            PropagationStep(
                step_index=1,
                kind=FlowPropagationKind.OPERATION_ARGUMENT,
                source_file="app.py",
                line_number=30,
                definition_id="definition-1",
                definition_name="handler",
                expression="cursor.execute(q)",
                explanation="The propagated value is used as an operation argument.",
            ),
        ],
        explanation="A supported propagation path was recorded.",
        limitations=["Static analysis only."],
    )


def make_flow_result(
    relationships: list[InputOperationRelationship],
) -> InputOperationFlowResult:
    def count(status: FlowResolutionStatus) -> int:
        return sum(relationship.resolution_status is status for relationship in relationships)

    return InputOperationFlowResult(
        root="/repository",
        relationships=relationships,
        source_issues=[],
        issues=[],
        summary=InputOperationFlowSummary(
            source_files_inspected=1,
            input_count=1,
            operation_count=1,
            relationship_count=len(relationships),
            resolved_relationship_count=count(FlowResolutionStatus.RESOLVED),
            ambiguous_relationship_count=count(FlowResolutionStatus.AMBIGUOUS),
            unresolved_relationship_count=count(FlowResolutionStatus.UNRESOLVED),
            unsupported_relationship_count=count(FlowResolutionStatus.UNSUPPORTED),
            inputs_with_relationships=1,
            operations_with_relationships=1,
            propagation_state_count=1,
            source_issue_count=0,
            issue_count=0,
            source_analysis_is_complete=True,
            is_complete=True,
            discovery_is_complete=True,
            discovery_truncation_reasons=[],
            max_source_files=2_000,
            max_source_file_size_bytes=1_048_576,
            max_propagation_depth=12,
            max_propagation_states=5_000,
            max_relationships=10_000,
            source_statuses=[],
        ),
    )


def test_only_resolved_relationships_generate_findings() -> None:
    flow = make_flow_result(
        [
            make_relationship(),
            make_relationship(resolution_status=FlowResolutionStatus.AMBIGUOUS),
            make_relationship(resolution_status=FlowResolutionStatus.UNRESOLVED),
            make_relationship(resolution_status=FlowResolutionStatus.UNSUPPORTED),
        ]
    )

    result = generate_findings(flow)

    assert len(result.findings) == 1
    assert result.eligible_relationship_count == 1
    assert result.skipped_relationship_count == 0
    assert result.limitations == []
    assert result.findings[0].title.startswith("Static input-to-operation flow")


def test_finding_severity_status_and_confidence_are_preserved() -> None:
    result = generate_findings(make_flow_result([make_relationship(detection_confidence=0.37)]))

    finding = result.findings[0]

    assert finding.severity is FindingSeverity.INFORMATIONAL
    assert finding.status is FindingStatus.NOT_TESTED
    assert finding.confidence == 0.37
    assert finding.category == "input_to_database_read"
    assert finding.remediation is None


def test_evidence_details_preserve_relationship_context() -> None:
    result = generate_findings(make_flow_result([make_relationship()]))

    finding = result.findings[0]
    details = finding.evidence[0].details

    assert details is not None
    assert details["relationship_id"] == "inputs[0]->operations[0]"
    assert details["input"] == {
        "id": "inputs[0]",
        "index": 0,
        "type": "query",
        "file": "app.py",
        "line": 20,
        "declaration": "request.args.get('q')",
        "resolution_status": "resolved",
        "detection_confidence": 0.8,
    }
    assert details["operation"] == {
        "id": "operations[0]",
        "index": 0,
        "category": "database_read",
        "file": "app.py",
        "line": 30,
        "declaration": "cursor.execute(q)",
        "resolution_status": "resolved",
        "detection_confidence": 0.9,
    }
    assert details["resolution_status"] == "resolved"
    assert details["detection_confidence"] == 0.72
    assert details["route_ids"] == ["route-1"]
    assert details["handler_references"][0]["handler_id"] == "handler-1"
    assert details["propagation_steps"][0]["kind"] == "input_access"
    assert details["propagation_steps"][1]["kind"] == "operation_argument"
    assert details["explanation"] == "A supported propagation path was recorded."
    assert details["limitations"] == ["Static analysis only."]
    assert "source_text" not in details
    json.dumps(details)


def test_resolved_relationship_without_propagation_steps_is_skipped() -> None:
    relationship = make_relationship().model_copy(update={"propagation_steps": []})

    result = generate_findings(make_flow_result([relationship]))

    assert result.findings == []
    assert result.eligible_relationship_count == 1
    assert result.skipped_relationship_count == 1
    assert "no source-backed propagation steps" in result.limitations[0]


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("nan")])
def test_invalid_confidence_is_skipped_without_clamping(confidence: float) -> None:
    relationship = make_relationship().model_copy(update={"detection_confidence": confidence})

    result = generate_findings(make_flow_result([relationship]))

    assert result.findings == []
    assert result.skipped_relationship_count == 1
    assert "detector confidence" in result.limitations[0]


def test_missing_required_evidence_is_skipped() -> None:
    relationship = make_relationship().model_copy(update={"input_declaration": ""})

    result = generate_findings(make_flow_result([relationship]))

    assert result.findings == []
    assert result.skipped_relationship_count == 1
    assert "required relationship evidence is missing" in result.limitations[0]
