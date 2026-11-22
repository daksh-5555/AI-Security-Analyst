from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.attack_surface import AnalysisIssue, HttpMethod, RouteFramework
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.input_sources import InputResolutionStatus, InputType
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
)


class FlowResolutionStatus(StrEnum):
    """Whether a supported input-to-operation data relationship was established."""

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"
    UNSUPPORTED = "unsupported"


class FlowPropagationKind(StrEnum):
    """Kind of one step in a statically supported propagation path."""

    INPUT_PARAMETER = "input_parameter"
    INPUT_ACCESS = "input_access"
    VARIABLE_ASSIGNMENT = "variable_assignment"
    DERIVED_EXPRESSION = "derived_expression"
    ARGUMENT = "argument"
    PARAMETER = "parameter"
    RETURN_VALUE = "return_value"
    CALL_RESULT = "call_result"
    OPERATION_ARGUMENT = "operation_argument"
    OPERATION_RECEIVER = "operation_receiver"


class FlowIssueCategory(StrEnum):
    """Reason a relationship or evidence anchor could not be analyzed cleanly."""

    NO_INPUT_EVIDENCE = "no_input_evidence"
    NO_SENSITIVE_OPERATION_EVIDENCE = "no_sensitive_operation_evidence"
    UNRESOLVED_INPUT_EVIDENCE = "unresolved_input_evidence"
    UNRESOLVED_OPERATION_EVIDENCE = "unresolved_operation_evidence"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    EVIDENCE_NOT_LOCATED = "evidence_not_located"
    AMBIGUOUS_EVIDENCE_LOCATION = "ambiguous_evidence_location"
    UNRESOLVED_CALL_PROPAGATION = "unresolved_call_propagation"
    AMBIGUOUS_CALL_PROPAGATION = "ambiguous_call_propagation"
    UNSUPPORTED_PROPAGATION = "unsupported_propagation"
    CYCLE_DETECTED = "cycle_detected"
    PROPAGATION_DEPTH_LIMIT = "propagation_depth_limit"
    PROPAGATION_STATE_LIMIT = "propagation_state_limit"
    RELATIONSHIP_LIMIT = "relationship_limit"


class FlowAnalysisSource(StrEnum):
    """Earlier analysis whose completeness is reported by this phase."""

    ATTACK_SURFACE_CORRELATION = "attack_surface_correlation"
    INPUT_SOURCES = "input_sources"
    SENSITIVE_OPERATIONS = "sensitive_operations"
    HANDLER_CALLS = "handler_calls"


class PropagationStep(BaseModel):
    """One deterministic, source-backed step in a data relationship."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(ge=0)
    kind: FlowPropagationKind
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    column_number: int | None = Field(default=None, ge=1)
    definition_id: str | None = None
    definition_name: str | None = None
    call_id: str | None = None
    variable_name: str | None = None
    expression: str = Field(
        min_length=1,
        description="Statically readable expression without runtime values.",
    )
    explanation: str = Field(
        min_length=1,
        description="What this step establishes and what it does not establish.",
    )


class HandlerReference(BaseModel):
    """Route handler evidence associated with a flow relationship."""

    model_config = ConfigDict(extra="forbid")

    handler_id: str = Field(min_length=1)
    route_id: str = Field(min_length=1)
    handler_name: str | None = None
    source_file: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    route_path: str = Field(min_length=1)
    http_method: HttpMethod
    framework: RouteFramework


class InputOperationRelationship(BaseModel):
    """One statically supported relationship between input and operation evidence.

    The relationship records a data-propagation path found in parsed source. It
    does not prove that the path executes at runtime, that any value reaches the
    operation at runtime, that validation is absent, or that a vulnerability
    exists.
    """

    model_config = ConfigDict(extra="forbid")

    relationship_id: str = Field(
        min_length=1,
        description="Deterministic identifier derived from the two evidence identifiers.",
    )
    input_id: str = Field(
        min_length=1,
        description="Stable identifier of the input evidence within its source result.",
    )
    input_index: int = Field(ge=0)
    input_type: InputType
    input_source_file: str = Field(min_length=1)
    input_line_number: int = Field(ge=1)
    input_declaration: str = Field(min_length=1)
    input_resolution_status: InputResolutionStatus
    input_detection_confidence: float = Field(ge=0.0, le=1.0)

    operation_id: str = Field(
        min_length=1,
        description="Stable identifier of the operation evidence within its source result.",
    )
    operation_index: int = Field(ge=0)
    operation_category: OperationCategory
    operation_source_file: str = Field(min_length=1)
    operation_line_number: int = Field(ge=1)
    operation_declaration: str = Field(min_length=1)
    operation_resolution_status: OperationResolutionStatus
    operation_detection_confidence: float = Field(ge=0.0, le=1.0)

    resolution_status: FlowResolutionStatus
    detection_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Minimum of the original evidence and call-resolution confidences. "
            "It is never higher than any contributing source confidence."
        ),
    )
    route_ids: list[str] = Field(default_factory=list)
    handler_references: list[HandlerReference] = Field(default_factory=list)
    intermediate_definition_ids: list[str] = Field(default_factory=list)
    intermediate_call_ids: list[str] = Field(default_factory=list)
    ambiguous_definition_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Alternative local targets of an ambiguous call retained as evidence, "
            "never selected as the sole target by name."
        ),
    )
    propagation_steps: list[PropagationStep] = Field(default_factory=list)
    explanation: str = Field(
        min_length=1,
        description="Deterministic rule and evidence supporting the relationship.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Known analysis limits explicitly affecting this relationship.",
    )


class InputOperationIssue(BaseModel):
    """An evidence or propagation pattern that could not be analyzed cleanly."""

    model_config = ConfigDict(extra="forbid")

    source_file: str = Field(min_length=1)
    line_number: int | None = Field(default=None, ge=1)
    category: FlowIssueCategory
    input_id: str | None = None
    operation_id: str | None = None
    call_id: str | None = None
    definition_id: str | None = None
    explanation: str = Field(
        min_length=1,
        description="Deterministic explanation without guessed targets or values.",
    )


class FlowSourceStatus(BaseModel):
    """Completeness and truncation information preserved from one input result."""

    model_config = ConfigDict(extra="forbid")

    source: FlowAnalysisSource
    is_complete: bool
    discovery_is_complete: bool
    issue_count: int = Field(ge=0)
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class InputOperationFlowSummary(BaseModel):
    """Counts, limits, and completeness information for one flow analysis run."""

    model_config = ConfigDict(extra="forbid")

    source_files_inspected: int = Field(ge=0)
    input_count: int = Field(ge=0)
    operation_count: int = Field(ge=0)
    relationship_count: int = Field(ge=0)
    resolved_relationship_count: int = Field(ge=0)
    ambiguous_relationship_count: int = Field(ge=0)
    unresolved_relationship_count: int = Field(ge=0)
    unsupported_relationship_count: int = Field(ge=0)
    inputs_with_relationships: int = Field(ge=0)
    operations_with_relationships: int = Field(ge=0)
    propagation_state_count: int = Field(ge=0)
    source_issue_count: int = Field(ge=0)
    issue_count: int = Field(ge=0)
    source_analysis_is_complete: bool
    is_complete: bool = Field(
        description=(
            "True only when every consumed analysis was complete, every relevant "
            "source file was inspected, and no propagation resource limit was hit."
        )
    )
    discovery_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)
    max_source_files: int = Field(ge=0)
    max_source_file_size_bytes: int = Field(ge=0)
    max_propagation_depth: int = Field(ge=0)
    max_propagation_states: int = Field(ge=0)
    max_relationships: int = Field(ge=0)
    source_statuses: list[FlowSourceStatus] = Field(default_factory=list)


class InputOperationFlowResult(BaseModel):
    """Deterministic evidence-backed input-to-operation flow inventory."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    relationships: list[InputOperationRelationship]
    source_issues: list[AnalysisIssue]
    issues: list[InputOperationIssue]
    summary: InputOperationFlowSummary


__all__ = [
    "FlowAnalysisSource",
    "FlowIssueCategory",
    "FlowPropagationKind",
    "FlowResolutionStatus",
    "FlowSourceStatus",
    "HandlerReference",
    "InputOperationFlowResult",
    "InputOperationFlowSummary",
    "InputOperationIssue",
    "InputOperationRelationship",
    "PropagationStep",
]
