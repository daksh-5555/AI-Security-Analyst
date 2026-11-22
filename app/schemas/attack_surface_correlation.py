from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.attack_surface import (
    HttpMethod,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.auth_controls import AuthControlCandidate
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.input_sources import InputCandidate
from app.schemas.sensitive_operations import SensitiveOperationCandidate


class CorrelationRelationshipType(StrEnum):
    """Kind of evidence relationship attached to a route."""

    ROUTE_TO_AUTH_CONTROL = "route_to_auth_control"
    ROUTE_TO_AUTHORIZATION_CONTROL = "route_to_authorization_control"
    ROUTE_TO_INPUT = "route_to_input"
    ROUTE_TO_SENSITIVE_OPERATION = "route_to_sensitive_operation"


class CorrelationEvidenceSource(StrEnum):
    """Earlier analysis result that supplied an associated evidence candidate."""

    AUTH_CONTROLS = "auth_controls"
    INPUT_SOURCES = "input_sources"
    SENSITIVE_OPERATIONS = "sensitive_operations"


class CorrelationResolutionStatus(StrEnum):
    """Whether an evidence-to-route relationship could be resolved."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"


class CorrelationIssueCategory(StrEnum):
    """Reason a correlation relationship could not be resolved cleanly."""

    UNASSOCIATED_EVIDENCE = "unassociated_evidence"
    UNRESOLVED_ROUTE_REFERENCE = "unresolved_route_reference"
    AMBIGUOUS_ROUTE_REFERENCE = "ambiguous_route_reference"
    UNRESOLVED_ROUTE = "unresolved_route"


class CorrelationAnalysisSource(StrEnum):
    """Analysis result whose completeness is reported by the correlation."""

    ATTACK_SURFACE = "attack_surface"
    AUTH_CONTROLS = "auth_controls"
    INPUT_SOURCES = "input_sources"
    SENSITIVE_OPERATIONS = "sensitive_operations"


class CorrelationRouteReference(BaseModel):
    """A route reference as recorded by an earlier analysis."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    http_method: HttpMethod
    framework: RouteFramework
    resolution_status: RouteResolutionStatus


class CorrelationRelationship(BaseModel):
    """One explainable evidence-to-route relationship."""

    model_config = ConfigDict(extra="forbid")

    relationship_type: CorrelationRelationshipType
    evidence_source: CorrelationEvidenceSource
    evidence_identifier: str = Field(
        min_length=1,
        description=(
            "Deterministic identifier of the evidence within its source result, "
            "for example 'controls[2]' or 'operations[0]'."
        ),
    )
    evidence_index: int = Field(
        ge=0,
        description=(
            "Zero-based position of the evidence in the deterministically sorted source list."
        ),
    )
    evidence_source_file: str = Field(
        min_length=1,
        description="Source file of the original evidence candidate.",
    )
    evidence_line_number: int = Field(ge=1)
    route_id: str = Field(
        min_length=1,
        description="Deterministic identifier of the correlated route declaration.",
    )
    resolution_status: CorrelationResolutionStatus
    explanation: str = Field(
        min_length=1,
        description="Deterministic matching rule and reason for the resolution status.",
    )


class CorrelationIssue(BaseModel):
    """A correlation relationship that could not be resolved cleanly."""

    model_config = ConfigDict(extra="forbid")

    source_file: str | None = Field(
        default=None,
        description="Source file of the affected evidence or route, when known.",
    )
    route: CorrelationRouteReference | None = Field(
        default=None,
        description="Route reference involved in the issue, when known.",
    )
    category: CorrelationIssueCategory
    explanation: str = Field(
        min_length=1,
        description="Deterministic explanation without guessed route identities.",
    )
    evidence_source: CorrelationEvidenceSource | None = None
    evidence_identifier: str | None = None


class CorrelatedRoute(BaseModel):
    """One route declaration with every associated evidence category."""

    model_config = ConfigDict(extra="forbid")

    route_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    http_method: HttpMethod
    framework: RouteFramework
    source_file: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    handler_name: str | None = None
    detection_confidence: float = Field(ge=0.0, le=1.0)
    resolution_status: RouteResolutionStatus
    authentication_controls: list[AuthControlCandidate] = Field(default_factory=list)
    authorization_controls: list[AuthControlCandidate] = Field(default_factory=list)
    input_candidates: list[InputCandidate] = Field(default_factory=list)
    sensitive_operations: list[SensitiveOperationCandidate] = Field(default_factory=list)
    relationships: list[CorrelationRelationship] = Field(default_factory=list)


class CorrelationSourceStatus(BaseModel):
    """Completeness and truncation information preserved from one input result."""

    model_config = ConfigDict(extra="forbid")

    source: CorrelationAnalysisSource
    is_complete: bool
    discovery_is_complete: bool
    issue_count: int = Field(ge=0)
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class AttackSurfaceCorrelationSummary(BaseModel):
    """Counts, completeness, and unresolved-association information."""

    model_config = ConfigDict(extra="forbid")

    total_route_count: int = Field(ge=0)
    routes_with_authentication: int = Field(
        ge=0,
        description=(
            "Routes with at least one associated authentication control, "
            "including ambiguous associations."
        ),
    )
    routes_with_authorization: int = Field(
        ge=0,
        description=(
            "Routes with at least one associated authorization control, "
            "including ambiguous associations."
        ),
    )
    routes_with_inputs: int = Field(
        ge=0,
        description=(
            "Routes with at least one associated input candidate, including ambiguous associations."
        ),
    )
    routes_with_sensitive_operations: int = Field(
        ge=0,
        description=(
            "Routes with at least one associated sensitive operation, including "
            "ambiguous associations."
        ),
    )
    routes_with_multiple_evidence_categories: int = Field(
        ge=0,
        description=(
            "Routes with non-empty evidence in at least two of the four evidence categories."
        ),
    )
    relationship_count: int = Field(ge=0)
    unresolved_association_count: int = Field(
        ge=0,
        description=(
            "Unresolved evidence-to-route relationships, plus evidence "
            "references with no matching route and evidence candidates with no "
            "route association."
        ),
    )
    ambiguous_association_count: int = Field(
        ge=0,
        description=(
            "Evidence-to-route relationships retained as ambiguous because "
            "multiple route declarations shared the same path, HTTP method, and "
            "framework."
        ),
    )
    issue_count: int = Field(ge=0)
    all_sources_complete: bool
    is_complete: bool = Field(
        description=(
            "True only when every source analysis is complete and no correlation "
            "issue was recorded."
        )
    )
    source_statuses: list[CorrelationSourceStatus]


class AttackSurfaceCorrelationResult(BaseModel):
    """Deterministic route-oriented aggregation of prior analysis evidence."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    routes: list[CorrelatedRoute]
    issues: list[CorrelationIssue]
    summary: AttackSurfaceCorrelationSummary


__all__ = [
    "AttackSurfaceCorrelationResult",
    "AttackSurfaceCorrelationSummary",
    "CorrelatedRoute",
    "CorrelationAnalysisSource",
    "CorrelationEvidenceSource",
    "CorrelationIssue",
    "CorrelationIssueCategory",
    "CorrelationRelationship",
    "CorrelationRelationshipType",
    "CorrelationResolutionStatus",
    "CorrelationRouteReference",
    "CorrelationSourceStatus",
]
