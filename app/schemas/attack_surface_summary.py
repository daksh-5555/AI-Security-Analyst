from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.attack_surface import (
    HttpMethod,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.attack_surface_correlation import CorrelationRelationship
from app.schemas.auth_controls import AuthControlCandidate
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.handler_calls import (
    CallRelationship,
    CallSite,
    LocalFunctionDefinition,
    RouteHandler,
)
from app.schemas.input_operation_flow import InputOperationRelationship
from app.schemas.input_sources import InputCandidate
from app.schemas.sensitive_operations import SensitiveOperationCandidate


class SummaryAnalysisSource(StrEnum):
    """Analysis result whose completeness and issues are represented in the summary."""

    ATTACK_SURFACE = "attack_surface"
    AUTH_CONTROLS = "auth_controls"
    INPUT_SOURCES = "input_sources"
    SENSITIVE_OPERATIONS = "sensitive_operations"
    ATTACK_SURFACE_CORRELATION = "attack_surface_correlation"
    HANDLER_CALLS = "handler_calls"
    INPUT_OPERATION_FLOW = "input_operation_flow"


class SummaryIssueKind(StrEnum):
    """Kind of issue retained by the summary."""

    INSPECTION = "inspection"
    CORRELATION = "correlation"
    HANDLER_CALL = "handler_call"
    INPUT_OPERATION_FLOW = "input_operation_flow"


class SummaryIssue(BaseModel):
    """One aggregated issue with its original evidence identifiers preserved.

    Equivalent records reported by several analyses are merged and all origins
    are retained. ``route_id`` is populated only when the source issue already
    carried a route identity or a definition/call that the earlier analyses had
    associated with exactly one route; otherwise the issue remains global.
    """

    model_config = ConfigDict(extra="forbid")

    issue_id: str = Field(
        min_length=1,
        description="Deterministic identifier assigned after issue deduplication and sorting.",
    )
    origins: list[SummaryAnalysisSource] = Field(
        min_length=1,
        description="Every source analysis that reported this equivalent issue.",
    )
    kind: SummaryIssueKind
    category: str = Field(
        min_length=1,
        description="Original issue category or reason value, preserved without reinterpretation.",
    )
    route_id: str | None = Field(
        default=None,
        description="Known route identifier, only when directly supported by the source issue.",
    )
    route_path: str | None = None
    route_http_method: HttpMethod | None = None
    route_framework: RouteFramework | None = None
    route_resolution_status: RouteResolutionStatus | None = None
    source_file: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    handler_id: str | None = None
    call_id: str | None = None
    definition_id: str | None = None
    input_id: str | None = None
    operation_id: str | None = None
    relationship_id: str | None = None
    evidence_identifier: str | None = Field(
        default=None,
        description="Original correlation evidence identifier such as 'controls[2]'.",
    )
    detail: str | None = Field(
        default=None,
        description="Original source-inspection detail, when one was recorded.",
    )
    explanation: str = Field(
        min_length=1,
        description="Original deterministic explanation without a security conclusion.",
    )


class SummarySourceStatus(BaseModel):
    """Completeness and truncation metadata preserved from one analysis source."""

    model_config = ConfigDict(extra="forbid")

    source: SummaryAnalysisSource
    is_complete: bool
    discovery_is_complete: bool
    route_analysis_is_complete: bool | None = Field(
        default=None,
        description="Route-analysis completeness when the source reports it separately.",
    )
    issue_count: int = Field(
        ge=0,
        description="Issue count recorded by the source before summary deduplication.",
    )
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)
    route_analysis_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class AttackSurfaceRouteSummary(BaseModel):
    """One route with all evidence previously associated with that route.

    The evidence records are the original models from the earlier analyses. A
    route with no authentication, input, operation, or flow evidence is recorded
    with an empty collection; the summary never turns absence into a negative
    security conclusion.
    """

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
    correlation_relationships: list[CorrelationRelationship] = Field(default_factory=list)

    handlers: list[RouteHandler] = Field(default_factory=list)
    handler_definitions: list[LocalFunctionDefinition] = Field(default_factory=list)
    call_sites: list[CallSite] = Field(default_factory=list)
    call_relationships: list[CallRelationship] = Field(default_factory=list)

    input_operation_relationships: list[InputOperationRelationship] = Field(default_factory=list)

    issue_ids: list[str] = Field(
        default_factory=list,
        description="Identifiers of aggregated issues directly associated with this route.",
    )


class GlobalAttackSurfaceEvidence(BaseModel):
    """Evidence retained because it could not be linked to a summarized route.

    Nothing in this collection is assigned to a route. The original evidence
    identifiers, source locations, resolution statuses, and confidences remain
    unchanged.
    """

    model_config = ConfigDict(extra="forbid")

    unlinked_handlers: list[RouteHandler] = Field(default_factory=list)
    unassociated_definitions: list[LocalFunctionDefinition] = Field(default_factory=list)
    unassociated_call_sites: list[CallSite] = Field(default_factory=list)
    unassociated_call_relationships: list[CallRelationship] = Field(default_factory=list)
    unassociated_input_operation_relationships: list[InputOperationRelationship] = Field(
        default_factory=list
    )


class AttackSurfaceSummaryMetrics(BaseModel):
    """Aggregate counts, resolution totals, and completeness for one summary run.

    Evidence counts are distinct original records attached to at least one route,
    not attachment occurrences. Route counts count routes with a non-empty
    category, including ambiguous evidence. Resolution counts are taken from the
    consumed analyses without changing their statuses.
    """

    model_config = ConfigDict(extra="forbid")

    route_count: int = Field(ge=0)
    routes_with_handlers: int = Field(ge=0)
    routes_without_handlers: int = Field(
        ge=0,
        description="Routes with no handler record; this is not an authentication conclusion.",
    )
    routes_with_resolved_handlers: int = Field(ge=0)
    routes_with_ambiguous_handlers: int = Field(ge=0)
    routes_with_unresolved_handlers: int = Field(ge=0)
    routes_with_authentication: int = Field(ge=0)
    routes_with_authorization: int = Field(ge=0)
    routes_with_inputs: int = Field(ge=0)
    routes_with_sensitive_operations: int = Field(ge=0)
    routes_with_input_operation_relationships: int = Field(ge=0)
    routes_with_multiple_evidence_categories: int = Field(
        ge=0,
        description=(
            "Routes with non-empty evidence in at least two of authentication, "
            "authorization, input, and sensitive-operation categories."
        ),
    )

    authentication_control_count: int = Field(ge=0)
    authorization_control_count: int = Field(ge=0)
    input_count: int = Field(ge=0)
    sensitive_operation_count: int = Field(ge=0)
    correlation_relationship_count: int = Field(ge=0)

    handler_count: int = Field(ge=0)
    handler_resolved_count: int = Field(ge=0)
    handler_ambiguous_count: int = Field(ge=0)
    handler_unresolved_count: int = Field(ge=0)
    definition_count: int = Field(ge=0)
    call_count: int = Field(ge=0)
    call_resolved_count: int = Field(ge=0)
    call_ambiguous_count: int = Field(ge=0)
    call_unresolved_count: int = Field(ge=0)
    call_external_count: int = Field(ge=0)
    call_relationship_count: int = Field(ge=0)
    call_relationship_resolved_count: int = Field(ge=0)
    call_relationship_ambiguous_count: int = Field(ge=0)
    call_relationship_unresolved_count: int = Field(ge=0)
    call_relationship_external_count: int = Field(ge=0)

    input_operation_relationship_count: int = Field(ge=0)
    input_operation_resolved_count: int = Field(ge=0)
    input_operation_ambiguous_count: int = Field(ge=0)
    input_operation_unresolved_count: int = Field(ge=0)
    input_operation_unsupported_count: int = Field(ge=0)
    unassociated_input_operation_relationship_count: int = Field(ge=0)

    issue_count: int = Field(ge=0)
    inspection_issue_count: int = Field(ge=0)
    correlation_issue_count: int = Field(ge=0)
    handler_call_issue_count: int = Field(ge=0)
    input_operation_issue_count: int = Field(ge=0)
    unresolved_issue_count: int = Field(
        ge=0,
        description="Aggregated issues whose original category denotes unresolved evidence.",
    )
    ambiguous_issue_count: int = Field(
        ge=0,
        description="Aggregated issues whose original category denotes ambiguous evidence.",
    )
    unsupported_issue_count: int = Field(
        ge=0,
        description="Aggregated issues whose original category denotes unsupported analysis.",
    )

    all_sources_complete: bool = Field(
        description="True only when every consumed analysis result reports completeness.",
    )
    is_complete: bool = Field(
        description=(
            "True only when all consumed analyses are complete. The summary adds no "
            "analysis, so unresolved and ambiguous evidence alone does not make it false."
        )
    )
    discovery_is_complete: bool
    route_analysis_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)
    route_analysis_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)
    source_statuses: list[SummarySourceStatus] = Field(default_factory=list)


class AttackSurfaceSummaryResult(BaseModel):
    """Deterministic, evidence-backed consolidation of the four analysis results."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(
        description=(
            "Internal resolved absolute repository root. This field is not exposed by the HTTP API."
        )
    )
    routes: list[AttackSurfaceRouteSummary]
    global_evidence: GlobalAttackSurfaceEvidence
    issues: list[SummaryIssue]
    summary: AttackSurfaceSummaryMetrics


class AttackSurfaceSummaryResponse(BaseModel):
    """HTTP representation of a summary that never exposes a host path."""

    model_config = ConfigDict(extra="forbid")

    repository: str = Field(
        min_length=1,
        description="Repository path relative to its configured allowed root.",
    )
    routes: list[AttackSurfaceRouteSummary]
    global_evidence: GlobalAttackSurfaceEvidence
    issues: list[SummaryIssue]
    summary: AttackSurfaceSummaryMetrics


__all__ = [
    "AttackSurfaceRouteSummary",
    "AttackSurfaceSummaryMetrics",
    "AttackSurfaceSummaryResponse",
    "AttackSurfaceSummaryResult",
    "GlobalAttackSurfaceEvidence",
    "SummaryAnalysisSource",
    "SummaryIssue",
    "SummaryIssueKind",
    "SummarySourceStatus",
]
