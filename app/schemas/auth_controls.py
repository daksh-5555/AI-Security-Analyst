from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.attack_surface import (
    AnalysisIssue,
    AnalysisIssueReason,
    HttpMethod,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.enums import DiscoveryTruncationReason


class ControlType(StrEnum):
    """Kind of authentication or authorization declaration detected."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"


class ControlScopeType(StrEnum):
    """Apparent scope of a declared authentication or authorization control."""

    ROUTE = "route"
    ROUTER = "router"
    APPLICATION = "application"
    CONTROLLER = "controller"
    CLASS = "class"
    FUNCTION = "function"
    UNKNOWN = "unknown"


class ControlResolutionStatus(StrEnum):
    """Whether a control's scope and route associations could be resolved statically."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class AssociatedRoute(BaseModel):
    """A route that a control apparently applies to, as observed statically."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    http_method: HttpMethod
    framework: RouteFramework
    resolution_status: RouteResolutionStatus


class AuthControlCandidate(BaseModel):
    """One statically detected authentication or authorization declaration.

    A candidate is evidence that a control was declared. It is not evidence that
    the control works, that it covers every code path, or that an associated route
    is secure.
    """

    model_config = ConfigDict(extra="forbid")

    control_type: ControlType
    framework: RouteFramework
    mechanism: str = Field(
        min_length=1,
        description="Framework mechanism or declaration that produced the candidate.",
    )
    declaration: str | None = Field(
        default=None,
        description="Statically readable source expression or decorator text.",
    )
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    symbol_name: str | None = Field(
        default=None,
        description="Statically readable function, class, router, or guard name.",
    )
    scope_type: ControlScopeType
    associated_routes: list[AssociatedRoute] = Field(default_factory=list)
    resolution_status: ControlResolutionStatus
    detection_confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = Field(
        min_length=1,
        description="What was observed and why it is relevant.",
    )
    classification_rule: str = Field(
        min_length=1,
        description="Deterministic rule used to classify the declaration.",
    )


class AuthControlSummary(BaseModel):
    """Counts, limits, and completeness information for one control analysis run."""

    model_config = ConfigDict(extra="forbid")

    source_files_inspected: int = Field(ge=0)
    authentication_control_count: int = Field(ge=0)
    authorization_control_count: int = Field(ge=0)
    route_association_count: int = Field(ge=0)
    unresolved_scope_count: int = Field(ge=0)
    issue_count: int = Field(ge=0)
    is_complete: bool = Field(
        description=(
            "True only when discovery was complete and every eligible source file "
            "was inspected without a limit or inspection failure."
        )
    )
    discovery_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class AuthControlResult(BaseModel):
    """Deterministic authentication and authorization declaration inventory."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    controls: list[AuthControlCandidate]
    issues: list[AnalysisIssue]
    summary: AuthControlSummary


__all__ = [
    "AnalysisIssue",
    "AnalysisIssueReason",
    "AssociatedRoute",
    "AuthControlCandidate",
    "AuthControlResult",
    "AuthControlSummary",
    "ControlResolutionStatus",
    "ControlScopeType",
    "ControlType",
]
