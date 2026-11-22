from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.attack_surface import (
    AnalysisIssue,
    AnalysisIssueReason,
    HttpMethod,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.auth_controls import AssociatedRoute
from app.schemas.enums import DiscoveryTruncationReason


class InputType(StrEnum):
    """Kind of external input source observed in application code."""

    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM = "form"
    FILE = "file"
    REQUEST_OBJECT = "request_object"
    OTHER = "other"


class InputResolutionStatus(StrEnum):
    """Whether an input source and its route associations could be resolved."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class InputCandidate(BaseModel):
    """One statically observed input declaration or access.

    A candidate is evidence that application code reads an external input. It is
    not evidence of a vulnerability, unsafe handling, or missing validation.
    """

    model_config = ConfigDict(extra="forbid")

    input_type: InputType
    framework: RouteFramework
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    parameter_name: str | None = Field(
        default=None,
        description="Statically readable parameter or field name, when available.",
    )
    variable_name: str | None = Field(
        default=None,
        description="Statically readable local variable or argument name, when available.",
    )
    handler_name: str | None = Field(
        default=None,
        description="Statically readable handler, view, or controller method name.",
    )
    associated_routes: list[AssociatedRoute] = Field(default_factory=list)
    declaration_or_access: str = Field(
        min_length=1,
        description="Statically readable declaration or access expression without runtime values.",
    )
    resolution_status: InputResolutionStatus
    detection_confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = Field(
        min_length=1,
        description="What was observed and why it is relevant.",
    )
    classification_rule: str = Field(
        min_length=1,
        description="Deterministic rule used to classify the input source.",
    )


class InputSourceSummary(BaseModel):
    """Counts, limits, and completeness information for one input analysis run."""

    model_config = ConfigDict(extra="forbid")

    source_files_inspected: int = Field(ge=0)
    input_count: int = Field(ge=0)
    named_parameter_count: int = Field(ge=0)
    route_association_count: int = Field(ge=0)
    unresolved_association_count: int = Field(ge=0)
    issue_count: int = Field(ge=0)
    is_complete: bool = Field(
        description=(
            "True only when discovery was complete and every eligible source file "
            "was inspected without a limit or inspection failure."
        )
    )
    discovery_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class InputSourceResult(BaseModel):
    """Deterministic inventory of external input declarations and accesses."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    inputs: list[InputCandidate]
    issues: list[AnalysisIssue]
    summary: InputSourceSummary


__all__ = [
    "AnalysisIssue",
    "AnalysisIssueReason",
    "AssociatedRoute",
    "HttpMethod",
    "InputCandidate",
    "InputResolutionStatus",
    "InputSourceResult",
    "InputSourceSummary",
    "InputType",
    "RouteFramework",
    "RouteResolutionStatus",
]
