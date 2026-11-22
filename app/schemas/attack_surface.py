from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import DiscoveryTruncationReason


class RouteFramework(StrEnum):
    """Framework that declared an API route."""

    FASTAPI = "fastapi"
    FLASK = "flask"
    DJANGO = "django"
    EXPRESS = "express"
    NESTJS = "nestjs"


class HttpMethod(StrEnum):
    """HTTP method associated with a route candidate."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    ANY = "ANY"


class RouteResolutionStatus(StrEnum):
    """Whether a route path could be determined statically."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class AnalysisIssueReason(StrEnum):
    """Reason a source file or route declaration could not be analyzed."""

    INVALID_PATH = "invalid_path"
    OUTSIDE_ROOT = "outside_root"
    SYMLINK = "symlink"
    NOT_REGULAR_FILE = "not_regular_file"
    TOO_LARGE = "too_large"
    INVALID_ENCODING = "invalid_encoding"
    INVALID_SYNTAX = "invalid_syntax"
    UNSUPPORTED_SYNTAX = "unsupported_syntax"
    PERMISSION_DENIED = "permission_denied"
    DISAPPEARED = "disappeared"
    INACCESSIBLE = "inaccessible"
    MAX_SOURCE_FILES = "max_source_files"
    EXCLUDED_PATH = "excluded_path"
    SENSITIVE_FILE = "sensitive_file"


class RouteCandidate(BaseModel):
    """One statically detected API route declaration."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        min_length=1,
        description=(
            "Route path as declared, with any statically determined prefix applied. "
            "For unresolved candidates this is the source expression or best-known "
            "fragment rather than an invented concrete path."
        ),
    )
    http_method: HttpMethod
    framework: RouteFramework
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    handler_name: str | None = Field(
        default=None,
        description="Statically readable handler or view name, when one is available.",
    )
    detection_confidence: float = Field(ge=0.0, le=1.0)
    resolution_status: RouteResolutionStatus


class AnalysisIssue(BaseModel):
    """A source file or declaration that could not be analyzed safely."""

    model_config = ConfigDict(extra="forbid")

    source_file: str = Field(min_length=1)
    reason: AnalysisIssueReason
    detail: str | None = None


class AttackSurfaceSummary(BaseModel):
    """Counts, limits, and completeness information for one analysis run."""

    model_config = ConfigDict(extra="forbid")

    source_files_inspected: int = Field(ge=0)
    route_count: int = Field(ge=0)
    resolved_route_count: int = Field(ge=0)
    unresolved_route_count: int = Field(ge=0)
    issue_count: int = Field(ge=0)
    is_complete: bool = Field(
        description=(
            "True only when discovery was complete and every eligible source file "
            "was inspected without a limit or inspection failure."
        )
    )
    discovery_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class AttackSurfaceResult(BaseModel):
    """Deterministic API route inventory for one repository."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    routes: list[RouteCandidate]
    issues: list[AnalysisIssue]
    summary: AttackSurfaceSummary
