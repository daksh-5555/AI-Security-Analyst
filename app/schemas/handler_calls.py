from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.attack_surface import (
    AnalysisIssue,
    HttpMethod,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.enums import DiscoveryTruncationReason


class FunctionKind(StrEnum):
    """Kind of statically identified local Python definition."""

    FUNCTION = "function"
    METHOD = "method"
    NESTED_FUNCTION = "nested_function"


class HandlerResolutionStatus(StrEnum):
    """Whether a route handler could be linked to one local definition."""

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


class CallResolutionStatus(StrEnum):
    """Whether a statically observed call target could be established."""

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"
    EXTERNAL = "external"


class CallRelationshipType(StrEnum):
    """Kind of local caller-to-callee relationship."""

    HANDLER_TO_FUNCTION = "handler_to_function"
    HANDLER_TO_METHOD = "handler_to_method"
    FUNCTION_TO_FUNCTION = "function_to_function"
    FUNCTION_TO_METHOD = "function_to_method"
    METHOD_TO_FUNCTION = "method_to_function"
    METHOD_TO_METHOD = "method_to_method"


class HandlerCallIssueCategory(StrEnum):
    """Reason a handler or local call relationship could not be resolved."""

    MISSING_HANDLER_NAME = "missing_handler_name"
    HANDLER_DEFINITION_NOT_FOUND = "handler_definition_not_found"
    AMBIGUOUS_HANDLER_DEFINITION = "ambiguous_handler_definition"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    UNRESOLVED_CALL = "unresolved_call"
    AMBIGUOUS_CALL = "ambiguous_call"


class RouteHandler(BaseModel):
    """One route declaration and its statically identified handler definition."""

    model_config = ConfigDict(extra="forbid")

    handler_id: str = Field(
        min_length=1,
        description="Deterministic identifier of the route-handler pairing.",
    )
    route_id: str = Field(
        min_length=1,
        description="Deterministic identifier of the route declaration.",
    )
    route_path: str = Field(min_length=1)
    http_method: HttpMethod
    framework: RouteFramework
    route_source_file: str = Field(
        min_length=1,
        description="POSIX-style path of the route declaration.",
    )
    route_line_number: int = Field(ge=1)
    route_resolution_status: RouteResolutionStatus
    handler_name: str | None = Field(
        default=None,
        description="Handler name recorded by route extraction, when available.",
    )
    definition_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Local definitions matching the handler: exactly one when resolved, "
            "several when ambiguous, and none when unresolved."
        ),
    )
    resolution_status: HandlerResolutionStatus
    detection_confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(
        min_length=1,
        description="Deterministic evidence and reason for the resolution status.",
    )


class LocalFunctionDefinition(BaseModel):
    """A function or method defined in an inspected Python source file."""

    model_config = ConfigDict(extra="forbid")

    definition_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    qualified_name: str = Field(
        min_length=1,
        description="Dot-separated class and function path without runtime values.",
    )
    kind: FunctionKind
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    column_number: int = Field(ge=1)
    end_line_number: int = Field(ge=1)
    class_name: str | None = None
    parent_definition_id: str | None = Field(
        default=None,
        description="Nearest enclosing function definition, for nested functions.",
    )
    is_async: bool
    parameter_count: int = Field(ge=0)
    is_route_handler: bool = False
    route_ids: list[str] = Field(default_factory=list)
    detection_confidence: float = Field(ge=0.0, le=1.0)


class CallSite(BaseModel):
    """One statically observed call expression inside a local definition.

    A call site is evidence that a call expression exists in source code. It is
    not evidence that the call executes, that arguments have particular values,
    or that a vulnerability exists.
    """

    model_config = ConfigDict(extra="forbid")

    call_id: str = Field(min_length=1)
    caller_definition_id: str = Field(min_length=1)
    caller_name: str = Field(min_length=1)
    caller_kind: FunctionKind
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    column_number: int = Field(ge=1)
    callee_expression: str = Field(
        min_length=1,
        description=(
            "Statically readable callee expression without argument values or runtime data."
        ),
    )
    callee_name: str = Field(min_length=1)
    receiver_expression: str | None = Field(
        default=None,
        description="Statically readable receiver expression, when the call is an attribute call.",
    )
    is_method_call: bool
    resolution_status: CallResolutionStatus
    target_definition_ids: list[str] = Field(default_factory=list)
    is_recursive: bool = Field(
        default=False,
        description="True when the caller itself is one of the resolved targets.",
    )
    detection_confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(
        min_length=1,
        description="Deterministic evidence and reason for the resolution status.",
    )


class CallRelationship(BaseModel):
    """One local caller-to-callee relationship supported by a call site."""

    model_config = ConfigDict(extra="forbid")

    relationship_id: str = Field(min_length=1)
    relationship_type: CallRelationshipType
    caller_definition_id: str = Field(min_length=1)
    callee_definition_id: str = Field(min_length=1)
    call_id: str = Field(min_length=1)
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path of the call site.",
    )
    line_number: int = Field(ge=1)
    resolution_status: CallResolutionStatus
    is_recursive: bool = False
    detection_confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(
        min_length=1,
        description="Deterministic matching rule and reason for the resolution status.",
    )


class HandlerCallIssue(BaseModel):
    """A handler or call relationship that could not be resolved cleanly."""

    model_config = ConfigDict(extra="forbid")

    source_file: str = Field(min_length=1)
    line_number: int | None = Field(default=None, ge=1)
    category: HandlerCallIssueCategory
    handler_id: str | None = None
    call_id: str | None = None
    definition_id: str | None = None
    explanation: str = Field(
        min_length=1,
        description="Deterministic explanation without guessed targets or values.",
    )


class HandlerCallSummary(BaseModel):
    """Counts, limits, and completeness information for one analysis run."""

    model_config = ConfigDict(extra="forbid")

    source_files_inspected: int = Field(ge=0)
    route_handler_count: int = Field(ge=0)
    resolved_handler_count: int = Field(ge=0)
    ambiguous_handler_count: int = Field(ge=0)
    unresolved_handler_count: int = Field(ge=0)
    definition_count: int = Field(ge=0)
    function_definition_count: int = Field(ge=0)
    method_definition_count: int = Field(ge=0)
    nested_function_definition_count: int = Field(ge=0)
    call_site_count: int = Field(ge=0)
    resolved_call_count: int = Field(ge=0)
    ambiguous_call_count: int = Field(ge=0)
    unresolved_call_count: int = Field(ge=0)
    external_call_count: int = Field(ge=0)
    recursive_call_count: int = Field(ge=0)
    relationship_count: int = Field(ge=0)
    issue_count: int = Field(ge=0, description="Source and import inspection issue count.")
    call_issue_count: int = Field(ge=0, description="Handler and call resolution issue count.")
    is_complete: bool = Field(
        description=(
            "True only when discovery and route analysis were complete and every "
            "eligible source file was inspected without an inspection failure."
        )
    )
    discovery_is_complete: bool
    route_analysis_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)
    route_analysis_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class HandlerCallResult(BaseModel):
    """Deterministic handler and local call-relationship inventory."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    handlers: list[RouteHandler]
    definitions: list[LocalFunctionDefinition]
    calls: list[CallSite]
    relationships: list[CallRelationship]
    issues: list[AnalysisIssue]
    call_issues: list[HandlerCallIssue]
    summary: HandlerCallSummary


__all__ = [
    "CallRelationship",
    "CallRelationshipType",
    "CallResolutionStatus",
    "CallSite",
    "FunctionKind",
    "HandlerCallIssue",
    "HandlerCallIssueCategory",
    "HandlerCallResult",
    "HandlerCallSummary",
    "HandlerResolutionStatus",
    "LocalFunctionDefinition",
    "RouteHandler",
]
