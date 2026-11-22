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


class OperationCategory(StrEnum):
    """Kind of statically observed database or sensitive operation."""

    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    DATABASE_DELETE = "database_delete"
    DATABASE_EXECUTE = "database_execute"
    DATABASE_TRANSACTION = "database_transaction"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_METADATA = "file_metadata"
    PROCESS_EXECUTION = "process_execution"
    DESERIALIZATION = "deserialization"
    ARCHIVE_EXTRACTION = "archive_extraction"
    DYNAMIC_CODE_EXECUTION = "dynamic_code_execution"
    FILE_UPLOAD = "file_upload"
    REDIRECT = "redirect"
    OTHER = "other"


class OperationResolutionStatus(StrEnum):
    """Whether an operation and its route associations could be resolved statically."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class SensitiveOperationCandidate(BaseModel):
    """One statically observed database or sensitive operation.

    A candidate is evidence that application code contains a recognizable
    operation. It is not evidence that the operation is reachable with attacker
    input, that validation is absent, or that a vulnerability exists.
    """

    model_config = ConfigDict(extra="forbid")

    operation_category: OperationCategory
    framework_or_library: str = Field(
        min_length=1,
        description="Framework, library, or runtime that supports the operation.",
    )
    operation_name: str = Field(
        min_length=1,
        description="Statically read operation, method, or API name.",
    )
    source_file: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    line_number: int = Field(ge=1)
    enclosing_function: str | None = Field(
        default=None,
        description="Statically read enclosing function or method name.",
    )
    enclosing_class: str | None = Field(
        default=None,
        description="Statically read enclosing class name, when available.",
    )
    receiver_name: str | None = Field(
        default=None,
        description="Statically read receiver expression without runtime values.",
    )
    resource_name: str | None = Field(
        default=None,
        description="Statically available model, table, or resource name.",
    )
    associated_routes: list[AssociatedRoute] = Field(default_factory=list)
    declaration_or_access: str = Field(
        min_length=1,
        description=(
            "Statically readable operation expression without argument values, "
            "SQL text, credentials, file contents, or runtime data."
        ),
    )
    resolution_status: OperationResolutionStatus
    detection_confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = Field(
        min_length=1,
        description="What was observed and why it is relevant.",
    )
    classification_rule: str = Field(
        min_length=1,
        description="Deterministic rule used to classify the operation.",
    )


class SensitiveOperationSummary(BaseModel):
    """Counts, limits, and completeness information for one operation analysis run."""

    model_config = ConfigDict(extra="forbid")

    source_files_inspected: int = Field(ge=0)
    operation_count: int = Field(ge=0)
    database_operation_count: int = Field(ge=0)
    filesystem_operation_count: int = Field(ge=0)
    process_execution_count: int = Field(ge=0)
    other_sensitive_operation_count: int = Field(ge=0)
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


class SensitiveOperationResult(BaseModel):
    """Deterministic inventory of database and sensitive operations."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    operations: list[SensitiveOperationCandidate]
    issues: list[AnalysisIssue]
    summary: SensitiveOperationSummary


__all__ = [
    "AnalysisIssue",
    "AnalysisIssueReason",
    "AssociatedRoute",
    "HttpMethod",
    "OperationCategory",
    "OperationResolutionStatus",
    "RouteFramework",
    "RouteResolutionStatus",
    "SensitiveOperationCandidate",
    "SensitiveOperationResult",
    "SensitiveOperationSummary",
]
