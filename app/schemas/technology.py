from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import DiscoveryTruncationReason


class TechnologyCategory(StrEnum):
    """Kind of technology detected in a repository."""

    LANGUAGE = "language"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    DATABASE = "database"
    INFRASTRUCTURE = "infrastructure"
    BUILD_TOOL = "build_tool"


class TechnologyDetectionMethod(StrEnum):
    """How a technology detection was produced."""

    FILE_EXTENSION = "file_extension"
    MANIFEST_DEPENDENCY = "manifest_dependency"
    MANIFEST_MARKER = "manifest_marker"
    FILENAME_MARKER = "filename_marker"


class TechnologyIssueReason(StrEnum):
    """Reason a manifest could not be inspected."""

    INVALID_PATH = "invalid_path"
    OUTSIDE_ROOT = "outside_root"
    SYMLINK = "symlink"
    NOT_REGULAR_FILE = "not_regular_file"
    TOO_LARGE = "too_large"
    INVALID_ENCODING = "invalid_encoding"
    INVALID_JSON = "invalid_json"
    INVALID_TOML = "invalid_toml"
    INVALID_XML = "invalid_xml"
    MALFORMED_MANIFEST = "malformed_manifest"
    PERMISSION_DENIED = "permission_denied"
    DISAPPEARED = "disappeared"
    INACCESSIBLE = "inaccessible"
    MAX_MANIFEST_FILES = "max_manifest_files"


class TechnologyEvidence(BaseModel):
    """One file or manifest fact supporting a detection."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    detail: str = Field(
        min_length=1,
        description="Human-readable explanation of what the evidence shows.",
    )


class TechnologyDetection(BaseModel):
    """A technology identified from repository metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    category: TechnologyCategory
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[TechnologyEvidence] = Field(min_length=1)
    method: TechnologyDetectionMethod
    file_count: int = Field(
        default=0,
        ge=0,
        description="Number of distinct inventoried files supporting this detection.",
    )


class TechnologyDetectionIssue(BaseModel):
    """A manifest that could not be read or parsed safely."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    reason: TechnologyIssueReason
    detail: str | None = None


class TechnologyDetectionSummary(BaseModel):
    """Counts and discovery-completeness information for one detection run."""

    model_config = ConfigDict(extra="forbid")

    detection_count: int = Field(ge=0)
    language_count: int = Field(ge=0)
    framework_count: int = Field(ge=0)
    library_count: int = Field(ge=0)
    database_count: int = Field(ge=0)
    infrastructure_count: int = Field(ge=0)
    build_tool_count: int = Field(ge=0)
    manifest_files_read: int = Field(
        ge=0,
        description=(
            "Number of allowlisted manifests whose contents were successfully "
            "decoded. Filename-only markers such as Dockerfile are not counted."
        ),
    )
    issue_count: int = Field(ge=0)
    discovery_is_complete: bool
    discovery_truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)


class TechnologyDetectionResult(BaseModel):
    """Deterministic technology inventory for one repository."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    detections: list[TechnologyDetection]
    issues: list[TechnologyDetectionIssue]
    summary: TechnologyDetectionSummary
