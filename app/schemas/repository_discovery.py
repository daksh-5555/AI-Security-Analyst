from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import (
    DiscoveryItemKind,
    DiscoverySkipReason,
    DiscoveryTruncationReason,
)


class DiscoveryLimits(BaseModel):
    """Resource limits applied to one discovery run."""

    model_config = ConfigDict(extra="forbid")

    max_file_count: int = Field(ge=0)
    max_depth: int = Field(ge=0)
    max_total_size_bytes: int = Field(ge=0)


class FileInventoryEntry(BaseModel):
    """A regular file discovered below the repository root."""

    model_config = ConfigDict(extra="forbid")

    relative_path: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    extension: str | None = Field(
        default=None,
        description="Lowercase extension without the leading dot, or None.",
    )
    size_bytes: int = Field(ge=0)


class SkippedItem(BaseModel):
    """A filesystem entry that was intentionally or unavoidably skipped."""

    model_config = ConfigDict(extra="forbid")

    relative_path: str = Field(
        min_length=1,
        description="POSIX-style path relative to the repository root.",
    )
    kind: DiscoveryItemKind
    reason: DiscoverySkipReason
    detail: str | None = None


class DiscoverySummary(BaseModel):
    """Counts, limits, and completeness information for one discovery run."""

    model_config = ConfigDict(extra="forbid")

    directory_count: int = Field(
        ge=0,
        description=(
            "Directories discovered below the root and selected for traversal; "
            "the root itself is not counted."
        ),
    )
    file_count: int = Field(ge=0)
    total_size_bytes: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    is_complete: bool = Field(
        description=(
            "False when a resource limit truncated the inventory or an unexpected "
            "filesystem error prevented part of it from being read."
        )
    )
    truncation_reasons: list[DiscoveryTruncationReason] = Field(default_factory=list)
    limits: DiscoveryLimits


class RepositoryDiscoveryResult(BaseModel):
    """Deterministic file inventory for one repository root."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(description="Resolved absolute repository root.")
    files: list[FileInventoryEntry]
    skipped: list[SkippedItem]
    summary: DiscoverySummary
