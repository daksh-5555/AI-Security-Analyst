"""Typed contracts shared by every analysis tool.

These models are the extension seam described in ADR-0001. A tool returns a
``ToolResult``; the pipeline consumes it without knowing which tool produced it.
Evidence is represented by ``EvidenceRecord`` (ADR-0002), which has no field for
raw sensitive values: callers must redact before constructing a record.

Validators enforce the invariants that matter for safety and honesty:

- locations are repository-relative or URL-path based and never absolute host
  paths;
- excerpts are bounded;
- a ``failed`` or ``cancelled`` result carries a safe error code, and a
  ``completed`` result does not;
- a result is only ``clean`` when it completed and produced no evidence.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Final

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

MAX_EXCERPT_LENGTH: Final[int] = 240
MAX_IDENTIFIER_LENGTH: Final[int] = 200
MAX_TEXT_LENGTH: Final[int] = 1_000
MAX_LOCATION_LENGTH: Final[int] = 1_024

_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9_.:\-]*$")
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


class ToolStatus(StrEnum):
    """Outcome of one tool invocation."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class SafeErrorCode(StrEnum):
    """Non-sensitive reason codes. Exception text is never stored."""

    TOOL_ERROR = "tool_error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    DISABLED = "disabled"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"
    POLICY_DENIED = "policy_denied"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INVALID_INPUT = "invalid_input"
    DEPENDENCY_FAILED = "dependency_failed"


class EvidenceSourceType(StrEnum):
    """Where a piece of evidence was observed."""

    REPOSITORY = "repository"
    DEPENDENCY = "dependency"
    HTTP = "http"
    CRAWLER = "crawler"
    RUNTIME_PROBE = "runtime_probe"
    AI_REFERENCE = "ai_reference"


def _validate_identifier(value: str, field: str) -> str:
    if len(value) > MAX_IDENTIFIER_LENGTH or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field} must be lowercase letters, digits, '_', '.', ':', or '-' "
            f"(at most {MAX_IDENTIFIER_LENGTH} characters)"
        )
    return value


def is_absolute_host_path(value: str) -> bool:
    """Return True for POSIX, Windows drive, UNC, or home-relative paths."""
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.startswith(("~", "\\\\", "//")):
        return True
    if PurePosixPath(stripped).is_absolute():
        return True
    windows = PureWindowsPath(stripped)
    return bool(windows.drive) or windows.is_absolute()


class ToolIdentity(BaseModel):
    """Stable identity of a tool and the rule set it applied."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Stable tool identifier, for example 'secret_scanner'.")
    version: str = Field(min_length=1, max_length=64)
    rule_set_version: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return _validate_identifier(value, "name")


class EvidenceLocation(BaseModel):
    """Where evidence was found, without disclosing host paths.

    Repository evidence uses ``path`` (repository-relative, POSIX separators) and
    optionally ``line``. Runtime evidence uses ``url_path`` (path and query keys
    only, never a scheme/host-qualified secret-bearing URL) and optionally
    ``parameter``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str | None = Field(default=None, min_length=1, max_length=MAX_LOCATION_LENGTH)
    line: int | None = Field(default=None, ge=1)
    url_path: str | None = Field(default=None, min_length=1, max_length=MAX_LOCATION_LENGTH)
    parameter: str | None = Field(default=None, min_length=1, max_length=MAX_IDENTIFIER_LENGTH)

    @field_validator("path")
    @classmethod
    def _relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if is_absolute_host_path(value):
            raise ValueError("path must be repository-relative, not an absolute host path")
        normalized = value.replace("\\", "/")
        if any(part == ".." for part in normalized.split("/")):
            raise ValueError("path must not contain '..' segments")
        return normalized

    @field_validator("url_path")
    @classmethod
    def _url_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("url_path must be an origin-relative path starting with '/'")
        if "@" in value.split("?", 1)[0]:
            raise ValueError("url_path must not contain credentials")
        return value

    @model_validator(mode="after")
    def _has_anchor(self) -> EvidenceLocation:
        if self.path is None and self.url_path is None:
            raise ValueError("a location needs a path or a url_path")
        if self.line is not None and self.path is None:
            raise ValueError("line requires path")
        return self


class EvidenceProvenance(BaseModel):
    """How and when a piece of evidence was produced."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: ToolIdentity
    rule_id: str
    observed_at: AwareDatetime
    method: str = Field(
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Deterministic method that produced the observation.",
    )

    @field_validator("rule_id")
    @classmethod
    def _rule_id(cls, value: str) -> str:
        return _validate_identifier(value, "rule_id")


class EvidenceRecord(BaseModel):
    """One normalized, already-redacted observation (blueprint §4.3).

    There is deliberately no field for a raw secret, token, cookie, header value,
    or full response body. ``redacted_excerpt`` must come from
    ``app.services.tooling.redaction``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_key: str = Field(
        description="Deterministic identity within a run (tool, rule, location, content).",
    )
    source_type: EvidenceSourceType
    provenance: EvidenceProvenance
    location: EvidenceLocation
    summary: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    redacted_excerpt: str | None = Field(default=None, max_length=MAX_EXCERPT_LENGTH)
    content_hash: str | None = Field(
        default=None,
        description="SHA-256 hex of the normalized observed content, or of a redacted form.",
    )
    fingerprint: str | None = Field(
        default=None,
        description="Keyed HMAC-SHA-256 hex used to deduplicate sensitive values.",
    )
    request_summary: dict[str, Any] | None = None
    response_summary: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_key")
    @classmethod
    def _key(cls, value: str) -> str:
        return _validate_identifier(value, "evidence_key")

    @field_validator("content_hash", "fingerprint")
    @classmethod
    def _hex_digest(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("digest must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > MAX_TEXT_LENGTH:
                raise ValueError("each limitation must be 1 to 1000 characters")
        return value


class ToolLimitation(BaseModel):
    """A bounded, non-sensitive statement about what a tool did not cover."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    detail: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)

    @field_validator("code")
    @classmethod
    def _code(cls, value: str) -> str:
        return _validate_identifier(value, "code")


class ResourceUsage(BaseModel):
    """Resources consumed by one tool invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wall_time_seconds: float = Field(default=0.0, ge=0.0)
    files_read: int = Field(default=0, ge=0)
    bytes_read: int = Field(default=0, ge=0)
    requests_made: int = Field(default=0, ge=0)


class ToolResult(BaseModel):
    """Typed outcome of one tool invocation (blueprint §4.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: ToolIdentity
    stage: str
    status: ToolStatus
    started_at: AwareDatetime
    finished_at: AwareDatetime
    error_code: SafeErrorCode | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list, max_length=50)
    limitations: list[ToolLimitation] = Field(default_factory=list, max_length=50)
    usage: ResourceUsage = Field(default_factory=ResourceUsage)

    @field_validator("stage")
    @classmethod
    def _stage(cls, value: str) -> str:
        return _validate_identifier(value, "stage")

    @field_validator("counts")
    @classmethod
    def _counts(cls, value: dict[str, int]) -> dict[str, int]:
        for key, count in value.items():
            _validate_identifier(key, "count name")
            if count < 0:
                raise ValueError("counts must be non-negative")
        return value

    @field_validator("warnings")
    @classmethod
    def _warnings(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > MAX_TEXT_LENGTH:
                raise ValueError("each warning must be 1 to 1000 characters")
        return value

    @model_validator(mode="after")
    def _consistency(self) -> ToolResult:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if self.status in {ToolStatus.FAILED, ToolStatus.CANCELLED, ToolStatus.SKIPPED}:
            if self.error_code is None:
                raise ValueError(f"a {self.status.value} result requires an error_code")
            if self.evidence and self.status is not ToolStatus.CANCELLED:
                raise ValueError(f"a {self.status.value} result cannot carry evidence")
        if self.status is ToolStatus.COMPLETED and self.error_code is not None:
            raise ValueError("a completed result must not carry an error_code")
        if self.status is ToolStatus.PARTIAL and not (self.limitations or self.error_code):
            raise ValueError("a partial result must explain what was not covered")
        keys = [record.evidence_key for record in self.evidence]
        if len(keys) != len(set(keys)):
            raise ValueError("evidence_key values must be unique within a result")
        return self

    @property
    def is_clean(self) -> bool:
        """True only when the tool completed fully and observed nothing."""
        return self.status is ToolStatus.COMPLETED and not self.evidence


__all__ = [
    "MAX_EXCERPT_LENGTH",
    "EvidenceLocation",
    "EvidenceProvenance",
    "EvidenceRecord",
    "EvidenceSourceType",
    "ResourceUsage",
    "SafeErrorCode",
    "ToolIdentity",
    "ToolLimitation",
    "ToolResult",
    "ToolStatus",
    "is_absolute_host_path",
]
