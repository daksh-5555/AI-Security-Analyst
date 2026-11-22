import uuid
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.enums import FindingSeverity, FindingStatus


class Evidence(BaseModel):
    """An observed fact that supports or contradicts a finding."""

    model_config = ConfigDict(extra="forbid")

    description: str = Field(
        min_length=1,
        description="Concise description of the observation.",
    )
    source: str = Field(
        min_length=1,
        description="Origin of the observation, such as a scanner, file, or runtime probe.",
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured details produced by the source.",
    )


class EvidenceRead(Evidence):
    """ORM-enabled read view of Evidence; adds no fields."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class Finding(BaseModel):
    """A normalized security finding.

    Evidence holds observed facts. Summary and remediation are explanatory or
    advisory text and do not by themselves confirm the finding.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, description="Short, specific finding title.")
    category: str = Field(
        min_length=1,
        description="Vulnerability category or type, such as SQL injection.",
    )
    severity: FindingSeverity
    status: FindingStatus
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the finding, from 0.0 to 1.0 inclusive.",
    )
    summary: str = Field(
        min_length=1,
        description="Explanation of the finding; not itself verification evidence.",
    )
    affected_component: str | None = Field(
        default=None,
        min_length=1,
        description="Optional component, file, endpoint, or asset affected by the finding.",
    )
    evidence: list[Evidence] = Field(
        description="Observed evidence collected for the finding.",
    )
    remediation: str | None = Field(
        default=None,
        min_length=1,
        description="Optional recommended remediation.",
    )


class FindingRead(Finding):
    """ORM-enabled read view of a persisted finding."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID = Field(description="Persisted finding identifier.")
    analysis_run_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Analysis run that produced the finding, or None for findings persisted "
            "before run association existed."
        ),
    )
    evidence: list[EvidenceRead]
    # M7 normalized fields (additive; None for findings persisted before 0017).
    rule_id: str | None = Field(default=None, description="Rule that produced the finding.")
    source_stage: str | None = Field(
        default=None, description="Pipeline stage (tool) that produced the finding."
    )
    verification_method: str | None = Field(
        default=None, description="How the status was established."
    )
    status_rationale: str | None = Field(
        default=None, description="Why this status and severity were assigned."
    )
    cwe_ids: list[str] | None = None
    cve_ids: list[str] | None = None
    first_seen_at: AwareDatetime | None = Field(
        default=None, description="First run in this assessment that reported the issue."
    )
    last_seen_at: AwareDatetime | None = Field(
        default=None, description="Most recent run that observed the issue."
    )
    previous_status: FindingStatus | None = Field(
        default=None, description="Status of the same issue in the previous completed run."
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Normalized evidence items (see /evidence) supporting this finding.",
    )


class EvidenceItemRead(BaseModel):
    """A normalized, redacted evidence item (never raw secrets or bodies)."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    analysis_run_id: uuid.UUID
    evidence_key: str
    source_type: str
    tool_name: str
    tool_version: str
    rule_set_version: str | None
    rule_id: str
    method: str
    location_path: str | None
    location_line: int | None
    url_path: str | None
    parameter: str | None
    summary: str
    redacted_excerpt: str | None
    content_hash: str | None
    fingerprint: str | None
    request_summary: dict[str, Any] | None
    response_summary: dict[str, Any] | None
    limitations: list[Any] | None
    details: dict[str, Any] | None
    observed_at: AwareDatetime
