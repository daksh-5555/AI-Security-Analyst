"""Read schemas for persisted analysis runs."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import AnalysisRunStatus


class AnalysisRunRead(BaseModel):
    """Bounded analysis-run view used by history listings."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID = Field(description="Analysis run identifier.")
    assessment_id: uuid.UUID = Field(description="Assessment the run belongs to.")
    status: AnalysisRunStatus = Field(description="Current lifecycle state of the run.")
    created_at: datetime = Field(description="When the run record was created.")
    started_at: datetime = Field(
        description=(
            "When analysis execution started. For a run still QUEUED this is its "
            "creation time; the worker overwrites it when it claims the run."
        )
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When the run reached a terminal state, or None while running.",
    )
    error_message: str | None = Field(
        default=None,
        description="Sanitized failure summary for a failed run.",
    )
    findings_count: int = Field(
        ge=0,
        description="Number of findings associated with this run.",
    )
    stage: str | None = Field(
        default=None,
        description=(
            "Current or last pipeline stage (queued, claimed, analysis, tools, "
            "finding_generation, finding_persistence, completion, or a terminal state)."
        ),
    )
    attempts: int = Field(
        default=0,
        ge=0,
        description="How many times the run has been started (worker retries included).",
    )
    error_code: str | None = Field(
        default=None,
        description="Stable machine-readable reason for a failed, cancelled, or retried run.",
    )
    cancel_requested_at: datetime | None = Field(
        default=None,
        description="When cancellation was requested, if it was.",
    )


class AnalysisRunDetail(AnalysisRunRead):
    """Analysis-run view including compact analysis metadata."""

    analysis_metadata: dict[str, Any] | None = Field(
        default=None,
        description="Compact quality, completeness, and finding-policy metadata.",
    )


class AnalysisRunCreated(AnalysisRunDetail):
    """Analysis-run view returned after creation.

    Synchronous mode (default) returns the final state with 201. Asynchronous
    mode (``?mode=async``) returns the QUEUED run with 202; poll the run's
    ``Location`` for progress.
    """
