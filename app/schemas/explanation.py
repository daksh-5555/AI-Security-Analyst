"""Read schema for advisory finding explanations (M9)."""

import uuid
from datetime import datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import ExplanationStatus
from app.services.explanations.contract import FindingExplanationOutput

ADVISORY_NOTICE: Final = (
    "AI-generated, advisory only. It does not change the finding's status, severity, "
    "or confidence, which come from deterministic analysis."
)


class FindingExplanationRead(BaseModel):
    """One stored explanation attempt and its provenance."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    assessment_id: uuid.UUID
    finding_id: uuid.UUID
    status: ExplanationStatus = Field(
        description="available, or unavailable when the provider failed or output was rejected."
    )
    error_code: str | None = Field(default=None, description="Why the explanation is unavailable.")
    explanation: FindingExplanationOutput | None = None
    provider: str
    model: str
    prompt_template_version: str
    supplied_evidence_ids: list[str] = Field(
        description="The finding and evidence IDs sent to the provider (grounding set)."
    )
    retrieval: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Reference material supplied (M11): status (used, none_relevant, unavailable, "
            "disabled), backend, knowledge-base version, and attributed source IDs."
        ),
    )
    input_tokens: int
    output_tokens: int
    created_at: datetime
    advisory_notice: str = ADVISORY_NOTICE
