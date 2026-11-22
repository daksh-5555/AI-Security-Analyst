import uuid

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.enums import AssessmentStatus, AssessmentType


class AssessmentCreate(BaseModel):
    """Request body for creating an assessment job."""

    model_config = ConfigDict(extra="forbid")

    assessment_type: AssessmentType


class AssessmentStatusUpdate(BaseModel):
    """Request body for changing an assessment's lifecycle status."""

    model_config = ConfigDict(extra="forbid")

    status: AssessmentStatus
    reason: str | None = Field(default=None, min_length=1, max_length=500)


class AssessmentRead(BaseModel):
    """Persisted assessment job returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID | None
    assessment_type: AssessmentType
    status: AssessmentStatus
    created_at: AwareDatetime
    updated_at: AwareDatetime


class AssessmentStatusHistoryRead(BaseModel):
    """A persisted assessment status transition."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    previous_status: AssessmentStatus
    new_status: AssessmentStatus
    changed_at: AwareDatetime
    reason: str | None
