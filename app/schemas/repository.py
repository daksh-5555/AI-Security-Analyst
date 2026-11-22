import uuid

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from app.schemas.enums import RepositorySourceKind


class RepositorySourceCreate(BaseModel):
    """Request body for registering a repository source."""

    model_config = ConfigDict(extra="forbid")

    source_kind: RepositorySourceKind
    location: str = Field(min_length=1, max_length=4096)

    @field_validator("source_kind")
    @classmethod
    def validate_local_path(cls, value: RepositorySourceKind) -> RepositorySourceKind:
        if value is not RepositorySourceKind.LOCAL_PATH:
            raise ValueError("Only 'local_path' repository sources are supported")
        return value


class RepositoryTargetRead(BaseModel):
    """Persisted repository target returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    source_kind: RepositorySourceKind
    location: str = Field(
        description=(
            "Repository location relative to its configured allowed root. "
            "Absolute server-side paths are never returned."
        )
    )
    created_at: AwareDatetime
    updated_at: AwareDatetime
