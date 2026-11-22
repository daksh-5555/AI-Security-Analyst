"""Assessment target authorization request and response schemas (M4)."""

import uuid
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.enums import AuthorizationBasis, TargetStatus, TargetType


class WebTargetCreate(BaseModel):
    """Register and explicitly authorize a web application target."""

    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(
        min_length=1,
        max_length=2048,
        description="http(s) base URL without credentials, query, or fragment.",
    )
    authorization_statement: str = Field(
        min_length=20,
        max_length=1000,
        description="Who authorized testing this system, and on what basis.",
    )
    confirm_authorized: Literal[True] = Field(
        description="Must be true: the caller confirms they are authorized to test this target.",
    )


class TargetAuthorizationRequest(BaseModel):
    """Explicitly (re-)authorize a pending or revoked target."""

    model_config = ConfigDict(extra="forbid")

    authorization_statement: str = Field(min_length=20, max_length=1000)
    confirm_authorized: Literal[True]


class AssessmentTargetRead(BaseModel):
    """A target and its authorization state. Repository paths are root-relative."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    assessment_id: uuid.UUID
    target_type: TargetType
    target: str = Field(description="Repository path relative to its root, or canonical URL.")
    status: TargetStatus
    authorization_basis: AuthorizationBasis | None
    authorization_statement: str | None
    created_by_user_id: uuid.UUID | None
    authorized_by_user_id: uuid.UUID | None
    authorized_at: AwareDatetime | None
    revoked_by_user_id: uuid.UUID | None
    revoked_at: AwareDatetime | None
    policy_snapshot: dict[str, Any] | None
    created_at: AwareDatetime
    updated_at: AwareDatetime
