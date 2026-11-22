"""Schemas for authenticated local-lab sessions (M15, ADR-0018)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class LabCredentialsRequest(BaseModel):
    """Operator-supplied known lab credentials. Used once to log in; never stored."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=200)
    password: SecretStr = Field(description="Lab password; used once, never stored or returned.")


class LabSessionRead(BaseModel):
    """Non-secret view of a configured lab session. The cookie is never exposed."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID
    configured: bool
    username: str | None = None
    login_path: str | None = None
    established_at: datetime | None = None
