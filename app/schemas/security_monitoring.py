"""Read-only security-monitoring API schemas."""

import uuid
from datetime import timedelta
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.audit_event import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.enums import AuditAction, AuditResourceType

DEFAULT_MIN_ATTEMPTS: Final[int] = 5
MIN_ATTEMPTS: Final[int] = 2
MAX_ATTEMPTS: Final[int] = 1000
MAX_WINDOW: Final[timedelta] = timedelta(days=30)


class DenialPattern(BaseModel):
    """One repeated-denial group aggregated over persisted audit events.

    A null ``actor_user_id`` is a distinct grouping key for denials that were
    unauthenticated or could not be attributed to a persisted user. It is never
    replaced with a fabricated identity.
    """

    model_config = ConfigDict(extra="forbid")

    actor_user_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Authenticated actor, or null when the denial was unauthenticated "
            "or could not be attributed. Null is a real grouping key."
        ),
    )
    resource_type: AuditResourceType = Field(description="Kind of resource involved.")
    resource_id: uuid.UUID | None = Field(
        default=None,
        description="Affected resource or attempted target, when recorded.",
    )
    action: AuditAction = Field(description="Denied audited operation.")
    attempt_count: int = Field(ge=1, description="Denied attempts in this group.")
    first_seen: AwareDatetime = Field(description="Earliest denial in this group.")
    last_seen: AwareDatetime = Field(description="Most recent denial in this group.")


class DenialPatternResponse(BaseModel):
    """Bounded repeated-denial monitoring result.

    Patterns are monitoring signals for human review. They do not confirm that
    an attack occurred and never trigger automatic blocking, revocation, or
    suspension.
    """

    model_config = ConfigDict(extra="forbid")

    from_time: AwareDatetime = Field(description="Inclusive start of the requested window.")
    to_time: AwareDatetime = Field(description="Exclusive end of the requested window.")
    min_attempts: int = Field(
        ge=MIN_ATTEMPTS,
        le=MAX_ATTEMPTS,
        description="Minimum denied attempts required for a group to be reported.",
    )
    total: int = Field(ge=0, description="Total matching groups before the result limit.")
    patterns: list[DenialPattern] = Field(
        description=(
            "Bounded denial-pattern signals ordered by attempt count, last seen, "
            "and deterministic grouping keys. These are not confirmed attacks."
        )
    )


__all__ = [
    "DEFAULT_LIMIT",
    "DEFAULT_MIN_ATTEMPTS",
    "MAX_ATTEMPTS",
    "MAX_LIMIT",
    "MAX_WINDOW",
    "MIN_ATTEMPTS",
    "DenialPattern",
    "DenialPatternResponse",
]
