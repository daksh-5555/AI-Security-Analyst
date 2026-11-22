"""Read-only audit-event API schemas."""

import uuid
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.schemas.enums import AuditAction, AuditOutcome, AuditResourceType

# Shared by the HTTP contract and the query service so the maximum page size
# cannot drift between the two layers.
DEFAULT_LIMIT: Final[int] = 50
MAX_LIMIT: Final[int] = 100


class AuditEventRead(BaseModel):
    """Approved audit-event fields exposed to administrative readers.

    ``context`` is deliberately excluded: it is operational metadata that may
    contain values not approved for the audit-query API.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID = Field(description="Audit event identifier.")
    actor_user_id: uuid.UUID | None = Field(
        default=None,
        description="Authenticated actor, or None for unauthenticated denials.",
    )
    assessment_id: uuid.UUID | None = Field(
        default=None,
        description="Related assessment when a durable foreign-key association exists.",
    )
    resource_type: AuditResourceType = Field(description="Kind of resource involved.")
    resource_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Identifier of the affected resource, or the attempted target for denied operations."
        ),
    )
    action: AuditAction = Field(description="Audited operation.")
    outcome: AuditOutcome = Field(
        description="Whether the operation succeeded, failed, or was denied."
    )
    occurred_at: AwareDatetime = Field(description="UTC timestamp when the event occurred.")


class AuditEventPage(BaseModel):
    """One bounded page of audit events plus matching-record metadata."""

    model_config = ConfigDict(extra="forbid")

    items: list[AuditEventRead] = Field(description="Audit events for this page.")
    total: int = Field(ge=0, description="Total events matching the filters.")
    limit: int = Field(ge=1, le=MAX_LIMIT, description="Maximum records requested for this page.")
    offset: int = Field(ge=0, description="Number of matching records skipped.")


__all__ = ["DEFAULT_LIMIT", "MAX_LIMIT", "AuditEventPage", "AuditEventRead"]
