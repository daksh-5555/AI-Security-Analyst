"""Read-only, SQL-filtered queries over persisted audit events.

This module never inserts, updates, or deletes audit records. Filters are
applied to both the count and the page query so pagination metadata always
describes the same result set.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, load_only
from sqlalchemy.sql.elements import ColumnElement

from app.models.audit_event import AuditEvent
from app.schemas.audit_event import DEFAULT_LIMIT, MAX_LIMIT
from app.schemas.enums import AuditAction, AuditOutcome

# Only the columns exposed by ``AuditEventRead``. ``context`` is deliberately
# never loaded because it is operational metadata outside the read API contract.
_READ_COLUMNS = (
    AuditEvent.id,
    AuditEvent.actor_user_id,
    AuditEvent.assessment_id,
    AuditEvent.resource_type,
    AuditEvent.resource_id,
    AuditEvent.action,
    AuditEvent.outcome,
    AuditEvent.occurred_at,
)


def list_audit_events(
    db: Session,
    *,
    action: AuditAction | None = None,
    outcome: AuditOutcome | None = None,
    actor_user_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    resource_id: uuid.UUID | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> tuple[list[AuditEvent], int]:
    """Return one bounded page of audit events and the matching total.

    ``from_time`` is inclusive (``occurred_at >= from_time``); ``to_time`` is
    exclusive (``occurred_at < to_time``). Ordering is deterministic:
    ``occurred_at`` descending, then ``id`` descending as a tie-breaker.

    ``assessment_id`` matches the durable foreign-key association, while
    ``resource_id`` matches the affected resource or attempted target (including
    denied assessment access attempts whose foreign key is null).

    Pagination is validated here as well as at the HTTP boundary so a future
    internal caller cannot request an unbounded page.
    """
    _validate_pagination(limit=limit, offset=offset)

    filters = _filters(
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        assessment_id=assessment_id,
        resource_id=resource_id,
        from_time=from_time,
        to_time=to_time,
    )

    total = db.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0

    statement = _ordered_events().where(*filters).offset(offset).limit(limit)
    return list(db.scalars(statement).all()), total


def _validate_pagination(*, limit: int, offset: int) -> None:
    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0:
        raise ValueError("offset must be zero or greater")


def _ordered_events() -> Select[tuple[AuditEvent]]:
    return (
        select(AuditEvent)
        .options(load_only(*_READ_COLUMNS))
        .order_by(
            AuditEvent.occurred_at.desc(),
            AuditEvent.id.desc(),
        )
    )


def _filters(
    *,
    action: AuditAction | None,
    outcome: AuditOutcome | None,
    actor_user_id: uuid.UUID | None,
    assessment_id: uuid.UUID | None,
    resource_id: uuid.UUID | None,
    from_time: datetime | None,
    to_time: datetime | None,
) -> list[ColumnElement[bool]]:
    filters: list[ColumnElement[bool]] = []
    if action is not None:
        filters.append(AuditEvent.action == action)
    if outcome is not None:
        filters.append(AuditEvent.outcome == outcome)
    if actor_user_id is not None:
        filters.append(AuditEvent.actor_user_id == actor_user_id)
    if assessment_id is not None:
        filters.append(AuditEvent.assessment_id == assessment_id)
    if resource_id is not None:
        filters.append(AuditEvent.resource_id == resource_id)
    if from_time is not None:
        filters.append(AuditEvent.occurred_at >= from_time)
    if to_time is not None:
        filters.append(AuditEvent.occurred_at < to_time)
    return filters


__all__ = ["DEFAULT_LIMIT", "MAX_LIMIT", "list_audit_events"]
