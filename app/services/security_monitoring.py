"""Read-only SQL aggregation of repeated authorization-denial signals.

Only persisted audit events with the ``denied`` outcome participate. Grouping,
filtering, counting, and thresholding happen in the database; this module never
loads individual audit rows and never selects the raw ``context`` column.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.schemas.enums import AuditOutcome
from app.schemas.security_monitoring import (
    DEFAULT_LIMIT,
    DEFAULT_MIN_ATTEMPTS,
    MAX_ATTEMPTS,
    MAX_LIMIT,
    MAX_WINDOW,
    MIN_ATTEMPTS,
    DenialPattern,
)

_TIME_RANGE_INVALID_DETAIL = "from_time must be earlier than to_time"
_TIME_OUT_OF_RANGE_DETAIL = "time bound is outside the supported datetime range"
_WINDOW_EXCEEDED_DETAIL = "time window must not exceed 30 days"


class TimeBoundsOutOfRangeError(ValueError):
    """Raised when an aware datetime cannot be represented in UTC."""


def normalize_window_bounds(
    from_time: datetime,
    to_time: datetime,
) -> tuple[datetime, datetime]:
    """Return both bounds as UTC, rejecting values outside datetime's range.

    ``astimezone(UTC)`` raises ``OverflowError`` for aware datetimes near the
    minimum or maximum year with a large UTC offset. Normalization happens
    before database binding so callers receive a validation error instead of an
    unhandled server error.
    """
    return (
        _normalize_utc(from_time, "from_time"),
        _normalize_utc(to_time, "to_time"),
    )


def _normalize_utc(value: datetime, name: str) -> datetime:
    _require_aware(value, name)
    try:
        return value.astimezone(UTC)
    except OverflowError:
        raise TimeBoundsOutOfRangeError(_TIME_OUT_OF_RANGE_DETAIL) from None


def list_denial_patterns(
    db: Session,
    *,
    from_time: datetime,
    to_time: datetime,
    min_attempts: int = DEFAULT_MIN_ATTEMPTS,
    limit: int = DEFAULT_LIMIT,
) -> tuple[list[DenialPattern], int]:
    """Return repeated-denial groups and the total number of matching groups.

    ``from_time`` is inclusive and ``to_time`` is exclusive. Only events whose
    outcome is exactly ``AuditOutcome.DENIED`` are aggregated. Groups are formed
    on ``(actor_user_id, resource_type, resource_id, action)`` and reported when
    they contain at least ``min_attempts`` denied events.

    Ordering is deterministic: attempt count descending, last seen descending,
    then the grouping keys ascending with null keys last. The returned list is
    bounded by ``limit`` while ``total`` still counts every matching group.

    Arguments are validated and normalized to UTC here as well as at the HTTP
    boundary so a future internal caller cannot request an unbounded or
    unrepresentable window or result set.
    """
    from_time, to_time = _validate_request(
        from_time=from_time,
        to_time=to_time,
        min_attempts=min_attempts,
        limit=limit,
    )

    grouped = _grouped_statement(
        from_time=from_time,
        to_time=to_time,
        min_attempts=min_attempts,
    )

    total = db.scalar(select(func.count()).select_from(grouped.subquery())) or 0

    statement = grouped.order_by(
        func.count(AuditEvent.id).desc(),
        func.max(AuditEvent.occurred_at).desc(),
        AuditEvent.actor_user_id.asc().nulls_last(),
        AuditEvent.resource_type.asc(),
        AuditEvent.resource_id.asc().nulls_last(),
        AuditEvent.action.asc(),
    ).limit(limit)
    rows = db.execute(statement).mappings().all()
    patterns = [
        DenialPattern(
            actor_user_id=row["actor_user_id"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            action=row["action"],
            attempt_count=row["attempt_count"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
        for row in rows
    ]
    return patterns, total


def _grouped_statement(
    *,
    from_time: datetime,
    to_time: datetime,
    min_attempts: int,
) -> Select[tuple[object, ...]]:
    """Build the database-side aggregation without ordering or limiting."""
    return (
        select(
            AuditEvent.actor_user_id.label("actor_user_id"),
            AuditEvent.resource_type.label("resource_type"),
            AuditEvent.resource_id.label("resource_id"),
            AuditEvent.action.label("action"),
            func.count(AuditEvent.id).label("attempt_count"),
            func.min(AuditEvent.occurred_at).label("first_seen"),
            func.max(AuditEvent.occurred_at).label("last_seen"),
        )
        .where(
            AuditEvent.outcome == AuditOutcome.DENIED,
            AuditEvent.occurred_at >= from_time,
            AuditEvent.occurred_at < to_time,
        )
        .group_by(
            AuditEvent.actor_user_id,
            AuditEvent.resource_type,
            AuditEvent.resource_id,
            AuditEvent.action,
        )
        .having(func.count(AuditEvent.id) >= min_attempts)
    )


def _validate_request(
    *,
    from_time: datetime,
    to_time: datetime,
    min_attempts: int,
    limit: int,
) -> tuple[datetime, datetime]:
    """Validate the request and return the window bounds normalized to UTC."""
    from_time, to_time = normalize_window_bounds(from_time, to_time)
    if from_time >= to_time:
        raise ValueError(_TIME_RANGE_INVALID_DETAIL)
    if to_time - from_time > MAX_WINDOW:
        raise ValueError(_WINDOW_EXCEEDED_DETAIL)
    if min_attempts < MIN_ATTEMPTS or min_attempts > MAX_ATTEMPTS:
        raise ValueError(f"min_attempts must be between {MIN_ATTEMPTS} and {MAX_ATTEMPTS}")
    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    return from_time, to_time


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


__all__ = [
    "DEFAULT_LIMIT",
    "DEFAULT_MIN_ATTEMPTS",
    "MAX_ATTEMPTS",
    "MAX_LIMIT",
    "MAX_WINDOW",
    "MIN_ATTEMPTS",
    "TimeBoundsOutOfRangeError",
    "list_denial_patterns",
    "normalize_window_bounds",
]
