"""Read-only administrative audit-event query route."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import AwareDatetime
from sqlalchemy.orm import Session

from app.api.constants import AUDIT_TIME_RANGE_INVALID_DETAIL
from app.api.dependencies import require_admin
from app.db.session import get_db
from app.schemas.audit_event import AuditEventPage, AuditEventRead
from app.schemas.enums import AuditAction, AuditOutcome
from app.services import audit_queries

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


@router.get(
    "/audit-events",
    response_model=AuditEventPage,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Missing or invalid access credentials.",
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Caller is not an administrator.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "Invalid filter value, pagination value, or time range.",
        },
    },
)
def list_audit_events(
    db: Annotated[Session, Depends(get_db)],
    action: Annotated[
        AuditAction | None,
        Query(description="Filter by the audited action."),
    ] = None,
    outcome: Annotated[
        AuditOutcome | None,
        Query(description="Filter by the audit outcome."),
    ] = None,
    actor_user_id: Annotated[
        uuid.UUID | None,
        Query(description="Filter by the authenticated actor."),
    ] = None,
    assessment_id: Annotated[
        uuid.UUID | None,
        Query(description="Filter by the durable assessment foreign-key association."),
    ] = None,
    resource_id: Annotated[
        uuid.UUID | None,
        Query(
            description=(
                "Filter by the identifier of the affected resource or attempted "
                "target, including denied assessment access attempts."
            )
        ),
    ] = None,
    from_time: Annotated[
        AwareDatetime | None,
        Query(description="Inclusive lower bound for occurred_at."),
    ] = None,
    to_time: Annotated[
        AwareDatetime | None,
        Query(description="Exclusive upper bound for occurred_at."),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=audit_queries.MAX_LIMIT),
    ] = audit_queries.DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditEventPage:
    """Return one bounded page of persisted audit events.

    ``from_time`` is inclusive and ``to_time`` is exclusive. Ordering is
    ``occurred_at`` descending with ``id`` descending as a deterministic
    tie-breaker.
    """
    if from_time is not None and to_time is not None and from_time >= to_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=AUDIT_TIME_RANGE_INVALID_DETAIL,
        )

    events, total = audit_queries.list_audit_events(
        db,
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        assessment_id=assessment_id,
        resource_id=resource_id,
        from_time=from_time,
        to_time=to_time,
        limit=limit,
        offset=offset,
    )
    return AuditEventPage(
        items=[AuditEventRead.model_validate(event) for event in events],
        total=total,
        limit=limit,
        offset=offset,
    )
