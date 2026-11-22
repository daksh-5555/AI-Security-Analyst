"""Read-only administrative security-monitoring route."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import AwareDatetime
from sqlalchemy.orm import Session

from app.api.constants import (
    AUDIT_TIME_RANGE_INVALID_DETAIL,
    MONITORING_TIME_OUT_OF_RANGE_DETAIL,
    MONITORING_WINDOW_EXCEEDED_DETAIL,
)
from app.api.dependencies import require_admin
from app.db.session import get_db
from app.schemas.security_monitoring import (
    DEFAULT_LIMIT,
    DEFAULT_MIN_ATTEMPTS,
    MAX_ATTEMPTS,
    MAX_LIMIT,
    MAX_WINDOW,
    MIN_ATTEMPTS,
    DenialPatternResponse,
)
from app.services import security_monitoring

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


@router.get(
    "/security-monitoring/denial-patterns",
    response_model=DenialPatternResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Missing or invalid access credentials.",
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Caller is not an administrator.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "Invalid time bounds, range, threshold, or limit.",
        },
    },
)
def get_denial_patterns(
    db: Annotated[Session, Depends(get_db)],
    from_time: Annotated[
        AwareDatetime,
        Query(description="Inclusive lower bound for denied audit events."),
    ],
    to_time: Annotated[
        AwareDatetime,
        Query(description="Exclusive upper bound for denied audit events."),
    ],
    min_attempts: Annotated[
        int,
        Query(
            ge=MIN_ATTEMPTS,
            le=MAX_ATTEMPTS,
            description="Minimum denied attempts required for a group to be reported.",
        ),
    ] = DEFAULT_MIN_ATTEMPTS,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_LIMIT,
            description="Maximum number of denial-pattern groups to return.",
        ),
    ] = DEFAULT_LIMIT,
) -> DenialPatternResponse:
    """Return repeated authorization-denial signals from persisted audit events.

    Only events with the ``denied`` outcome are aggregated, grouped by actor,
    resource type, resource, and action. A null actor means the denial was
    unauthenticated or could not be attributed; it is never replaced with a
    fabricated identity.

    Results are monitoring signals for human review, not confirmation that an
    attack occurred. This endpoint is read-only and never blocks, revokes, or
    suspends anything.
    """
    try:
        from_time, to_time = security_monitoring.normalize_window_bounds(
            from_time,
            to_time,
        )
    except security_monitoring.TimeBoundsOutOfRangeError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=MONITORING_TIME_OUT_OF_RANGE_DETAIL,
        ) from None

    if from_time >= to_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=AUDIT_TIME_RANGE_INVALID_DETAIL,
        )
    if to_time - from_time > MAX_WINDOW:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=MONITORING_WINDOW_EXCEEDED_DETAIL,
        )

    patterns, total = security_monitoring.list_denial_patterns(
        db,
        from_time=from_time,
        to_time=to_time,
        min_attempts=min_attempts,
        limit=limit,
    )
    return DenialPatternResponse(
        from_time=from_time,
        to_time=to_time,
        min_attempts=min_attempts,
        total=total,
        patterns=patterns,
    )
