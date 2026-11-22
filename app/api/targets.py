"""Assessment target registration, listing, authorization, and revocation (M4)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.constants import (
    TARGET_ALREADY_REGISTERED_DETAIL,
    TARGET_INVALID_DETAIL,
    TARGET_NOT_ALLOWLISTED_DETAIL,
    TARGET_NOT_FOUND_DETAIL,
    TARGET_NOT_QUEUED_DETAIL,
    TARGET_TRANSITION_DETAIL,
    TARGET_WRONG_ASSESSMENT_DETAIL,
)
from app.api.dependencies import (
    AssessmentManager,
    ManageableAssessment,
    ReadableAssessment,
    get_current_principal,
)
from app.db.session import get_db
from app.models.assessment_target import AssessmentTarget
from app.models.repository_target import RepositoryTarget
from app.schemas.target import (
    AssessmentTargetRead,
    TargetAuthorizationRequest,
    WebTargetCreate,
)
from app.services import target_authorization as service

router = APIRouter(
    prefix="/api/v1",
    tags=["targets"],
    dependencies=[Depends(get_current_principal)],
)

DbSession = Annotated[Session, Depends(get_db)]

_ERRORS: dict[type[service.TargetAuthorizationError], tuple[int, str]] = {
    service.InvalidTargetError: (status.HTTP_422_UNPROCESSABLE_CONTENT, TARGET_INVALID_DETAIL),
    service.TargetNotAllowlistedError: (
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        TARGET_NOT_ALLOWLISTED_DETAIL,
    ),
    service.TargetAlreadyRegisteredError: (
        status.HTTP_409_CONFLICT,
        TARGET_ALREADY_REGISTERED_DETAIL,
    ),
    service.AssessmentNotWebError: (status.HTTP_409_CONFLICT, TARGET_WRONG_ASSESSMENT_DETAIL),
    service.AssessmentNotQueuedForTargetError: (status.HTTP_409_CONFLICT, TARGET_NOT_QUEUED_DETAIL),
    service.TargetNotFoundError: (status.HTTP_404_NOT_FOUND, TARGET_NOT_FOUND_DETAIL),
    service.InvalidTargetTransitionError: (status.HTTP_409_CONFLICT, TARGET_TRANSITION_DETAIL),
}


def _http_error(exc: service.TargetAuthorizationError) -> HTTPException:
    for error_type, (code, detail) in _ERRORS.items():
        if isinstance(exc, error_type):
            return HTTPException(status_code=code, detail=detail)
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=TARGET_TRANSITION_DETAIL)


def _read(db: Session, target: AssessmentTarget) -> AssessmentTargetRead:
    repository = (
        db.get(RepositoryTarget, target.repository_target_id)
        if target.repository_target_id
        else None
    )
    return AssessmentTargetRead(
        id=target.id,
        assessment_id=target.assessment_id,
        target_type=target.target_type,
        target=service.display_target(target, repository),
        status=target.status,
        authorization_basis=target.authorization_basis,
        authorization_statement=target.authorization_statement,
        created_by_user_id=target.created_by_user_id,
        authorized_by_user_id=target.authorized_by_user_id,
        authorized_at=target.authorized_at,
        revoked_by_user_id=target.revoked_by_user_id,
        revoked_at=target.revoked_at,
        policy_snapshot=target.policy_snapshot,
        created_at=target.created_at,
        updated_at=target.updated_at,
    )


@router.post(
    "/assessments/{assessment_id}/web-target",
    response_model=AssessmentTargetRead,
    status_code=status.HTTP_201_CREATED,
)
def register_web_target(
    payload: WebTargetCreate,
    db: DbSession,
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> AssessmentTargetRead:
    """Register an allowlisted web target with an explicit authorization statement."""
    try:
        target = service.register_web_target(
            db,
            assessment,
            base_url=payload.base_url,
            authorization_statement=payload.authorization_statement,
            actor_user_id=principal.user_id,
        )
    except service.TargetAuthorizationError as exc:
        raise _http_error(exc) from exc
    return _read(db, target)


@router.get(
    "/assessments/{assessment_id}/targets",
    response_model=list[AssessmentTargetRead],
)
def list_targets(db: DbSession, assessment: ReadableAssessment) -> list[AssessmentTargetRead]:
    """List the assessment's targets and their authorization state."""
    return [_read(db, target) for target in service.list_targets(db, assessment.id)]


@router.post(
    "/assessments/{assessment_id}/targets/{target_id}/authorize",
    response_model=AssessmentTargetRead,
)
def authorize_target(
    target_id: uuid.UUID,
    payload: TargetAuthorizationRequest,
    db: DbSession,
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> AssessmentTargetRead:
    """Explicitly authorize a pending or revoked target."""
    try:
        target = service.authorize_target(
            db,
            assessment,
            target_id,
            authorization_statement=payload.authorization_statement,
            actor_user_id=principal.user_id,
        )
    except service.TargetAuthorizationError as exc:
        raise _http_error(exc) from exc
    return _read(db, target)


@router.post(
    "/assessments/{assessment_id}/targets/{target_id}/revoke",
    response_model=AssessmentTargetRead,
)
def revoke_target(
    target_id: uuid.UUID,
    db: DbSession,
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> AssessmentTargetRead:
    """Revoke a target's authorization; analysis is refused until re-authorized."""
    try:
        target = service.revoke_target(db, assessment, target_id, actor_user_id=principal.user_id)
    except service.TargetAuthorizationError as exc:
        raise _http_error(exc) from exc
    return _read(db, target)
