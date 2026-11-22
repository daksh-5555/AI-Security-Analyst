"""Authenticated local-lab session configuration for web targets (M15, ADR-0018).

Lets an analyst log a scanner into an authorized local web lab (e.g. DVWA) with
known credentials so the crawler and probes can see the authenticated surface.
Off by default, local targets only, login-only (never credential guessing). The
password is used once and never stored; only the resulting session cookie is
kept, and it is never returned, logged, or placed in evidence.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.constants import (
    LAB_AUTH_DISABLED_DETAIL,
    LAB_AUTH_FAILED_DETAIL,
    LAB_SESSION_NOT_FOUND_DETAIL,
    LAB_TARGET_NOT_LOCAL_DETAIL,
    TARGET_NOT_AUTHORIZED_DETAIL,
    WEB_TARGET_NOT_FOUND_DETAIL,
)
from app.api.dependencies import (
    AssessmentManager,
    ManageableAssessment,
    ReadableAssessment,
    get_current_principal,
)
from app.db.session import get_db
from app.schemas.lab_credentials import LabCredentialsRequest, LabSessionRead
from app.services import lab_credentials as service
from app.services.net.lab_session import LabAuthDisabledError, LabAuthError
from app.services.target_authorization import TargetNotAuthorizedError, WebTargetNotFoundError

router = APIRouter(
    prefix="/api/v1",
    tags=["lab-credentials"],
    dependencies=[Depends(get_current_principal)],
)

PATH = "/assessments/{assessment_id}/web-target/lab-credentials"


def _read(assessment_id: uuid.UUID, row) -> LabSessionRead:  # noqa: ANN001
    if row is None:
        return LabSessionRead(assessment_id=assessment_id, configured=False)
    return LabSessionRead(
        assessment_id=assessment_id,
        configured=True,
        username=row.username,
        login_path=row.login_path,
        established_at=row.established_at,
    )


@router.post(
    PATH,
    response_model=LabSessionRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "The lab-auth feature is not enabled."},
        status.HTTP_404_NOT_FOUND: {"description": "No web target registered."},
        status.HTTP_409_CONFLICT: {"description": "Target not authorized or not a local address."},
        status.HTTP_502_BAD_GATEWAY: {"description": "The lab login did not succeed."},
    },
)
def configure_lab_credentials(
    body: LabCredentialsRequest,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> LabSessionRead:
    """Establish a lab session with known credentials (one login; password not stored)."""
    assessment_id = assessment.id
    try:
        row = service.configure_lab_session(
            db,
            assessment_id,
            username=body.username,
            password=body.password.get_secret_value(),
            actor_user_id=principal.user_id,
        )
    except LabAuthDisabledError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=LAB_AUTH_DISABLED_DETAIL) from exc
    except WebTargetNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=WEB_TARGET_NOT_FOUND_DETAIL) from exc
    except TargetNotAuthorizedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=TARGET_NOT_AUTHORIZED_DETAIL) from exc
    except LabAuthError as exc:
        if exc.code == "target_not_local":
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail=LAB_TARGET_NOT_LOCAL_DETAIL
            ) from exc
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=LAB_AUTH_FAILED_DETAIL) from exc
    return _read(assessment_id, row)


@router.get(PATH, response_model=LabSessionRead)
def read_lab_credentials(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> LabSessionRead:
    """Whether a lab session is configured (never returns the cookie)."""
    return _read(assessment.id, service.get_lab_session(db, assessment.id))


@router.delete(
    PATH,
    status_code=status.HTTP_204_NO_CONTENT,
    responses={status.HTTP_404_NOT_FOUND: {"description": "No lab session configured."}},
)
def delete_lab_credentials(
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> None:
    """Clear the stored lab session."""
    if not service.clear_lab_session(db, assessment.id, actor_user_id=principal.user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=LAB_SESSION_NOT_FOUND_DETAIL)
