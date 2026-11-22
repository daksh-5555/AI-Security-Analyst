import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.constants import (
    ANALYSIS_RUN_NOT_FOUND_DETAIL,
    ASSESSMENT_NOT_FOUND_DETAIL,
    REPOSITORY_LOCATION_INVALID_DETAIL,
    REPOSITORY_TARGET_NOT_FOUND_DETAIL,
)
from app.api.dependencies import (
    AssessmentManager,
    AssessmentReader,
    ManageableAssessment,
    ReadableAssessment,
    get_current_principal,
)
from app.db.session import get_db
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.assessment_status_history import AssessmentStatusHistory
from app.models.repository_target import RepositoryTarget
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentRead,
    AssessmentStatusHistoryRead,
    AssessmentStatusUpdate,
)
from app.schemas.finding import FindingRead
from app.schemas.repository import RepositorySourceCreate, RepositoryTargetRead
from app.services import assessments as assessment_service
from app.services import authorization
from app.services import findings as finding_service
from app.services import repository_targets as repository_target_service
from app.services.assessments import InvalidStatusTransitionError
from app.services.repository_targets import (
    AssessmentNotFoundError,
    AssessmentNotQueuedError,
    AssessmentNotRepositoryError,
    DuplicateRepositoryTargetError,
    InvalidRepositoryLocationError,
)

router = APIRouter(
    prefix="/api/v1",
    tags=["assessments"],
    dependencies=[Depends(get_current_principal)],
)


def _repository_target_read(target: RepositoryTarget) -> RepositoryTargetRead:
    """Serialize a repository target without exposing its absolute path."""
    return RepositoryTargetRead(
        id=target.id,
        assessment_id=target.assessment_id,
        source_kind=target.source_kind,
        location=repository_target_service.repository_target_display_location(target.location),
        created_at=target.created_at,
        updated_at=target.updated_at,
    )


@router.post(
    "/assessments",
    response_model=AssessmentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_assessment(
    payload: AssessmentCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: AssessmentManager,
) -> AssessmentJob:
    """Create a queued assessment job owned by the authenticated caller."""
    return assessment_service.create_assessment(
        db,
        payload.assessment_type,
        owner_id=principal.user_id,
        actor_user_id=principal.user_id,
    )


@router.get("/assessments", response_model=list[AssessmentRead])
def list_assessments(
    db: Annotated[Session, Depends(get_db)],
    principal: AssessmentReader,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AssessmentJob]:
    """List assessments visible to the caller, newest first."""
    return authorization.list_visible_assessments(
        db,
        principal,
        limit=limit,
        offset=offset,
    )


@router.get("/assessments/{assessment_id}", response_model=AssessmentRead)
def get_assessment(
    assessment: ReadableAssessment,
) -> AssessmentJob:
    """Retrieve a single assessment visible to the caller."""
    return assessment


@router.patch(
    "/assessments/{assessment_id}/status",
    response_model=AssessmentRead,
)
def update_assessment_status(
    payload: AssessmentStatusUpdate,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> AssessmentJob:
    """Apply a validated lifecycle status transition."""
    try:
        return assessment_service.apply_status_change(
            db,
            assessment,
            payload.status,
            payload.reason,
            actor_user_id=principal.user_id,
        )
    except InvalidStatusTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc


@router.get(
    "/assessments/{assessment_id}/history",
    response_model=list[AssessmentStatusHistoryRead],
)
def get_assessment_history(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> list[AssessmentStatusHistory]:
    """Return status transitions in chronological order."""
    history = assessment_service.list_status_history(db, assessment.id)
    if history is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ASSESSMENT_NOT_FOUND_DETAIL,
        )
    return history


@router.post(
    "/assessments/{assessment_id}/repository",
    response_model=RepositoryTargetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_repository_target(
    payload: RepositorySourceCreate,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> RepositoryTargetRead:
    """Register a local repository target for a queued repository assessment."""
    try:
        target = repository_target_service.create_repository_target(
            db,
            assessment,
            payload,
            actor_user_id=principal.user_id,
        )
    except AssessmentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except (
        AssessmentNotRepositoryError,
        AssessmentNotQueuedError,
        DuplicateRepositoryTargetError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except InvalidRepositoryLocationError as exc:
        # The specific reason stays internal: distinct messages would reveal
        # whether arbitrary server paths exist and whether they are directories.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=REPOSITORY_LOCATION_INVALID_DETAIL,
        ) from exc

    return _repository_target_read(target)


@router.get(
    "/assessments/{assessment_id}/repository",
    response_model=RepositoryTargetRead,
)
def get_repository_target(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> RepositoryTargetRead:
    """Retrieve the repository target registered for an assessment."""
    try:
        target = repository_target_service.get_repository_target(db, assessment.id)
    except AssessmentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=REPOSITORY_TARGET_NOT_FOUND_DETAIL,
        )
    return _repository_target_read(target)


@router.get(
    "/assessments/{assessment_id}/findings",
    response_model=list[FindingRead],
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Assessment not found, or analysis run unknown or not owned by it.",
        },
    },
)
def list_assessment_findings(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
    analysis_run_id: Annotated[
        uuid.UUID | None,
        Query(
            description=(
                "Return only findings associated with this analysis run. "
                "When omitted, findings for the whole assessment are returned."
            ),
        ),
    ] = None,
) -> list[AssessmentFinding]:
    """Return persisted findings and their evidence for an assessment."""
    try:
        findings = finding_service.list_findings(
            db,
            assessment.id,
            analysis_run_id=analysis_run_id,
        )
    except finding_service.AnalysisRunNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ANALYSIS_RUN_NOT_FOUND_DETAIL,
        ) from exc

    if findings is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ASSESSMENT_NOT_FOUND_DETAIL,
        )
    return findings
