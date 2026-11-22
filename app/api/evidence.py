"""Read-only access to normalized evidence items (M7)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.constants import ANALYSIS_RUN_NOT_FOUND_DETAIL, EVIDENCE_NOT_FOUND_DETAIL
from app.api.dependencies import ReadableAssessment, get_current_principal
from app.db.session import get_db
from app.schemas.finding import EvidenceItemRead
from app.services import findings as finding_service

router = APIRouter(
    prefix="/api/v1",
    tags=["evidence"],
    dependencies=[Depends(get_current_principal)],
)


@router.get(
    "/assessments/{assessment_id}/evidence",
    response_model=list[EvidenceItemRead],
)
def list_evidence(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
    analysis_run_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[EvidenceItemRead]:
    """Evidence items for an assessment, optionally for one run, oldest first."""
    try:
        items = finding_service.list_evidence(
            db, assessment.id, analysis_run_id=analysis_run_id, limit=limit, offset=offset
        )
    except finding_service.AnalysisRunNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=ANALYSIS_RUN_NOT_FOUND_DETAIL
        ) from exc
    return [EvidenceItemRead.model_validate(item) for item in items]


@router.get(
    "/assessments/{assessment_id}/evidence/{evidence_id}",
    response_model=EvidenceItemRead,
)
def get_evidence(
    evidence_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> EvidenceItemRead:
    """One evidence item; 404 if it belongs to another assessment."""
    item = finding_service.get_evidence(db, assessment.id, evidence_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=EVIDENCE_NOT_FOUND_DETAIL)
    return EvidenceItemRead.model_validate(item)
