"""Advisory LLM explanations of findings (M9, ADR-0012)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.constants import (
    ANALYSIS_RATE_LIMITED_DETAIL,
    EXPLANATION_BUDGET_DETAIL,
    EXPLANATIONS_DISABLED_DETAIL,
    FINDING_NOT_FOUND_DETAIL,
)
from app.api.dependencies import (
    AssessmentManager,
    ManageableAssessment,
    ReadableAssessment,
    get_current_principal,
)
from app.db.session import get_db
from app.models.finding_explanation import FindingExplanation
from app.schemas.explanation import FindingExplanationRead
from app.services.analysis_admission import (
    EXPLANATION_SCOPE,
    AnalysisRateLimitExceeded,
    analysis_admission,
)
from app.services.explanations import service
from app.services.explanations.provider import ExplanationProvider, build_provider

router = APIRouter(
    prefix="/api/v1",
    tags=["explanations"],
    dependencies=[Depends(get_current_principal)],
)

EXPLANATIONS_PATH = "/assessments/{assessment_id}/findings/{finding_id}/explanations"


def get_explanation_provider() -> ExplanationProvider:
    """The configured provider; replaced by a scripted fake in tests."""
    return build_provider()


def _read(explanation: FindingExplanation) -> FindingExplanationRead:
    return FindingExplanationRead(
        id=explanation.id,
        assessment_id=explanation.assessment_id,
        finding_id=explanation.finding_id,
        status=explanation.status,
        error_code=explanation.error_code,
        explanation=explanation.output,
        provider=explanation.provider,
        model=explanation.model,
        prompt_template_version=explanation.prompt_template_version,
        supplied_evidence_ids=explanation.supplied_evidence_ids,
        retrieval=explanation.retrieval,
        input_tokens=explanation.input_tokens,
        output_tokens=explanation.output_tokens,
        created_at=explanation.created_at,
    )


@router.post(
    EXPLANATIONS_PATH,
    response_model=FindingExplanationRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_201_CREATED: {
            "description": (
                "The stored attempt: status available with a validated explanation, or "
                "unavailable with an error code. The finding itself is never changed."
            ),
        },
        status.HTTP_400_BAD_REQUEST: {"description": "AI explanations are not enabled."},
        status.HTTP_404_NOT_FOUND: {"description": "Assessment or finding not found."},
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "description": "Rate limit or the assessment's explanation token budget is exhausted.",
        },
    },
)
def create_finding_explanation(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
    provider: Annotated[ExplanationProvider, Depends(get_explanation_provider)],
) -> FindingExplanationRead:
    """Ask the configured LLM to explain one finding (advisory only)."""
    assessment_id = assessment.id
    try:
        analysis_admission.check_rate_limit(EXPLANATION_SCOPE, principal.user_id)
        explanation = service.explain_finding(
            db,
            assessment_id,
            finding_id,
            provider=provider,
            actor_user_id=principal.user_id,
        )
    except service.ExplanationsDisabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=EXPLANATIONS_DISABLED_DETAIL
        ) from exc
    except service.FindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=FINDING_NOT_FOUND_DETAIL
        ) from exc
    except AnalysisRateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=ANALYSIS_RATE_LIMITED_DETAIL,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except service.ExplanationBudgetExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=EXPLANATION_BUDGET_DETAIL
        ) from exc
    return _read(explanation)


@router.get(
    EXPLANATIONS_PATH,
    response_model=list[FindingExplanationRead],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Assessment or finding not found."}},
)
def list_finding_explanations(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> list[FindingExplanationRead]:
    """Stored explanation attempts for one finding, newest first."""
    try:
        rows = service.list_explanations(db, assessment.id, finding_id)
    except service.FindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=FINDING_NOT_FOUND_DETAIL
        ) from exc
    return [_read(row) for row in rows]
