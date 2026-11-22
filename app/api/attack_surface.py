import logging
import re
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.constants import (
    ANALYSIS_CAPACITY_DETAIL,
    ANALYSIS_RATE_LIMITED_DETAIL,
    ANALYSIS_TIMED_OUT_DETAIL,
    ASSESSMENT_NOT_FOUND_DETAIL,
    PERSISTED_SUMMARY_NOT_FOUND_DETAIL,
    REPOSITORY_TARGET_NOT_FOUND_DETAIL,
    TARGET_NOT_AUTHORIZED_DETAIL,
)
from app.api.dependencies import AssessmentReader, ReadableAssessment, get_current_principal
from app.db.session import get_db
from app.schemas.attack_surface_summary import AttackSurfaceSummaryResponse
from app.services import analysis_runs as analysis_run_service
from app.services import attack_surface_reporting
from app.services.analysis_admission import (
    ANALYSIS_SUMMARY_SCOPE,
    AnalysisCapacityExceeded,
    AnalysisRateLimitExceeded,
    analysis_admission,
)
from app.services.analysis_execution_context import AnalysisDeadlineExceededError
from app.services.attack_surface import InvalidAttackSurfaceRootError
from app.services.attack_surface_correlation import InvalidCorrelationRootError
from app.services.attack_surface_reporting import RepositoryTargetNotFoundError
from app.services.attack_surface_summary import InvalidAttackSurfaceSummaryRootError
from app.services.auth_controls import InvalidAuthControlRootError
from app.services.handler_calls import InvalidHandlerCallRootError
from app.services.input_operation_flow import InvalidInputOperationRootError
from app.services.input_sources import InvalidInputSourceRootError
from app.services.repository_discovery import InvalidRepositoryRootError
from app.services.repository_targets import (
    AssessmentNotFoundError,
    repository_target_display_location,
)
from app.services.sensitive_operations import InvalidSensitiveOperationRootError
from app.services.target_authorization import TargetNotAuthorizedError
from app.services.technology_detector import InvalidTechnologyDetectionRootError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["attack-surface"],
    dependencies=[Depends(get_current_principal)],
)

SUMMARY_ROUTE_PATH = "/assessments/{assessment_id}/attack-surface/summary"
INVALID_REPOSITORY_TARGET_DETAIL = "Registered repository target is no longer valid"
SUMMARY_FAILED_DETAIL = "Attack surface summary could not be generated"

ROOT_VALIDATION_ERRORS: tuple[type[Exception], ...] = (
    InvalidRepositoryRootError,
    InvalidTechnologyDetectionRootError,
    InvalidAttackSurfaceRootError,
    InvalidAuthControlRootError,
    InvalidInputSourceRootError,
    InvalidSensitiveOperationRootError,
    InvalidCorrelationRootError,
    InvalidHandlerCallRootError,
    InvalidInputOperationRootError,
    InvalidAttackSurfaceSummaryRootError,
)

_SUMMARY_PATH_PATTERN = re.compile(r"^/api/v1/assessments/[^/]+/attack-surface/summary/?$")


def is_summary_request_path(path: str) -> bool:
    """Return True only for the attack-surface summary endpoint path."""
    return _SUMMARY_PATH_PATTERN.fullmatch(path) is not None


@router.get(
    SUMMARY_ROUTE_PATH,
    response_model=AttackSurfaceSummaryResponse,
    responses={
        status.HTTP_200_OK: {
            "model": AttackSurfaceSummaryResponse,
            "description": (
                "The recalculated attack-surface summary, or with source=persisted the "
                "summary stored by the newest completed analysis run."
            ),
        },
        status.HTTP_404_NOT_FOUND: {
            "description": (
                "Assessment or registered repository target not found, or "
                "(source=persisted) no completed run has stored a summary."
            ),
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "description": "The per-user summary rate limit was exhausted.",
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "Global analysis capacity was not available within the queue wait.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "Invalid assessment identifier or repository location.",
        },
        status.HTTP_504_GATEWAY_TIMEOUT: {
            "description": "The analysis deadline expired while generating the summary.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Unexpected failure while generating the summary.",
        },
    },
)
def get_attack_surface_summary(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
    principal: AssessmentReader,
    source: Annotated[
        Literal["live", "persisted"],
        Query(
            description=(
                "live (default): recalculate from the repository now. persisted: "
                "return the summary stored by the newest completed analysis run, "
                "without re-running the pipeline."
            ),
        ),
    ] = "live",
) -> AttackSurfaceSummaryResponse:
    """Return the read-only attack-surface summary (recalculated, or stored)."""
    # Capture plain values and end the dependency read transaction before any
    # admission wait so no worker thread blocks while holding a connection.
    assessment_id = assessment.id
    user_id = principal.user_id
    if source == "persisted":
        snapshot = analysis_run_service.latest_summary_snapshot(db, assessment_id)
        db.rollback()
        if snapshot is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=PERSISTED_SUMMARY_NOT_FOUND_DETAIL,
            )
        return AttackSurfaceSummaryResponse.model_validate(snapshot)
    db.rollback()
    try:
        analysis_admission.check_rate_limit(ANALYSIS_SUMMARY_SCOPE, user_id)
        with analysis_admission.global_slot():
            result = attack_surface_reporting.summarize_assessment_repository(
                db,
                assessment_id,
            )
    except AnalysisRateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=ANALYSIS_RATE_LIMITED_DETAIL,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except AnalysisCapacityExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=ANALYSIS_CAPACITY_DETAIL,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except AssessmentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ASSESSMENT_NOT_FOUND_DETAIL,
        ) from exc
    except RepositoryTargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=REPOSITORY_TARGET_NOT_FOUND_DETAIL,
        ) from exc
    except TargetNotAuthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=TARGET_NOT_AUTHORIZED_DETAIL,
        ) from exc
    except AnalysisDeadlineExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=ANALYSIS_TIMED_OUT_DETAIL,
        ) from exc
    except ROOT_VALIDATION_ERRORS as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=INVALID_REPOSITORY_TARGET_DETAIL,
        ) from exc
    except Exception as exc:
        logger.exception(
            "Unexpected failure generating attack surface summary for assessment %s",
            assessment_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=SUMMARY_FAILED_DETAIL,
        ) from exc

    return AttackSurfaceSummaryResponse(
        repository=repository_target_display_location(result.root),
        routes=result.routes,
        global_evidence=result.global_evidence,
        issues=result.issues,
        summary=result.summary,
    )
