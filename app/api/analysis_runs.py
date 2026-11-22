"""Analysis-run execution and history routes."""

import logging
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.attack_surface import (
    INVALID_REPOSITORY_TARGET_DETAIL,
    ROOT_VALIDATION_ERRORS,
)
from app.api.constants import (
    ANALYSIS_ASYNC_DISABLED_DETAIL,
    ANALYSIS_CAPACITY_DETAIL,
    ANALYSIS_RATE_LIMITED_DETAIL,
    ANALYSIS_RUN_CONFLICT_DETAIL,
    ANALYSIS_RUN_FAILED_DETAIL,
    ANALYSIS_RUN_FINISHED_DETAIL,
    ANALYSIS_RUN_NOT_FOUND_DETAIL,
    ANALYSIS_RUN_STOPPED_DETAIL,
    ANALYSIS_TIMED_OUT_DETAIL,
    ANALYSIS_USER_CONCURRENCY_DETAIL,
    ASSESSMENT_NOT_FOUND_DETAIL,
    REPOSITORY_TARGET_NOT_FOUND_DETAIL,
    TARGET_NOT_AUTHORIZED_DETAIL,
    WEB_TARGET_NOT_FOUND_DETAIL,
)
from app.api.dependencies import (
    AssessmentManager,
    ManageableAssessment,
    ReadableAssessment,
    get_current_principal,
)
from app.core.config import settings
from app.db.session import get_db
from app.models.analysis_run import AnalysisRun
from app.schemas.analysis_run import (
    AnalysisRunCreated,
    AnalysisRunDetail,
    AnalysisRunRead,
)
from app.services import analysis_execution
from app.services import analysis_runs as analysis_run_service
from app.services.analysis_admission import (
    ANALYSIS_RUN_SCOPE,
    AnalysisCapacityExceeded,
    AnalysisRateLimitExceeded,
    AnalysisUserConcurrencyExceeded,
    analysis_admission,
)
from app.services.analysis_execution import ActiveAnalysisRunError
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
)
from app.services.analysis_runs import AnalysisRunAlreadyFinishedError
from app.services.attack_surface_reporting import RepositoryTargetNotFoundError
from app.services.repository_targets import AssessmentNotFoundError
from app.services.target_authorization import TargetNotAuthorizedError, WebTargetNotFoundError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["analysis-runs"],
    dependencies=[Depends(get_current_principal)],
)

ASSESSMENT_RUNS_PATH = "/assessments/{assessment_id}/analysis-runs"


def _run_path(assessment_id: uuid.UUID, run_id: uuid.UUID) -> str:
    return f"/api/v1/assessments/{assessment_id}/analysis-runs/{run_id}"


def _run_read(run: AnalysisRun, findings_count: int) -> AnalysisRunRead:
    return AnalysisRunRead(
        id=run.id,
        assessment_id=run.assessment_id,
        status=run.status,
        created_at=run.created_at,
        started_at=run.started_at,
        completed_at=run.completed_at,
        error_message=run.error_message,
        findings_count=findings_count,
        stage=run.stage,
        attempts=run.attempts or 0,
        error_code=run.error_code,
        cancel_requested_at=run.cancel_requested_at,
    )


def _run_detail(run: AnalysisRun, findings_count: int) -> AnalysisRunDetail:
    return AnalysisRunDetail(
        **_run_read(run, findings_count).model_dump(),
        analysis_metadata=run.analysis_metadata,
    )


@router.post(
    ASSESSMENT_RUNS_PATH,
    response_model=AnalysisRunCreated,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_201_CREATED: {
            "model": AnalysisRunCreated,
            "description": (
                "The analysis run after synchronous execution completes, including "
                "its final status and finding count."
            ),
        },
        status.HTTP_202_ACCEPTED: {
            "model": AnalysisRunCreated,
            "description": (
                "mode=async: the run was queued for the background worker. Poll the "
                "Location header for status, stage, and results."
            ),
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "mode=async was requested but asynchronous analysis is not enabled.",
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Assessment or registered repository target not found.",
        },
        status.HTTP_409_CONFLICT: {
            "description": (
                "The assessment already has an active analysis run, its target is not "
                "authorized, or the synchronous run was cancelled before completion."
            ),
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "description": (
                "The per-user analysis rate limit or concurrent-run quota was exhausted. "
                "A concurrent same-user request may receive this response before the "
                "active-run conflict is evaluated."
            ),
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "Global analysis capacity was not available within the queue wait.",
        },
        status.HTTP_504_GATEWAY_TIMEOUT: {
            "description": "The analysis deadline expired; the failed run is retained.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "Invalid assessment identifier or repository location.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Analysis execution failed; the failed run is retained.",
        },
    },
)
def create_assessment_analysis_run(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
    mode: Annotated[
        Literal["sync", "async"],
        Query(
            description=(
                "sync (default): execute now and return the final state (201). "
                "async: queue for the background worker and return immediately (202)."
            ),
        ),
    ] = "sync",
) -> AnalysisRunCreated:
    """Execute one analysis run, synchronously by default or queued with mode=async."""
    # Capture plain values before rolling back: the dependency read transaction
    # must not stay open while admission may block a worker thread.
    assessment_id = assessment.id
    actor_user_id = principal.user_id
    db.rollback()
    if mode == "async" and not settings.analysis_async_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ANALYSIS_ASYNC_DISABLED_DETAIL,
        )
    try:
        analysis_admission.check_rate_limit(ANALYSIS_RUN_SCOPE, actor_user_id)
        if mode == "async":
            # Durable per-user quota over queued and running runs in every process.
            active = analysis_run_service.count_active_runs_for_user(
                db, actor_user_id, exclude_assessment_id=assessment_id
            )
            db.rollback()
            if active >= settings.analysis_max_concurrent_jobs_per_user:
                raise AnalysisUserConcurrencyExceeded(
                    settings.analysis_worker_poll_interval_seconds
                )
            run = analysis_execution.enqueue_assessment_analysis(
                db,
                assessment_id,
                actor_user_id=actor_user_id,
            )
            response.status_code = status.HTTP_202_ACCEPTED
            response.headers["Location"] = _run_path(assessment_id, run.id)
            return AnalysisRunCreated(**_run_detail(run, 0).model_dump())
        with analysis_admission.run_slot(actor_user_id):
            with analysis_admission.global_slot():
                run = analysis_execution.execute_assessment_analysis(
                    db,
                    assessment_id,
                    actor_user_id=actor_user_id,
                )
    except AnalysisRateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=ANALYSIS_RATE_LIMITED_DETAIL,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except AnalysisUserConcurrencyExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=ANALYSIS_USER_CONCURRENCY_DETAIL,
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
    except WebTargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=WEB_TARGET_NOT_FOUND_DETAIL,
        ) from exc
    except TargetNotAuthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=TARGET_NOT_AUTHORIZED_DETAIL,
        ) from exc
    except ActiveAnalysisRunError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ANALYSIS_RUN_CONFLICT_DETAIL,
        ) from exc
    except AnalysisDeadlineExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=ANALYSIS_TIMED_OUT_DETAIL,
        ) from exc
    except AnalysisExecutionAbortedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ANALYSIS_RUN_STOPPED_DETAIL,
        ) from exc
    except ROOT_VALIDATION_ERRORS as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=INVALID_REPOSITORY_TARGET_DETAIL,
        ) from exc
    except Exception as exc:
        logger.exception(
            "Unexpected failure executing analysis run for assessment %s",
            assessment_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ANALYSIS_RUN_FAILED_DETAIL,
        ) from exc

    findings_count = analysis_run_service.count_analysis_run_findings(db, run.id)
    response.headers["Location"] = _run_path(assessment_id, run.id)
    return AnalysisRunCreated(**_run_detail(run, findings_count).model_dump())


@router.get(
    ASSESSMENT_RUNS_PATH,
    response_model=list[AnalysisRunRead],
    responses={
        status.HTTP_200_OK: {
            "model": list[AnalysisRunRead],
            "description": "Analysis runs for the assessment, newest first.",
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Assessment not found.",
        },
    },
)
def list_assessment_analysis_runs(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> list[AnalysisRunRead]:
    """List analysis runs for one assessment, newest first."""
    rows = analysis_run_service.list_assessment_analysis_runs(db, assessment.id)
    if rows is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ASSESSMENT_NOT_FOUND_DETAIL,
        )
    return [_run_read(run, findings_count) for run, findings_count in rows]


@router.get(
    f"{ASSESSMENT_RUNS_PATH}/{{run_id}}",
    response_model=AnalysisRunDetail,
    responses={
        status.HTTP_200_OK: {
            "model": AnalysisRunDetail,
            "description": "One analysis run with compact metadata and finding count.",
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Assessment not found, or run unknown or not owned by it.",
        },
    },
)
def get_assessment_analysis_run(
    run_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> AnalysisRunDetail:
    """Return one analysis run belonging to the assessment."""
    row = analysis_run_service.get_assessment_analysis_run(db, assessment.id, run_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ANALYSIS_RUN_NOT_FOUND_DETAIL,
        )

    run, findings_count = row
    return _run_detail(run, findings_count)


@router.post(
    f"{ASSESSMENT_RUNS_PATH}/{{run_id}}/cancel",
    response_model=AnalysisRunDetail,
    responses={
        status.HTTP_200_OK: {
            "model": AnalysisRunDetail,
            "description": (
                "A queued run is now cancelled. A running run has cancellation "
                "requested (cancel_requested_at set); it stops at the next stage "
                "boundary or heartbeat and then reports status cancelled."
            ),
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Assessment not found, or run unknown or not owned by it.",
        },
        status.HTTP_409_CONFLICT: {
            "description": "The run has already finished.",
        },
    },
)
def cancel_assessment_analysis_run(
    run_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> AnalysisRunDetail:
    """Cancel a queued run, or request cancellation of a running run."""
    assessment_id = assessment.id
    try:
        row = analysis_run_service.request_cancellation(
            db, assessment_id, run_id, actor_user_id=principal.user_id
        )
    except AnalysisRunAlreadyFinishedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ANALYSIS_RUN_FINISHED_DETAIL,
        ) from exc
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ANALYSIS_RUN_NOT_FOUND_DETAIL,
        )
    run, findings_count = row
    return _run_detail(run, findings_count)
