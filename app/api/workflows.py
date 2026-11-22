"""Bounded, approval-gated assessment workflows (M10, ADR-0013).

Workflows run synchronously in the request until they finish, pause for a
human approval, or hit a retryable error; ``resume`` continues them.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.constants import (
    ANALYSIS_RATE_LIMITED_DETAIL,
    WORKFLOW_ACTIVE_DETAIL,
    WORKFLOW_APPROVAL_DETAIL,
    WORKFLOW_NOT_FOUND_DETAIL,
    WORKFLOW_STATE_DETAIL,
)
from app.api.dependencies import (
    AssessmentManager,
    ManageableAssessment,
    ReadableAssessment,
    get_current_principal,
)
from app.api.explanations import get_explanation_provider
from app.core.config import settings
from app.db.session import get_db
from app.models.workflow import AssessmentWorkflow
from app.schemas.workflow import (
    WorkflowApproval,
    WorkflowCreate,
    WorkflowDetail,
    WorkflowEventRead,
    WorkflowRead,
)
from app.services.analysis_admission import (
    ANALYSIS_RUN_SCOPE,
    AnalysisRateLimitExceeded,
    analysis_admission,
)
from app.services.explanations.provider import ExplanationProvider
from app.services.workflow import engine
from app.services.workflow.plan import pending_approvals

router = APIRouter(
    prefix="/api/v1",
    tags=["workflows"],
    dependencies=[Depends(get_current_principal)],
)

WORKFLOWS_PATH = "/assessments/{assessment_id}/workflows"
WORKFLOW_PATH = f"{WORKFLOWS_PATH}/{{workflow_id}}"


def _read(workflow: AssessmentWorkflow) -> WorkflowRead:
    approvals = workflow.state.get("approvals", {})
    return WorkflowRead(
        id=workflow.id,
        assessment_id=workflow.assessment_id,
        status=workflow.status,
        graph_version=workflow.graph_version,
        current_node=workflow.current_node,
        step_count=workflow.step_count,
        max_steps=settings.workflow_max_steps,
        options=workflow.options,
        plan=workflow.plan,
        approvals=approvals,
        pending_approvals=pending_approvals(workflow.plan, approvals) if workflow.plan else [],
        analysis_run_id=workflow.analysis_run_id,
        error_code=workflow.error_code,
        created_at=workflow.created_at,
        updated_at=workflow.updated_at,
        completed_at=workflow.completed_at,
    )


def _detail(db: Session, workflow: AssessmentWorkflow) -> WorkflowDetail:
    events = [WorkflowEventRead.model_validate(e) for e in engine.list_events(db, workflow.id)]
    return WorkflowDetail(**_read(workflow).model_dump(), events=events)


def _http(exc: engine.WorkflowError) -> HTTPException:
    if isinstance(exc, engine.WorkflowNotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=WORKFLOW_NOT_FOUND_DETAIL)
    if isinstance(exc, engine.ActiveWorkflowError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=WORKFLOW_ACTIVE_DETAIL)
    if isinstance(exc, engine.InvalidApprovalError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=WORKFLOW_APPROVAL_DETAIL)
    return HTTPException(status.HTTP_409_CONFLICT, detail=WORKFLOW_STATE_DETAIL)


_ERRORS = {
    status.HTTP_404_NOT_FOUND: {"description": "Assessment or workflow not found."},
    status.HTTP_409_CONFLICT: {"description": "Not allowed in the workflow's current state."},
}


@router.post(
    WORKFLOWS_PATH,
    response_model=WorkflowDetail,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_201_CREATED: {
            "description": (
                "The workflow after it ran as far as it could: completed, failed, "
                "awaiting_approval, or running (a retryable error; call resume)."
            )
        },
        status.HTTP_409_CONFLICT: {"description": "The assessment has an active workflow."},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Analysis rate limit exhausted."},
    },
)
def start_workflow(
    body: WorkflowCreate,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
    provider: Annotated[ExplanationProvider, Depends(get_explanation_provider)],
) -> WorkflowDetail:
    """Start a bounded workflow over the pre-approved checks for this assessment."""
    assessment_id = assessment.id
    db.rollback()
    try:
        analysis_admission.check_rate_limit(ANALYSIS_RUN_SCOPE, principal.user_id)
        workflow = engine.start_workflow(
            db,
            assessment_id,
            actor_user_id=principal.user_id,
            explain_findings=body.explain_findings,
            provider_factory=lambda: provider,
        )
    except AnalysisRateLimitExceeded as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=ANALYSIS_RATE_LIMITED_DETAIL,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except engine.WorkflowError as exc:
        raise _http(exc) from exc
    return _detail(db, workflow)


@router.get(WORKFLOWS_PATH, response_model=list[WorkflowRead])
def list_workflows(
    db: Annotated[Session, Depends(get_db)], assessment: ReadableAssessment
) -> list[WorkflowRead]:
    """Workflows for the assessment, newest first."""
    return [_read(item) for item in engine.list_workflows(db, assessment.id)]


@router.get(WORKFLOW_PATH, response_model=WorkflowDetail, responses=_ERRORS)
def get_workflow(
    workflow_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
) -> WorkflowDetail:
    """One workflow with its plan, approvals, and full event log."""
    try:
        workflow = engine.get_workflow(db, assessment.id, workflow_id)
    except engine.WorkflowError as exc:
        raise _http(exc) from exc
    return _detail(db, workflow)


@router.post(f"{WORKFLOW_PATH}/approvals", response_model=WorkflowDetail, responses=_ERRORS)
def decide_approval(
    workflow_id: uuid.UUID,
    body: WorkflowApproval,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
    provider: Annotated[ExplanationProvider, Depends(get_explanation_provider)],
) -> WorkflowDetail:
    """Approve or deny a pending high-risk check; the workflow then continues."""
    try:
        workflow = engine.record_approval(
            db,
            assessment.id,
            workflow_id,
            check=body.check,
            approved=body.decision == "approve",
            reason=body.reason,
            actor_user_id=principal.user_id,
            provider_factory=lambda: provider,
        )
    except engine.WorkflowError as exc:
        raise _http(exc) from exc
    return _detail(db, workflow)


@router.post(f"{WORKFLOW_PATH}/resume", response_model=WorkflowDetail, responses=_ERRORS)
def resume_workflow(
    workflow_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
    provider: Annotated[ExplanationProvider, Depends(get_explanation_provider)],
) -> WorkflowDetail:
    """Continue a running workflow after an error or an interruption."""
    try:
        workflow = engine.resume_workflow(
            db,
            assessment.id,
            workflow_id,
            actor_user_id=principal.user_id,
            provider_factory=lambda: provider,
        )
    except engine.WorkflowError as exc:
        raise _http(exc) from exc
    return _detail(db, workflow)


@router.post(f"{WORKFLOW_PATH}/cancel", response_model=WorkflowDetail, responses=_ERRORS)
def cancel_workflow(
    workflow_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    assessment: ManageableAssessment,
    principal: AssessmentManager,
) -> WorkflowDetail:
    """Cancel a running or awaiting-approval workflow (and request its run's cancellation)."""
    try:
        workflow = engine.cancel_workflow(
            db, assessment.id, workflow_id, actor_user_id=principal.user_id
        )
    except engine.WorkflowError as exc:
        raise _http(exc) from exc
    return _detail(db, workflow)
