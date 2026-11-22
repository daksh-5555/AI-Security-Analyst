"""Execution engine for bounded assessment workflows (M10, ADR-0013).

Each step:

1. **Claim.** A conditional UPDATE claims the next node execution. The
   workflow must still be ``running`` and at the same node and step count, so
   two concurrent ``advance`` calls cannot run the same step. The claim also
   enforces the step budget (``WORKFLOW_MAX_STEPS``) and per-node attempts
   (``WORKFLOW_MAX_NODE_ATTEMPTS``).
2. **Run.** The node runs. It may only call the deterministic analysis
   pipeline (through ``execute_assessment_analysis``, which re-checks target
   authorization) and the M9 explanation service.
3. **Persist.** The result (state, plan, next node, status, event, audit) is
   committed in one transaction, conditional on the claim still holding.

An exception inside a node is recorded as a retryable ``error`` event. The
workflow stays at that node until ``resume`` is called, and it fails once the
attempts are used up. A workflow interrupted by a crash is resumed the same
way. ``run_analysis`` finds the run it already started instead of starting a
second one.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.workflow import AssessmentWorkflow, WorkflowEvent
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    FindingSeverity,
    WorkflowStatus,
)
from app.services import analysis_runs as analysis_run_service
from app.services.analysis_admission import (
    AnalysisAdmissionError,
    analysis_admission,
)
from app.services.analysis_execution import (
    TARGET_VALIDATION_ERRORS,
    ActiveAnalysisRunError,
    execute_assessment_analysis,
    validate_analysis_target,
)
from app.services.audit import record_audit_event
from app.services.explanations import service as explanation_service
from app.services.explanations.provider import ExplanationProvider, build_provider
from app.services.reports.builder import build_report
from app.services.repository_targets import AssessmentNotFoundError
from app.services.workflow.plan import (
    GRAPH_VERSION,
    NODE_SEQUENCE,
    RUN,
    config_snapshot,
    excluded_tool_stages,
    next_node,
    pending_approvals,
    plan_checks,
)

logger = logging.getLogger(__name__)

ProviderFactory = Callable[[], ExplanationProvider]
_ACTIVE = (WorkflowStatus.RUNNING, WorkflowStatus.AWAITING_APPROVAL)
_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.UNKNOWN: 4,
    FindingSeverity.INFORMATIONAL: 5,
}
_MAX_REASON = 500


class WorkflowError(RuntimeError):
    """Base class for workflow request errors."""


class ActiveWorkflowError(WorkflowError):
    """The assessment already has a running or awaiting-approval workflow."""


class WorkflowNotFoundError(WorkflowError):
    """Unknown workflow, or it belongs to another assessment."""


class WorkflowStateError(WorkflowError):
    """The operation is not allowed in the workflow's current state."""


class InvalidApprovalError(WorkflowError):
    """The check is not awaiting approval in this workflow."""


@dataclass
class NodeResult:
    outcome: str  # completed | skipped | paused | failed | error
    detail: dict[str, Any] = field(default_factory=dict)
    state_updates: dict[str, Any] = field(default_factory=dict)
    plan: dict[str, Any] | None = None
    analysis_run_id: uuid.UUID | None = None
    error_code: str | None = None


@dataclass
class NodeContext:
    db: Session
    workflow_id: uuid.UUID
    assessment_id: uuid.UUID
    options: dict[str, Any]
    plan: dict[str, Any] | None
    state: dict[str, Any]
    requested_by: uuid.UUID | None
    provider_factory: ProviderFactory


def _now() -> datetime:
    return datetime.now(UTC)


# --- nodes ------------------------------------------------------------------


def _load_assessment(ctx: NodeContext) -> NodeResult:
    assessment = ctx.db.get(AssessmentJob, ctx.assessment_id)
    if assessment is None:
        return NodeResult("failed", error_code="assessment_not_found")
    kind = assessment.assessment_type.value
    return NodeResult(
        "completed", detail={"assessment_type": kind}, state_updates={"assessment_type": kind}
    )


def _validate_authorization(ctx: NodeContext) -> NodeResult:
    try:
        is_web = validate_analysis_target(ctx.db, ctx.assessment_id)
    except AssessmentNotFoundError:
        return NodeResult("failed", error_code="assessment_not_found")
    except TARGET_VALIDATION_ERRORS as exc:
        return NodeResult(
            "failed", detail={"reason": type(exc).__name__}, error_code="target_not_authorized"
        )
    finally:
        ctx.db.rollback()
    return NodeResult(
        "completed", detail={"target_type": "web_application" if is_web else "repository"}
    )


def _plan_enabled_checks(ctx: NodeContext) -> NodeResult:
    plan = plan_checks(AssessmentType(ctx.state["assessment_type"]), ctx.options, config_snapshot())
    return NodeResult(
        "completed",
        detail={"checks": {item["check"]: item["decision"] for item in plan["checks"]}},
        plan=plan,
    )


def _approval_gate(ctx: NodeContext) -> NodeResult:
    assert ctx.plan is not None
    pending = pending_approvals(ctx.plan, ctx.state.get("approvals", {}))
    if pending:
        return NodeResult("paused", detail={"pending_approvals": pending})
    return NodeResult(
        "completed",
        detail={
            "approvals": {
                check: entry["decision"] for check, entry in ctx.state.get("approvals", {}).items()
            }
        },
    )


def _run_outcome(run: AnalysisRun) -> NodeResult:
    metadata = run.analysis_metadata or {}
    detail = {
        "analysis_run_id": str(run.id),
        "run_status": run.status.value,
        "finding_count": metadata.get("finding_count"),
        "tools": [
            {"stage": tool.get("stage"), "status": tool.get("status")}
            for tool in metadata.get("tools", [])
        ],
        "is_complete": (metadata.get("completeness") or {}).get("is_complete"),
    }
    if run.status is AnalysisRunStatus.COMPLETED:
        return NodeResult("completed", detail=detail, analysis_run_id=run.id)
    if run.status in (AnalysisRunStatus.QUEUED, AnalysisRunStatus.RUNNING):
        return NodeResult(
            "error", detail=detail, analysis_run_id=run.id, error_code="analysis_in_progress"
        )
    code = "analysis_cancelled" if run.status is AnalysisRunStatus.CANCELLED else "analysis_failed"
    return NodeResult("failed", detail=detail, analysis_run_id=run.id, error_code=code)


def _started_run(ctx: NodeContext) -> AnalysisRun | None:
    run_id = ctx.state.get("analysis_run_id")
    if run_id:
        return ctx.db.get(AnalysisRun, uuid.UUID(run_id))
    started = ctx.state.get("analysis_started_at")
    if not started:
        return None
    return ctx.db.scalar(
        select(AnalysisRun)
        .where(
            AnalysisRun.assessment_id == ctx.assessment_id,
            AnalysisRun.created_at >= datetime.fromisoformat(started),
        )
        .order_by(AnalysisRun.created_at.desc())
        .limit(1)
    )


def _run_analysis(ctx: NodeContext) -> NodeResult:
    assert ctx.plan is not None
    existing = _started_run(ctx)
    if existing is not None:
        # Resumed after an interruption: adopt the run instead of starting another.
        return _run_outcome(existing)
    excluded = excluded_tool_stages(ctx.plan, ctx.state.get("approvals", {}))
    _patch_state(ctx.db, ctx.workflow_id, {"analysis_started_at": _now().isoformat()})
    actor = ctx.requested_by
    try:
        with analysis_admission.global_slot():
            run = execute_assessment_analysis(
                ctx.db,
                ctx.assessment_id,
                actor_user_id=actor,
                excluded_stages=excluded,
            )
    except AnalysisAdmissionError:
        return NodeResult("error", error_code="capacity_unavailable")
    except ActiveAnalysisRunError:
        return NodeResult("error", error_code="active_run_conflict")
    except TARGET_VALIDATION_ERRORS:
        return NodeResult("failed", error_code="target_not_authorized")
    except Exception:
        # The run records its own sanitized failure; adopt it if it exists.
        ctx.db.rollback()
        ctx.state["analysis_started_at"] = _started_at(ctx.db, ctx.workflow_id)
        failed = _started_run(ctx)
        if failed is not None:
            return _run_outcome(failed)
        return NodeResult("failed", error_code="analysis_failed")
    result = _run_outcome(run)
    result.detail["excluded_checks"] = sorted(excluded)
    return result


def _explain_findings(ctx: NodeContext) -> NodeResult:
    assert ctx.plan is not None
    check = next(item for item in ctx.plan["checks"] if item["check"] == "explain_findings")
    if check["decision"] != RUN:
        return NodeResult("skipped", detail={"reason": check["reason"]})
    run_id = ctx.state.get("analysis_run_id")
    findings = list(
        ctx.db.scalars(
            select(AssessmentFinding).where(AssessmentFinding.analysis_run_id == uuid.UUID(run_id))
        )
    )
    findings.sort(key=lambda item: (_SEVERITY_RANK.get(item.severity, 9), item.position))
    selected = [item.id for item in findings[: settings.workflow_max_explanations]]
    ctx.db.rollback()
    provider = ctx.provider_factory()
    counts = {"requested": 0, "available": 0, "unavailable": 0}
    stopped: str | None = None
    explanation_ids: list[str] = []
    for finding_id in selected:
        try:
            explanation = explanation_service.explain_finding(
                ctx.db,
                ctx.assessment_id,
                finding_id,
                provider=provider,
                actor_user_id=ctx.requested_by,
            )
        except explanation_service.ExplanationBudgetExceededError:
            stopped = "budget_exhausted"
            break
        except explanation_service.ExplanationsDisabledError:
            stopped = "disabled_by_configuration"
            break
        counts["requested"] += 1
        counts[explanation.status.value] += 1
        explanation_ids.append(str(explanation.id))
    detail: dict[str, Any] = {**counts, "explanation_ids": explanation_ids}
    if stopped:
        detail["stopped"] = stopped
    # Explanations are advisory: their failure never fails the workflow.
    return NodeResult("completed", detail=detail)


def _generate_report(ctx: NodeContext) -> NodeResult:
    """Build the report for this workflow's run and record its identity.

    Nothing is stored except the content hash and counts in the event; the
    report can be downloaded at any time and will hash identically while the
    persisted data is unchanged.
    """
    run_id = ctx.state.get("analysis_run_id")
    try:
        report = build_report(
            ctx.db,
            ctx.assessment_id,
            analysis_run_id=uuid.UUID(run_id) if run_id else None,
        )
    finally:
        ctx.db.rollback()
    return NodeResult(
        "completed",
        detail={
            "schema_version": report["schema_version"],
            "content_hash": report["content_hash"],
            "finding_count": report["counts"]["total"],
            "checks_not_run": [item["stage"] for item in report["checks_not_run"]],
        },
    )


def _finalize_run(ctx: NodeContext) -> NodeResult:
    return NodeResult("completed", detail={"analysis_run_id": ctx.state.get("analysis_run_id")})


NODE_HANDLERS: dict[str, Callable[[NodeContext], NodeResult]] = {
    "load_assessment": _load_assessment,
    "validate_authorization": _validate_authorization,
    "plan_enabled_checks": _plan_enabled_checks,
    "approval_gate": _approval_gate,
    "run_analysis": _run_analysis,
    "explain_findings": _explain_findings,
    "generate_report": _generate_report,
    "finalize_run": _finalize_run,
}
assert tuple(NODE_HANDLERS) == NODE_SEQUENCE


# --- persistence helpers ------------------------------------------------------


def _is_stale(marker: dict[str, Any]) -> bool:
    """A step marker older than the run lease belongs to a process that died."""
    started = datetime.fromisoformat(marker["started_at"])
    return (_now() - started).total_seconds() > settings.analysis_stale_after_seconds


def _started_at(db: Session, workflow_id: uuid.UUID) -> str | None:
    state = db.scalar(select(AssessmentWorkflow.state).where(AssessmentWorkflow.id == workflow_id))
    db.rollback()
    return (state or {}).get("analysis_started_at")


def _patch_state(db: Session, workflow_id: uuid.UUID, updates: dict[str, Any]) -> None:
    db.rollback()
    db.expire_all()
    workflow = db.get(AssessmentWorkflow, workflow_id)
    assert workflow is not None
    workflow.state = {**workflow.state, **updates}
    workflow.updated_at = _now()
    db.commit()


def _append_event(
    db: Session,
    workflow_id: uuid.UUID,
    *,
    node: str,
    outcome: str,
    attempt: int,
    detail: dict[str, Any] | None,
    actor_user_id: uuid.UUID | None,
) -> None:
    sequence = (
        db.scalar(
            select(func.max(WorkflowEvent.sequence)).where(WorkflowEvent.workflow_id == workflow_id)
        )
        or 0
    ) + 1
    db.add(
        WorkflowEvent(
            workflow_id=workflow_id,
            sequence=sequence,
            node=node,
            outcome=outcome,
            attempt=attempt,
            detail=detail,
            actor_user_id=actor_user_id,
            occurred_at=_now(),
        )
    )


def _audit_finish(
    db: Session, workflow: AssessmentWorkflow, actor: uuid.UUID | None, status: WorkflowStatus
) -> None:
    record_audit_event(
        db,
        action=AuditAction.WORKFLOW_FINISHED,
        outcome=AuditOutcome.SUCCESS
        if status is WorkflowStatus.COMPLETED
        else AuditOutcome.FAILURE,
        resource_type=AuditResourceType.WORKFLOW,
        resource_id=workflow.id,
        assessment_id=workflow.assessment_id,
        actor_user_id=actor,
        context={
            "status": status.value,
            "error_code": workflow.error_code,
            "steps": workflow.step_count,
            "analysis_run_id": str(workflow.analysis_run_id) if workflow.analysis_run_id else None,
        },
    )


def _fail(db: Session, workflow: AssessmentWorkflow, code: str, actor: uuid.UUID | None) -> None:
    result = db.execute(
        update(AssessmentWorkflow)
        .where(
            AssessmentWorkflow.id == workflow.id,
            AssessmentWorkflow.status == WorkflowStatus.RUNNING,
            AssessmentWorkflow.step_count == workflow.step_count,
        )
        .values(
            status=WorkflowStatus.FAILED,
            error_code=code,
            completed_at=_now(),
            updated_at=_now(),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        return
    _append_event(
        db,
        workflow.id,
        node=workflow.current_node,
        outcome="failed",
        attempt=0,
        detail={"error_code": code},
        actor_user_id=actor,
    )
    db.flush()
    db.expire_all()
    refreshed = db.get(AssessmentWorkflow, workflow.id)
    assert refreshed is not None
    _audit_finish(db, refreshed, actor, WorkflowStatus.FAILED)
    db.commit()


# --- engine -------------------------------------------------------------------


def run_step_for_node(
    db: Session,
    workflow_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
    provider_factory: ProviderFactory,
) -> bool:
    """Execute the workflow's current node once.

    Returns ``True`` when the caller should run another step, and ``False`` when
    the workflow paused for approval, errored, failed, completed, or was moved
    away concurrently. This is the single unit of work shared by the built-in
    driver and the LangGraph driver (ADR-0017), so both enforce the identical
    budget, claim, persistence, approval, and audit guarantees.
    """
    db.expire_all()
    workflow = db.get(AssessmentWorkflow, workflow_id)
    if workflow is None:
        raise WorkflowNotFoundError
    if workflow.status is not WorkflowStatus.RUNNING:
        return False
    node = workflow.current_node
    attempts = dict(workflow.state.get("node_attempts", {}))
    attempt = attempts.get(node, 0) + 1
    if workflow.step_count >= settings.workflow_max_steps:
        _fail(db, workflow, "step_budget_exhausted", actor_user_id)
        return False
    if attempt > settings.workflow_max_node_attempts:
        _fail(db, workflow, "node_attempts_exhausted", actor_user_id)
        return False
    running = workflow.state.get("running_step")
    if running and not _is_stale(running):
        raise WorkflowStateError("a workflow step is already running")
    attempts[node] = attempt
    claimed_step = workflow.step_count + 1
    marker = {"node": node, "step": claimed_step, "started_at": _now().isoformat()}
    claim = db.execute(
        update(AssessmentWorkflow)
        .where(
            AssessmentWorkflow.id == workflow_id,
            AssessmentWorkflow.status == WorkflowStatus.RUNNING,
            AssessmentWorkflow.current_node == node,
            AssessmentWorkflow.step_count == workflow.step_count,
        )
        .values(
            step_count=claimed_step,
            state={**workflow.state, "node_attempts": attempts, "running_step": marker},
            updated_at=_now(),
        )
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        db.rollback()
        raise WorkflowStateError("workflow is being advanced concurrently")
    db.commit()

    ctx = NodeContext(
        db=db,
        workflow_id=workflow_id,
        assessment_id=workflow.assessment_id,
        options=dict(workflow.options),
        plan=workflow.plan,
        state={**workflow.state, "node_attempts": attempts},
        requested_by=workflow.requested_by_user_id,
        provider_factory=provider_factory,
    )
    try:
        result = NODE_HANDLERS[node](ctx)
    except Exception as exc:
        db.rollback()
        logger.warning("Workflow %s node %s raised %s", workflow_id, node, type(exc).__name__)
        result = NodeResult("error", error_code=f"{node}_error")
    if not _apply(db, workflow_id, node, claimed_step, attempt, result, actor_user_id):
        return False
    return result.outcome not in ("paused", "error", "failed")


def advance(
    db: Session,
    workflow_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
    provider_factory: ProviderFactory = build_provider,
) -> AssessmentWorkflow:
    """Run nodes until the workflow finishes, pauses for approval, or errors.

    Delegates to the configured orchestration engine (``WORKFLOW_ENGINE``).
    ``builtin`` loops in process; ``langgraph`` drives the same steps through a
    bounded LangGraph ``StateGraph`` (ADR-0017). Both call
    :func:`run_step_for_node`, so the security and persistence guarantees are
    identical and the engine is a drop-in choice.
    """
    if settings.workflow_engine == "langgraph":
        from app.services.workflow import langgraph_engine

        langgraph_engine.drive(
            db, workflow_id, actor_user_id=actor_user_id, provider_factory=provider_factory
        )
    else:
        for _ in range(settings.workflow_max_steps + 1):
            if not run_step_for_node(
                db,
                workflow_id,
                actor_user_id=actor_user_id,
                provider_factory=provider_factory,
            ):
                break
    db.expire_all()
    final = db.get(AssessmentWorkflow, workflow_id)
    assert final is not None
    return final


def _apply(
    db: Session,
    workflow_id: uuid.UUID,
    node: str,
    claimed_step: int,
    attempt: int,
    result: NodeResult,
    actor_user_id: uuid.UUID | None,
) -> bool:
    """Persist one node result, conditional on the claim still holding."""
    db.rollback()
    # A rollback outside a transaction expires nothing; always re-read the row.
    db.expire_all()
    workflow = db.get(AssessmentWorkflow, workflow_id)
    assert workflow is not None
    if workflow.status is not WorkflowStatus.RUNNING or workflow.step_count != claimed_step:
        # Cancelled (or otherwise changed) while the node ran: record, do not apply.
        _append_event(
            db,
            workflow_id,
            node=node,
            outcome="discarded",
            attempt=attempt,
            detail={"node_outcome": result.outcome, **result.detail},
            actor_user_id=actor_user_id,
        )
        db.commit()
        return False

    state = dict(workflow.state)
    state.pop("running_step", None)
    state.update(result.state_updates)
    if result.analysis_run_id is not None:
        state["analysis_run_id"] = str(result.analysis_run_id)
        workflow.analysis_run_id = result.analysis_run_id
    if result.plan is not None:
        workflow.plan = result.plan
    if result.outcome == "paused":
        attempts = dict(state.get("node_attempts", {}))
        attempts[node] = 0  # waiting for a person is not a failed attempt
        state["node_attempts"] = attempts
        workflow.status = WorkflowStatus.AWAITING_APPROVAL
    elif result.outcome in ("completed", "skipped"):
        following = next_node(node)
        if following is None:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = _now()
        else:
            workflow.current_node = following
    elif result.outcome == "failed":
        workflow.status = WorkflowStatus.FAILED
        workflow.error_code = result.error_code
        workflow.completed_at = _now()
    else:  # error: stays at this node for resume
        workflow.error_code = result.error_code
    if result.outcome in ("completed", "skipped") and workflow.status is WorkflowStatus.RUNNING:
        workflow.error_code = None
    workflow.state = state
    workflow.updated_at = _now()
    detail = dict(result.detail)
    if result.error_code:
        detail["error_code"] = result.error_code
    _append_event(
        db,
        workflow_id,
        node=node,
        outcome=result.outcome,
        attempt=attempt,
        detail=detail or None,
        actor_user_id=actor_user_id,
    )
    if workflow.status in (WorkflowStatus.COMPLETED, WorkflowStatus.FAILED):
        db.flush()
        _audit_finish(db, workflow, actor_user_id, workflow.status)
    db.commit()
    return True


def start_workflow(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
    explain_findings: bool = False,
    provider_factory: ProviderFactory = build_provider,
) -> AssessmentWorkflow:
    now = _now()
    workflow = AssessmentWorkflow(
        assessment_id=assessment_id,
        status=WorkflowStatus.RUNNING,
        graph_version=GRAPH_VERSION,
        current_node=NODE_SEQUENCE[0],
        step_count=0,
        options={"explain_findings": explain_findings},
        plan=None,
        state={"node_attempts": {}, "approvals": {}},
        requested_by_user_id=actor_user_id,
        created_at=now,
        updated_at=now,
    )
    db.add(workflow)
    try:
        db.flush()
        record_audit_event(
            db,
            action=AuditAction.WORKFLOW_STARTED,
            outcome=AuditOutcome.SUCCESS,
            resource_type=AuditResourceType.WORKFLOW,
            resource_id=workflow.id,
            assessment_id=assessment_id,
            actor_user_id=actor_user_id,
            occurred_at=now,
            context={"graph_version": GRAPH_VERSION, "options": workflow.options},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ActiveWorkflowError from exc
    return advance(db, workflow.id, actor_user_id=actor_user_id, provider_factory=provider_factory)


def get_workflow(
    db: Session, assessment_id: uuid.UUID, workflow_id: uuid.UUID
) -> AssessmentWorkflow:
    workflow = db.get(AssessmentWorkflow, workflow_id)
    if workflow is None or workflow.assessment_id != assessment_id:
        raise WorkflowNotFoundError
    return workflow


def record_approval(
    db: Session,
    assessment_id: uuid.UUID,
    workflow_id: uuid.UUID,
    *,
    check: str,
    approved: bool,
    reason: str,
    actor_user_id: uuid.UUID | None,
    provider_factory: ProviderFactory = build_provider,
) -> AssessmentWorkflow:
    """Record a human decision on a pending high-risk check, then continue."""
    workflow = get_workflow(db, assessment_id, workflow_id)
    if workflow.status is not WorkflowStatus.AWAITING_APPROVAL or workflow.plan is None:
        raise WorkflowStateError("workflow is not awaiting approval")
    approvals = dict(workflow.state.get("approvals", {}))
    if check not in pending_approvals(workflow.plan, approvals):
        raise InvalidApprovalError
    decision = "approved" if approved else "denied"
    now = _now()
    approvals[check] = {
        "decision": decision,
        "by": str(actor_user_id) if actor_user_id else None,
        "at": now.isoformat(),
        "reason": reason.strip()[:_MAX_REASON],
    }
    result = db.execute(
        update(AssessmentWorkflow)
        .where(
            AssessmentWorkflow.id == workflow_id,
            AssessmentWorkflow.status == WorkflowStatus.AWAITING_APPROVAL,
            AssessmentWorkflow.step_count == workflow.step_count,
        )
        .values(
            status=WorkflowStatus.RUNNING,
            state={**workflow.state, "approvals": approvals},
            updated_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise WorkflowStateError("workflow changed concurrently")
    _append_event(
        db,
        workflow_id,
        node="approval_gate",
        outcome="approval_recorded",
        attempt=0,
        detail={"check": check, "decision": decision},
        actor_user_id=actor_user_id,
    )
    record_audit_event(
        db,
        action=AuditAction.WORKFLOW_APPROVAL_RECORDED,
        outcome=AuditOutcome.SUCCESS,
        resource_type=AuditResourceType.WORKFLOW,
        resource_id=workflow_id,
        assessment_id=assessment_id,
        actor_user_id=actor_user_id,
        occurred_at=now,
        context={"check": check, "decision": decision},
    )
    db.commit()
    return advance(db, workflow_id, actor_user_id=actor_user_id, provider_factory=provider_factory)


def resume_workflow(
    db: Session,
    assessment_id: uuid.UUID,
    workflow_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
    provider_factory: ProviderFactory = build_provider,
) -> AssessmentWorkflow:
    workflow = get_workflow(db, assessment_id, workflow_id)
    if workflow.status is not WorkflowStatus.RUNNING:
        raise WorkflowStateError("only a running workflow can be resumed")
    return advance(db, workflow_id, actor_user_id=actor_user_id, provider_factory=provider_factory)


def cancel_workflow(
    db: Session,
    assessment_id: uuid.UUID,
    workflow_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
) -> AssessmentWorkflow:
    workflow = get_workflow(db, assessment_id, workflow_id)
    if workflow.status not in _ACTIVE:
        raise WorkflowStateError("workflow has already finished")
    run_id = workflow.analysis_run_id
    result = db.execute(
        update(AssessmentWorkflow)
        .where(AssessmentWorkflow.id == workflow_id, AssessmentWorkflow.status.in_(_ACTIVE))
        .values(
            status=WorkflowStatus.CANCELLED,
            error_code="cancelled",
            completed_at=_now(),
            updated_at=_now(),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise WorkflowStateError("workflow has already finished")
    _append_event(
        db,
        workflow_id,
        node=workflow.current_node,
        outcome="cancelled",
        attempt=0,
        detail=None,
        actor_user_id=actor_user_id,
    )
    db.flush()
    db.expire_all()
    refreshed = get_workflow(db, assessment_id, workflow_id)
    _audit_finish(db, refreshed, actor_user_id, WorkflowStatus.CANCELLED)
    db.commit()
    if run_id is None:
        run_id = db.scalar(
            select(AnalysisRun.id).where(
                AnalysisRun.assessment_id == assessment_id,
                AnalysisRun.status.in_((AnalysisRunStatus.QUEUED, AnalysisRunStatus.RUNNING)),
            )
        )
        db.rollback()
    if run_id is not None and workflow.current_node == "run_analysis":
        try:  # best effort: also stop the analysis the workflow started
            analysis_run_service.request_cancellation(
                db, assessment_id, run_id, actor_user_id=actor_user_id
            )
        except analysis_run_service.AnalysisRunAlreadyFinishedError:
            pass
    db.expire_all()
    return get_workflow(db, assessment_id, workflow_id)


def list_workflows(db: Session, assessment_id: uuid.UUID) -> list[AssessmentWorkflow]:
    return list(
        db.scalars(
            select(AssessmentWorkflow)
            .where(AssessmentWorkflow.assessment_id == assessment_id)
            .order_by(AssessmentWorkflow.created_at.desc(), AssessmentWorkflow.id.desc())
        )
    )


def list_events(db: Session, workflow_id: uuid.UUID) -> list[WorkflowEvent]:
    return list(
        db.scalars(
            select(WorkflowEvent)
            .where(WorkflowEvent.workflow_id == workflow_id)
            .order_by(WorkflowEvent.sequence)
        )
    )


__all__ = [
    "ActiveWorkflowError",
    "InvalidApprovalError",
    "NODE_HANDLERS",
    "WorkflowError",
    "WorkflowNotFoundError",
    "WorkflowStateError",
    "advance",
    "run_step_for_node",
    "cancel_workflow",
    "get_workflow",
    "list_events",
    "list_workflows",
    "record_approval",
    "resume_workflow",
    "start_workflow",
]
