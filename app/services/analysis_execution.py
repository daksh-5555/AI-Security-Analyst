"""Execute one assessment analysis and persist its findings and run state."""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.schemas.attack_surface_summary import AttackSurfaceSummaryResponse
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
)
from app.schemas.tooling import SafeErrorCode, ToolStatus
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionContext,
    AnalysisExecutionError,
)
from app.services.analysis_heartbeat import AnalysisHeartbeat, resolve_engine
from app.services.analysis_tools import (
    crawl_inventory,
    normalized_findings_from_outcome,
    run_supplementary_tools,
    run_web_tools,
    tool_metadata,
)
from app.services.attack_surface_reporting import (
    AssessmentAnalysisResults,
    RepositoryTargetNotFoundError,
    collect_assessment_analysis,
)
from app.services.audit import record_audit_event
from app.services.finding_normalization import static_normalized
from app.services.finding_policy import FindingGenerationResult, generate_findings
from app.services.findings import RetestSummary, add_normalized_findings
from app.services.repository_discovery import InvalidRepositoryRootError
from app.services.repository_targets import (
    AssessmentNotFoundError,
    InvalidRepositoryLocationError,
    get_repository_target,
    repository_roots_for_owner,
    repository_target_display_location,
    validate_repository_location,
)
from app.services.target_authorization import (
    TargetNotAuthorizedError,
    WebTargetNotFoundError,
    require_authorized_repository_target,
    require_authorized_web_target,
)
from app.services.tooling import PipelineOutcome
from app.services.tooling.adapters import STATIC_STAGE

logger = logging.getLogger(__name__)

_MAX_ERROR_MESSAGE_LENGTH: Final = 200
_MAX_METADATA_LIMITATIONS: Final = 50
_MAX_RUN_INSERT_ATTEMPTS: Final = 2
_FAILURE_MESSAGES: Final[dict[str, str]] = {
    "analysis": "Assessment analysis failed.",
    "finding_generation": "Finding generation failed.",
    "finding_persistence": "Finding persistence failed.",
    "completion": "Analysis run completion failed.",
    "deadline": "Analysis timed out.",
    "target_validation": "Analysis target is no longer valid or authorized.",
    "lease_expired": "Analysis run stopped responding and its lease expired.",
    "transient_retries_exhausted": "Analysis run failed after repeated transient errors.",
}
_ERROR_CODES: Final[dict[str, str]] = {
    "deadline": "deadline_exceeded",
    "lease_expired": "lease_expired",
    "transient_retries_exhausted": "transient_retries_exhausted",
    "target_validation": "target_validation_failed",
}
CANCELLED_MESSAGE: Final = "Analysis run was cancelled."
CANCELLED_ERROR_CODE: Final = "cancelled"
ACTIVE_STATUSES: Final = (AnalysisRunStatus.QUEUED, AnalysisRunStatus.RUNNING)


class ActiveAnalysisRunError(RuntimeError):
    """Raised when the assessment already has a QUEUED or RUNNING analysis run."""

    def __init__(self) -> None:
        super().__init__("Assessment analysis is already running")


class AnalysisRunStateConflictError(RuntimeError):
    """Raised when a terminal transition no longer targets a RUNNING run."""

    def __init__(self, run_id: uuid.UUID) -> None:
        super().__init__(f"Analysis run {run_id} is no longer RUNNING")


def validate_analysis_target(db: Session, assessment_id: uuid.UUID) -> bool:
    """Validate that the assessment has an authorized, still-valid target.

    Returns ``True`` for a web assessment. Called before a run is created and
    again by the worker immediately before a queued run executes, so a target
    revoked or moved while the run waited is never analysed.
    """
    assessment = db.get(AssessmentJob, assessment_id)
    if assessment is None:
        raise AssessmentNotFoundError
    if assessment.assessment_type is AssessmentType.WEB_SECURITY:
        # No run record is created without an authorized web target.
        require_authorized_web_target(db, assessment_id)
        return True

    target = get_repository_target(db, assessment_id)
    if target is None:
        raise RepositoryTargetNotFoundError
    # No run record is created for a target without an authorized record.
    require_authorized_repository_target(db, assessment_id, target)

    # Revalidate immediately before creating the run. Discovery validates
    # again just before traversal; this early check prevents a run record from
    # being created for a repository that was removed, replaced by a file, or
    # moved outside the configured allowed roots (or the owner's sub-root)
    # after registration.
    try:
        validate_repository_location(
            target.location,
            allowed_roots=repository_roots_for_owner(assessment.owner_id),
        )
    except InvalidRepositoryLocationError as exc:
        raise InvalidRepositoryRootError("Registered repository target is no longer valid") from exc
    return False


TARGET_VALIDATION_ERRORS: Final[tuple[type[Exception], ...]] = (
    RepositoryTargetNotFoundError,
    WebTargetNotFoundError,
    TargetNotAuthorizedError,
    InvalidRepositoryRootError,
)


def execute_assessment_analysis(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    clock: Callable[[], float] | None = None,
    excluded_stages: frozenset[str] = frozenset(),
) -> AnalysisRun:
    """Run one assessment analysis synchronously and persist its findings.

    ``excluded_stages`` can only narrow the configured tool set (used by the
    workflow engine for checks that were not approved); it never enables a
    stage that configuration disables.

    The RUNNING run and its start audit event are committed before the analysis
    pipeline starts because the pipeline rolls the session transaction back
    after repository discovery. Findings, the COMPLETED run state, and the
    completion audit event are committed together. A failure keeps the committed
    run record, removes any partial findings, and records a FAILED status and
    failure audit event atomically in a separate transaction.

    After the RUNNING row commits, a dedicated heartbeat thread renews its
    lease with an independent session. Cooperative deadline and abort checks
    stop pipeline work at stage boundaries. A deadline is recorded as a FAILED
    run with ``failure_stage="deadline"`` and the sanitized message
    ``Analysis timed out.``. A cancellation request is recorded as CANCELLED.

    At most one active (QUEUED or RUNNING) run per assessment is permitted. The
    database enforces this with a partial unique index; conflicts raise
    :class:`ActiveAnalysisRunError`.
    """
    is_web = validate_analysis_target(db, assessment_id)
    active_run_id = _find_active_run(db, assessment_id)
    # End the validation read transaction before inserting. Besides returning the
    # connection promptly, this avoids SQLite lock-upgrade deadlocks between two
    # concurrent insert attempts.
    db.rollback()
    if active_run_id is not None:
        raise ActiveAnalysisRunError

    run = _start_running_run(db, assessment_id, actor_user_id=actor_user_id)
    return _execute_run(
        db,
        run.id,
        assessment_id,
        is_web=is_web,
        actor_user_id=actor_user_id,
        clock=clock,
        lease_owner=None,
        excluded_stages=excluded_stages,
    )


def enqueue_assessment_analysis(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
) -> AnalysisRun:
    """Validate the target and commit a QUEUED run for the background worker.

    The queued run and its ``analysis_run.queued`` audit event commit together.
    The worker validates the target again when it claims the run.
    """
    validate_analysis_target(db, assessment_id)
    active_run_id = _find_active_run(db, assessment_id)
    db.rollback()
    if active_run_id is not None:
        raise ActiveAnalysisRunError
    return _insert_run(
        db,
        assessment_id,
        status=AnalysisRunStatus.QUEUED,
        audit_action=AuditAction.ANALYSIS_RUN_QUEUED,
        actor_user_id=actor_user_id,
    )


def execute_claimed_run(
    db: Session,
    run_id: uuid.UUID,
    *,
    lease_owner: str,
    clock: Callable[[], float] | None = None,
) -> AnalysisRun | None:
    """Execute a run the worker already claimed (RUNNING, leased to ``lease_owner``).

    The target is validated again first. A target that was revoked, removed, or
    moved while the run was queued fails the run permanently (no retry). Returns
    ``None`` when the run no longer exists.
    """
    row = db.execute(
        select(AnalysisRun.assessment_id, AnalysisRun.requested_by_user_id).where(
            AnalysisRun.id == run_id
        )
    ).first()
    if row is None:
        db.rollback()
        return None
    assessment_id, actor_user_id = row
    try:
        is_web = validate_analysis_target(db, assessment_id)
    except AssessmentNotFoundError:
        db.rollback()
        return None
    except TARGET_VALIDATION_ERRORS:
        db.rollback()
        logger.warning("Queued analysis run %s failed target revalidation", run_id)
        _mark_run_failed(
            db,
            run_id,
            "target_validation",
            actor_user_id=actor_user_id,
            lease_owner=lease_owner,
        )
        raise
    db.rollback()
    return _execute_run(
        db,
        run_id,
        assessment_id,
        is_web=is_web,
        actor_user_id=actor_user_id,
        clock=clock,
        lease_owner=lease_owner,
    )


def is_transient_failure(exc: BaseException) -> bool:
    """Database connectivity or lock errors that a later attempt may not hit."""
    return isinstance(exc, OperationalError)


def _summary_snapshot(results: AssessmentAnalysisResults) -> dict[str, Any] | None:
    """The API summary view of this run, stored for ``source=persisted`` reads.

    The snapshot is a convenience copy, not an authoritative result: if it
    cannot be built, the run still completes and simply stores no snapshot.
    """
    summary = results.summary
    try:
        return AttackSurfaceSummaryResponse(
            repository=repository_target_display_location(summary.root),
            routes=summary.routes,
            global_evidence=summary.global_evidence,
            issues=summary.issues,
            summary=summary.summary,
        ).model_dump(mode="json")
    except (AttributeError, TypeError, ValueError):
        logger.warning("Attack-surface summary snapshot could not be built; storing none")
        return None


def _execute_run(
    db: Session,
    run_id: uuid.UUID,
    assessment_id: uuid.UUID,
    *,
    is_web: bool,
    actor_user_id: uuid.UUID | None,
    clock: Callable[[], float] | None,
    lease_owner: str | None,
    excluded_stages: frozenset[str] = frozenset(),
) -> AnalysisRun:
    """Shared pipeline for synchronous and worker-claimed RUNNING runs.

    Every terminal transition is conditional on the run still being RUNNING
    and, for worker runs, on ``lease_owner`` still holding the lease. A worker
    whose lease was recovered by another worker therefore cannot complete,
    fail, or duplicate findings for the run.
    """
    stage = "analysis"
    results: AssessmentAnalysisResults | None = None
    generation: FindingGenerationResult | None = None
    heartbeat: AnalysisHeartbeat | None = None

    try:
        # The deadline starts only after the RUNNING row and start audit have
        # committed. The heartbeat also starts here, so it can never renew a
        # run whose start was not durably recorded.
        execution_context = AnalysisExecutionContext(
            settings.analysis_execution_timeout_seconds,
            clock=clock,
        )
        heartbeat = AnalysisHeartbeat(
            run_id=run_id,
            engine=resolve_engine(db),
            interval_seconds=settings.analysis_heartbeat_interval_seconds,
            abort_event=execution_context.abort_event,
            lease_owner=lease_owner,
            lease_seconds=settings.analysis_stale_after_seconds,
        )
        heartbeat.stage = stage
        heartbeat.start()

        execution_context.check()
        web_target_url: str | None = None
        if is_web:
            # Web assessments: registry tools (the crawler in M5) against the
            # authorized target through its host-bound guarded client.
            web_target_url, tool_outcome = run_web_tools(
                db,
                assessment_id,
                execution_context,
                analysis_run_id=run_id,
                excluded_stages=excluded_stages,
            )
        else:
            results = collect_assessment_analysis(
                db,
                assessment_id,
                execution_context=execution_context,
            )
            execution_context.check()
            # Registry-based tools (secret scanner, dependency audit) run over the
            # same validated inventory. Tool failures are contained and reported in
            # the metadata; cancellation or the run deadline still fails the run at
            # the next check below.
            heartbeat.stage = "tools"
            tool_outcome = run_supplementary_tools(
                results.discovery,
                execution_context,
                assessment_id=assessment_id,
                analysis_run_id=run_id,
                excluded_stages=excluded_stages,
            )

        stage = heartbeat.stage = "finding_generation"
        execution_context.check()
        if results is not None:
            generation = generate_findings(results.input_operation_flow)
        normalized = [
            *(static_normalized(generation, datetime.now(UTC)) if generation is not None else []),
            *normalized_findings_from_outcome(tool_outcome),
        ]
        completed_stages = {
            result.stage for result in tool_outcome.results if result.status is ToolStatus.COMPLETED
        }
        if results is not None and results.summary.summary.is_complete:
            completed_stages.add(STATIC_STAGE)

        stage = heartbeat.stage = "finding_persistence"
        execution_context.check()
        retest = add_normalized_findings(
            db,
            assessment_id,
            normalized,
            analysis_run_id=run_id,
            completed_stages=frozenset(completed_stages),
        )

        stage = heartbeat.stage = "completion"
        # Check immediately before claiming the terminal transition. Once the
        # conditional UPDATE succeeds, no later abort or deadline check runs,
        # so a timeout cannot produce both a completed and a failed event.
        execution_context.check()
        completed_at = datetime.now(UTC)
        if not _transition_run_if_running(
            db,
            run_id,
            status=AnalysisRunStatus.COMPLETED,
            completed_at=completed_at,
            error_message=None,
            analysis_metadata=(
                _build_analysis_metadata(
                    results,
                    generation,
                    tool_outcome=tool_outcome,
                    total_findings=retest.findings,
                    retest=retest,
                )
                if results is not None and generation is not None
                else _build_web_analysis_metadata(
                    web_target_url or "",
                    tool_outcome=tool_outcome,
                    total_findings=retest.findings,
                    retest=retest,
                )
            ),
            lease_owner=lease_owner,
            extra_values=(
                {"stage": "completed", "summary_snapshot": snapshot}
                if results is not None and (snapshot := _summary_snapshot(results)) is not None
                else {"stage": "completed"}
            ),
        ):
            raise AnalysisRunStateConflictError(run_id)
        record_audit_event(
            db,
            action=AuditAction.ANALYSIS_RUN_COMPLETED,
            outcome=AuditOutcome.SUCCESS,
            resource_type=AuditResourceType.ANALYSIS_RUN,
            resource_id=run_id,
            assessment_id=assessment_id,
            actor_user_id=actor_user_id,
            occurred_at=completed_at,
            context={"finding_count": retest.findings},
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        failure_stage = "deadline" if isinstance(exc, AnalysisDeadlineExceededError) else stage
        if isinstance(exc, AnalysisExecutionError):
            logger.warning(
                "Analysis execution stopped for assessment %s (run %s, stage %s): %s",
                assessment_id,
                run_id,
                stage,
                type(exc).__name__,
            )
        else:
            logger.exception(
                "Analysis execution failed for assessment %s (run %s, stage %s)",
                assessment_id,
                run_id,
                stage,
            )
        retryable = lease_owner is not None and is_transient_failure(exc)
        if retryable and _requeue_after_transient_failure(db, run_id, lease_owner=lease_owner):
            raise
        if retryable:
            failure_stage = "transient_retries_exhausted"
        _mark_run_failed(
            db,
            run_id,
            failure_stage,
            actor_user_id=actor_user_id,
            lease_owner=lease_owner,
        )
        raise
    finally:
        if heartbeat is not None:
            heartbeat.stop()

    # The completion transition bypasses the ORM identity map, so reload the
    # committed row before returning it to the caller.
    db.expire_all()
    persisted_run = db.get(AnalysisRun, run_id)
    if persisted_run is None:  # pragma: no cover - defensive
        raise RuntimeError("Analysis run disappeared after completion")
    return persisted_run


def _find_active_run(db: Session, assessment_id: uuid.UUID) -> uuid.UUID | None:
    """Return the identifier of an existing QUEUED or RUNNING run for the assessment."""
    return db.scalar(
        select(AnalysisRun.id)
        .where(
            AnalysisRun.assessment_id == assessment_id,
            AnalysisRun.status.in_(ACTIVE_STATUSES),
        )
        .limit(1)
    )


def _new_run(
    assessment_id: uuid.UUID,
    status: AnalysisRunStatus,
    actor_user_id: uuid.UUID | None,
) -> AnalysisRun:
    now = datetime.now(UTC)
    running = status is AnalysisRunStatus.RUNNING
    return AnalysisRun(
        assessment_id=assessment_id,
        status=status,
        created_at=now,
        # ``started_at`` is non-nullable in the existing API contract. A queued
        # run carries its creation time until a worker claims it and records the
        # real start time.
        started_at=now,
        heartbeat_at=now if running else None,
        lease_expires_at=(
            now + timedelta(seconds=settings.analysis_stale_after_seconds) if running else None
        ),
        stage="analysis" if running else "queued",
        attempts=1 if running else 0,
        requested_by_user_id=actor_user_id,
    )


def _new_running_run(assessment_id: uuid.UUID) -> AnalysisRun:
    return _new_run(assessment_id, AnalysisRunStatus.RUNNING, None)


def _start_running_run(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
) -> AnalysisRun:
    """Insert and commit a RUNNING run, translating unique conflicts."""
    return _insert_run(
        db,
        assessment_id,
        status=AnalysisRunStatus.RUNNING,
        audit_action=AuditAction.ANALYSIS_RUN_STARTED,
        actor_user_id=actor_user_id,
    )


def _insert_run(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    status: AnalysisRunStatus,
    audit_action: AuditAction,
    actor_user_id: uuid.UUID | None,
) -> AnalysisRun:
    """Insert and commit a QUEUED or RUNNING run, translating unique conflicts.

    The audit event is committed with the run row, so an execution cannot start
    without an attributable record. The insert may fail because another request
    won the database race. The conflict is classified by re-querying for an
    active run rather than parsing driver error text. If the conflicting run
    finished in the meantime, a single bounded retry distinguishes that
    transient case from a non-conflict integrity error.
    """
    for attempt in range(_MAX_RUN_INSERT_ATTEMPTS):
        run = _new_run(assessment_id, status, actor_user_id)
        db.add(run)
        try:
            db.flush()
            record_audit_event(
                db,
                action=audit_action,
                outcome=AuditOutcome.SUCCESS,
                resource_type=AuditResourceType.ANALYSIS_RUN,
                resource_id=run.id,
                assessment_id=assessment_id,
                actor_user_id=actor_user_id,
                occurred_at=run.created_at,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if _find_active_run(db, assessment_id) is not None:
                raise ActiveAnalysisRunError from exc
            db.rollback()
            if attempt + 1 == _MAX_RUN_INSERT_ATTEMPTS:
                raise
        except Exception:
            db.rollback()
            raise
        else:
            return run

    raise AssertionError("unreachable")


def _transition_run_if_running(
    db: Session,
    run_id: uuid.UUID,
    *,
    status: AnalysisRunStatus,
    completed_at: datetime,
    error_message: str | None,
    analysis_metadata: dict[str, Any] | None,
    lease_owner: str | None = None,
    extra_values: dict[str, Any] | None = None,
    extra_conditions: tuple[Any, ...] = (),
) -> bool:
    """Atomically move a RUNNING run to a terminal state.

    This is the only terminal-transition statement; completion, failure,
    cancellation, and recovery all go through it.

    The status predicate is part of the UPDATE, so concurrent completion and
    failure handlers cannot both claim the same run. When ``lease_owner`` is
    given, the predicate also requires that worker to still hold the lease.
    Returns ``True`` only when exactly one row transitioned; callers must not
    write a terminal audit event otherwise.
    """
    conditions = [
        AnalysisRun.id == run_id,
        AnalysisRun.status == AnalysisRunStatus.RUNNING,
        *extra_conditions,
    ]
    if lease_owner is not None:
        conditions.append(AnalysisRun.lease_owner == lease_owner)
    result = db.execute(
        update(AnalysisRun)
        .where(*conditions)
        .values(
            status=status,
            completed_at=completed_at,
            error_message=error_message,
            analysis_metadata=analysis_metadata,
            lease_expires_at=None,
            **(extra_values or {}),
        )
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _requeue_after_transient_failure(
    db: Session,
    run_id: uuid.UUID,
    *,
    lease_owner: str,
) -> bool:
    """Return a worker run to QUEUED when retry attempts remain.

    Conditional on the run still being RUNNING under this lease. Returns
    ``False`` (so the caller records a terminal failure) when attempts are
    exhausted, cancellation was requested, or the update itself fails.
    """
    try:
        with Session(bind=db.get_bind(), expire_on_commit=False) as recovery:
            result = recovery.execute(
                update(AnalysisRun)
                .where(
                    AnalysisRun.id == run_id,
                    AnalysisRun.status == AnalysisRunStatus.RUNNING,
                    AnalysisRun.lease_owner == lease_owner,
                    AnalysisRun.cancel_requested_at.is_(None),
                    AnalysisRun.attempts < settings.analysis_worker_max_attempts,
                )
                .values(
                    status=AnalysisRunStatus.QUEUED,
                    lease_owner=None,
                    lease_expires_at=None,
                    stage="queued",
                    error_code="transient_retry",
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                recovery.rollback()
                return False
            recovery.commit()
    except Exception:
        logger.exception("Failed to requeue analysis run %s", run_id)
        return False
    logger.warning("Analysis run %s requeued after a transient failure", run_id)
    return True


def _mark_run_failed(
    db: Session,
    run_id: uuid.UUID,
    stage: str,
    *,
    actor_user_id: uuid.UUID | None,
    lease_owner: str | None = None,
) -> None:
    """Best-effort terminal-state persistence in an independent transaction.

    A fresh session bound to the same engine is used so a poisoned or closed
    transaction on the original session cannot prevent the status update. The
    terminal state and its audit event are committed atomically: if the audit
    insert fails, the status update is rolled back too and the run remains
    RUNNING rather than reaching a terminal state without an audit record. The
    transition is conditional on the run still being RUNNING (and, for worker
    runs, still leased to ``lease_owner``), so repeated or concurrent calls
    cannot overwrite a terminal run or duplicate a terminal audit event.

    A run whose cancellation was requested ends CANCELLED with an
    ``analysis_run.cancelled`` event instead of FAILED. A single attempt is
    made; failures are logged and never replace the original execution
    exception.
    """
    try:
        bind = db.get_bind()
    except Exception:
        logger.exception("Unable to resolve a database bind for analysis run %s", run_id)
        return

    try:
        with Session(bind=bind, expire_on_commit=False) as recovery:
            finish_run_unsuccessfully(
                recovery,
                run_id,
                stage,
                actor_user_id=actor_user_id,
                lease_owner=lease_owner,
            )
            recovery.commit()
    except Exception:
        logger.exception(
            "Failed to mark analysis run %s as FAILED; it may remain RUNNING",
            run_id,
        )


def finish_run_unsuccessfully(
    db: Session,
    run_id: uuid.UUID,
    stage: str,
    *,
    actor_user_id: uuid.UUID | None,
    lease_owner: str | None = None,
    extra_conditions: tuple[Any, ...] = (),
) -> AnalysisRunStatus | None:
    """Conditionally move a RUNNING run to FAILED or CANCELLED with its audit event.

    The caller owns the transaction (commit or rollback). Returns the terminal
    status written, or ``None`` when the run was not RUNNING (or no longer
    matched the lease and extra conditions), in which case nothing is written.
    """
    cancel_requested = db.scalar(
        select(AnalysisRun.cancel_requested_at).where(AnalysisRun.id == run_id)
    )
    cancelled = cancel_requested is not None
    status = AnalysisRunStatus.CANCELLED if cancelled else AnalysisRunStatus.FAILED
    completed_at = datetime.now(UTC)
    transitioned = _transition_run_if_running(
        db,
        run_id,
        status=status,
        completed_at=completed_at,
        error_message=CANCELLED_MESSAGE if cancelled else _failure_message(stage),
        analysis_metadata={"failure_stage": stage},
        lease_owner=lease_owner,
        extra_values={
            "error_code": CANCELLED_ERROR_CODE if cancelled else _error_code(stage),
            "stage": status.value,
        },
        extra_conditions=extra_conditions,
    )
    if not transitioned:
        db.rollback()
        logger.warning(
            "Analysis run %s is no longer RUNNING; not recording another terminal state",
            run_id,
        )
        return None

    # The row is locked by the successful conditional UPDATE, so this read
    # observes the same run that was just transitioned.
    assessment_id = db.scalar(select(AnalysisRun.assessment_id).where(AnalysisRun.id == run_id))
    if assessment_id is None:  # pragma: no cover - defensive
        db.rollback()
        logger.warning("Analysis run %s disappeared after its terminal transition", run_id)
        return None

    record_audit_event(
        db,
        action=(
            AuditAction.ANALYSIS_RUN_CANCELLED if cancelled else AuditAction.ANALYSIS_RUN_FAILED
        ),
        outcome=AuditOutcome.SUCCESS if cancelled else AuditOutcome.FAILURE,
        resource_type=AuditResourceType.ANALYSIS_RUN,
        resource_id=run_id,
        assessment_id=assessment_id,
        actor_user_id=actor_user_id,
        occurred_at=completed_at,
        context={"failure_stage": stage},
    )
    return status


def _error_code(stage: str) -> str:
    return _ERROR_CODES.get(stage, f"{stage}_failed")[:64]


def _failure_message(stage: str) -> str:
    message = _FAILURE_MESSAGES.get(stage, "Assessment analysis failed.")
    return message[:_MAX_ERROR_MESSAGE_LENGTH]


def _incomplete_tools(tool_outcome: PipelineOutcome) -> list[str]:
    # A tool with nothing to analyse (``skipped``/``not_applicable``) does not
    # make the run incomplete. Disabled, failed, cancelled, and partial tools do.
    return [
        result.stage
        for result in tool_outcome.results
        if result.status is not ToolStatus.COMPLETED
        and not (
            result.status is ToolStatus.SKIPPED
            and result.error_code is SafeErrorCode.NOT_APPLICABLE
        )
    ]


def _build_web_analysis_metadata(
    target_url: str,
    *,
    tool_outcome: PipelineOutcome,
    total_findings: int,
    retest: RetestSummary,
) -> dict[str, Any]:
    incomplete = _incomplete_tools(tool_outcome)
    return {
        "analyzer": {"name": settings.app_name, "version": settings.app_version},
        "target": {"type": "web_application", "url": target_url},
        "finding_count": total_findings,
        "completeness": {
            "is_complete": not incomplete,
            "tools_are_complete": not incomplete,
            "incomplete_tools": incomplete,
        },
        "tools": tool_metadata(tool_outcome),
        "crawl_inventory": crawl_inventory(tool_outcome),
        "retest": retest.as_metadata(),
    }


def _build_analysis_metadata(
    results: AssessmentAnalysisResults,
    generation: FindingGenerationResult,
    *,
    tool_outcome: PipelineOutcome,
    total_findings: int,
    retest: RetestSummary,
) -> dict[str, Any]:
    summary = results.summary.summary
    limitations = list(generation.limitations)
    stored_limitations = limitations[:_MAX_METADATA_LIMITATIONS]
    incomplete_tools = _incomplete_tools(tool_outcome)
    tools_complete = not incomplete_tools

    return {
        "analyzer": {
            "name": settings.app_name,
            "version": settings.app_version,
        },
        "finding_count": total_findings,
        "analysis_issue_count": summary.issue_count,
        "completeness": {
            # A run is complete only when the static pipeline and every registered
            # tool completed; a failed, skipped, or partial tool is never "clean".
            "is_complete": summary.is_complete and tools_complete,
            "static_analysis_is_complete": summary.is_complete,
            "tools_are_complete": tools_complete,
            "incomplete_tools": incomplete_tools,
            "all_sources_complete": summary.all_sources_complete,
            "discovery_is_complete": summary.discovery_is_complete,
            "route_analysis_is_complete": summary.route_analysis_is_complete,
        },
        "truncation": {
            "discovery_reasons": [reason.value for reason in summary.discovery_truncation_reasons],
            "route_analysis_reasons": [
                reason.value for reason in summary.route_analysis_truncation_reasons
            ],
        },
        "sources": [
            {
                "source": status.source.value,
                "is_complete": status.is_complete,
                "discovery_is_complete": status.discovery_is_complete,
                "route_analysis_is_complete": status.route_analysis_is_complete,
                "issue_count": status.issue_count,
                "discovery_truncation_reasons": [
                    reason.value for reason in status.discovery_truncation_reasons
                ],
                "route_analysis_truncation_reasons": [
                    reason.value for reason in status.route_analysis_truncation_reasons
                ],
            }
            for status in summary.source_statuses
        ],
        "tools": tool_metadata(tool_outcome),
        "retest": retest.as_metadata(),
        "finding_policy": {
            "eligible_relationship_count": generation.eligible_relationship_count,
            "generated_finding_count": len(generation.findings),
            "skipped_relationship_count": generation.skipped_relationship_count,
            "limitations": stored_limitations,
            "limitations_truncated": len(limitations) > len(stored_limitations),
        },
    }


__all__ = [
    "ACTIVE_STATUSES",
    "ActiveAnalysisRunError",
    "AnalysisRunStateConflictError",
    "TARGET_VALIDATION_ERRORS",
    "enqueue_assessment_analysis",
    "execute_assessment_analysis",
    "execute_claimed_run",
    "validate_analysis_target",
    "finish_run_unsuccessfully",
    "is_transient_failure",
]
