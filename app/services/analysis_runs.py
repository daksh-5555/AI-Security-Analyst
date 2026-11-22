"""Access to persisted analysis runs, their finding counts, and cancellation."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.schemas.enums import (
    AnalysisRunStatus,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
)
from app.services.audit import record_audit_event

AnalysisRunRow = tuple[AnalysisRun, int]


def _finding_count_query():
    return (
        select(func.count(AssessmentFinding.id))
        .where(AssessmentFinding.analysis_run_id == AnalysisRun.id)
        .correlate(AnalysisRun)
        .scalar_subquery()
    )


def list_assessment_analysis_runs(
    db: Session,
    assessment_id: uuid.UUID,
) -> list[AnalysisRunRow] | None:
    """Return assessment runs newest first, or None if the assessment is unknown."""
    if db.get(AssessmentJob, assessment_id) is None:
        return None

    statement = (
        select(AnalysisRun, _finding_count_query().label("findings_count"))
        .where(AnalysisRun.assessment_id == assessment_id)
        .order_by(AnalysisRun.created_at.desc(), AnalysisRun.id.desc())
    )
    return [(row[0], row[1]) for row in db.execute(statement).all()]


def get_assessment_analysis_run(
    db: Session,
    assessment_id: uuid.UUID,
    run_id: uuid.UUID,
) -> AnalysisRunRow | None:
    """Return one run owned by the assessment, or None when it does not match."""
    statement = select(AnalysisRun, _finding_count_query().label("findings_count")).where(
        AnalysisRun.id == run_id,
        AnalysisRun.assessment_id == assessment_id,
    )
    row = db.execute(statement).first()
    return None if row is None else (row[0], row[1])


def count_analysis_run_findings(db: Session, run_id: uuid.UUID) -> int:
    """Return the number of findings associated with one run."""
    count = db.scalar(
        select(func.count(AssessmentFinding.id)).where(AssessmentFinding.analysis_run_id == run_id)
    )
    return count or 0


class AnalysisRunAlreadyFinishedError(RuntimeError):
    """Raised when cancellation targets a run that is no longer queued or running."""


CANCELLED_MESSAGE = "Analysis run was cancelled."


def request_cancellation(
    db: Session,
    assessment_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
) -> AnalysisRunRow | None:
    """Cancel a QUEUED run immediately, or request cancellation of a RUNNING run.

    A queued run becomes CANCELLED in one conditional UPDATE committed with its
    ``analysis_run.cancelled`` audit event. A running run only has
    ``cancel_requested_at`` set: its heartbeat stops renewing, the pipeline
    aborts at the next stage boundary, and the executing process records the
    CANCELLED state and audit event (or the recovery sweep does, if that process
    is gone). Repeating the request for a running run is harmless. Returns ``None`` for an unknown
    run; raises :class:`AnalysisRunAlreadyFinishedError` for a terminal run.
    """
    now = datetime.now(UTC)
    owned = (AnalysisRun.id == run_id, AnalysisRun.assessment_id == assessment_id)
    queued = db.execute(
        update(AnalysisRun)
        .where(*owned, AnalysisRun.status == AnalysisRunStatus.QUEUED)
        .values(
            status=AnalysisRunStatus.CANCELLED,
            completed_at=now,
            cancel_requested_at=now,
            cancel_requested_by_user_id=actor_user_id,
            error_message=CANCELLED_MESSAGE,
            error_code="cancelled",
            stage="cancelled",
        )
        .execution_options(synchronize_session=False)
    )
    if queued.rowcount == 1:
        record_audit_event(
            db,
            action=AuditAction.ANALYSIS_RUN_CANCELLED,
            outcome=AuditOutcome.SUCCESS,
            resource_type=AuditResourceType.ANALYSIS_RUN,
            resource_id=run_id,
            assessment_id=assessment_id,
            actor_user_id=actor_user_id,
            occurred_at=now,
            context={"from_status": "queued"},
        )
    else:
        db.execute(
            update(AnalysisRun)
            .where(
                *owned,
                AnalysisRun.status == AnalysisRunStatus.RUNNING,
                AnalysisRun.cancel_requested_at.is_(None),
            )
            .values(cancel_requested_at=now, cancel_requested_by_user_id=actor_user_id)
            .execution_options(synchronize_session=False)
        )
    db.commit()
    db.expire_all()
    row = get_assessment_analysis_run(db, assessment_id, run_id)
    if row is None:
        return None
    if queued.rowcount != 1 and row[0].status is not AnalysisRunStatus.RUNNING:
        raise AnalysisRunAlreadyFinishedError
    return row


def count_active_runs_for_user(
    db: Session,
    user_id: uuid.UUID,
    *,
    exclude_assessment_id: uuid.UUID | None = None,
) -> int:
    """Durable count of the user's QUEUED and RUNNING runs (all processes).

    Runs of ``exclude_assessment_id`` are left out, so a duplicate request for
    an assessment that already has an active run gets the clearer 409 conflict
    rather than a quota rejection.
    """
    conditions = [
        AnalysisRun.requested_by_user_id == user_id,
        AnalysisRun.status.in_((AnalysisRunStatus.QUEUED, AnalysisRunStatus.RUNNING)),
    ]
    if exclude_assessment_id is not None:
        conditions.append(AnalysisRun.assessment_id != exclude_assessment_id)
    return db.scalar(select(func.count(AnalysisRun.id)).where(*conditions)) or 0


def latest_summary_snapshot(db: Session, assessment_id: uuid.UUID) -> dict[str, Any] | None:
    """Summary stored by the newest COMPLETED run that has one."""
    return db.scalar(
        select(AnalysisRun.summary_snapshot)
        .where(
            AnalysisRun.assessment_id == assessment_id,
            AnalysisRun.status == AnalysisRunStatus.COMPLETED,
            AnalysisRun.summary_snapshot.is_not(None),
        )
        .order_by(AnalysisRun.completed_at.desc(), AnalysisRun.id.desc())
        .limit(1)
    )
