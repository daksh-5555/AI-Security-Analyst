import uuid
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.assessment import AssessmentJob
from app.models.assessment_status_history import AssessmentStatusHistory
from app.schemas.enums import (
    AssessmentStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
)
from app.services.audit import record_audit_event, record_audit_event_safely

ALLOWED_STATUS_TRANSITIONS: Final[dict[AssessmentStatus, frozenset[AssessmentStatus]]] = {
    AssessmentStatus.QUEUED: frozenset({AssessmentStatus.RUNNING}),
    AssessmentStatus.RUNNING: frozenset({AssessmentStatus.COMPLETED, AssessmentStatus.FAILED}),
    AssessmentStatus.COMPLETED: frozenset(),
    AssessmentStatus.FAILED: frozenset(),
}


class InvalidStatusTransitionError(ValueError):
    """Raised when an assessment status transition is not allowed."""

    def __init__(
        self,
        current_status: AssessmentStatus,
        requested_status: AssessmentStatus,
    ) -> None:
        self.current_status = current_status
        self.requested_status = requested_status
        super().__init__(
            f"Invalid status transition from '{current_status.value}' to '{requested_status.value}'"
        )


def can_transition_status(
    current_status: AssessmentStatus,
    requested_status: AssessmentStatus,
) -> bool:
    return requested_status in ALLOWED_STATUS_TRANSITIONS.get(
        current_status,
        frozenset(),
    )


def create_assessment(
    db: Session,
    assessment_type: AssessmentType,
    *,
    owner_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> AssessmentJob:
    """Create a queued assessment and its creation audit event atomically.

    ``owner_id`` must come from an authenticated principal. Legacy records may
    retain a null owner; this helper does not backfill ownership. The audit row
    is written in the same transaction, so a forced audit failure rolls the
    assessment back rather than producing an unaudited mutation.
    """
    now = datetime.now(UTC)
    assessment = AssessmentJob(
        owner_id=owner_id,
        assessment_type=assessment_type,
        status=AssessmentStatus.QUEUED,
        created_at=now,
        updated_at=now,
    )
    db.add(assessment)
    try:
        db.flush()
        record_audit_event(
            db,
            action=AuditAction.ASSESSMENT_CREATED,
            outcome=AuditOutcome.SUCCESS,
            resource_type=AuditResourceType.ASSESSMENT,
            resource_id=assessment.id,
            assessment_id=assessment.id,
            actor_user_id=actor_user_id,
            occurred_at=now,
            context={"assessment_type": assessment_type.value},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return assessment


def _record_status_change(
    db: Session,
    assessment: AssessmentJob,
    new_status: AssessmentStatus,
    reason: str | None = None,
    *,
    actor_user_id: uuid.UUID | None = None,
) -> AssessmentStatusHistory:
    """Apply a status transition and flush it without owning the transaction.

    Internal implementation detail. Production code must use
    :func:`apply_status_change`, which performs the atomic conditional claim
    before calling this helper. This function validates the transition and
    stages the status, history, and success audit rows in one transaction, but
    it does not claim the row against concurrent writers.
    """
    previous_status = assessment.status
    if not can_transition_status(previous_status, new_status):
        raise InvalidStatusTransitionError(previous_status, new_status)

    changed_at = datetime.now(UTC)
    assessment.status = new_status
    assessment.updated_at = changed_at
    history = AssessmentStatusHistory(
        assessment_id=assessment.id,
        previous_status=previous_status,
        new_status=new_status,
        changed_at=changed_at,
        reason=reason,
    )
    db.add(history)
    record_audit_event(
        db,
        action=AuditAction.ASSESSMENT_LIFECYCLE_CHANGED,
        outcome=AuditOutcome.SUCCESS,
        resource_type=AuditResourceType.ASSESSMENT,
        resource_id=assessment.id,
        assessment_id=assessment.id,
        actor_user_id=actor_user_id,
        occurred_at=changed_at,
        context={
            "previous_status": previous_status.value,
            "new_status": new_status.value,
        },
    )
    db.flush()
    return history


def _claim_status_transition(
    db: Session,
    assessment_id: uuid.UUID,
    expected_status: AssessmentStatus,
) -> bool:
    """Atomically confirm the row is still in ``expected_status``.

    Two concurrent transitions can both read the same previous status. The
    conditional UPDATE turns the second attempt into a zero-row result instead
    of allowing duplicate history or a misleading audit record.
    """
    result = db.execute(
        update(AssessmentJob)
        .where(
            AssessmentJob.id == assessment_id,
            AssessmentJob.status == expected_status,
        )
        .values(status=expected_status)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _record_lifecycle_denial(
    db: Session,
    assessment_id: uuid.UUID | None,
    *,
    previous_status: AssessmentStatus,
    requested_status: AssessmentStatus,
    actor_user_id: uuid.UUID | None,
) -> None:
    record_audit_event_safely(
        db,
        action=AuditAction.ASSESSMENT_LIFECYCLE_DENIED,
        outcome=AuditOutcome.DENIED,
        resource_type=AuditResourceType.ASSESSMENT,
        resource_id=assessment_id,
        # The request is rejected, so do not establish a foreign-key link that
        # would imply the transition succeeded against this assessment row.
        assessment_id=None,
        actor_user_id=actor_user_id,
        context={
            "previous_status": previous_status.value,
            "requested_status": requested_status.value,
        },
    )


def apply_status_change(
    db: Session,
    assessment: AssessmentJob,
    new_status: AssessmentStatus,
    reason: str | None = None,
    *,
    actor_user_id: uuid.UUID | None = None,
) -> AssessmentJob:
    """Apply and commit one authorized transition through the only write path.

    Invalid and lost-update attempts are rejected before the assessment row is
    mutated. Rejected attempts are recorded separately because the business
    transaction is rolled back.
    """
    previous_status = assessment.status
    if not can_transition_status(previous_status, new_status):
        _record_lifecycle_denial(
            db,
            assessment.id,
            previous_status=previous_status,
            requested_status=new_status,
            actor_user_id=actor_user_id,
        )
        raise InvalidStatusTransitionError(previous_status, new_status)

    if not _claim_status_transition(db, assessment.id, previous_status):
        db.rollback()
        current = db.get(AssessmentJob, assessment.id)
        current_status = current.status if current is not None else previous_status
        _record_lifecycle_denial(
            db,
            assessment.id,
            previous_status=current_status,
            requested_status=new_status,
            actor_user_id=actor_user_id,
        )
        raise InvalidStatusTransitionError(current_status, new_status)

    try:
        _record_status_change(
            db,
            assessment,
            new_status,
            reason,
            actor_user_id=actor_user_id,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return assessment


def list_status_history(
    db: Session,
    assessment_id: uuid.UUID,
) -> list[AssessmentStatusHistory] | None:
    if db.get(AssessmentJob, assessment_id) is None:
        return None

    statement = (
        select(AssessmentStatusHistory)
        .where(AssessmentStatusHistory.assessment_id == assessment_id)
        .order_by(
            AssessmentStatusHistory.changed_at.asc(),
            AssessmentStatusHistory.id.asc(),
        )
    )
    return list(db.scalars(statement).all())
