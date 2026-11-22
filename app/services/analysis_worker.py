"""Durable background execution of queued analysis runs (M8, ADR-0011).

A worker process repeatedly:

1. recovers stale RUNNING runs whose lease expired (the executing process
   crashed, was killed, or lost its database connection);
2. atomically claims the oldest QUEUED run, subject to a deployment-wide cap
   on worker-claimed RUNNING runs;
3. executes it through the same pipeline as synchronous runs, with a
   heartbeat that extends the lease and records progress.

Every state change is a conditional UPDATE, so two workers can never claim the
same run, a worker whose lease was recovered cannot complete or fail the run,
and findings are written only inside the single completion transaction (a
crashed attempt leaves no findings behind, and a retry cannot duplicate them).
"""

from __future__ import annotations

import logging
import os
import platform
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, aliased

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.schemas.enums import (
    AnalysisRunStatus,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
)
from app.services.analysis_execution import (
    execute_claimed_run,
    finish_run_unsuccessfully,
)
from app.services.audit import record_audit_event

logger = logging.getLogger(__name__)

_MAX_RECOVERY_BATCH: Final = 100
# Arbitrary constant identifying the claim lock (PostgreSQL advisory locks).
CLAIM_ADVISORY_LOCK_KEY: Final = 4706981573


def new_worker_id() -> str:
    """A lease-owner identifier unique to this worker process instance."""
    host = platform.node()[:100] or "host"
    return f"{host}:{os.getpid()}:{uuid.uuid4().hex[:12]}"


def claim_next_run(
    engine: Engine,
    worker_id: str,
    *,
    now: datetime | None = None,
) -> uuid.UUID | None:
    """Claim the oldest QUEUED run, or return ``None``.

    The claim is one conditional UPDATE: the row must still be QUEUED and the
    number of worker-claimed RUNNING runs must be below
    ``ANALYSIS_WORKER_MAX_RUNNING``. The start audit event commits in the same
    transaction.

    - SQLite serializes writes, so the cap is exact.
    - PostgreSQL (M13) first takes a transaction-scoped advisory lock, so the
      cap check and the claim are serialized across workers, and it selects the
      candidate with ``FOR UPDATE SKIP LOCKED``. The cap is exact there too, and
      a worker never waits on a row another worker is claiming.
    """
    current = now or datetime.now(UTC)
    postgres = engine.dialect.name == "postgresql"
    with Session(bind=engine, expire_on_commit=False) as session:
        query = (
            select(AnalysisRun.id, AnalysisRun.assessment_id, AnalysisRun.requested_by_user_id)
            .where(AnalysisRun.status == AnalysisRunStatus.QUEUED)
            .order_by(AnalysisRun.created_at, AnalysisRun.id)
            .limit(1)
        )
        if postgres:
            session.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": CLAIM_ADVISORY_LOCK_KEY}
            )
            query = query.with_for_update(skip_locked=True, of=AnalysisRun)
        candidate = session.execute(query).first()
        if not postgres:
            # SQLite: end the read transaction before the write (lock upgrade).
            session.rollback()
        if candidate is None:
            session.rollback()
            return None
        run_id, assessment_id, requested_by = candidate

        other = aliased(AnalysisRun)
        running = (
            select(func.count(other.id))
            .where(other.status == AnalysisRunStatus.RUNNING, other.lease_owner.is_not(None))
            .scalar_subquery()
        )
        result = session.execute(
            update(AnalysisRun)
            .where(
                AnalysisRun.id == run_id,
                AnalysisRun.status == AnalysisRunStatus.QUEUED,
                running < settings.analysis_worker_max_running,
            )
            .values(
                status=AnalysisRunStatus.RUNNING,
                lease_owner=worker_id,
                lease_expires_at=current + timedelta(seconds=settings.analysis_stale_after_seconds),
                started_at=current,
                heartbeat_at=current,
                stage="claimed",
                attempts=AnalysisRun.attempts + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            session.rollback()
            return None
        attempt = session.scalar(select(AnalysisRun.attempts).where(AnalysisRun.id == run_id))
        record_audit_event(
            session,
            action=AuditAction.ANALYSIS_RUN_STARTED,
            outcome=AuditOutcome.SUCCESS,
            resource_type=AuditResourceType.ANALYSIS_RUN,
            resource_id=run_id,
            assessment_id=assessment_id,
            actor_user_id=requested_by,
            occurred_at=current,
            context={"attempt": attempt, "mode": "async"},
        )
        session.commit()
        return run_id


@dataclass
class RecoverySummary:
    requeued: list[uuid.UUID] = field(default_factory=list)
    failed: list[uuid.UUID] = field(default_factory=list)
    cancelled: list[uuid.UUID] = field(default_factory=list)


def _stale_condition(now: datetime):  # noqa: ANN202 - SQLAlchemy expression
    stale_before = now - timedelta(seconds=settings.analysis_stale_after_seconds)
    return or_(
        AnalysisRun.lease_expires_at < now,
        and_(
            AnalysisRun.lease_expires_at.is_(None),
            func.coalesce(AnalysisRun.heartbeat_at, AnalysisRun.started_at) < stale_before,
        ),
    )


def recover_stale_runs(engine: Engine, *, now: datetime | None = None) -> RecoverySummary:
    """Recover RUNNING runs whose lease expired.

    - cancellation requested: CANCELLED (``analysis_run.cancelled``);
    - worker run with attempts remaining: requeued for another worker;
    - otherwise (synchronous run, or attempts exhausted): FAILED with error
      code ``lease_expired``.

    Each transition repeats the staleness predicate, so a run whose heartbeat
    renewed in the meantime is left alone.
    """
    current = now or datetime.now(UTC)
    summary = RecoverySummary()
    with Session(bind=engine, expire_on_commit=False) as session:
        stale = session.execute(
            select(
                AnalysisRun.id,
                AnalysisRun.lease_owner,
                AnalysisRun.attempts,
                AnalysisRun.cancel_requested_at,
                AnalysisRun.requested_by_user_id,
            )
            .where(AnalysisRun.status == AnalysisRunStatus.RUNNING, _stale_condition(current))
            .order_by(AnalysisRun.created_at)
            .limit(_MAX_RECOVERY_BATCH)
        ).all()
        session.rollback()

        for run_id, owner, attempts, cancel_requested_at, requested_by in stale:
            still_stale = (_stale_condition(current),)
            if (
                cancel_requested_at is None
                and owner is not None
                and attempts < settings.analysis_worker_max_attempts
            ):
                result = session.execute(
                    update(AnalysisRun)
                    .where(
                        AnalysisRun.id == run_id,
                        AnalysisRun.status == AnalysisRunStatus.RUNNING,
                        AnalysisRun.lease_owner == owner,
                        *still_stale,
                    )
                    .values(
                        status=AnalysisRunStatus.QUEUED,
                        lease_owner=None,
                        lease_expires_at=None,
                        stage="queued",
                        error_code="lease_expired_retry",
                    )
                    .execution_options(synchronize_session=False)
                )
                if result.rowcount == 1:
                    session.commit()
                    summary.requeued.append(run_id)
                    logger.warning("Requeued analysis run %s after its lease expired", run_id)
                else:
                    session.rollback()
                continue

            status = finish_run_unsuccessfully(
                session,
                run_id,
                "lease_expired",
                actor_user_id=requested_by,
                extra_conditions=still_stale,
            )
            if status is None:
                continue
            session.commit()
            if status is AnalysisRunStatus.CANCELLED:
                summary.cancelled.append(run_id)
            else:
                summary.failed.append(run_id)
                logger.warning("Analysis run %s failed: lease expired", run_id)
    return summary


class AnalysisWorker:
    """Single-run-at-a-time worker loop. Run several processes to scale out."""

    def __init__(self, engine: Engine, *, worker_id: str | None = None) -> None:
        self.engine = engine
        self.worker_id = worker_id or new_worker_id()

    def run_once(self) -> uuid.UUID | None:
        """Recover stale runs, then claim and execute at most one run."""
        try:
            recover_stale_runs(self.engine)
        except Exception:
            logger.exception("Stale-run recovery failed; continuing")
        run_id = claim_next_run(self.engine, self.worker_id)
        if run_id is None:
            return None
        with Session(bind=self.engine, expire_on_commit=False) as db:
            try:
                execute_claimed_run(db, run_id, lease_owner=self.worker_id)
            except Exception as exc:
                # The run state (failed, cancelled, or requeued) is already
                # persisted by the execution path; the worker keeps going.
                logger.warning("Analysis run %s did not complete: %s", run_id, type(exc).__name__)
        return run_id

    def run_forever(self, stop_event: threading.Event) -> None:
        logger.info("Analysis worker %s started", self.worker_id)
        while not stop_event.is_set():
            try:
                ran = self.run_once()
            except Exception:
                logger.exception("Analysis worker iteration failed")
                ran = None
            if ran is None:
                stop_event.wait(settings.analysis_worker_poll_interval_seconds)
        logger.info("Analysis worker %s stopped", self.worker_id)


__all__ = [
    "AnalysisWorker",
    "RecoverySummary",
    "claim_next_run",
    "new_worker_id",
    "recover_stale_runs",
]
