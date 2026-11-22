"""Background lease renewal for a RUNNING analysis run."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from app.models.analysis_run import AnalysisRun
from app.schemas.enums import AnalysisRunStatus

logger = logging.getLogger(__name__)

DEFAULT_JOIN_TIMEOUT_SECONDS = 5.0


class HeartbeatEngineResolutionError(RuntimeError):
    """Raised when a request session cannot yield an independent engine."""


def resolve_engine(db: Session) -> Engine:
    """Resolve the Engine behind a request session.

    A session may be bound directly to an Engine or to a Connection. A
    Connection must never be shared with the heartbeat thread, so its Engine is
    resolved instead and the heartbeat opens its own connection.
    """
    bind = db.get_bind()
    if isinstance(bind, Engine):
        return bind
    if isinstance(bind, Connection):
        return bind.engine
    raise HeartbeatEngineResolutionError(
        f"Cannot resolve an Engine from session bind type {type(bind).__name__}"
    )


class AnalysisHeartbeat:
    """Renew ``analysis_runs.heartbeat_at`` from a dedicated daemon thread.

    Only primitive values are held by the thread. Each renewal uses a new
    Session bound to the resolved Engine, so it never shares the request
    session, its transaction, or any ORM instance.
    """

    def __init__(
        self,
        *,
        run_id: uuid.UUID,
        engine: Engine,
        interval_seconds: float,
        abort_event: threading.Event,
        join_timeout_seconds: float = DEFAULT_JOIN_TIMEOUT_SECONDS,
        lease_owner: str | None = None,
        lease_seconds: float | None = None,
    ) -> None:
        self._run_id = run_id
        self._lease_owner = lease_owner
        self._lease_seconds = lease_seconds
        # Pipeline stage reported with each renewal. Assigned by the executing
        # thread; a plain string attribute is safe to read from this thread.
        self.stage: str | None = None
        self._engine = engine
        self._interval_seconds = interval_seconds
        self._abort_event = abort_event
        self._join_timeout_seconds = join_timeout_seconds
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"analysis-heartbeat-{run_id}",
            daemon=True,
        )

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    @property
    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Signal the thread to stop and join it with a bounded wait."""
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(self._join_timeout_seconds)

    def renew(self) -> bool:
        """Perform one conditional heartbeat update.

        Returns ``True`` when the row was renewed. A zero-row update means the
        run is no longer RUNNING, cancellation was requested, or (for a worker
        run) another worker now holds the lease; the abort event is set and
        ``False`` is returned. Each renewal also extends ``lease_expires_at``
        and records the current pipeline stage.
        """
        heartbeat_at = datetime.now(UTC)
        conditions = [
            AnalysisRun.id == self._run_id,
            AnalysisRun.status == AnalysisRunStatus.RUNNING,
            AnalysisRun.cancel_requested_at.is_(None),
        ]
        if self._lease_owner is not None:
            conditions.append(AnalysisRun.lease_owner == self._lease_owner)
        values: dict[str, object] = {"heartbeat_at": heartbeat_at}
        if self._lease_seconds is not None:
            values["lease_expires_at"] = heartbeat_at + timedelta(seconds=self._lease_seconds)
        stage = self.stage
        if stage is not None:
            values["stage"] = stage
        with Session(bind=self._engine, expire_on_commit=False) as session:
            try:
                result = session.execute(
                    update(AnalysisRun)
                    .where(*conditions)
                    .values(**values)
                    .execution_options(synchronize_session=False)
                )
                if result.rowcount != 1:
                    session.rollback()
                    self._abort_event.set()
                    return False
                session.commit()
                return True
            except Exception:
                session.rollback()
                raise

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval_seconds):
            if self._abort_event.is_set():
                return
            try:
                self.renew()
            except Exception:
                # A temporary SQLite writer lock or any other transient database
                # error must not fail the analysis. The next interval retries.
                logger.warning(
                    "Analysis heartbeat renewal failed for run %s; retrying next interval",
                    self._run_id,
                    exc_info=True,
                )


__all__ = [
    "AnalysisHeartbeat",
    "HeartbeatEngineResolutionError",
    "resolve_engine",
]
