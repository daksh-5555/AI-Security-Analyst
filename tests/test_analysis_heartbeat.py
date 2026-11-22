"""Deterministic tests for the analysis-run heartbeat lifecycle."""

import sqlite3
import threading
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.models.analysis_run import AnalysisRun
from app.schemas.enums import AnalysisRunStatus, AssessmentType
from app.services import analysis_heartbeat
from app.services import assessments as assessment_service
from app.services.analysis_heartbeat import AnalysisHeartbeat, resolve_engine


def create_running_run(
    session: Session,
    *,
    heartbeat_at: datetime | None = None,
    cancel_requested: bool = False,
) -> uuid.UUID:
    assessment = assessment_service.create_assessment(session, AssessmentType.REPOSITORY)
    now = datetime.now(UTC)
    run = AnalysisRun(
        assessment_id=assessment.id,
        status=AnalysisRunStatus.RUNNING,
        created_at=now,
        started_at=now,
        heartbeat_at=heartbeat_at,
        cancel_requested_at=now if cancel_requested else None,
    )
    session.add(run)
    session.commit()
    return run.id


def test_renew_updates_only_the_heartbeat(
    session_factory: sessionmaker[Session],
) -> None:
    old_heartbeat = datetime(2026, 1, 1, tzinfo=UTC)
    with session_factory() as session:
        run_id = create_running_run(session, heartbeat_at=old_heartbeat)
        run = session.get(AnalysisRun, run_id)
        assert run is not None
        run.analysis_metadata = {"keep": True}
        session.commit()

        heartbeat = AnalysisHeartbeat(
            run_id=run_id,
            engine=resolve_engine(session),
            interval_seconds=1,
            abort_event=threading.Event(),
        )
        assert heartbeat.renew() is True

    with session_factory() as session:
        stored = session.get(AnalysisRun, run_id)

    assert stored is not None
    assert stored.heartbeat_at is not None
    assert stored.heartbeat_at > old_heartbeat
    assert stored.status is AnalysisRunStatus.RUNNING
    assert stored.completed_at is None
    assert stored.error_message is None
    assert stored.analysis_metadata == {"keep": True}


def test_renew_uses_an_independent_session(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[Session] = []
    real_session = analysis_heartbeat.Session

    def recording_session(*args: object, **kwargs: object) -> Session:
        session = real_session(*args, **kwargs)
        created.append(session)
        return session

    monkeypatch.setattr(analysis_heartbeat, "Session", recording_session)

    with session_factory() as request_session:
        run_id = create_running_run(request_session)
        heartbeat = AnalysisHeartbeat(
            run_id=run_id,
            engine=resolve_engine(request_session),
            interval_seconds=1,
            abort_event=threading.Event(),
        )
        assert heartbeat.renew() is True

    assert len(created) == 1
    assert created[0] is not request_session


def test_resolve_engine_uses_test_override_and_connection_engine(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assert resolve_engine(session) is db_engine

    connection = db_engine.connect()
    try:
        with Session(bind=connection) as connection_session:
            resolved = resolve_engine(connection_session)
            assert resolved is db_engine
            assert resolved is not connection
    finally:
        connection.close()


def test_zero_row_update_signals_abort(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        run_id = create_running_run(session, cancel_requested=True)
        abort_event = threading.Event()
        heartbeat = AnalysisHeartbeat(
            run_id=run_id,
            engine=resolve_engine(session),
            interval_seconds=1,
            abort_event=abort_event,
        )

        assert heartbeat.renew() is False
        assert abort_event.is_set() is True


def test_zero_row_update_for_terminal_run_signals_abort(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        run_id = create_running_run(session)
        run = session.get(AnalysisRun, run_id)
        assert run is not None
        run.status = AnalysisRunStatus.COMPLETED
        run.completed_at = datetime.now(UTC)
        session.commit()

        abort_event = threading.Event()
        heartbeat = AnalysisHeartbeat(
            run_id=run_id,
            engine=resolve_engine(session),
            interval_seconds=1,
            abort_event=abort_event,
        )

        assert heartbeat.renew() is False
        assert abort_event.is_set() is True


def test_database_lock_error_is_logged_and_retried(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    first_attempt = threading.Event()
    second_attempt = threading.Event()
    real_session = analysis_heartbeat.Session

    def flaky_session(*args: object, **kwargs: object) -> Session:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            first_attempt.set()
            raise OperationalError(
                "UPDATE analysis_runs SET heartbeat_at = ?",
                {},
                sqlite3.OperationalError("database is locked"),
            )
        second_attempt.set()
        return real_session(*args, **kwargs)

    monkeypatch.setattr(analysis_heartbeat, "Session", flaky_session)

    with session_factory() as session:
        run_id = create_running_run(session)

    abort_event = threading.Event()
    heartbeat = AnalysisHeartbeat(
        run_id=run_id,
        engine=db_engine,
        interval_seconds=0.01,
        abort_event=abort_event,
        join_timeout_seconds=2,
    )
    heartbeat.start()
    try:
        assert first_attempt.wait(2)
        assert second_attempt.wait(2)
    finally:
        heartbeat.stop()

    assert attempts >= 2
    assert abort_event.is_set() is False
    assert heartbeat.is_alive is False

    with session_factory() as session:
        stored = session.get(AnalysisRun, run_id)
        assert stored is not None
        assert stored.status is AnalysisRunStatus.RUNNING
        assert stored.heartbeat_at is not None


def test_thread_stops_after_abort_without_further_renewals(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        run_id = create_running_run(session)

    abort_event = threading.Event()
    abort_event.set()
    heartbeat = AnalysisHeartbeat(
        run_id=run_id,
        engine=db_engine,
        interval_seconds=0.01,
        abort_event=abort_event,
        join_timeout_seconds=2,
    )
    heartbeat.start()
    heartbeat.stop()

    assert heartbeat.is_alive is False
    assert heartbeat.stop_event.is_set() is True

    with session_factory() as session:
        stored = session.get(AnalysisRun, run_id)
        assert stored is not None
        assert stored.heartbeat_at is None
