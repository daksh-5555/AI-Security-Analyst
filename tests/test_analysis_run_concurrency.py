import logging
import queue
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from db_triggers import create_failure_trigger
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.session import create_db_engine
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    RepositorySourceKind,
)
from app.schemas.repository import RepositorySourceCreate
from app.services import analysis_execution, repository_targets
from app.services import assessments as assessment_service

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_RUN_INDEX = "uq_analysis_runs_active_assessment"


@pytest.fixture
def repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


@pytest.fixture
def repository(repository_root: Path) -> Path:
    target = repository_root / "project"
    target.mkdir()
    (target / "app.py").write_text("", encoding="utf-8")
    return target


def migration_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def create_assessment(session: Session) -> AssessmentJob:
    return assessment_service.create_assessment(session, AssessmentType.REPOSITORY)


def add_repository_target(
    session: Session,
    assessment: AssessmentJob,
    repository: Path,
) -> None:
    repository_targets.create_repository_target(
        session,
        assessment,
        RepositorySourceCreate(
            source_kind=RepositorySourceKind.LOCAL_PATH,
            location=str(repository),
        ),
    )


def make_run(
    session: Session,
    assessment_id: uuid.UUID,
    status: AnalysisRunStatus = AnalysisRunStatus.RUNNING,
) -> AnalysisRun:
    now = datetime.now(UTC)
    run = AnalysisRun(
        assessment_id=assessment_id,
        status=status,
        created_at=now,
        started_at=now,
        completed_at=None if status is AnalysisRunStatus.RUNNING else now,
    )
    session.add(run)
    session.commit()
    return run


def test_creating_a_running_run_when_none_exists(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        run = make_run(session, assessment.id)

        assert run.status is AnalysisRunStatus.RUNNING
        assert (
            session.scalar(
                select(func.count())
                .select_from(AnalysisRun)
                .where(AnalysisRun.status == AnalysisRunStatus.RUNNING)
            )
            == 1
        )


def test_second_running_run_for_same_assessment_is_rejected(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        make_run(session, assessment.id)

        session.add(AnalysisRun(assessment_id=assessment.id))
        with pytest.raises(
            IntegrityError, match="UNIQUE constraint failed|uq_analysis_runs_active_assessment"
        ):
            session.commit()
        session.rollback()

        assert (
            session.scalar(
                select(func.count())
                .select_from(AnalysisRun)
                .where(AnalysisRun.status == AnalysisRunStatus.RUNNING)
            )
            == 1
        )


def test_multiple_completed_runs_are_allowed(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        first = make_run(session, assessment.id, AnalysisRunStatus.COMPLETED)
        second = make_run(session, assessment.id, AnalysisRunStatus.COMPLETED)

        assert first.status is AnalysisRunStatus.COMPLETED
        assert second.status is AnalysisRunStatus.COMPLETED
        assert (
            session.scalar(
                select(func.count())
                .select_from(AnalysisRun)
                .where(AnalysisRun.assessment_id == assessment.id)
            )
            == 2
        )


def test_each_assessment_can_have_its_own_running_run(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        first = create_assessment(session)
        second = create_assessment(session)
        first_run = make_run(session, first.id)
        second_run = make_run(session, second.id)

        assert first_run.assessment_id == first.id
        assert second_run.assessment_id == second.id


def test_completed_and_failed_history_survives_new_running_run(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        make_run(session, assessment.id, AnalysisRunStatus.COMPLETED)
        make_run(session, assessment.id, AnalysisRunStatus.FAILED)
        active = make_run(session, assessment.id)

        runs = session.scalars(
            select(AnalysisRun).where(AnalysisRun.assessment_id == assessment.id)
        ).all()

        assert len(runs) == 3
        assert active.id in {run.id for run in runs}
        assert {run.status for run in runs} == {
            AnalysisRunStatus.COMPLETED,
            AnalysisRunStatus.FAILED,
            AnalysisRunStatus.RUNNING,
        }


def test_service_rejects_existing_active_run_without_creating_another(
    session_factory: sessionmaker[Session],
    repository: Path,
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        add_repository_target(session, assessment, repository)
        existing = make_run(session, assessment.id)
        existing_id = existing.id

        with pytest.raises(analysis_execution.ActiveAnalysisRunError):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

    with session_factory() as session:
        runs = session.scalars(select(AnalysisRun)).all()
        assert len(runs) == 1
        assert runs[0].id == existing_id
        assert runs[0].status is AnalysisRunStatus.RUNNING


def test_concurrent_executions_create_exactly_one_run(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        assessment_id = assessment.id
        add_repository_target(session, assessment, repository)

    barrier = threading.Barrier(2)
    analysis_entered = threading.Event()
    conflict_observed = threading.Event()
    outcomes: queue.Queue[tuple[str, object]] = queue.Queue()

    def blocking_collect(
        _db: Session,
        _assessment_id: uuid.UUID,
        **_kwargs: object,
    ) -> object:
        analysis_entered.set()
        assert conflict_observed.wait(15)
        return SimpleNamespace(
            discovery=None,
            summary=SimpleNamespace(summary=SimpleNamespace(is_complete=True)),
            input_operation_flow=SimpleNamespace(relationships=[]),
        )

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        blocking_collect,
    )
    monkeypatch.setattr(
        analysis_execution,
        "_build_analysis_metadata",
        lambda _results, _generation, **_kwargs: {"test": True},
    )

    def attempt() -> None:
        with session_factory() as session:
            barrier.wait(15)
            try:
                run = analysis_execution.execute_assessment_analysis(
                    session,
                    assessment_id,
                )
            except analysis_execution.ActiveAnalysisRunError:
                conflict_observed.set()
                outcomes.put(("conflict", None))
            except BaseException as exc:  # pragma: no cover - surfaced via outcomes
                conflict_observed.set()
                outcomes.put(("error", repr(exc)))
            else:
                outcomes.put(("success", run.id))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert all(not thread.is_alive() for thread in threads)
    assert analysis_entered.is_set()
    results = [outcomes.get_nowait() for _ in range(outcomes.qsize())]
    assert sorted(result[0] for result in results) == ["conflict", "success"], results

    with session_factory() as session:
        runs = session.scalars(select(AnalysisRun)).all()
        assert len(runs) == 1
        assert runs[0].status is AnalysisRunStatus.COMPLETED
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0


def test_database_conflict_is_translated_when_precheck_is_bypassed(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        assessment_id = assessment.id
        add_repository_target(session, assessment, repository)
        existing = make_run(session, assessment_id)
        existing_id = existing.id

    real_find_active_run = analysis_execution._find_active_run
    calls = 0

    def skip_first_precheck(
        db: Session,
        requested_assessment_id: uuid.UUID,
    ) -> uuid.UUID | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            return None
        return real_find_active_run(db, requested_assessment_id)

    monkeypatch.setattr(
        analysis_execution,
        "_find_active_run",
        skip_first_precheck,
    )

    with session_factory() as session:
        with pytest.raises(analysis_execution.ActiveAnalysisRunError) as exc_info:
            analysis_execution.execute_assessment_analysis(session, assessment_id)

    assert isinstance(exc_info.value.__cause__, IntegrityError)

    with session_factory() as session:
        runs = session.scalars(select(AnalysisRun)).all()
        assert [run.id for run in runs] == [existing_id]
        assert runs[0].status is AnalysisRunStatus.RUNNING


def test_failed_run_insert_leaves_no_partial_run(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    repository: Path,
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        assessment_id = assessment.id
        add_repository_target(session, assessment, repository)
        other_assessment = create_assessment(session)
        other_run = make_run(session, other_assessment.id, AnalysisRunStatus.COMPLETED)
        other_run_id = other_run.id

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_analysis_run_insert",
            table="analysis_runs",
            event="INSERT",
            message="forced insert failure",
        )

    with session_factory() as session:
        with pytest.raises(IntegrityError, match="forced insert failure"):
            analysis_execution.execute_assessment_analysis(session, assessment_id)

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 1
        other_run = session.get(AnalysisRun, other_run_id)
        assert other_run is not None
        assert other_run.status is AnalysisRunStatus.COMPLETED


def test_failure_marking_failure_is_logged_and_does_not_hide_the_cause(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        assessment_id = assessment.id
        add_repository_target(session, assessment, repository)

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_analysis_run_failed_state",
            table="analysis_runs",
            event="UPDATE",
            message="forced failure-state error",
            when="NEW.status = 'failed'",
        )

    def fail_analysis(
        _db: Session,
        _assessment_id: uuid.UUID,
        **_kwargs: object,
    ) -> object:
        raise RuntimeError("original analysis failure")

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        fail_analysis,
    )

    with caplog.at_level(logging.ERROR, logger="app.services.analysis_execution"):
        with session_factory() as session:
            with pytest.raises(RuntimeError, match="original analysis failure"):
                analysis_execution.execute_assessment_analysis(session, assessment_id)

    assert "Failed to mark analysis run" in caplog.text

    with session_factory() as session:
        run = session.scalar(select(AnalysisRun))
        assert run is not None
        assert run.status is AnalysisRunStatus.RUNNING
        assert run.error_message is None


def test_active_run_index_migration_upgrade_and_downgrade(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = migration_config(database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            index_sql = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'index' AND name = 'uq_analysis_runs_active_assessment'"
            ).scalar_one_or_none()
        assert index_sql is not None
        assert "UNIQUE" in index_sql.upper()
        # At head, migration 0018 widened the predicate to queued or running runs.
        assert "WHERE status IN ('queued', 'running')" in index_sql
    finally:
        engine.dispose()

    command.downgrade(config, "0006")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            index_sql = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'index' AND name = 'uq_analysis_runs_active_assessment'"
            ).scalar_one_or_none()
        assert index_sql is None
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            index_sql = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'index' AND name = 'uq_analysis_runs_active_assessment'"
            ).scalar_one_or_none()
        assert index_sql is not None
    finally:
        engine.dispose()
