"""Analysis-run lifecycle auditing and transaction-consistency regression tests."""

import logging
import textwrap
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from db_triggers import create_failure_trigger, drop_failure_trigger
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from test_analysis_execution import make_relationship

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment_finding import AssessmentFinding
from app.models.audit_event import AuditEvent
from app.models.finding_evidence import FindingEvidence
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    FindingSeverity,
    FindingStatus,
    RepositorySourceKind,
)
from app.schemas.finding import Evidence, Finding
from app.schemas.repository import RepositorySourceCreate
from app.services import analysis_execution, repository_targets
from app.services import assessments as assessment_service
from app.services.finding_policy import FindingGenerationResult
from app.services.findings import RetestSummary

ASSESSMENTS_URL = "/api/v1/assessments"
SOURCE = textwrap.dedent(
    """
    import sqlite3

    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/direct")
    def handler():
        cursor = sqlite3.connect("app.db").cursor()
        cursor.execute(request.args.get("q"))
        return "ok"
    """
).lstrip()


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
    (target / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (target / "app.py").write_text(SOURCE, encoding="utf-8")
    return target


def create_assessment_with_target(
    session: Session,
    repository: Path,
) -> uuid.UUID:
    assessment = assessment_service.create_assessment(
        session,
        AssessmentType.REPOSITORY,
    )
    repository_targets.create_repository_target(
        session,
        assessment,
        RepositorySourceCreate(
            source_kind=RepositorySourceKind.LOCAL_PATH,
            location=str(repository),
        ),
    )
    return assessment.id


def events_for_run(session: Session, run_id: uuid.UUID) -> list[AuditEvent]:
    return list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.resource_id == run_id)
            .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
        ).all()
    )


def make_finding() -> Finding:
    return Finding(
        title="Static flow finding",
        category="input_to_database_read",
        severity=FindingSeverity.INFORMATIONAL,
        status=FindingStatus.NOT_TESTED,
        confidence=0.7,
        summary="Static evidence only.",
        evidence=[
            Evidence(
                description="Static input-to-operation evidence.",
                source="input_operation_flow",
                details={"relationship_id": "inputs[0]->operations[0]"},
            )
        ],
    )


def generation_with_one_finding() -> FindingGenerationResult:
    return FindingGenerationResult(
        findings=[make_finding()],
        eligible_relationship_count=1,
        skipped_relationship_count=0,
        limitations=[],
        # Normalized persistence (M7) requires each finding's source relationship.
        relationships=[make_relationship()],
    )


def install_audit_insert_failure(
    db_engine: Engine,
    *,
    action: AuditAction,
    trigger_name: str,
) -> None:
    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            trigger_name,
            table="audit_events",
            event="INSERT",
            message="forced audit insert failure",
            when=f"NEW.action = '{action.value}'",
        )


def drop_trigger(db_engine: Engine, trigger_name: str) -> None:
    with db_engine.begin() as connection:
        drop_failure_trigger(connection, trigger_name, table="audit_events")


def test_successful_run_records_started_and_completed_events(
    session_factory: sessionmaker[Session],
    repository: Path,
    make_assessment_principal,
) -> None:
    actor_id, _ = make_assessment_principal()

    with session_factory() as session:
        assessment_id = create_assessment_with_target(session, repository)
        run = analysis_execution.execute_assessment_analysis(
            session,
            assessment_id,
            actor_user_id=actor_id,
        )
        run_id = run.id
        finding_count = run.analysis_metadata["finding_count"]

    with session_factory() as session:
        stored_run = session.get(AnalysisRun, run_id)
        events = events_for_run(session, run_id)

    assert stored_run is not None
    assert stored_run.status is AnalysisRunStatus.COMPLETED
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_COMPLETED,
    ]
    for event in events:
        assert event.actor_user_id == actor_id
        assert event.assessment_id == assessment_id
        assert event.resource_type is AuditResourceType.ANALYSIS_RUN
        assert event.resource_id == run_id
        assert event.outcome is AuditOutcome.SUCCESS
    assert events[0].context is None
    assert events[1].context == {"finding_count": finding_count}


def test_failed_run_records_failure_event_without_sensitive_data(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "failure at C:\\secret\\repository token=abc123"

    def fail_analysis(
        _db: Session,
        _assessment_id: uuid.UUID,
        **_kwargs: object,
    ) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        fail_analysis,
    )

    with session_factory() as session:
        assessment_id = create_assessment_with_target(session, repository)
        with pytest.raises(RuntimeError, match="secret"):
            analysis_execution.execute_assessment_analysis(session, assessment_id)

    with session_factory() as session:
        stored_run = session.scalar(select(AnalysisRun))
        assert stored_run is not None
        events = events_for_run(session, stored_run.id)

    assert stored_run.status is AnalysisRunStatus.FAILED
    assert stored_run.completed_at is not None
    assert stored_run.error_message == "Assessment analysis failed."
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    failure_event = events[1]
    assert failure_event.outcome is AuditOutcome.FAILURE
    assert failure_event.assessment_id == assessment_id
    assert failure_event.resource_id == stored_run.id
    assert failure_event.context == {"failure_stage": "analysis"}
    for event in events:
        serialized = str(event.context)
        assert "secret" not in serialized
        assert "abc123" not in serialized
        assert "C:\\" not in serialized


def test_start_audit_failure_leaves_no_run_or_start_event(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    repository: Path,
) -> None:
    with session_factory() as session:
        assessment_id = create_assessment_with_target(session, repository)

    install_audit_insert_failure(
        db_engine,
        action=AuditAction.ANALYSIS_RUN_STARTED,
        trigger_name="fail_start_audit_insert",
    )
    try:
        with session_factory() as session:
            with pytest.raises(IntegrityError, match="forced audit insert failure"):
                analysis_execution.execute_assessment_analysis(session, assessment_id)
    finally:
        drop_trigger(db_engine, "fail_start_audit_insert")

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        started = session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == AuditAction.ANALYSIS_RUN_STARTED)
        )
        assert started == 0


@pytest.mark.anyio
async def test_completion_audit_failure_marks_run_failed_and_hides_details(
    client: httpx.AsyncClient,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    make_assessment_principal,
) -> None:
    actor_id, headers = make_assessment_principal()
    created = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": AssessmentType.REPOSITORY.value},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    registered = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={
            "source_kind": RepositorySourceKind.LOCAL_PATH.value,
            "location": str(repository),
        },
        headers=headers,
    )
    assert registered.status_code == 201, registered.text

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        lambda _db, _assessment_id, **_kwargs: SimpleNamespace(
            discovery=None,
            summary=SimpleNamespace(summary=SimpleNamespace(is_complete=True)),
            input_operation_flow=SimpleNamespace(relationships=[]),
        ),
    )
    monkeypatch.setattr(
        analysis_execution,
        "generate_findings",
        lambda _flow: generation_with_one_finding(),
    )
    monkeypatch.setattr(
        analysis_execution,
        "_build_analysis_metadata",
        lambda _results, _generation, **_kwargs: {"test": True},
    )
    install_audit_insert_failure(
        db_engine,
        action=AuditAction.ANALYSIS_RUN_COMPLETED,
        trigger_name="fail_completed_audit_insert",
    )
    try:
        response = await client.post(
            f"{ASSESSMENTS_URL}/{assessment_id}/analysis-runs",
            headers=headers,
        )
    finally:
        drop_trigger(db_engine, "fail_completed_audit_insert")

    assert response.status_code == 500
    assert response.json() == {"detail": "Analysis run failed"}
    assert "forced audit insert failure" not in response.text
    assert "audit_events" not in response.text

    with session_factory() as session:
        stored_run = session.scalar(select(AnalysisRun))
        assert stored_run is not None
        events = events_for_run(session, stored_run.id)
        findings = session.scalar(select(func.count()).select_from(AssessmentFinding))
        evidence = session.scalar(select(func.count()).select_from(FindingEvidence))

    assert stored_run.status is AnalysisRunStatus.FAILED
    assert stored_run.error_message == "Analysis run completion failed."
    assert stored_run.analysis_metadata == {"failure_stage": "completion"}
    assert findings == 0
    assert evidence == 0
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    assert events[1].outcome is AuditOutcome.FAILURE
    assert events[1].context == {"failure_stage": "completion"}
    assert events[1].actor_user_id == actor_id
    assert all(event.action is not AuditAction.ANALYSIS_RUN_COMPLETED for event in events)


@pytest.mark.anyio
async def test_failure_audit_failure_keeps_run_non_terminal_and_hides_details(
    client: httpx.AsyncClient,
    assessment_client: None,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    created = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": AssessmentType.REPOSITORY.value},
    )
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    registered = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={
            "source_kind": RepositorySourceKind.LOCAL_PATH.value,
            "location": str(repository),
        },
    )
    assert registered.status_code == 201, registered.text

    def fail_analysis(
        _db: Session,
        _assessment_id: uuid.UUID,
        **_kwargs: object,
    ) -> object:
        raise RuntimeError("failure at C:\\secret\\repository token=abc123")

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        fail_analysis,
    )
    install_audit_insert_failure(
        db_engine,
        action=AuditAction.ANALYSIS_RUN_FAILED,
        trigger_name="fail_failed_audit_insert",
    )
    try:
        with caplog.at_level(logging.ERROR, logger="app.services.analysis_execution"):
            response = await client.post(f"{ASSESSMENTS_URL}/{assessment_id}/analysis-runs")
    finally:
        drop_trigger(db_engine, "fail_failed_audit_insert")

    assert response.status_code == 500
    assert response.json() == {"detail": "Analysis run failed"}
    assert "secret" not in response.text
    assert "forced audit insert failure" not in response.text
    assert "audit_events" not in response.text
    assert "Failed to mark analysis run" in caplog.text

    with session_factory() as session:
        stored_run = session.scalar(select(AnalysisRun))
        assert stored_run is not None
        events = events_for_run(session, stored_run.id)

    # The failure state and its audit event are atomic, so a failed audit write
    # leaves the run RUNNING rather than FAILED without a matching record.
    assert stored_run.status is AnalysisRunStatus.RUNNING
    assert stored_run.completed_at is None
    assert stored_run.error_message is None
    assert [event.action for event in events] == [AuditAction.ANALYSIS_RUN_STARTED]


def test_repeated_failure_marking_is_idempotent_and_never_overwrites_completed(
    session_factory: sessionmaker[Session],
    repository: Path,
) -> None:
    timestamp = datetime.now(UTC)
    with session_factory() as session:
        assessment_id = create_assessment_with_target(session, repository)
        running = AnalysisRun(
            assessment_id=assessment_id,
            status=AnalysisRunStatus.RUNNING,
            created_at=timestamp,
            started_at=timestamp,
        )
        completed = AnalysisRun(
            assessment_id=assessment_id,
            status=AnalysisRunStatus.COMPLETED,
            created_at=timestamp,
            started_at=timestamp,
            completed_at=timestamp,
        )
        session.add_all([running, completed])
        session.commit()
        running_id = running.id
        completed_id = completed.id

        analysis_execution._mark_run_failed(
            session,
            running_id,
            "analysis",
            actor_user_id=None,
        )
        session.expire_all()
        first_completed_at = session.get(AnalysisRun, running_id).completed_at
        first_error = session.get(AnalysisRun, running_id).error_message

        analysis_execution._mark_run_failed(
            session,
            running_id,
            "finding_generation",
            actor_user_id=None,
        )
        analysis_execution._mark_run_failed(
            session,
            completed_id,
            "analysis",
            actor_user_id=None,
        )

    with session_factory() as session:
        running = session.get(AnalysisRun, running_id)
        completed = session.get(AnalysisRun, completed_id)
        running_events = events_for_run(session, running_id)
        completed_events = events_for_run(session, completed_id)

    assert running is not None
    assert running.status is AnalysisRunStatus.FAILED
    assert running.completed_at == first_completed_at
    assert running.error_message == first_error == "Assessment analysis failed."
    assert len(running_events) == 1
    assert running_events[0].action is AuditAction.ANALYSIS_RUN_FAILED
    assert running_events[0].context == {"failure_stage": "analysis"}

    assert completed is not None
    assert completed.status is AnalysisRunStatus.COMPLETED
    assert completed.completed_at == timestamp
    assert completed_events == []


def test_terminal_transition_predicate_requires_running_status(
    session_factory: sessionmaker[Session],
) -> None:
    timestamp = datetime.now(UTC)
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        completed = AnalysisRun(
            assessment_id=assessment.id,
            status=AnalysisRunStatus.COMPLETED,
            created_at=timestamp,
            started_at=timestamp,
            completed_at=timestamp,
        )
        session.add(completed)
        session.commit()
        run_id = completed.id

        transitioned = analysis_execution._transition_run_if_running(
            session,
            run_id,
            status=AnalysisRunStatus.FAILED,
            completed_at=datetime.now(UTC),
            error_message="should not be written",
            analysis_metadata={"failure_stage": "analysis"},
        )
        session.rollback()

    assert transitioned is False
    with session_factory() as session:
        stored = session.get(AnalysisRun, run_id)
        assert stored is not None
        assert stored.status is AnalysisRunStatus.COMPLETED
        assert stored.error_message is None
        assert stored.analysis_metadata is None


def test_concurrent_failure_handlers_record_exactly_one_terminal_event(
    session_factory: sessionmaker[Session],
    make_assessment_principal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_id, _ = make_assessment_principal()
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        run = analysis_execution._start_running_run(
            session,
            assessment.id,
            actor_user_id=actor_id,
        )
        run_id = run.id

    barrier = threading.Barrier(2)
    winner_committed = threading.Event()
    real_transition = analysis_execution._transition_run_if_running

    def sequenced_transition(*args, **kwargs):
        # Both handlers reach the transition point. The rival waits until the
        # winner has committed, so SQLite write serialization cannot make the
        # assertion flaky while the database predicate is still exercised.
        if threading.current_thread().name == "rival":
            barrier.wait(timeout=15)
            assert winner_committed.wait(timeout=15)
        else:
            barrier.wait(timeout=15)
        return real_transition(*args, **kwargs)

    monkeypatch.setattr(
        analysis_execution,
        "_transition_run_if_running",
        sequenced_transition,
    )

    def winner_worker() -> None:
        with session_factory() as session:
            analysis_execution._mark_run_failed(
                session,
                run_id,
                "analysis",
                actor_user_id=actor_id,
            )
        winner_committed.set()

    def rival_worker() -> None:
        with session_factory() as session:
            analysis_execution._mark_run_failed(
                session,
                run_id,
                "finding_generation",
                actor_user_id=actor_id,
            )

    winner = threading.Thread(target=winner_worker, name="winner")
    rival = threading.Thread(target=rival_worker, name="rival")
    winner.start()
    rival.start()
    winner.join(30)
    rival.join(30)

    assert not winner.is_alive()
    assert not rival.is_alive()

    with session_factory() as session:
        stored_run = session.get(AnalysisRun, run_id)
        events = events_for_run(session, run_id)

    assert stored_run is not None
    assert stored_run.status is AnalysisRunStatus.FAILED
    assert stored_run.error_message == "Assessment analysis failed."
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    terminal_events = [
        event
        for event in events
        if event.action in {AuditAction.ANALYSIS_RUN_COMPLETED, AuditAction.ANALYSIS_RUN_FAILED}
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0].action is AuditAction.ANALYSIS_RUN_FAILED
    assert terminal_events[0].outcome is AuditOutcome.FAILURE
    assert terminal_events[0].context == {"failure_stage": "analysis"}
    assert terminal_events[0].actor_user_id == actor_id


def test_completion_losing_to_failure_records_only_the_failure_event(
    session_factory: sessionmaker[Session],
    repository: Path,
    make_assessment_principal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor_id, _ = make_assessment_principal()
    with session_factory() as session:
        assessment_id = create_assessment_with_target(session, repository)

    completion_ready = threading.Event()
    failure_committed = threading.Event()
    shared: dict[str, uuid.UUID] = {}
    real_transition = analysis_execution._transition_run_if_running

    def racing_transition(db: Session, run_id: uuid.UUID, **kwargs):
        if threading.current_thread().name == "completion":
            shared["run_id"] = run_id
            completion_ready.set()
            assert failure_committed.wait(timeout=15)
        return real_transition(db, run_id, **kwargs)

    monkeypatch.setattr(
        analysis_execution,
        "_transition_run_if_running",
        racing_transition,
    )
    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        lambda _db, _assessment_id, **_kwargs: SimpleNamespace(
            discovery=None,
            summary=SimpleNamespace(summary=SimpleNamespace(is_complete=True)),
            input_operation_flow=SimpleNamespace(relationships=[]),
        ),
    )
    monkeypatch.setattr(
        analysis_execution,
        "_build_analysis_metadata",
        lambda _results, _generation, **_kwargs: {"test": True},
    )
    # Keep the completion transaction free of SQLite write locks so the failure
    # handler can commit while completion is paused at the transition.
    monkeypatch.setattr(
        analysis_execution,
        "add_normalized_findings",
        lambda *_args, **_kwargs: RetestSummary(
            previous_run_id=None,
            new=0,
            recurring=0,
            not_reproduced=0,
            evidence_items=0,
            findings=0,
        ),
    )

    outcomes: dict[str, BaseException] = {}

    def completion_worker() -> None:
        with session_factory() as session:
            try:
                analysis_execution.execute_assessment_analysis(
                    session,
                    assessment_id,
                    actor_user_id=actor_id,
                )
            except BaseException as exc:  # pragma: no cover - surfaced via outcomes
                outcomes["error"] = exc

    def failure_worker() -> None:
        assert completion_ready.wait(timeout=15)
        with session_factory() as session:
            analysis_execution._mark_run_failed(
                session,
                shared["run_id"],
                "analysis",
                actor_user_id=actor_id,
            )
        failure_committed.set()

    completion = threading.Thread(target=completion_worker, name="completion")
    failure = threading.Thread(target=failure_worker, name="failure")
    completion.start()
    failure.start()
    completion.join(30)
    failure.join(30)

    assert not completion.is_alive()
    assert not failure.is_alive()
    assert isinstance(outcomes.get("error"), analysis_execution.AnalysisRunStateConflictError)

    with session_factory() as session:
        stored_run = session.get(AnalysisRun, shared["run_id"])
        events = events_for_run(session, shared["run_id"])

    assert stored_run is not None
    assert stored_run.status is AnalysisRunStatus.FAILED
    assert stored_run.error_message == "Assessment analysis failed."
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    assert all(event.action is not AuditAction.ANALYSIS_RUN_COMPLETED for event in events)
    assert events[1].context == {"failure_stage": "analysis"}
    assert events[1].actor_user_id == actor_id


def test_completion_transition_conflict_rolls_back_findings_and_terminal_state(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        assessment_id = create_assessment_with_target(session, repository)

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        lambda _db, _assessment_id, **_kwargs: SimpleNamespace(
            discovery=None,
            summary=SimpleNamespace(summary=SimpleNamespace(is_complete=True)),
            input_operation_flow=SimpleNamespace(relationships=[]),
        ),
    )
    monkeypatch.setattr(
        analysis_execution,
        "generate_findings",
        lambda _flow: generation_with_one_finding(),
    )
    monkeypatch.setattr(
        analysis_execution,
        "_build_analysis_metadata",
        lambda _results, _generation, **_kwargs: {"test": True},
    )

    real_transition = analysis_execution._transition_run_if_running
    completion_conflicts = 0

    def lose_completion_transition(db: Session, run_id: uuid.UUID, **kwargs):
        nonlocal completion_conflicts
        if kwargs["status"] is AnalysisRunStatus.COMPLETED:
            completion_conflicts += 1
            # add_findings flushed the finding and evidence before the
            # transition attempt; the rollback must remove both.
            assert db.scalar(select(func.count()).select_from(AssessmentFinding)) == 1
            assert db.scalar(select(func.count()).select_from(FindingEvidence)) == 1
            return False
        return real_transition(db, run_id, **kwargs)

    monkeypatch.setattr(
        analysis_execution,
        "_transition_run_if_running",
        lose_completion_transition,
    )

    with session_factory() as session:
        with pytest.raises(analysis_execution.AnalysisRunStateConflictError):
            analysis_execution.execute_assessment_analysis(session, assessment_id)

    assert completion_conflicts == 1

    with session_factory() as session:
        stored_run = session.scalar(select(AnalysisRun))
        assert stored_run is not None
        events = events_for_run(session, stored_run.id)
        findings = session.scalar(select(func.count()).select_from(AssessmentFinding))
        evidence = session.scalar(select(func.count()).select_from(FindingEvidence))

    assert stored_run.status is AnalysisRunStatus.FAILED
    assert stored_run.error_message == "Analysis run completion failed."
    assert stored_run.analysis_metadata == {"failure_stage": "completion"}
    assert findings == 0
    assert evidence == 0
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    assert all(event.action is not AuditAction.ANALYSIS_RUN_COMPLETED for event in events)
    assert events[1].context == {"failure_stage": "completion"}


@pytest.mark.anyio
async def test_cross_owner_run_start_is_denied_without_run_or_audit(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
    repository_root: Path,
) -> None:
    _, owner_headers = make_assessment_principal()
    _, other_headers = make_assessment_principal()
    created = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": AssessmentType.REPOSITORY.value},
        headers=owner_headers,
    )
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    repository = repository_root / "project"
    repository.mkdir()
    (repository / "app.py").write_text(SOURCE, encoding="utf-8")
    registered = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={
            "source_kind": RepositorySourceKind.LOCAL_PATH.value,
            "location": str(repository),
        },
        headers=owner_headers,
    )
    assert registered.status_code == 201, registered.text

    response = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/analysis-runs",
        headers=other_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        started = session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == AuditAction.ANALYSIS_RUN_STARTED)
        )
        assert started == 0
