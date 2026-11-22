import shutil
import textwrap
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from db_triggers import create_failure_trigger
from sqlalchemy import func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.session import create_db_engine
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.audit_event import AuditEvent
from app.models.finding_evidence import FindingEvidence
from app.schemas.attack_surface import HttpMethod, RouteFramework
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    AuditAction,
    FindingSeverity,
    FindingStatus,
    RepositorySourceKind,
)
from app.schemas.finding import Evidence, Finding
from app.schemas.input_operation_flow import (
    FlowPropagationKind,
    FlowResolutionStatus,
    HandlerReference,
    InputOperationRelationship,
    PropagationStep,
)
from app.schemas.input_sources import InputResolutionStatus, InputType
from app.schemas.repository import RepositorySourceCreate
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
)
from app.services import (
    analysis_execution,
    attack_surface_reporting,
    repository_targets,
)
from app.services import assessments as assessment_service
from app.services import findings as finding_service
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
)
from app.services.analysis_heartbeat import AnalysisHeartbeat
from app.services.repository_discovery import InvalidRepositoryRootError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
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
def allowed_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


@pytest.fixture
def repository(allowed_root: Path) -> Path:
    target = allowed_root / "project"
    target.mkdir()
    (target / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (target / "app.py").write_text(SOURCE, encoding="utf-8")
    return target


def create_assessment_with_target(
    session: Session,
    repository: Path,
) -> AssessmentJob:
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
    return assessment


def make_run(session: Session, assessment: AssessmentJob) -> AnalysisRun:
    now = datetime.now(UTC)
    run = AnalysisRun(
        assessment_id=assessment.id,
        status=AnalysisRunStatus.COMPLETED,
        created_at=now,
        started_at=now,
        completed_at=now,
    )
    session.add(run)
    session.commit()
    return run


def make_finding(title: str = "Static flow finding") -> Finding:
    return Finding(
        title=title,
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


def make_relationship() -> InputOperationRelationship:
    return InputOperationRelationship(
        relationship_id="inputs[0]->operations[0]",
        input_id="inputs[0]",
        input_index=0,
        input_type=InputType.QUERY,
        input_source_file="app.py",
        input_line_number=20,
        input_declaration="request.args.get('q')",
        input_resolution_status=InputResolutionStatus.RESOLVED,
        input_detection_confidence=0.8,
        operation_id="operations[0]",
        operation_index=0,
        operation_category=OperationCategory.DATABASE_READ,
        operation_source_file="app.py",
        operation_line_number=30,
        operation_declaration="cursor.execute(q)",
        operation_resolution_status=OperationResolutionStatus.RESOLVED,
        operation_detection_confidence=0.9,
        resolution_status=FlowResolutionStatus.RESOLVED,
        detection_confidence=0.72,
        route_ids=["route-1"],
        handler_references=[
            HandlerReference(
                handler_id="handler-1",
                route_id="route-1",
                handler_name="handler",
                source_file="app.py",
                line_number=18,
                route_path="/direct",
                http_method=HttpMethod.GET,
                framework=RouteFramework.FLASK,
            )
        ],
        propagation_steps=[
            PropagationStep(
                step_index=0,
                kind=FlowPropagationKind.INPUT_ACCESS,
                source_file="app.py",
                line_number=20,
                expression="request.args.get('q')",
                explanation="The input access was observed.",
            )
        ],
        explanation="A supported propagation path was recorded.",
        limitations=["Static analysis only."],
    )


def install_heartbeat_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> list[AnalysisHeartbeat]:
    """Capture heartbeat instances so tests can assert bounded shutdown."""
    captured: list[AnalysisHeartbeat] = []

    class CapturingHeartbeat(AnalysisHeartbeat):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)  # type: ignore[arg-type]
            captured.append(self)

    monkeypatch.setattr(analysis_execution, "AnalysisHeartbeat", CapturingHeartbeat)
    return captured


def test_collect_assessment_analysis_returns_every_stage_output(
    session_factory: sessionmaker[Session],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = SimpleNamespace(root=str(tmp_path))
    stages = {
        "technologies": "detect_technologies",
        "attack_surface": "identify_attack_surface",
        "auth_controls": "identify_auth_controls",
        "input_sources": "identify_input_sources",
        "sensitive_operations": "identify_sensitive_operations",
        "correlation": "correlate_attack_surface",
        "handler_calls": "analyze_handler_calls",
        "input_operation_flow": "analyze_input_operation_flow",
        "summary": "summarize_attack_surface",
    }
    values = {attribute: object() for attribute in stages}
    calls: list[str] = []

    def stage(name: str):
        def run(*_args: object) -> object:
            calls.append(name)
            return values[name]

        return run

    monkeypatch.setattr(
        attack_surface_reporting,
        "discover_registered_repository",
        lambda _db, _assessment_id, **_kwargs: discovery,
    )
    for attribute, function_name in stages.items():
        monkeypatch.setattr(
            attack_surface_reporting,
            function_name,
            stage(attribute),
        )

    with session_factory() as session:
        bundle = attack_surface_reporting.collect_assessment_analysis(
            session,
            uuid.uuid4(),
        )

    assert bundle.discovery is discovery
    for attribute, value in values.items():
        assert getattr(bundle, attribute) is value
    assert calls == list(values)


def test_summary_wrapper_returns_collector_summary(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summary = object()
    expected = SimpleNamespace(summary=summary)

    monkeypatch.setattr(
        attack_surface_reporting,
        "collect_assessment_analysis",
        lambda _db, _assessment_id, **_kwargs: expected,
    )

    with session_factory() as session:
        result = attack_surface_reporting.summarize_assessment_repository(
            session,
            uuid.uuid4(),
        )

    assert result is summary


def test_add_findings_associates_findings_with_the_run(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        run = make_run(session, assessment)

        persisted = finding_service.add_findings(
            session,
            assessment.id,
            [make_finding()],
            analysis_run_id=run.id,
        )
        session.commit()

        assert persisted[0].analysis_run_id == run.id

    with session_factory() as session:
        stored = session.scalar(select(AssessmentFinding))
        assert stored is not None
        assert stored.analysis_run_id == run.id


def test_add_findings_rejects_invalid_run_ownership(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        first = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        second = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        other_run = make_run(session, second)

        with pytest.raises(finding_service.AnalysisRunNotFoundError):
            finding_service.add_findings(
                session,
                first.id,
                [make_finding()],
                analysis_run_id=other_run.id,
            )
        session.rollback()

        with pytest.raises(finding_service.AnalysisRunNotFoundError):
            finding_service.add_findings(
                session,
                first.id,
                [make_finding()],
                analysis_run_id=uuid.uuid4(),
            )
        session.rollback()

        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0


def test_assessment_wide_positions_remain_unique_across_runs(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        first_run = make_run(session, assessment)
        second_run = make_run(session, assessment)

        finding_service.add_findings(
            session,
            assessment.id,
            [make_finding("First"), make_finding("Second")],
            analysis_run_id=first_run.id,
        )
        finding_service.add_findings(
            session,
            assessment.id,
            [make_finding("Third")],
            analysis_run_id=second_run.id,
        )
        session.commit()

        findings = session.scalars(
            select(AssessmentFinding).order_by(AssessmentFinding.position.asc())
        ).all()

        assert [finding.position for finding in findings] == [0, 1, 2]


def test_list_findings_supports_run_filter_and_legacy_rows(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        first_run = make_run(session, assessment)
        second_run = make_run(session, assessment)

        finding_service.add_findings(
            session,
            assessment.id,
            [make_finding("Legacy")],
        )
        finding_service.add_findings(
            session,
            assessment.id,
            [make_finding("First run")],
            analysis_run_id=first_run.id,
        )
        finding_service.add_findings(
            session,
            assessment.id,
            [make_finding("Second run")],
            analysis_run_id=second_run.id,
        )
        session.commit()

        all_findings = finding_service.list_findings(session, assessment.id)
        first_findings = finding_service.list_findings(
            session,
            assessment.id,
            analysis_run_id=first_run.id,
        )
        second_findings = finding_service.list_findings(
            session,
            assessment.id,
            analysis_run_id=second_run.id,
        )

        assert all_findings is not None
        assert [finding.title for finding in all_findings] == [
            "Legacy",
            "First run",
            "Second run",
        ]
        assert all_findings[0].analysis_run_id is None
        assert first_findings is not None
        assert [finding.title for finding in first_findings] == ["First run"]
        assert second_findings is not None
        assert [finding.title for finding in second_findings] == ["Second run"]

        with pytest.raises(finding_service.AnalysisRunNotFoundError):
            finding_service.list_findings(
                session,
                assessment.id,
                analysis_run_id=uuid.uuid4(),
            )


def test_add_findings_without_run_id_preserves_legacy_behavior(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )

        finding_service.add_findings(session, assessment.id, [make_finding()])
        session.commit()

        listed = finding_service.list_findings(session, assessment.id)

        assert listed is not None
        assert len(listed) == 1
        assert listed[0].analysis_run_id is None


def test_missing_assessment_is_rejected_before_run_creation(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        with pytest.raises(repository_targets.AssessmentNotFoundError):
            analysis_execution.execute_assessment_analysis(session, uuid.uuid4())

        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_missing_repository_target_is_rejected_before_run_creation(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )

        with pytest.raises(attack_surface_reporting.RepositoryTargetNotFoundError):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_stale_repository_target_is_rejected_before_run_creation(
    session_factory: sessionmaker[Session],
    repository: Path,
) -> None:
    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)
        shutil.rmtree(repository)

        with pytest.raises(InvalidRepositoryRootError, match="no longer valid"):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_repository_outside_allowed_roots_is_rejected_before_run_creation(
    session_factory: sessionmaker[Session],
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)
        other_root = tmp_path / "other"
        other_root.mkdir()
        monkeypatch.setattr(settings, "repository_allowed_roots", [other_root])

        with pytest.raises(InvalidRepositoryRootError, match="no longer valid"):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_running_run_is_committed_before_the_pipeline_executes(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_heartbeats = install_heartbeat_capture(monkeypatch)
    observed: dict[str, object] = {}

    def fail_after_observation(
        _db: Session,
        _assessment_id: uuid.UUID,
        **_kwargs: object,
    ) -> object:
        with session_factory() as observer:
            run = observer.scalar(select(AnalysisRun))
            assert run is not None
            observed["status"] = run.status
            observed["completed_at"] = run.completed_at
        raise RuntimeError("pipeline failed at C:\\secret\\repository")

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        fail_after_observation,
    )

    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)

        with pytest.raises(RuntimeError, match="pipeline failed"):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

    assert observed["status"] is AnalysisRunStatus.RUNNING
    assert observed["completed_at"] is None

    with session_factory() as session:
        run = session.scalar(select(AnalysisRun))
        assert run is not None
        assert run.status is AnalysisRunStatus.FAILED
        assert run.completed_at is not None
        assert run.error_message == "Assessment analysis failed."
        assert "secret" not in (run.error_message or "")
        assert "pipeline failed" not in (run.error_message or "")
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0

    assert len(captured_heartbeats) == 1
    assert captured_heartbeats[0].stop_event.is_set() is True
    assert captured_heartbeats[0].is_alive is False


def test_failed_completion_rolls_back_findings_and_marks_run_failed(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)
        assessment_id = assessment.id

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_completed_analysis_run",
            table="analysis_runs",
            event="UPDATE",
            message="forced completion failure",
            when="NEW.status = 'completed'",
        )

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        lambda _db, _assessment_id, **_kwargs: SimpleNamespace(
            discovery=None,
            summary=SimpleNamespace(summary=SimpleNamespace(is_complete=True)),
            input_operation_flow=SimpleNamespace(
                relationships=[make_relationship()],
            ),
        ),
    )
    monkeypatch.setattr(
        analysis_execution,
        "_build_analysis_metadata",
        lambda _results, _generation, **_kwargs: {"test": True},
    )

    with session_factory() as session:
        with pytest.raises(DBAPIError, match="forced completion failure"):
            analysis_execution.execute_assessment_analysis(session, assessment_id)

    with session_factory() as session:
        run = session.scalar(select(AnalysisRun))
        assert run is not None
        assert run.status is AnalysisRunStatus.FAILED
        assert run.completed_at is not None
        assert run.error_message == "Analysis run completion failed."
        assert "forced" not in (run.error_message or "")
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0


def test_deadline_expires_and_records_one_failure_event(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_heartbeats = install_heartbeat_capture(monkeypatch)
    monkeypatch.setattr(settings, "analysis_execution_timeout_seconds", 0)

    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)

        with pytest.raises(AnalysisDeadlineExceededError):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

    with session_factory() as session:
        run = session.scalar(select(AnalysisRun))
        assert run is not None
        events = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.resource_id == run.id)
                .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
            ).all()
        )
        findings = session.scalar(select(func.count()).select_from(AssessmentFinding))

    assert run.status is AnalysisRunStatus.FAILED
    assert run.completed_at is not None
    assert run.error_message == "Analysis timed out."
    assert run.analysis_metadata == {"failure_stage": "deadline"}
    assert findings == 0
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    assert events[1].context == {"failure_stage": "deadline"}

    assert len(captured_heartbeats) == 1
    assert captured_heartbeats[0].stop_event.is_set() is True
    assert captured_heartbeats[0].is_alive is False


def test_lease_loss_prevents_findings_and_completion(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def abort_during_collection(
        _db: Session,
        _assessment_id: uuid.UUID,
        *,
        execution_context: object,
    ) -> object:
        execution_context.request_abort()  # type: ignore[attr-defined]
        return SimpleNamespace(
            discovery=None,
            summary=SimpleNamespace(summary=SimpleNamespace(is_complete=True)),
            input_operation_flow=SimpleNamespace(relationships=[]),
        )

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        abort_during_collection,
    )

    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)

        with pytest.raises(AnalysisExecutionAbortedError):
            analysis_execution.execute_assessment_analysis(session, assessment.id)

    with session_factory() as session:
        run = session.scalar(select(AnalysisRun))
        assert run is not None
        events = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.resource_id == run.id)
                .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
            ).all()
        )
        findings = session.scalar(select(func.count()).select_from(AssessmentFinding))

    assert run.status is AnalysisRunStatus.FAILED
    assert run.status is not AnalysisRunStatus.COMPLETED
    assert findings == 0
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]


def test_successful_execution_persists_findings_and_completed_run(
    session_factory: sessionmaker[Session],
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_heartbeats = install_heartbeat_capture(monkeypatch)
    with session_factory() as session:
        assessment = create_assessment_with_target(session, repository)

        run = analysis_execution.execute_assessment_analysis(session, assessment.id)
        run_id = run.id

        assert run.status is AnalysisRunStatus.COMPLETED
        assert run.completed_at is not None
        assert run.error_message is None
        assert run.heartbeat_at is not None
        assert run.analysis_metadata is not None
        assert run.analysis_metadata["analyzer"]["version"] == settings.app_version
        assert run.analysis_metadata["finding_count"] >= 1
        assert run.analysis_metadata["finding_policy"]["generated_finding_count"] >= 1

        run_findings = finding_service.list_findings(
            session,
            assessment.id,
            analysis_run_id=run_id,
        )
        all_findings = finding_service.list_findings(session, assessment.id)

        assert run_findings is not None
        assert run_findings
        assert all_findings is not None
        assert all_findings == run_findings
        assert all(finding.analysis_run_id == run_id for finding in run_findings)
        assert all(finding.severity is FindingSeverity.INFORMATIONAL for finding in run_findings)
        assert all(finding.status is FindingStatus.NOT_TESTED for finding in run_findings)
        assert all(
            finding.evidence[0].details is not None
            and finding.evidence[0].details["relationship_id"]
            for finding in run_findings
        )

    assert len(captured_heartbeats) == 1
    assert captured_heartbeats[0].stop_event.is_set() is True
    assert captured_heartbeats[0].is_alive is False


def test_analysis_metadata_migration_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        columns = {column["name"] for column in inspect(engine).get_columns("analysis_runs")}
        assert "analysis_metadata" in columns
    finally:
        engine.dispose()

    command.downgrade(config, "0005")

    engine = create_db_engine(database_url)
    try:
        columns = {column["name"] for column in inspect(engine).get_columns("analysis_runs")}
        assert "analysis_metadata" not in columns
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        columns = {column["name"] for column in inspect(engine).get_columns("analysis_runs")}
        assert "analysis_metadata" in columns
    finally:
        engine.dispose()
