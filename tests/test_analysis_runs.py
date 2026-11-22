import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, func, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import create_db_engine
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.finding_evidence import FindingEvidence
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    FindingSeverity,
    FindingStatus,
)
from app.schemas.finding import Evidence, Finding
from app.services import assessments as assessment_service
from app.services import findings as finding_service

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def migration_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def create_assessment(session: Session) -> AssessmentJob:
    return assessment_service.create_assessment(session, AssessmentType.REPOSITORY)


def make_run(session: Session, assessment: AssessmentJob) -> AnalysisRun:
    run = AnalysisRun(
        assessment_id=assessment.id,
        status=AnalysisRunStatus.COMPLETED,
        completed_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()
    return run


def make_finding(
    assessment_id: uuid.UUID,
    *,
    position: int = 0,
    analysis_run_id: uuid.UUID | None = None,
    with_evidence: bool = False,
) -> AssessmentFinding:
    return AssessmentFinding(
        assessment_id=assessment_id,
        analysis_run_id=analysis_run_id,
        position=position,
        title="Observed input reaches a sensitive operation",
        category="input_to_sensitive_operation",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.INCONCLUSIVE,
        confidence=0.7,
        summary="A static propagation path was observed.",
        evidence=(
            [
                FindingEvidence(
                    position=0,
                    description="Static flow evidence",
                    source="input_operation_flow",
                    details={"relationship_id": "inputs[0]->operations[0]"},
                )
            ]
            if with_evidence
            else []
        ),
    )


def test_analysis_run_creation_and_defaults(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        run = AnalysisRun(assessment_id=assessment.id)

        session.add(run)
        session.commit()
        session.refresh(run)

        assert isinstance(run.id, uuid.UUID)
        assert run.status is AnalysisRunStatus.RUNNING
        assert run.created_at.tzinfo is not None
        assert run.started_at.tzinfo is not None
        assert run.completed_at is None
        assert run.error_message is None
        assert run.heartbeat_at is None
        assert run.cancel_requested_at is None
        assert run.cancel_requested_by_user_id is None


def test_analysis_run_assessment_relationship(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        run = make_run(session, assessment)
        session.commit()

        assert run.assessment.id == assessment.id
        assert assessment.analysis_runs == [run]


def test_assessment_deletion_cascades_to_runs(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        run = make_run(session, assessment)
        session.commit()
        run_id = run.id

        session.delete(assessment)
        session.commit()

        assert session.get(AnalysisRun, run_id) is None
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_run_deletion_cascades_to_findings_and_evidence(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        run = make_run(session, assessment)
        finding = make_finding(
            assessment.id,
            analysis_run_id=run.id,
            with_evidence=True,
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id
        run_id = run.id

        session.delete(run)
        session.commit()

        assert session.get(AnalysisRun, run_id) is None
        assert session.get(AssessmentFinding, finding_id) is None
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0


def test_assessment_deletion_cascades_through_both_run_and_finding_paths(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        run = make_run(session, assessment)
        finding = make_finding(
            assessment.id,
            analysis_run_id=run.id,
            with_evidence=True,
        )
        session.add(finding)
        session.commit()

        session.delete(assessment)
        session.commit()

        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0


def test_existing_findings_remain_valid_with_null_analysis_run_id(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        persisted = finding_service.add_findings(
            session,
            assessment.id,
            [
                Finding(
                    title="Legacy finding",
                    category="legacy",
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.INCONCLUSIVE,
                    confidence=0.5,
                    summary="Created without an analysis run.",
                    evidence=[Evidence(description="Legacy evidence", source="test")],
                )
            ],
        )
        session.commit()

        stored = session.get(AssessmentFinding, persisted[0].id)
        assert stored is not None
        assert stored.analysis_run_id is None
        assert finding_service.list_findings(session, assessment.id) == [stored]


def test_analysis_run_migration_upgrade_and_downgrade(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = migration_config(database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        assert "analysis_runs" in tables
        assert {column["name"] for column in inspector.get_columns("analysis_runs")} == {
            "id",
            "assessment_id",
            "status",
            "created_at",
            "started_at",
            "completed_at",
            "error_message",
            "analysis_metadata",
            "heartbeat_at",
            "cancel_requested_at",
            "cancel_requested_by_user_id",
            # 0018 (M8): durable background execution.
            "requested_by_user_id",
            "lease_owner",
            "lease_expires_at",
            "stage",
            "attempts",
            "error_code",
            "summary_snapshot",
        }
        assert any(
            index["name"] == "ix_analysis_runs_assessment_id_created_at"
            and index["column_names"] == ["assessment_id", "created_at"]
            for index in inspector.get_indexes("analysis_runs")
        )
        assert any(
            foreign_key["referred_table"] == "assessment_jobs"
            and foreign_key["constrained_columns"] == ["assessment_id"]
            and foreign_key["options"].get("ondelete") == "CASCADE"
            for foreign_key in inspector.get_foreign_keys("analysis_runs")
        )

        finding_columns = {
            column["name"] for column in inspector.get_columns("assessment_findings")
        }
        assert "analysis_run_id" in finding_columns
        assert any(
            index["name"] == "ix_assessment_findings_analysis_run_id"
            and index["column_names"] == ["analysis_run_id"]
            for index in inspector.get_indexes("assessment_findings")
        )
        assert any(
            foreign_key["referred_table"] == "analysis_runs"
            and foreign_key["constrained_columns"] == ["analysis_run_id"]
            and foreign_key["options"].get("ondelete") == "CASCADE"
            for foreign_key in inspector.get_foreign_keys("assessment_findings")
        )
    finally:
        engine.dispose()

    command.downgrade(config, "0004")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        assert "analysis_runs" not in tables
        assert "analysis_run_id" not in {
            column["name"] for column in inspector.get_columns("assessment_findings")
        }
        assert any(
            constraint["column_names"] == ["assessment_id", "position"]
            for constraint in inspector.get_unique_constraints("assessment_findings")
        )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert "analysis_runs" in set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_migration_preserves_existing_assessment_and_finding_rows(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = migration_config(database_url)

    command.upgrade(config, "0004")

    assessment_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    now = datetime.now(UTC)

    engine = create_db_engine(database_url)
    try:
        metadata = MetaData()
        assessments = Table("assessment_jobs", metadata, autoload_with=engine)
        findings = Table("assessment_findings", metadata, autoload_with=engine)

        with engine.begin() as connection:
            connection.execute(
                assessments.insert().values(
                    id=assessment_id.hex,
                    assessment_type="repository",
                    status="queued",
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                findings.insert().values(
                    id=finding_id.hex,
                    assessment_id=assessment_id.hex,
                    position=0,
                    title="Legacy finding",
                    category="legacy",
                    severity="medium",
                    status="inconclusive",
                    confidence=0.5,
                    summary="Created before analysis runs existed.",
                    affected_component=None,
                    remediation=None,
                    created_at=now,
                    updated_at=now,
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        with Session(engine) as session:
            stored = session.get(AssessmentFinding, finding_id)

            assert stored is not None
            assert stored.analysis_run_id is None
            assert stored.title == "Legacy finding"
            assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
    finally:
        engine.dispose()


def test_assessment_wide_finding_position_uniqueness_remains_enforced(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment(session)
        first_run = make_run(session, assessment)
        second_run = make_run(session, assessment)

        session.add_all(
            [
                make_finding(assessment.id, position=0, analysis_run_id=first_run.id),
                make_finding(assessment.id, position=0, analysis_run_id=second_run.id),
            ]
        )

        with pytest.raises(IntegrityError):
            session.commit()

        session.rollback()

        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
