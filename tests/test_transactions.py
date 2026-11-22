from typing import Any

import pytest
from db_triggers import create_failure_trigger
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.assessment_status_history import AssessmentStatusHistory
from app.models.finding_evidence import FindingEvidence
from app.schemas.enums import AssessmentStatus, AssessmentType
from app.schemas.finding import Evidence, Finding
from app.services import assessments as assessment_service
from app.services import findings as finding_service


def make_evidence(
    description: str = "Request input is concatenated into a SQL query.",
    source: str = "static-analysis",
    details: dict[str, Any] | None = None,
) -> Evidence:
    return Evidence(description=description, source=source, details=details)


def make_finding(
    title: str,
    evidence: list[Evidence] | None = None,
) -> Finding:
    return Finding(
        title=title,
        category="SQL injection",
        severity="high",
        status="inconclusive",
        confidence=0.6,
        summary="User input reaches a query without parameterization.",
        affected_component="app/search.py:42",
        remediation="Use parameterized queries.",
        evidence=evidence
        if evidence is not None
        else [make_evidence(details={"rule_id": "sql-injection"})],
    )


def create_assessment_with_status(
    session: Session,
    status: AssessmentStatus,
) -> AssessmentJob:
    assessment = assessment_service.create_assessment(session, AssessmentType.REPOSITORY)
    if status is not AssessmentStatus.QUEUED:
        assessment_service.apply_status_change(session, assessment, status)
    return assessment


def test_findings_and_status_change_compose_in_one_transaction(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment_with_status(session, AssessmentStatus.RUNNING)
        assessment_id = assessment.id

    with session_factory() as session:
        assessment = session.get(AssessmentJob, assessment_id)
        assert assessment is not None
        assert assessment.status is AssessmentStatus.RUNNING

        added = finding_service.add_findings(
            session,
            assessment_id,
            [
                make_finding(
                    "First finding",
                    evidence=[
                        make_evidence("First evidence", "scanner-a", {"order": 1}),
                        make_evidence("Second evidence", "scanner-b", {"order": 2}),
                    ],
                ),
                make_finding(
                    "Second finding",
                    evidence=[make_evidence("Third evidence", "scanner-c", {"order": 3})],
                ),
            ],
        )
        history = assessment_service._record_status_change(
            session,
            assessment,
            AssessmentStatus.COMPLETED,
            reason="Scan finished.",
        )

        assert [finding.title for finding in added] == ["First finding", "Second finding"]
        assert history.previous_status is AssessmentStatus.RUNNING
        assert history.new_status is AssessmentStatus.COMPLETED
        assert history.reason == "Scan finished."
        assert assessment.status is AssessmentStatus.COMPLETED
        session.commit()

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)
        assert stored is not None
        assert stored.status is AssessmentStatus.COMPLETED

        findings = list(
            session.scalars(
                select(AssessmentFinding).order_by(AssessmentFinding.position.asc())
            ).all()
        )
        assert [finding.title for finding in findings] == ["First finding", "Second finding"]
        assert [finding.position for finding in findings] == [0, 1]

        evidence = list(session.scalars(select(FindingEvidence)).all())
        assert len(evidence) == 3

        history_records = list(
            session.scalars(
                select(AssessmentStatusHistory).order_by(
                    AssessmentStatusHistory.changed_at.asc(),
                    AssessmentStatusHistory.id.asc(),
                )
            ).all()
        )
        assert [(record.previous_status, record.new_status) for record in history_records] == [
            (AssessmentStatus.QUEUED, AssessmentStatus.RUNNING),
            (AssessmentStatus.RUNNING, AssessmentStatus.COMPLETED),
        ]
        assert history_records[1].reason == "Scan finished."


def test_composed_operations_roll_back_atomically(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment_with_status(session, AssessmentStatus.RUNNING)
        assessment_id = assessment.id

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_completed_history_insert",
            table="assessment_status_history",
            event="INSERT",
            message="forced completed history failure",
            when="NEW.new_status = 'completed'",
        )

    with session_factory() as session:
        assessment = session.get(AssessmentJob, assessment_id)
        assert assessment is not None
        assert assessment.status is AssessmentStatus.RUNNING

        finding_service.add_findings(
            session,
            assessment_id,
            [
                make_finding(
                    "First finding",
                    evidence=[make_evidence("First evidence", "scanner-a")],
                ),
                make_finding(
                    "Second finding",
                    evidence=[
                        make_evidence("Second evidence", "scanner-b"),
                        make_evidence("Third evidence", "scanner-c"),
                    ],
                ),
            ],
        )

        with pytest.raises(DBAPIError, match="forced completed history failure"):
            assessment_service._record_status_change(
                session,
                assessment,
                AssessmentStatus.COMPLETED,
                reason="This transition must not persist.",
            )

        session.rollback()

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)
        assert stored is not None
        assert stored.status is AssessmentStatus.RUNNING

        finding_count = session.scalar(select(func.count()).select_from(AssessmentFinding))
        evidence_count = session.scalar(select(func.count()).select_from(FindingEvidence))
        assert finding_count == 0
        assert evidence_count == 0

        history_records = list(session.scalars(select(AssessmentStatusHistory)).all())
        assert len(history_records) == 1
        assert history_records[0].previous_status is AssessmentStatus.QUEUED
        assert history_records[0].new_status is AssessmentStatus.RUNNING
        completed_count = session.scalar(
            select(func.count())
            .select_from(AssessmentStatusHistory)
            .where(AssessmentStatusHistory.new_status == AssessmentStatus.COMPLETED)
        )
        assert completed_count == 0


def test_internal_operations_do_not_commit(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = create_assessment_with_status(session, AssessmentStatus.RUNNING)
        assessment_id = assessment.id

    with session_factory() as session:
        assessment = session.get(AssessmentJob, assessment_id)
        assert assessment is not None

        finding_service.add_findings(session, assessment_id, [make_finding("Uncommitted finding")])
        assessment_service._record_status_change(
            session,
            assessment,
            AssessmentStatus.COMPLETED,
        )
        # Closing the session without committing must roll the transaction back.

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)
        assert stored is not None
        assert stored.status is AssessmentStatus.RUNNING
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0
        assert session.scalar(select(func.count()).select_from(AssessmentStatusHistory)) == 1
