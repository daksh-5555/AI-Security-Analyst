import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from db_triggers import create_failure_trigger
from sqlalchemy import delete, func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import create_db_engine
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.finding_evidence import FindingEvidence
from app.schemas.enums import AssessmentType, FindingSeverity, FindingStatus
from app.schemas.finding import Evidence, Finding
from app.services import assessments as assessment_service
from app.services import findings as finding_service

ASSESSMENTS_URL = "/api/v1/assessments"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
# Additive normalized-finding fields (migration 0017, M7).
M7_FIELDS = frozenset(
    {
        "rule_id",
        "source_stage",
        "verification_method",
        "status_rationale",
        "cwe_ids",
        "cve_ids",
        "first_seen_at",
        "last_seen_at",
        "previous_status",
        "evidence_ids",
    }
)
LEGACY_M7_VALUES = {key: None for key in M7_FIELDS} | {"evidence_ids": []}

pytestmark = pytest.mark.usefixtures("assessment_client")


async def create_assessment(
    client: httpx.AsyncClient,
    assessment_type: str = "repository",
) -> dict[str, Any]:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": assessment_type},
    )
    assert response.status_code == 201
    return response.json()


def make_evidence(
    description: str = "Request input is concatenated into a SQL query.",
    source: str = "static-analysis",
    details: dict[str, Any] | None = None,
) -> Evidence:
    return Evidence(description=description, source=source, details=details)


def make_finding(
    title: str = "SQL injection in search endpoint",
    *,
    category: str = "SQL injection",
    severity: str = "high",
    status: str = "inconclusive",
    confidence: float = 0.6,
    summary: str = "User input reaches a query without parameterization.",
    affected_component: str | None = "app/search.py:42",
    remediation: str | None = "Use parameterized queries.",
    evidence: list[Evidence] | None = None,
) -> Finding:
    return Finding(
        title=title,
        category=category,
        severity=severity,
        status=status,
        confidence=confidence,
        summary=summary,
        affected_component=affected_component,
        evidence=evidence
        if evidence is not None
        else [make_evidence(details={"rule_id": "sql-injection"})],
        remediation=remediation,
    )


@pytest.mark.anyio
async def test_persist_and_list_findings(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])
    finding = make_finding()

    with session_factory() as session:
        persisted = finding_service.persist_findings(session, assessment_id, [finding])

        assert len(persisted) == 1
        stored = persisted[0]
        assert isinstance(stored, AssessmentFinding)
        assert stored.assessment_id == assessment_id
        assert stored.position == 0
        assert stored.title == finding.title
        assert stored.category == finding.category
        assert stored.severity is FindingSeverity.HIGH
        assert stored.status is FindingStatus.INCONCLUSIVE
        assert stored.confidence == finding.confidence
        assert stored.summary == finding.summary
        assert stored.affected_component == finding.affected_component
        assert stored.remediation == finding.remediation
        assert stored.created_at.tzinfo is not None
        assert stored.updated_at.tzinfo is not None
        assert len(stored.evidence) == 1
        assert stored.evidence[0].position == 0
        assert stored.evidence[0].description == finding.evidence[0].description
        assert stored.evidence[0].source == finding.evidence[0].source
        assert stored.evidence[0].details == finding.evidence[0].details

    with session_factory() as session:
        listed = finding_service.list_findings(session, assessment_id)

        assert listed is not None
        assert len(listed) == 1
        assert listed[0].title == finding.title
        assert listed[0].severity is FindingSeverity.HIGH
        assert listed[0].status is FindingStatus.INCONCLUSIVE
        assert listed[0].evidence[0].details == finding.evidence[0].details

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == str(stored.id)
    assert body[0]["analysis_run_id"] is None
    assert {
        key: value
        for key, value in body[0].items()
        if key not in {"id", "analysis_run_id", *M7_FIELDS}
    } == finding.model_dump(mode="json")
    # Findings persisted through the legacy path expose the additive M7 fields empty.
    assert {key: body[0][key] for key in M7_FIELDS} == LEGACY_M7_VALUES


@pytest.mark.anyio
async def test_multiple_findings_and_evidence_preserve_order(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])
    first = make_finding(
        title="First finding",
        evidence=[
            make_evidence("First evidence", "scanner-a", {"order": 1}),
            make_evidence("Second evidence", "scanner-b", {"order": 2}),
        ],
    )
    second = make_finding(
        title="Second finding",
        severity="critical",
        status="confirmed",
        evidence=[make_evidence("Third evidence", "scanner-c", {"order": 3})],
    )

    with session_factory() as session:
        persisted = finding_service.persist_findings(session, assessment_id, [first, second])

        assert [item.position for item in persisted] == [0, 1]
        assert [item.title for item in persisted] == ["First finding", "Second finding"]
        assert [evidence.position for evidence in persisted[0].evidence] == [0, 1]
        assert [evidence.description for evidence in persisted[0].evidence] == [
            "First evidence",
            "Second evidence",
        ]

    with session_factory() as session:
        third = make_finding(
            title="Third finding",
            evidence=[make_evidence("Fourth evidence", "scanner-d", {"order": 4})],
        )
        appended = finding_service.persist_findings(session, assessment_id, [third])

        assert appended[0].position == 2

    with session_factory() as session:
        listed = finding_service.list_findings(session, assessment_id)

        assert listed is not None
        assert [item.title for item in listed] == [
            "First finding",
            "Second finding",
            "Third finding",
        ]
        assert [evidence.position for evidence in listed[0].evidence] == [0, 1]
        assert [evidence.description for evidence in listed[0].evidence] == [
            "First evidence",
            "Second evidence",
        ]

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    body = response.json()
    assert [item["title"] for item in body] == [
        "First finding",
        "Second finding",
        "Third finding",
    ]
    assert [evidence["description"] for evidence in body[0]["evidence"]] == [
        "First evidence",
        "Second evidence",
    ]


@pytest.mark.anyio
async def test_json_details_and_enum_round_trip(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])
    details = {
        "rule_id": "sql-injection",
        "locations": [{"file": "app/search.py", "line": 42}],
        "enabled": True,
        "score": 0.9,
        "nothing": None,
    }
    finding = make_finding(
        severity="critical",
        status="confirmed",
        evidence=[make_evidence("Structured evidence", "static-analysis", details)],
    )

    with session_factory() as session:
        finding_service.persist_findings(session, assessment_id, [finding])

    with session_factory() as session:
        stored = session.scalar(select(AssessmentFinding))
        evidence = session.scalar(select(FindingEvidence))

        assert stored is not None
        assert stored.severity is FindingSeverity.CRITICAL
        assert stored.status is FindingStatus.CONFIRMED
        assert evidence is not None
        assert evidence.details == details

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    body = response.json()
    assert body[0]["severity"] == "critical"
    assert body[0]["status"] == "confirmed"
    assert body[0]["evidence"][0]["details"] == details


@pytest.mark.anyio
async def test_optional_fields_and_empty_evidence_round_trip(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])
    finding = make_finding(
        affected_component=None,
        remediation=None,
        evidence=[],
    )

    with session_factory() as session:
        persisted = finding_service.persist_findings(session, assessment_id, [finding])
        finding_id = persisted[0].id

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == str(finding_id)
    assert body[0]["analysis_run_id"] is None
    assert {
        key: value
        for key, value in body[0].items()
        if key not in {"id", "analysis_run_id", *M7_FIELDS}
    } == finding.model_dump(mode="json")
    # Findings persisted through the legacy path expose the additive M7 fields empty.
    assert {key: body[0][key] for key in M7_FIELDS} == LEGACY_M7_VALUES


@pytest.mark.anyio
async def test_null_evidence_details_round_trip(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])
    finding = make_finding(
        evidence=[Evidence(description="Manual observation.", source="manual")],
    )

    with session_factory() as session:
        persisted = finding_service.persist_findings(session, assessment_id, [finding])
        finding_id = persisted[0].id

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == str(finding_id)
    assert body[0]["analysis_run_id"] is None
    assert {
        key: value
        for key, value in body[0].items()
        if key not in {"id", "analysis_run_id", *M7_FIELDS}
    } == finding.model_dump(mode="json")
    # Findings persisted through the legacy path expose the additive M7 fields empty.
    assert {key: body[0][key] for key in M7_FIELDS} == LEGACY_M7_VALUES
    assert body[0]["evidence"][0]["details"] is None


@pytest.mark.anyio
async def test_empty_findings_return_empty_list(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])

    with session_factory() as session:
        assert finding_service.persist_findings(session, assessment_id, []) == []
        assert finding_service.list_findings(session, assessment_id) == []

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.anyio
async def test_unknown_assessment_returns_404_and_service_none(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    unknown_id = uuid.uuid4()

    with session_factory() as session:
        assert finding_service.list_findings(session, unknown_id) is None
        with pytest.raises(finding_service.AssessmentNotFoundError):
            finding_service.persist_findings(session, unknown_id, [make_finding()])

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0

    response = await client.get(f"{ASSESSMENTS_URL}/{unknown_id}/findings")

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_deleting_assessment_cascades_findings_and_evidence(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(assessment["id"])

    with session_factory() as session:
        finding_service.persist_findings(session, assessment_id, [make_finding()])

    with session_factory() as session:
        session.execute(delete(AssessmentJob).where(AssessmentJob.id == assessment_id))
        session.commit()

        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0


@pytest.mark.anyio
async def test_findings_submission_endpoint_is_not_exposed(
    client: httpx.AsyncClient,
) -> None:
    assessment = await create_assessment(client)

    response = await client.post(
        f"{ASSESSMENTS_URL}/{assessment['id']}/findings",
        json={},
    )

    assert response.status_code == 405


def test_persistence_failure_rolls_back_findings_and_evidence(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        assessment_id = assessment.id

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_finding_evidence_insert",
            table="finding_evidence",
            event="INSERT",
            message="forced evidence failure",
        )

    with session_factory() as session:
        with pytest.raises(DBAPIError, match="forced evidence failure"):
            finding_service.persist_findings(session, assessment_id, [make_finding()])

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AssessmentFinding)) == 0
        assert session.scalar(select(func.count()).select_from(FindingEvidence)) == 0


def test_findings_migration_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "assessment_findings" in tables
        assert "finding_evidence" in tables

        finding_columns = {
            column["name"] for column in inspector.get_columns("assessment_findings")
        }
        assert finding_columns == {
            "id",
            "assessment_id",
            "analysis_run_id",
            "position",
            "title",
            "category",
            "severity",
            "status",
            "confidence",
            "summary",
            "affected_component",
            "remediation",
            "created_at",
            "updated_at",
            # Added by migration 0017 (normalized findings, M7).
            "rule_id",
            "source_stage",
            "identity_key",
            "verification_method",
            "status_rationale",
            "cwe_ids",
            "cve_ids",
            "first_seen_at",
            "last_seen_at",
            "previous_status",
            "previous_finding_id",
        }

        evidence_columns = {column["name"] for column in inspector.get_columns("finding_evidence")}
        assert evidence_columns == {
            "id",
            "finding_id",
            "position",
            "description",
            "source",
            "details",
            "created_at",
        }

        finding_uniques = inspector.get_unique_constraints("assessment_findings")
        assert any(
            constraint["column_names"] == ["assessment_id", "position"]
            for constraint in finding_uniques
        )
        evidence_uniques = inspector.get_unique_constraints("finding_evidence")
        assert any(
            constraint["column_names"] == ["finding_id", "position"]
            for constraint in evidence_uniques
        )

        finding_foreign_keys = inspector.get_foreign_keys("assessment_findings")
        assert any(
            foreign_key["referred_table"] == "assessment_jobs"
            and foreign_key["constrained_columns"] == ["assessment_id"]
            and foreign_key["options"].get("ondelete") == "CASCADE"
            for foreign_key in finding_foreign_keys
        )
        evidence_foreign_keys = inspector.get_foreign_keys("finding_evidence")
        assert any(
            foreign_key["referred_table"] == "assessment_findings"
            and foreign_key["constrained_columns"] == ["finding_id"]
            and foreign_key["options"].get("ondelete") == "CASCADE"
            for foreign_key in evidence_foreign_keys
        )

        finding_checks = inspector.get_check_constraints("assessment_findings")
        assert any("confidence" in constraint["sqltext"] for constraint in finding_checks)
        assert any("position" in constraint["sqltext"] for constraint in finding_checks)
        evidence_checks = inspector.get_check_constraints("finding_evidence")
        assert any("position" in constraint["sqltext"] for constraint in evidence_checks)
    finally:
        engine.dispose()

    command.downgrade(config, "0003")

    engine = create_db_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert "assessment_findings" not in tables
        assert "finding_evidence" not in tables
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert "assessment_findings" in tables
        assert "finding_evidence" in tables
    finally:
        engine.dispose()
