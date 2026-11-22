import shutil
import textwrap
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from disclosure_helpers import assert_no_path_disclosure
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import get_current_principal
from app.core.config import settings
from app.main import app
from app.models.analysis_run import AnalysisRun
from app.models.assessment_finding import AssessmentFinding
from app.models.audit_event import AuditEvent
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentType,
    AuditAction,
    FindingSeverity,
    FindingStatus,
    RepositorySourceKind,
)
from app.schemas.finding import Evidence, Finding
from app.services import analysis_execution
from app.services import findings as finding_service
from app.services.analysis_admission import ANALYSIS_RUN_SCOPE, analysis_admission
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
)

ASSESSMENTS_URL = "/api/v1/assessments"

pytestmark = pytest.mark.usefixtures("assessment_client")
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


async def create_assessment(
    client: httpx.AsyncClient,
    assessment_type: AssessmentType = AssessmentType.REPOSITORY,
) -> dict[str, object]:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": assessment_type.value},
    )
    assert response.status_code == 201
    return response.json()


async def create_assessment_with_repository(
    client: httpx.AsyncClient,
    repository: Path,
) -> dict[str, object]:
    assessment = await create_assessment(client)
    assessment_id = assessment["id"]
    response = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={
            "source_kind": RepositorySourceKind.LOCAL_PATH.value,
            "location": str(repository),
        },
    )
    assert response.status_code == 201
    return assessment


def runs_url(assessment_id: object) -> str:
    return f"{ASSESSMENTS_URL}/{assessment_id}/analysis-runs"


def run_url(assessment_id: object, run_id: object) -> str:
    return f"{runs_url(assessment_id)}/{run_id}"


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


def create_run(
    session: Session,
    assessment_id: uuid.UUID,
    *,
    run_id: uuid.UUID | None = None,
    created_at: datetime | None = None,
    status: AnalysisRunStatus = AnalysisRunStatus.COMPLETED,
    analysis_metadata: dict[str, object] | None = None,
) -> AnalysisRun:
    timestamp = created_at or datetime.now(UTC)
    run = AnalysisRun(
        id=run_id or uuid.uuid4(),
        assessment_id=assessment_id,
        status=status,
        created_at=timestamp,
        started_at=timestamp,
        completed_at=timestamp if status is not AnalysisRunStatus.RUNNING else None,
        analysis_metadata=analysis_metadata,
    )
    session.add(run)
    session.flush()
    return run


def add_run_findings(
    session: Session,
    assessment_id: uuid.UUID,
    run_id: uuid.UUID,
    titles: list[str],
) -> None:
    finding_service.add_findings(
        session,
        assessment_id,
        [make_finding(title) for title in titles],
        analysis_run_id=run_id,
    )
    session.commit()


@pytest.mark.anyio
async def test_post_executes_synchronously_and_returns_created_run(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment = await create_assessment_with_repository(client, repository)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 201
    body = response.json()
    assert response.headers["location"] == run_url(assessment["id"], body["id"])
    assert body["assessment_id"] == assessment["id"]
    assert body["status"] == AnalysisRunStatus.COMPLETED.value
    assert body["completed_at"] is not None
    assert body["error_message"] is None
    assert body["findings_count"] >= 1
    assert body["analysis_metadata"]["analyzer"]["version"] == settings.app_version
    assert body["analysis_metadata"]["finding_count"] == body["findings_count"]
    assert "findings" not in body

    detail = await client.get(run_url(assessment["id"], body["id"]))
    assert detail.status_code == 200
    assert detail.json()["id"] == body["id"]


@pytest.mark.anyio
async def test_post_finding_count_matches_run_scoped_findings(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment_with_repository(client, repository)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 201
    body = response.json()
    with session_factory() as session:
        findings = finding_service.list_findings(
            session,
            uuid.UUID(assessment["id"]),
            analysis_run_id=uuid.UUID(body["id"]),
        )
        assert findings is not None
        assert body["findings_count"] == len(findings)
        assert all(finding.analysis_run_id == uuid.UUID(body["id"]) for finding in findings)


@pytest.mark.anyio
async def test_post_unknown_assessment_returns_not_found(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(runs_url(uuid.uuid4()))

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_post_without_repository_target_returns_not_found(
    client: httpx.AsyncClient,
) -> None:
    assessment = await create_assessment(client)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 404
    assert response.json() == {"detail": "Repository target not found"}


@pytest.mark.anyio
async def test_post_with_stale_repository_target_returns_sanitized_422(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    shutil.rmtree(repository)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 422
    assert response.json() == {"detail": "Registered repository target is no longer valid"}
    assert_no_path_disclosure(response.json(), repository)
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


@pytest.mark.anyio
async def test_post_conflict_returns_sanitized_409(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    assessment_id = uuid.UUID(str(assessment["id"]))

    with session_factory() as session:
        active = AnalysisRun(assessment_id=assessment_id)
        session.add(active)
        session.commit()
        active_id = active.id

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 409
    assert response.json() == {"detail": "Analysis run already in progress"}
    assert "UNIQUE" not in response.text
    assert "uq_analysis_runs_active_assessment" not in response.text
    assert "analysis_runs" not in response.text
    assert "INSERT" not in response.text

    history = await client.get(runs_url(assessment["id"]))
    assert history.status_code == 200
    assert [item["id"] for item in history.json()] == [str(active_id)]
    assert history.json()[0]["status"] == AnalysisRunStatus.RUNNING.value


@pytest.mark.anyio
async def test_failed_run_returns_generic_error_and_retains_failed_run(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_analysis(
        _db: Session,
        _assessment_id: uuid.UUID,
        **_kwargs: object,
    ) -> object:
        raise RuntimeError("failure at C:\\secret\\repository")

    monkeypatch.setattr(
        analysis_execution,
        "collect_assessment_analysis",
        fail_analysis,
    )
    assessment = await create_assessment_with_repository(client, repository)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 500
    assert response.json() == {"detail": "Analysis run failed"}
    assert "secret" not in response.text

    with session_factory() as session:
        run = session.scalar(select(AnalysisRun))
        assert run is not None
        assert run.status is AnalysisRunStatus.FAILED
        assert run.completed_at is not None
        assert run.error_message == "Assessment analysis failed."


@pytest.mark.anyio
async def test_deadline_returns_504_and_records_one_terminal_event(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_execution_timeout_seconds", 0)
    assessment = await create_assessment_with_repository(client, repository)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 504
    assert response.json() == {"detail": "Analysis timed out"}
    assert "Traceback" not in response.text
    assert "C:\\" not in response.text

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
    assert run.error_message == "Analysis timed out."
    assert run.analysis_metadata == {"failure_stage": "deadline"}
    assert findings == 0
    assert [event.action for event in events] == [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    assert events[1].context == {"failure_stage": "deadline"}


@pytest.mark.anyio
async def test_list_returns_runs_newest_first_with_finding_counts(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(str(assessment["id"]))
    base = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    with session_factory() as session:
        oldest = create_run(session, assessment_id, created_at=base)
        middle = create_run(
            session,
            assessment_id,
            created_at=base + timedelta(minutes=1),
        )
        newest = create_run(
            session,
            assessment_id,
            created_at=base + timedelta(minutes=2),
        )
        add_run_findings(
            session,
            assessment_id,
            newest.id,
            ["First", "Second"],
        )

    response = await client.get(runs_url(assessment["id"]))

    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body] == [
        str(newest.id),
        str(middle.id),
        str(oldest.id),
    ]
    assert [item["findings_count"] for item in body] == [2, 0, 0]
    assert "analysis_metadata" not in body[0]
    assert "findings" not in body[0]


@pytest.mark.anyio
async def test_list_breaks_created_at_ties_by_descending_run_id(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(str(assessment["id"]))
    timestamp = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    with session_factory() as session:
        lower = create_run(
            session,
            assessment_id,
            run_id=uuid.UUID(int=1),
            created_at=timestamp,
        )
        higher = create_run(
            session,
            assessment_id,
            run_id=uuid.UUID(int=2),
            created_at=timestamp,
        )
        session.commit()

    response = await client.get(runs_url(assessment["id"]))

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [
        str(higher.id),
        str(lower.id),
    ]


@pytest.mark.anyio
async def test_list_unknown_assessment_returns_not_found(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(runs_url(uuid.uuid4()))

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_get_returns_detail_with_metadata_and_finding_count(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(str(assessment["id"]))
    metadata = {"finding_count": 1, "completeness": {"is_complete": True}}

    with session_factory() as session:
        run = create_run(
            session,
            assessment_id,
            analysis_metadata=metadata,
        )
        add_run_findings(session, assessment_id, run.id, ["Only finding"])

    response = await client.get(run_url(assessment["id"], run.id))

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(run.id)
    assert body["analysis_metadata"] == metadata
    assert body["findings_count"] == 1
    assert "findings" not in body


@pytest.mark.anyio
async def test_get_unknown_run_returns_not_found(
    client: httpx.AsyncClient,
) -> None:
    assessment = await create_assessment(client)

    response = await client.get(run_url(assessment["id"], uuid.uuid4()))

    assert response.status_code == 404
    assert response.json() == {"detail": "Analysis run not found"}


@pytest.mark.anyio
async def test_get_run_from_another_assessment_returns_not_found(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    first = await create_assessment(client)
    second = await create_assessment(client)

    with session_factory() as session:
        other_run = create_run(session, uuid.UUID(str(second["id"])))
        session.commit()

    response = await client.get(run_url(first["id"], other_run.id))

    assert response.status_code == 404
    assert response.json() == {"detail": "Analysis run not found"}


@pytest.mark.anyio
async def test_findings_without_run_filter_keep_assessment_wide_behavior(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(str(assessment["id"]))

    with session_factory() as session:
        run = create_run(session, assessment_id)
        add_run_findings(session, assessment_id, run.id, ["Run finding"])
        finding_service.add_findings(session, assessment_id, [make_finding("Legacy finding")])
        session.commit()
        legacy = session.scalar(
            select(AssessmentFinding).where(AssessmentFinding.title == "Legacy finding")
        )
        assert legacy is not None
        legacy_id = legacy.id

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert response.status_code == 200
    body = response.json()
    assert [item["title"] for item in body] == ["Run finding", "Legacy finding"]
    assert body[0]["analysis_run_id"] == str(run.id)
    assert body[1]["analysis_run_id"] is None
    assert body[1]["id"] == str(legacy_id)


@pytest.mark.anyio
async def test_findings_run_filter_returns_only_that_run(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment(client)
    assessment_id = uuid.UUID(str(assessment["id"]))

    with session_factory() as session:
        first_run = create_run(session, assessment_id)
        second_run = create_run(session, assessment_id)
        add_run_findings(session, assessment_id, first_run.id, ["First run finding"])
        add_run_findings(session, assessment_id, second_run.id, ["Second run finding"])

    response = await client.get(
        f"{ASSESSMENTS_URL}/{assessment['id']}/findings",
        params={"analysis_run_id": str(second_run.id)},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["title"] == "Second run finding"
    assert body[0]["analysis_run_id"] == str(second_run.id)
    assert uuid.UUID(body[0]["id"])


@pytest.mark.anyio
async def test_findings_filter_rejects_unknown_or_mismatched_run(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    first = await create_assessment(client)
    second = await create_assessment(client)

    with session_factory() as session:
        other_run = create_run(session, uuid.UUID(str(second["id"])))
        session.commit()

    unknown = await client.get(
        f"{ASSESSMENTS_URL}/{first['id']}/findings",
        params={"analysis_run_id": str(uuid.uuid4())},
    )
    mismatched = await client.get(
        f"{ASSESSMENTS_URL}/{first['id']}/findings",
        params={"analysis_run_id": str(other_run.id)},
    )

    assert unknown.status_code == 404
    assert unknown.json() == {"detail": "Analysis run not found"}
    assert mismatched.status_code == 404
    assert mismatched.json() == {"detail": "Analysis run not found"}


@pytest.mark.anyio
async def test_openapi_documents_new_routes_and_findings_filter(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    paths = schema["paths"]
    assert "/api/v1/assessments/{assessment_id}/analysis-runs" in paths
    assert "/api/v1/assessments/{assessment_id}/analysis-runs/{run_id}" in paths
    assert "post" in paths["/api/v1/assessments/{assessment_id}/analysis-runs"]
    assert "get" in paths["/api/v1/assessments/{assessment_id}/analysis-runs"]

    post_responses = paths["/api/v1/assessments/{assessment_id}/analysis-runs"]["post"]["responses"]
    assert "201" in post_responses
    assert "404" in post_responses
    assert "409" in post_responses
    assert "504" in post_responses

    parameters = paths["/api/v1/assessments/{assessment_id}/findings"]["get"]["parameters"]
    run_parameter = next(
        parameter for parameter in parameters if parameter["name"] == "analysis_run_id"
    )
    assert run_parameter["in"] == "query"
    assert run_parameter["required"] is False
    assert run_parameter["schema"]["anyOf"][0]["format"] == "uuid"


@pytest.mark.anyio
async def test_existing_attack_surface_summary_remains_unchanged(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment = await create_assessment_with_repository(client, repository)

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/attack-surface/summary")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert "root" not in body
    assert body["repository"] == "project"
    assert_no_path_disclosure(response.json(), repository)
    assert "routes" in body
    assert "summary" in body


@pytest.mark.anyio
async def test_existing_assessment_and_findings_endpoints_remain_compatible(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment = await create_assessment_with_repository(client, repository)

    assessment_response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}")
    findings_response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/findings")

    assert assessment_response.status_code == 200
    assert assessment_response.json()["id"] == assessment["id"]
    assert findings_response.status_code == 200
    assert findings_response.json() == []


def current_principal_user_id() -> uuid.UUID:
    """Return the user id installed by the assessment_client fixture."""
    return app.dependency_overrides[get_current_principal]().user_id


def lifecycle_event_count(session: Session) -> int:
    actions = [
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_COMPLETED,
        AuditAction.ANALYSIS_RUN_FAILED,
    ]
    return (
        session.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action.in_(actions))
        )
        or 0
    )


@pytest.mark.anyio
async def test_post_global_capacity_saturation_returns_503_without_creating_a_run(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    analysis_admission.reset(global_limit=1, per_user_limit=1, queue_wait_seconds=0)
    try:
        with analysis_admission.global_slot():
            response = await client.post(runs_url(assessment["id"]))
    finally:
        analysis_admission.reset()

    assert response.status_code == 503
    assert response.json() == {"detail": "Analysis capacity is temporarily unavailable"}
    assert response.headers["retry-after"] == "1"

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        assert lifecycle_event_count(session) == 0


@pytest.mark.anyio
async def test_post_per_user_quota_returns_429_without_creating_a_run(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    user_id = current_principal_user_id()
    with analysis_admission.run_slot(user_id):
        response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 429
    assert response.json() == {"detail": "Too many concurrent analysis runs for this user"}
    assert int(response.headers["retry-after"]) >= 1

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        assert lifecycle_event_count(session) == 0


@pytest.mark.anyio
async def test_post_rate_limit_returns_429_without_creating_a_run(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 1)
    assessment = await create_assessment_with_repository(client, repository)
    analysis_admission.check_rate_limit(ANALYSIS_RUN_SCOPE, current_principal_user_id())

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 429
    assert response.json() == {"detail": "Analysis request rate limit exceeded"}
    assert int(response.headers["retry-after"]) >= 1

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0
        assert lifecycle_event_count(session) == 0


@pytest.mark.anyio
async def test_post_releases_admission_slots_after_success(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    user_id = current_principal_user_id()

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 201
    assert analysis_admission.active_global == 0
    assert analysis_admission.active_for_user(user_id) == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("error_type", "expected_status"),
    [
        (AnalysisDeadlineExceededError, 504),
        # M8: a cancelled/stopped synchronous run is a 409, not a server error.
        (AnalysisExecutionAbortedError, 409),
        (RuntimeError, 500),
    ],
)
async def test_post_releases_admission_slots_after_pipeline_failure(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    expected_status: int,
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    user_id = current_principal_user_id()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise error_type()

    monkeypatch.setattr(analysis_execution, "execute_assessment_analysis", fail)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == expected_status
    assert analysis_admission.active_global == 0
    assert analysis_admission.active_for_user(user_id) == 0


@pytest.mark.anyio
async def test_post_invalid_and_unauthenticated_requests_acquire_no_slots(
    client: httpx.AsyncClient,
) -> None:
    malformed = await client.post("/api/v1/assessments/not-a-uuid/analysis-runs")
    missing = await client.post(runs_url(uuid.uuid4()))

    assert malformed.status_code == 422
    assert missing.status_code == 404

    override = app.dependency_overrides.pop(get_current_principal)
    try:
        unauthorized = await client.post(runs_url(uuid.uuid4()))
    finally:
        app.dependency_overrides[get_current_principal] = override

    assert unauthorized.status_code == 401
    assert analysis_admission.active_global == 0


@pytest.mark.anyio
async def test_execution_deadline_context_is_created_after_admission(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment = await create_assessment_with_repository(client, repository)
    observed_active_permits: list[int] = []
    real_context = analysis_execution.AnalysisExecutionContext

    def recording_context(*args: object, **kwargs: object):
        observed_active_permits.append(analysis_admission.active_global)
        return real_context(*args, **kwargs)

    monkeypatch.setattr(analysis_execution, "AnalysisExecutionContext", recording_context)

    response = await client.post(runs_url(assessment["id"]))

    assert response.status_code == 201
    assert observed_active_permits == [1]
