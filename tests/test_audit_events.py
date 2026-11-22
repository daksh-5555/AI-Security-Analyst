"""Durable audit-trail and lifecycle-authority regression tests."""

import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from db_triggers import create_failure_trigger, drop_failure_trigger
from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.main import app
from app.models.assessment import AssessmentJob
from app.models.assessment_status_history import AssessmentStatusHistory
from app.models.audit_event import AuditEvent
from app.schemas.enums import (
    AssessmentStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    RoleName,
)
from app.services import assessments as assessment_service
from app.services.assessments import InvalidStatusTransitionError
from app.services.audit import record_audit_event_safely

ASSESSMENTS_URL = "/api/v1/assessments"

SOURCE = """\
from flask import Flask, request

app = Flask(__name__)


@app.get("/search")
def search():
    return request.args.get("q", "")
"""


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
def fail_denial_audit_insert(db_engine: Engine) -> Generator[None, None, None]:
    """Fail only ``assessment.access_denied`` inserts with a real DB trigger."""

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_denial_audit_insert",
            table="audit_events",
            event="INSERT",
            message="forced denial audit failure",
            when="NEW.action = 'assessment.access_denied'",
        )
    try:
        yield
    finally:
        with db_engine.begin() as connection:
            drop_failure_trigger(connection, "fail_denial_audit_insert", table="audit_events")


async def create_assessment(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    assessment_type: str = "repository",
) -> dict[str, Any]:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": assessment_type},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def audit_events(
    session: Session,
    action: AuditAction | None = None,
) -> list[AuditEvent]:
    statement = select(AuditEvent).order_by(
        AuditEvent.occurred_at.asc(),
        AuditEvent.id.asc(),
    )
    if action is not None:
        statement = statement.where(AuditEvent.action == action)
    return list(session.scalars(statement).all())


@pytest.mark.anyio
async def test_assessment_creation_records_actor_and_resource(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    user_id, headers = make_assessment_principal(role=RoleName.SECURITY_ANALYST)

    created = await create_assessment(client, headers)

    assessment_id = uuid.UUID(created["id"])
    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ASSESSMENT_CREATED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.id is not None
    assert event.actor_user_id == user_id
    assert event.actor_user_id == uuid.UUID(created["owner_id"])
    assert event.assessment_id == assessment_id
    assert event.resource_id == assessment_id
    assert event.resource_type is AuditResourceType.ASSESSMENT
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.context == {"assessment_type": "repository"}
    assert isinstance(event.occurred_at, datetime)
    assert event.occurred_at.tzinfo is not None


@pytest.mark.anyio
async def test_lifecycle_transition_records_actor_and_statuses(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    user_id, headers = make_assessment_principal()
    created = await create_assessment(client, headers)

    response = await client.patch(
        f"{ASSESSMENTS_URL}/{created['id']}/status",
        json={"status": "running", "reason": "Worker claimed the job."},
        headers=headers,
    )
    assert response.status_code == 200, response.text

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_CHANGED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id == user_id
    assert event.assessment_id == uuid.UUID(created["id"])
    assert event.resource_id == uuid.UUID(created["id"])
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.context == {
        "previous_status": "queued",
        "new_status": "running",
    }
    # The user-supplied reason belongs to the status history, not the audit context.
    assert "reason" not in (event.context or {})


@pytest.mark.anyio
async def test_rejected_transition_records_denial_without_mutation(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    user_id, headers = make_assessment_principal()
    created = await create_assessment(client, headers)

    response = await client.patch(
        f"{ASSESSMENTS_URL}/{created['id']}/status",
        json={"status": "completed", "reason": "Must not persist."},
        headers=headers,
    )
    assert response.status_code == 422

    current = await client.get(f"{ASSESSMENTS_URL}/{created['id']}", headers=headers)
    assert current.json()["status"] == "queued"
    history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history", headers=headers)
    assert history.json() == []

    with session_factory() as session:
        denied = audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_DENIED)
        changed = audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_CHANGED)

    assert changed == []
    assert len(denied) == 1
    event = denied[0]
    assert event.actor_user_id == user_id
    assert event.resource_id == uuid.UUID(created["id"])
    assert event.assessment_id is None
    assert event.outcome is AuditOutcome.DENIED
    assert event.context == {
        "previous_status": "queued",
        "requested_status": "completed",
    }


@pytest.mark.anyio
async def test_repository_target_creation_is_audited_without_absolute_path(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
    repository_root: Path,
) -> None:
    user_id, headers = make_assessment_principal()
    created = await create_assessment(client, headers)
    repository = repository_root / "project"
    repository.mkdir()

    response = await client.post(
        f"{ASSESSMENTS_URL}/{created['id']}/repository",
        json={"source_kind": "local_path", "location": str(repository)},
        headers=headers,
    )
    assert response.status_code == 201, response.text

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.REPOSITORY_TARGET_CREATED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id == user_id
    assert event.resource_type is AuditResourceType.REPOSITORY_TARGET
    assert event.resource_id == uuid.UUID(response.json()["id"])
    assert event.assessment_id == uuid.UUID(created["id"])
    assert event.context == {"source_kind": "local_path"}
    assert str(repository.resolve()) not in str(event.context)
    assert headers["Authorization"] not in str(event.context)


@pytest.mark.anyio
async def test_analysis_run_initiation_is_attributed(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
    repository_root: Path,
) -> None:
    user_id, headers = make_assessment_principal()
    created = await create_assessment(client, headers)
    repository = repository_root / "project"
    repository.mkdir()
    (repository / "app.py").write_text(SOURCE, encoding="utf-8")

    registered = await client.post(
        f"{ASSESSMENTS_URL}/{created['id']}/repository",
        json={"source_kind": "local_path", "location": str(repository)},
        headers=headers,
    )
    assert registered.status_code == 201, registered.text

    response = await client.post(
        f"{ASSESSMENTS_URL}/{created['id']}/analysis-runs",
        headers=headers,
    )
    assert response.status_code == 201, response.text

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ANALYSIS_RUN_STARTED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id == user_id
    assert event.resource_type is AuditResourceType.ANALYSIS_RUN
    assert event.resource_id == uuid.UUID(response.json()["id"])
    assert event.assessment_id == uuid.UUID(created["id"])
    assert event.outcome is AuditOutcome.SUCCESS


@pytest.mark.anyio
async def test_cross_owner_denial_is_recorded_and_hides_existence(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, owner_headers = make_assessment_principal()
    other_id, other_headers = make_assessment_principal()
    created = await create_assessment(client, owner_headers)

    response = await client.get(
        f"{ASSESSMENTS_URL}/{created['id']}",
        headers=other_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id == other_id
    assert event.resource_id == uuid.UUID(created["id"])
    assert event.assessment_id is None
    assert event.outcome is AuditOutcome.DENIED
    assert event.context == {"reason": "not_visible", "operation": "read"}


@pytest.mark.anyio
async def test_nonexistent_assessment_denial_is_indistinguishable(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    user_id, headers = make_assessment_principal()
    requested = uuid.uuid4()

    response = await client.get(f"{ASSESSMENTS_URL}/{requested}", headers=headers)

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id == user_id
    assert event.resource_id == requested
    assert event.assessment_id is None
    assert event.context == {"reason": "not_visible", "operation": "read"}


@pytest.mark.anyio
async def test_viewer_write_denial_is_recorded_once(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    viewer_id, headers = make_assessment_principal(role=RoleName.VIEWER)

    response = await client.patch(
        f"{ASSESSMENTS_URL}/{uuid.uuid4()}/status",
        json={"status": "running"},
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions for this assessment operation"}

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id == viewer_id
    assert event.resource_id is None
    assert event.assessment_id is None
    assert event.context == {"reason": "insufficient_role", "required": "manage"}


@pytest.mark.anyio
async def test_admin_lifecycle_change_is_attributed_and_not_denied(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, owner_headers = make_assessment_principal()
    admin_id, admin_headers = make_assessment_principal(role=RoleName.ADMIN)
    created = await create_assessment(client, owner_headers)

    response = await client.patch(
        f"{ASSESSMENTS_URL}/{created['id']}/status",
        json={"status": "running"},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text

    with session_factory() as session:
        changed = audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_CHANGED)
        denied = audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED)

    assert len(changed) == 1
    assert changed[0].actor_user_id == admin_id
    assert denied == []


@pytest.mark.anyio
async def test_unauthenticated_denial_records_null_actor(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    requested = uuid.uuid4()

    response = await client.get(f"{ASSESSMENTS_URL}/{requested}")

    assert response.status_code == 401

    with session_factory() as session:
        recorded = audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED)

    assert len(recorded) == 1
    event = recorded[0]
    assert event.actor_user_id is None
    assert event.resource_id == requested
    assert event.assessment_id is None
    assert event.context == {"reason": "unauthenticated"}


@pytest.mark.anyio
async def test_unauthenticated_denial_survives_audit_insert_failure(
    client: httpx.AsyncClient,
    fail_denial_audit_insert: None,
    session_factory: sessionmaker[Session],
) -> None:
    requested = uuid.uuid4()

    response = await client.get(f"{ASSESSMENTS_URL}/{requested}")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired access token"}
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert "forced denial audit failure" not in response.text
    assert "audit_events" not in response.text
    assert "sqlite" not in response.text.lower()

    with session_factory() as session:
        assert audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED) == []
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0


@pytest.mark.anyio
async def test_viewer_denial_survives_audit_insert_failure(
    client: httpx.AsyncClient,
    fail_denial_audit_insert: None,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.VIEWER)

    response = await client.patch(
        f"{ASSESSMENTS_URL}/{uuid.uuid4()}/status",
        json={"status": "running"},
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions for this assessment operation"}
    assert "WWW-Authenticate" not in response.headers
    assert "forced denial audit failure" not in response.text
    assert "audit_events" not in response.text
    assert "sqlite" not in response.text.lower()

    with session_factory() as session:
        assert audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED) == []
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0


@pytest.mark.anyio
async def test_cross_owner_denial_survives_audit_insert_failure(
    client: httpx.AsyncClient,
    fail_denial_audit_insert: None,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, owner_headers = make_assessment_principal()
    _, other_headers = make_assessment_principal()
    created = await create_assessment(client, owner_headers)

    response = await client.get(
        f"{ASSESSMENTS_URL}/{created['id']}",
        headers=other_headers,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}
    assert "WWW-Authenticate" not in response.headers
    assert "forced denial audit failure" not in response.text
    assert "audit_events" not in response.text
    assert "sqlite" not in response.text.lower()

    with session_factory() as session:
        assert audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED) == []
        # The trigger is scoped to denial events, so the successful creation
        # audit is preserved and the table holds no partial denial row.
        assert len(audit_events(session, AuditAction.ASSESSMENT_CREATED)) == 1


def test_denial_audit_failure_leaves_session_clean_and_usable(
    fail_denial_audit_insert: None,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        record_audit_event_safely(
            session,
            action=AuditAction.ASSESSMENT_ACCESS_DENIED,
            outcome=AuditOutcome.DENIED,
            resource_type=AuditResourceType.ASSESSMENT,
            resource_id=None,
            assessment_id=None,
            actor_user_id=None,
            context={"reason": "unauthenticated"},
        )

        # The failed insert left no partial row and no poisoned transaction.
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0

        created = assessment_service.create_assessment(session, AssessmentType.REPOSITORY)
        assessment_id = created.id

    with session_factory() as session:
        assert session.get(AssessmentJob, assessment_id) is not None
        assert len(audit_events(session, AuditAction.ASSESSMENT_CREATED)) == 1
        assert audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED) == []


def test_record_audit_event_safely_discards_pending_business_work(
    session_factory: sessionmaker[Session],
) -> None:
    now = datetime.now(UTC)
    with session_factory() as session:
        staged = AssessmentJob(
            assessment_type=AssessmentType.REPOSITORY,
            status=AssessmentStatus.QUEUED,
            created_at=now,
            updated_at=now,
        )
        session.add(staged)
        session.flush()
        staged_id = staged.id

        # This is the documented precondition: the helper is only for rejection
        # paths where nothing staged needs to survive. It deliberately discards
        # pending business state before writing the denial event.
        record_audit_event_safely(
            session,
            action=AuditAction.ASSESSMENT_ACCESS_DENIED,
            outcome=AuditOutcome.DENIED,
            resource_type=AuditResourceType.ASSESSMENT,
            resource_id=None,
            assessment_id=None,
            actor_user_id=None,
            context={"reason": "unauthenticated"},
        )

    with session_factory() as session:
        assert session.get(AssessmentJob, staged_id) is None
        denied = audit_events(session, AuditAction.ASSESSMENT_ACCESS_DENIED)

    assert len(denied) == 1
    assert denied[0].assessment_id is None


@pytest.mark.anyio
async def test_audit_write_failure_rolls_back_assessment_creation(
    client: httpx.AsyncClient,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    # ``client`` installs the test-database dependency override. A second
    # transport suppresses Starlette's re-raise so the sanitized 500 body can be
    # observed.
    _, headers = make_assessment_principal()

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_audit_insert",
            table="audit_events",
            event="INSERT",
            message="forced audit failure",
        )

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as raw:
        response = await raw.post(
            ASSESSMENTS_URL,
            json={"assessment_type": "repository"},
            headers=headers,
        )

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert "forced audit failure" not in response.text
    assert "audit_events" not in response.text

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AssessmentJob)) == 0
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0


def test_audit_write_failure_rolls_back_lifecycle_change(
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
            "fail_audit_insert",
            table="audit_events",
            event="INSERT",
            message="forced audit failure",
        )

    with session_factory() as session:
        assessment = session.get(AssessmentJob, assessment_id)
        assert assessment is not None
        with pytest.raises(DBAPIError, match="forced audit failure"):
            assessment_service.apply_status_change(
                session,
                assessment,
                AssessmentStatus.RUNNING,
            )

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)
        assert stored is not None
        assert stored.status is AssessmentStatus.QUEUED
        assert session.scalar(select(func.count()).select_from(AssessmentStatusHistory)) == 0
        assert audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_CHANGED) == []


def test_public_service_api_exposes_only_authoritative_status_mutation() -> None:
    assert not hasattr(assessment_service, "record_status_change")
    assert callable(assessment_service.apply_status_change)

    public_status_mutators = {
        name
        for name in dir(assessment_service)
        if not name.startswith("_")
        and callable(getattr(assessment_service, name))
        and name.endswith("_status_change")
    }
    assert public_status_mutators == {"apply_status_change"}


def test_stale_transition_via_public_api_is_rejected_without_duplicate_history_or_audit(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        assessment_id = assessment.id

    with session_factory() as first, session_factory() as second:
        current = first.get(AssessmentJob, assessment_id)
        stale = second.get(AssessmentJob, assessment_id)
        assert current is not None
        assert stale is not None

        assessment_service.apply_status_change(
            first,
            current,
            AssessmentStatus.RUNNING,
        )

        with pytest.raises(InvalidStatusTransitionError):
            assessment_service.apply_status_change(
                second,
                stale,
                AssessmentStatus.RUNNING,
            )

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AssessmentStatusHistory)) == 1
        changed = audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_CHANGED)
        denied = audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_DENIED)
        assert len(changed) == 1
        assert len(denied) == 1
        assert denied[0].context == {
            "previous_status": "running",
            "requested_status": "running",
        }


def test_internal_record_status_change_rejects_invalid_transition_without_mutation(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        assessment_id = assessment.id

        with pytest.raises(InvalidStatusTransitionError):
            assessment_service._record_status_change(
                session,
                assessment,
                AssessmentStatus.COMPLETED,
            )
        session.rollback()

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)
        assert stored is not None
        assert stored.status is AssessmentStatus.QUEUED
        assert audit_events(session, AuditAction.ASSESSMENT_LIFECYCLE_CHANGED) == []


@pytest.mark.anyio
async def test_audit_history_survives_assessment_deletion(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal()
    created = await create_assessment(client, headers)
    assessment_id = uuid.UUID(created["id"])

    with session_factory() as session:
        session.execute(
            delete(AssessmentJob)
            .where(AssessmentJob.id == assessment_id)
            .execution_options(synchronize_session=False)
        )
        session.commit()

    with session_factory() as session:
        recorded = list(
            session.scalars(select(AuditEvent).where(AuditEvent.resource_id == assessment_id)).all()
        )

    assert len(recorded) == 1
    event = recorded[0]
    assert event.assessment_id is None
    assert event.resource_id == assessment_id
    assert event.action is AuditAction.ASSESSMENT_CREATED
