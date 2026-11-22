"""Authorization regression tests for the assessment domain."""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from auth_helpers import remove_role
from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.orm import Session, sessionmaker

from app.api.constants import (
    ANALYSIS_RUN_NOT_FOUND_DETAIL,
    REPOSITORY_TARGET_NOT_FOUND_DETAIL,
)
from app.api.dependencies import require_assessment_manager, require_assessment_reader
from app.core.config import settings
from app.core.security import decode_access_token
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.user_session import UserSession
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentStatus,
    AssessmentType,
    RoleName,
)
from app.services import assessments as assessment_service
from app.services import authorization

ASSESSMENTS_URL = "/api/v1/assessments"
AUTH_FAILURE = {"detail": "Invalid or expired access token"}
FORBIDDEN = {"detail": "Insufficient permissions for this assessment operation"}
NOT_FOUND = {"detail": "Assessment not found"}

PrincipalFactory = Callable[..., tuple[uuid.UUID, dict[str, str]]]


@dataclass(frozen=True)
class StubPrincipal:
    user_id: uuid.UUID
    roles: tuple[str, ...]


@pytest.fixture
def repository_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


async def create_assessment(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    assessment_type: str = "repository",
) -> dict[str, object]:
    response = await client.post(
        ASSESSMENTS_URL,
        headers=headers,
        json={"assessment_type": assessment_type},
    )
    assert response.status_code == 201, response.text
    return response.json()


def assessment_url(assessment_id: object, suffix: str = "") -> str:
    return f"{ASSESSMENTS_URL}/{assessment_id}{suffix}"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("post", ASSESSMENTS_URL, {"json": {"assessment_type": "repository"}}),
        ("get", ASSESSMENTS_URL, {}),
        ("get", assessment_url(uuid.uuid4()), {}),
        (
            "patch",
            assessment_url(uuid.uuid4(), "/status"),
            {"json": {"status": "running"}},
        ),
        ("get", assessment_url(uuid.uuid4(), "/history"), {}),
        (
            "post",
            assessment_url(uuid.uuid4(), "/repository"),
            {"json": {"source_kind": "local_path", "location": "/tmp/repository"}},
        ),
        ("get", assessment_url(uuid.uuid4(), "/repository"), {}),
        ("get", assessment_url(uuid.uuid4(), "/findings"), {}),
        ("get", assessment_url(uuid.uuid4(), "/attack-surface/summary"), {}),
        ("post", assessment_url(uuid.uuid4(), "/analysis-runs"), {}),
        ("get", assessment_url(uuid.uuid4(), "/analysis-runs"), {}),
        (
            "get",
            assessment_url(uuid.uuid4(), f"/analysis-runs/{uuid.uuid4()}"),
            {},
        ),
    ],
)
async def test_anonymous_requests_are_rejected(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    kwargs: dict[str, object],
) -> None:
    response = await client.request(method, path, **kwargs)

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE
    assert response.headers.get("WWW-Authenticate") == "Bearer"


@pytest.mark.anyio
async def test_create_uses_principal_owner_and_rejects_owner_spoofing(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    user_id, headers = make_assessment_principal()

    created = await create_assessment(client, headers)

    assert created["owner_id"] == str(user_id)
    with session_factory() as session:
        stored = session.get(AssessmentJob, uuid.UUID(str(created["id"])))
        assert stored is not None
        assert stored.owner_id == user_id

    body_spoof = await client.post(
        ASSESSMENTS_URL,
        headers=headers,
        json={"assessment_type": "repository", "owner_id": str(uuid.uuid4())},
    )
    assert body_spoof.status_code == 422

    query_spoof = await client.post(
        ASSESSMENTS_URL,
        headers=headers,
        params={"owner_id": str(uuid.uuid4())},
        json={"assessment_type": "repository"},
    )
    assert query_spoof.status_code == 201
    assert query_spoof.json()["owner_id"] == str(user_id)


@pytest.mark.anyio
async def test_viewer_and_roleless_users_cannot_create_assessments(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, viewer_headers = make_assessment_principal(role=RoleName.VIEWER)
    _, roleless_headers = make_assessment_principal(role=None)

    viewer_response = await client.post(
        ASSESSMENTS_URL,
        headers=viewer_headers,
        json={"assessment_type": "repository"},
    )
    roleless_response = await client.post(
        ASSESSMENTS_URL,
        headers=roleless_headers,
        json={"assessment_type": "repository"},
    )

    assert viewer_response.status_code == 403
    assert viewer_response.json() == FORBIDDEN
    assert roleless_response.status_code == 403
    assert roleless_response.json() == FORBIDDEN


@pytest.mark.anyio
async def test_non_admin_lists_and_reads_only_own_assessments(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, first_headers = make_assessment_principal()
    _, second_headers = make_assessment_principal()
    _, admin_headers = make_assessment_principal(role=RoleName.ADMIN)

    first = await create_assessment(client, first_headers)
    second = await create_assessment(client, second_headers)

    second_list = await client.get(ASSESSMENTS_URL, headers=second_headers)
    second_read = await client.get(
        assessment_url(first["id"]),
        headers=second_headers,
    )
    missing = await client.get(
        assessment_url(uuid.uuid4()),
        headers=second_headers,
    )

    assert second_list.status_code == 200
    assert [item["id"] for item in second_list.json()] == [second["id"]]
    assert second_read.status_code == 404
    assert missing.status_code == 404
    assert second_read.json() == missing.json() == NOT_FOUND

    admin_list = await client.get(ASSESSMENTS_URL, headers=admin_headers)
    admin_first = await client.get(assessment_url(first["id"]), headers=admin_headers)

    assert admin_list.status_code == 200
    assert {item["id"] for item in admin_list.json()} == {first["id"], second["id"]}
    assert admin_first.status_code == 200
    assert admin_first.json()["id"] == first["id"]


@pytest.mark.anyio
async def test_null_owner_legacy_assessment_is_admin_only(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    with session_factory() as session:
        legacy = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        legacy_id = legacy.id

    _, analyst_headers = make_assessment_principal()
    _, viewer_headers = make_assessment_principal(role=RoleName.VIEWER)
    _, admin_headers = make_assessment_principal(role=RoleName.ADMIN)

    analyst_read = await client.get(assessment_url(legacy_id), headers=analyst_headers)
    viewer_read = await client.get(assessment_url(legacy_id), headers=viewer_headers)
    admin_read = await client.get(assessment_url(legacy_id), headers=admin_headers)
    analyst_list = await client.get(ASSESSMENTS_URL, headers=analyst_headers)
    admin_list = await client.get(ASSESSMENTS_URL, headers=admin_headers)

    assert analyst_read.status_code == 404
    assert viewer_read.status_code == 404
    assert analyst_read.json() == viewer_read.json() == NOT_FOUND
    assert analyst_list.json() == []
    assert admin_read.status_code == 200
    assert admin_read.json()["owner_id"] is None
    assert [item["id"] for item in admin_list.json()] == [str(legacy_id)]


@pytest.mark.anyio
async def test_cross_user_nested_reads_match_missing_resource_behavior(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, owner_headers = make_assessment_principal()
    _, other_headers = make_assessment_principal()
    owned = await create_assessment(client, owner_headers)
    missing_id = uuid.uuid4()
    missing_run = uuid.uuid4()

    paths = [
        "",
        "/history",
        "/repository",
        "/findings",
        "/attack-surface/summary",
        "/analysis-runs",
        f"/analysis-runs/{missing_run}",
    ]
    for suffix in paths:
        visible = await client.get(assessment_url(owned["id"], suffix), headers=other_headers)
        missing = await client.get(assessment_url(missing_id, suffix), headers=other_headers)
        assert visible.status_code == 404, suffix
        assert visible.json() == missing.json() == NOT_FOUND, suffix


@pytest.mark.anyio
async def test_cross_user_writes_and_execution_are_denied(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
    repository_root,
) -> None:
    _, owner_headers = make_assessment_principal()
    _, other_headers = make_assessment_principal()
    owned = await create_assessment(client, owner_headers)
    missing_id = uuid.uuid4()
    repository = repository_root / "project"
    repository.mkdir()

    payloads = [
        ("patch", "/status", {"json": {"status": "running"}}),
        (
            "post",
            "/repository",
            {"json": {"source_kind": "local_path", "location": str(repository)}},
        ),
        ("post", "/analysis-runs", {}),
    ]
    for method, suffix, kwargs in payloads:
        denied = await client.request(
            method,
            assessment_url(owned["id"], suffix),
            headers=other_headers,
            **kwargs,
        )
        missing = await client.request(
            method,
            assessment_url(missing_id, suffix),
            headers=other_headers,
            **kwargs,
        )
        assert denied.status_code == 404, suffix
        assert denied.json() == missing.json() == NOT_FOUND, suffix


@pytest.mark.anyio
async def test_viewer_reads_owned_assessment_but_cannot_mutate_or_execute(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
    repository_root,
) -> None:
    _, analyst_headers = make_assessment_principal()
    viewer_id, viewer_headers = make_assessment_principal(role=RoleName.VIEWER)
    owned = await create_assessment(client, analyst_headers)

    with session_factory() as session:
        session.execute(
            update(AssessmentJob)
            .where(AssessmentJob.id == uuid.UUID(str(owned["id"])))
            .values(owner_id=viewer_id)
        )
        session.commit()

    read = await client.get(assessment_url(owned["id"]), headers=viewer_headers)
    listed = await client.get(ASSESSMENTS_URL, headers=viewer_headers)
    status_change = await client.patch(
        assessment_url(owned["id"], "/status"),
        headers=viewer_headers,
        json={"status": "running"},
    )
    repository = repository_root / "viewer-repository"
    repository.mkdir()
    register = await client.post(
        assessment_url(owned["id"], "/repository"),
        headers=viewer_headers,
        json={"source_kind": "local_path", "location": str(repository)},
    )
    execute = await client.post(
        assessment_url(owned["id"], "/analysis-runs"),
        headers=viewer_headers,
    )

    assert read.status_code == 200
    assert [item["id"] for item in listed.json()] == [owned["id"]]
    for response in (status_change, register, execute):
        assert response.status_code == 403
        assert response.json() == FORBIDDEN


@pytest.mark.anyio
async def test_security_analyst_can_manage_owned_assessment(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, analyst_headers = make_assessment_principal()
    owned = await create_assessment(client, analyst_headers)

    transition = await client.patch(
        assessment_url(owned["id"], "/status"),
        headers=analyst_headers,
        json={"status": "running", "reason": "starting"},
    )
    history = await client.get(
        assessment_url(owned["id"], "/history"),
        headers=analyst_headers,
    )

    assert transition.status_code == 200
    assert transition.json()["status"] == "running"
    assert history.status_code == 200
    assert history.json()[0]["new_status"] == "running"


@pytest.mark.anyio
async def test_admin_can_manage_assessments_across_owners(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, analyst_headers = make_assessment_principal()
    _, admin_headers = make_assessment_principal(role=RoleName.ADMIN)
    owned = await create_assessment(client, analyst_headers)

    transition = await client.patch(
        assessment_url(owned["id"], "/status"),
        headers=admin_headers,
        json={"status": "running"},
    )
    read = await client.get(assessment_url(owned["id"]), headers=admin_headers)

    assert transition.status_code == 200
    assert transition.json()["status"] == "running"
    assert read.status_code == 200


@pytest.mark.anyio
async def test_roleless_user_has_no_assessment_access(
    client: httpx.AsyncClient,
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, roleless_headers = make_assessment_principal(role=None)
    _, admin_headers = make_assessment_principal(role=RoleName.ADMIN)
    owned = await create_assessment(client, admin_headers)

    with_id = await client.get(assessment_url(owned["id"]), headers=roleless_headers)
    random_id = await client.get(assessment_url(uuid.uuid4()), headers=roleless_headers)
    listing = await client.get(ASSESSMENTS_URL, headers=roleless_headers)

    assert with_id.status_code == random_id.status_code == listing.status_code == 403
    assert with_id.json() == random_id.json() == listing.json() == FORBIDDEN


def test_legacy_assessment_has_no_owner() -> None:
    """Guard the migration contract: legacy rows remain nullable and unowned."""
    assessment = AssessmentJob(
        assessment_type=AssessmentType.REPOSITORY,
        status=AssessmentStatus.QUEUED,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    assert assessment.owner_id is None


def test_malformed_roles_fail_closed() -> None:
    principal = StubPrincipal(
        user_id=uuid.uuid4(),
        roles=("ADMIN", "Security-Analyst", "superuser", "", " security_analyst"),
    )

    assert authorization.is_admin(principal) is False
    assert authorization.can_read_assessments(principal) is False
    assert authorization.can_manage_assessments(principal) is False

    statement = authorization.visible_assessments_statement(principal)
    assert "assessment_jobs.owner_id" in str(statement)

    for dependency in (require_assessment_reader, require_assessment_manager):
        with pytest.raises(HTTPException) as exc_info:
            dependency(principal)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == FORBIDDEN["detail"]


@pytest.mark.anyio
async def test_existing_run_from_another_assessment_is_not_reachable_through_mismatched_parent(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, headers = make_assessment_principal()
    parent = await create_assessment(client, headers)
    run_owner = await create_assessment(client, headers)

    now = datetime.now(UTC)
    with session_factory() as session:
        run = AnalysisRun(
            assessment_id=uuid.UUID(str(run_owner["id"])),
            status=AnalysisRunStatus.COMPLETED,
            created_at=now,
            started_at=now,
            completed_at=now,
        )
        session.add(run)
        session.commit()
        run_id = run.id

    mismatched = await client.get(
        assessment_url(parent["id"], f"/analysis-runs/{run_id}"),
        headers=headers,
    )
    correct_parent = await client.get(
        assessment_url(run_owner["id"], f"/analysis-runs/{run_id}"),
        headers=headers,
    )

    assert mismatched.status_code == 404
    assert mismatched.json() == {"detail": ANALYSIS_RUN_NOT_FOUND_DETAIL}
    assert correct_parent.status_code == 200
    assert correct_parent.json()["id"] == str(run_id)


@pytest.mark.anyio
async def test_admin_can_access_legacy_null_owner_nested_resources(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    with session_factory() as session:
        legacy = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        legacy_id = legacy.id

    _, analyst_headers = make_assessment_principal()
    _, admin_headers = make_assessment_principal(role=RoleName.ADMIN)

    analyst_history = await client.get(
        assessment_url(legacy_id, "/history"),
        headers=analyst_headers,
    )
    admin_history = await client.get(
        assessment_url(legacy_id, "/history"),
        headers=admin_headers,
    )
    admin_findings = await client.get(
        assessment_url(legacy_id, "/findings"),
        headers=admin_headers,
    )
    admin_runs = await client.get(
        assessment_url(legacy_id, "/analysis-runs"),
        headers=admin_headers,
    )
    admin_repository = await client.get(
        assessment_url(legacy_id, "/repository"),
        headers=admin_headers,
    )
    admin_missing_run = await client.get(
        assessment_url(legacy_id, f"/analysis-runs/{uuid.uuid4()}"),
        headers=admin_headers,
    )

    assert analyst_history.status_code == 404
    assert analyst_history.json() == NOT_FOUND
    assert admin_history.status_code == 200
    assert admin_history.json() == []
    assert admin_findings.status_code == 200
    assert admin_findings.json() == []
    assert admin_runs.status_code == 200
    assert admin_runs.json() == []
    assert admin_repository.status_code == 404
    assert admin_repository.json() == {"detail": REPOSITORY_TARGET_NOT_FOUND_DETAIL}
    assert admin_missing_run.status_code == 404
    assert admin_missing_run.json() == {"detail": ANALYSIS_RUN_NOT_FOUND_DETAIL}


@pytest.mark.anyio
async def test_owner_id_cannot_be_injected_into_update_body(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    owner_id, headers = make_assessment_principal()
    other_id, _ = make_assessment_principal()
    created = await create_assessment(client, headers)

    response = await client.patch(
        assessment_url(created["id"], "/status"),
        headers=headers,
        json={"status": "running", "owner_id": str(other_id)},
    )

    assert response.status_code == 422
    with session_factory() as session:
        stored = session.get(AssessmentJob, uuid.UUID(str(created["id"])))
        assert stored is not None
        assert stored.owner_id == owner_id
        assert stored.status is AssessmentStatus.QUEUED


@pytest.mark.anyio
async def test_session_revocation_is_reflected_on_assessment_access(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    _, headers = make_assessment_principal()
    created = await create_assessment(client, headers)
    assert (await client.get(assessment_url(created["id"]), headers=headers)).status_code == 200

    token = headers["Authorization"].removeprefix("Bearer ")
    session_id = decode_access_token(token).sid
    with session_factory() as session:
        user_session = session.get(UserSession, session_id)
        assert user_session is not None
        user_session.revoked_at = datetime.now(UTC)
        session.commit()

    revoked = await client.get(assessment_url(created["id"]), headers=headers)

    assert revoked.status_code == 401
    assert revoked.json() == AUTH_FAILURE


@pytest.mark.anyio
async def test_role_revocation_is_reflected_on_assessment_access(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal: PrincipalFactory,
) -> None:
    user_id, headers = make_assessment_principal()
    created = await create_assessment(client, headers)
    assert (await client.get(assessment_url(created["id"]), headers=headers)).status_code == 200

    remove_role(session_factory, user_id, RoleName.SECURITY_ANALYST)

    revoked = await client.get(assessment_url(created["id"]), headers=headers)

    assert revoked.status_code == 403
    assert revoked.json() == FORBIDDEN
