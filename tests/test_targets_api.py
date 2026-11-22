"""Target authorization API, analysis gating, and repository isolation (M4).

Uses real access tokens (not a principal override) so ownership and roles are
exercised end to end across several users.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment_target import AssessmentTarget
from app.models.audit_event import AuditEvent
from app.schemas.enums import AuditAction, RoleName, TargetStatus

URL = "/api/v1/assessments"
STATEMENT = "Owner of dvwa.test lab environment authorized this test (ticket LAB-1)."


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    allowed = tmp_path / "repositories"
    allowed.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["dvwa.test"])
    return allowed


@pytest.fixture
def users(make_assessment_principal):
    owner_id, owner = make_assessment_principal()
    _other_id, other = make_assessment_principal()
    _viewer_id, viewer = make_assessment_principal(role=RoleName.VIEWER)
    _admin_id, admin = make_assessment_principal(role=RoleName.ADMIN)
    return {"owner_id": owner_id, "owner": owner, "other": other, "viewer": viewer, "admin": admin}


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return path


async def create(client: httpx.AsyncClient, headers: dict, kind: str = "web_security") -> str:
    response = await client.post(URL, json={"assessment_type": kind}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def register_web(client, headers, assessment_id, **overrides):  # noqa: ANN001, ANN201
    body = {
        "base_url": "http://DVWA.test/app/",
        "authorization_statement": STATEMENT,
        "confirm_authorized": True,
        **overrides,
    }
    return await client.post(f"{URL}/{assessment_id}/web-target", json=body, headers=headers)


@pytest.mark.anyio
async def test_web_target_registration_is_explicit_audited_and_listed(
    client: httpx.AsyncClient, root: Path, users: dict, session_factory: sessionmaker[Session]
) -> None:
    assessment_id = await create(client, users["owner"])
    response = await register_web(client, users["owner"], assessment_id)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["target"] == "http://dvwa.test/app/"
    assert body["status"] == "authorized"
    assert body["authorization_basis"] == "explicit_confirmation"
    assert body["authorization_statement"] == STATEMENT
    assert body["authorized_by_user_id"] == str(users["owner_id"])
    assert body["policy_snapshot"]["allowed_schemes"] == ["http", "https"]

    listed = await client.get(f"{URL}/{assessment_id}/targets", headers=users["owner"])
    assert [item["id"] for item in listed.json()] == [body["id"]]
    with session_factory() as session:
        actions = session.scalars(
            select(AuditEvent.action).where(AuditEvent.resource_id == uuid.UUID(body["id"]))
        ).all()
    assert actions == [AuditAction.ASSESSMENT_TARGET_AUTHORIZED]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("overrides", "status"),
    [
        ({"confirm_authorized": False}, 422),
        ({"authorization_statement": "too short"}, 422),
        ({"base_url": "http://not-allowlisted.test/"}, 422),
        ({"base_url": "http://user:pw@dvwa.test/"}, 422),
        ({"base_url": "file:///etc/passwd"}, 422),
        ({"base_url": "http://dvwa.test/?id=1"}, 422),
    ],
)
async def test_web_target_registration_rejections(
    client: httpx.AsyncClient, root: Path, users: dict, overrides: dict, status: int
) -> None:
    assessment_id = await create(client, users["owner"])
    response = await register_web(client, users["owner"], assessment_id, **overrides)
    assert response.status_code == status
    assert "pw" not in response.text


@pytest.mark.anyio
async def test_wrong_type_duplicate_and_unqueued_are_conflicts(
    client: httpx.AsyncClient, root: Path, users: dict
) -> None:
    repo_assessment = await create(client, users["owner"], kind="repository")
    assert (await register_web(client, users["owner"], repo_assessment)).status_code == 409

    web = await create(client, users["owner"])
    assert (await register_web(client, users["owner"], web)).status_code == 201
    assert (await register_web(client, users["owner"], web)).status_code == 409

    running = await create(client, users["owner"])
    await client.patch(
        f"{URL}/{running}/status", json={"status": "running"}, headers=users["owner"]
    )
    assert (await register_web(client, users["owner"], running)).status_code == 409


@pytest.mark.anyio
async def test_only_owner_or_admin_can_manage_targets(
    client: httpx.AsyncClient, root: Path, users: dict
) -> None:
    assessment_id = await create(client, users["owner"])
    target = (await register_web(client, users["owner"], assessment_id)).json()
    revoke = f"{URL}/{assessment_id}/targets/{target['id']}/revoke"

    assert (await register_web(client, users["other"], assessment_id)).status_code == 404
    assert (await client.post(revoke, headers=users["other"])).status_code == 404
    assert (await client.post(revoke, headers=users["viewer"])).status_code == 403
    assert (
        await client.get(f"{URL}/{assessment_id}/targets", headers=users["other"])
    ).status_code == 404
    assert (await client.post(revoke, headers=users["admin"])).status_code == 200


@pytest.mark.anyio
async def test_revocation_blocks_analysis_until_reauthorized(
    client: httpx.AsyncClient, root: Path, users: dict, session_factory: sessionmaker[Session]
) -> None:
    assessment_id = await create(client, users["owner"], kind="repository")
    repo = make_repo(root / "project")
    registered = await client.post(
        f"{URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repo)},
        headers=users["owner"],
    )
    assert registered.status_code == 201

    targets = (await client.get(f"{URL}/{assessment_id}/targets", headers=users["owner"])).json()
    assert len(targets) == 1
    repository_target = targets[0]
    assert repository_target["target_type"] == "repository"
    assert repository_target["target"] == "project"  # never the absolute path
    assert repository_target["authorization_basis"] == "owner_registration"
    assert str(root) not in str(targets)

    revoked = await client.post(
        f"{URL}/{assessment_id}/targets/{repository_target['id']}/revoke", headers=users["owner"]
    )
    assert revoked.json()["status"] == "revoked"
    run = await client.post(f"{URL}/{assessment_id}/analysis-runs", headers=users["owner"])
    summary = await client.get(
        f"{URL}/{assessment_id}/attack-surface/summary", headers=users["owner"]
    )
    assert run.status_code == 409 and summary.status_code == 409
    assert run.json() == {"detail": "Target authorization is required before analysis"}
    with session_factory() as session:
        assert session.scalar(select(func.count(AnalysisRun.id))) == 0  # no run record created

    again = await client.post(
        f"{URL}/{assessment_id}/targets/{repository_target['id']}/revoke", headers=users["owner"]
    )
    assert again.status_code == 409
    reauthorized = await client.post(
        f"{URL}/{assessment_id}/targets/{repository_target['id']}/authorize",
        json={"authorization_statement": STATEMENT, "confirm_authorized": True},
        headers=users["owner"],
    )
    assert reauthorized.status_code == 200
    assert reauthorized.json()["authorization_basis"] == "explicit_confirmation"
    run = await client.post(f"{URL}/{assessment_id}/analysis-runs", headers=users["owner"])
    assert run.status_code == 201


@pytest.mark.anyio
async def test_legacy_pending_target_is_blocked(
    client: httpx.AsyncClient, root: Path, users: dict, session_factory: sessionmaker[Session]
) -> None:
    assessment_id = await create(client, users["owner"], kind="repository")
    repo = make_repo(root / "legacy")
    await client.post(
        f"{URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repo)},
        headers=users["owner"],
    )
    with session_factory() as session:
        session.execute(
            update(AssessmentTarget).values(
                status=TargetStatus.PENDING_AUTHORIZATION, authorization_basis=None
            )
        )
        session.commit()
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs", headers=users["owner"])
    assert response.status_code == 409


@pytest.mark.anyio
async def test_unknown_target_returns_404(
    client: httpx.AsyncClient, root: Path, users: dict
) -> None:
    assessment_id = await create(client, users["owner"])
    other = await create(client, users["owner"])
    target = (await register_web(client, users["owner"], other)).json()
    response = await client.post(
        f"{URL}/{assessment_id}/targets/{target['id']}/revoke", headers=users["owner"]
    )
    assert response.status_code == 404


# --- per-user repository isolation (fixes S-7) -----------------------------------


@pytest.mark.anyio
async def test_per_user_isolation_confines_repositories_to_the_owner_subroot(
    client: httpx.AsyncClient,
    root: Path,
    users: dict,
    make_assessment_principal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "repository_isolation", "per_user")
    other_id, other = make_assessment_principal()
    own = make_repo(root / str(users["owner_id"]) / "mine")
    theirs = make_repo(root / str(other_id) / "secret-project")
    shared = make_repo(root / "shared-project")

    async def register(headers: dict, location: Path) -> httpx.Response:
        assessment_id = await create(client, headers, kind="repository")
        return await client.post(
            f"{URL}/{assessment_id}/repository",
            json={"source_kind": "local_path", "location": str(location)},
            headers=headers,
        )

    accepted = await register(users["owner"], own)
    assert accepted.status_code == 201
    stolen = await register(users["owner"], theirs)
    outside = await register(users["owner"], shared)
    assert stolen.status_code == outside.status_code == 422
    assert stolen.text == outside.text  # no hint that the other user's path exists
    assert "secret-project" not in stolen.text

    run = await client.post(
        f"{URL}/{accepted.json()['assessment_id']}/analysis-runs", headers=users["owner"]
    )
    assert run.status_code == 201


@pytest.mark.anyio
async def test_isolation_is_rechecked_at_analysis_time(
    client: httpx.AsyncClient, root: Path, users: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = make_repo(root / "shared-project")
    assessment_id = await create(client, users["owner"], kind="repository")
    registered = await client.post(
        f"{URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(shared)},
        headers=users["owner"],
    )
    assert registered.status_code == 201  # allowed under the shared layout
    monkeypatch.setattr(settings, "repository_isolation", "per_user")
    run = await client.post(f"{URL}/{assessment_id}/analysis-runs", headers=users["owner"])
    summary = await client.get(
        f"{URL}/{assessment_id}/attack-surface/summary", headers=users["owner"]
    )
    assert run.status_code == 422 and summary.status_code == 422
