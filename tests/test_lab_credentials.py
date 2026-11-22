"""Authenticated local-lab sessions for web targets (M15, ADR-0018). Loopback only."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import httpx
import pytest
from dvwa_fixtures import DvwaHandler, dvwa_site
from sqlalchemy.orm import Session, sessionmaker
from test_security_config import DEPLOYMENT_SETTINGS, TEST_SECRET

from app.core.config import (
    SecurityConfigurationError,
    Settings,
    settings,
    validate_security_configuration,
)
from app.models.audit_event import AuditEvent
from app.models.web_target_lab_session import WebTargetLabSession
from app.schemas.enums import AuditAction
from app.services.net import lab_session as lab_session_mod

URL = "/api/v1/assessments"

pytestmark = pytest.mark.usefixtures("assessment_client")


@pytest.fixture
def lab(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["127.0.0.1"])
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])
    monkeypatch.setattr(settings, "web_target_max_requests_per_second", 50.0)
    monkeypatch.setattr(settings, "crawler_respect_robots", False)
    monkeypatch.setattr(settings, "web_auth_lab_enabled", True)
    with dvwa_site() as port:
        yield port


async def web_target(client: httpx.AsyncClient, port: int) -> str:
    assessment_id = (await client.post(URL, json={"assessment_type": "web_security"})).json()["id"]
    response = await client.post(
        f"{URL}/{assessment_id}/web-target",
        json={
            "base_url": f"http://127.0.0.1:{port}/",
            "authorization_statement": "Local DVWA-style lab owned by the test.",
            "confirm_authorized": True,
        },
    )
    assert response.status_code == 201, response.text
    return assessment_id


def lab_path(assessment_id: str) -> str:
    return f"{URL}/{assessment_id}/web-target/lab-credentials"


# --- establish / store ----------------------------------------------------------


@pytest.mark.anyio
async def test_login_stores_only_the_cookie_never_the_password(
    client: httpx.AsyncClient, lab: int, session_factory: sessionmaker[Session]
) -> None:
    assessment_id = await web_target(client, lab)
    response = await client.post(
        lab_path(assessment_id), json={"username": "admin", "password": "password"}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body == {
        "assessment_id": assessment_id,
        "configured": True,
        "username": "admin",
        "login_path": "/login.php",
        "established_at": body["established_at"],
    }
    assert "cookie" not in json.dumps(body).lower()
    # Exactly one login attempt: login-only, never guessing.
    assert DvwaHandler.counters["login_attempts"] == 1

    with session_factory() as session:
        row = session.scalar(select_lab(uuid.UUID(assessment_id)))
        assert row is not None and row.cookie_header and "PHPSESSID=" in row.cookie_header
        assert "password" not in row.cookie_header
        # The password is nowhere in the stored row.
        dumped = json.dumps({c.name: str(getattr(row, c.name)) for c in row.__table__.columns})
        assert "password" not in dumped
        event = session.scalar(select_audit(AuditAction.WEB_TARGET_LAB_SESSION_ESTABLISHED))
        assert event is not None and "password" not in json.dumps(event.context or {})


def select_lab(assessment_id: uuid.UUID):  # noqa: ANN201
    from sqlalchemy import select

    return select(WebTargetLabSession).where(WebTargetLabSession.assessment_id == assessment_id)


def select_audit(action: AuditAction):  # noqa: ANN201
    from sqlalchemy import select

    return select(AuditEvent).where(AuditEvent.action == action)


@pytest.mark.anyio
async def test_get_reports_configured_without_the_cookie(
    client: httpx.AsyncClient, lab: int
) -> None:
    assessment_id = await web_target(client, lab)
    before = (await client.get(lab_path(assessment_id))).json()
    assert before["configured"] is False and before["username"] is None
    await client.post(lab_path(assessment_id), json={"username": "admin", "password": "password"})
    after = (await client.get(lab_path(assessment_id))).json()
    assert after["configured"] is True and after["username"] == "admin"
    assert "cookie" not in json.dumps(after).lower()


@pytest.mark.anyio
async def test_wrong_credentials_do_not_establish_a_session(
    client: httpx.AsyncClient, lab: int
) -> None:
    assessment_id = await web_target(client, lab)
    response = await client.post(
        lab_path(assessment_id), json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 502
    assert (await client.get(lab_path(assessment_id))).json()["configured"] is False


@pytest.mark.anyio
async def test_feature_disabled_by_default(
    client: httpx.AsyncClient, lab: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "web_auth_lab_enabled", False)
    assessment_id = await web_target(client, lab)
    response = await client.post(
        lab_path(assessment_id), json={"username": "admin", "password": "password"}
    )
    assert response.status_code == 400
    assert DvwaHandler.counters["login_attempts"] == 0  # nothing contacted


@pytest.mark.anyio
async def test_delete_clears_the_session(client: httpx.AsyncClient, lab: int) -> None:
    assessment_id = await web_target(client, lab)
    await client.post(lab_path(assessment_id), json={"username": "admin", "password": "password"})
    assert (await client.delete(lab_path(assessment_id))).status_code == 204
    assert (await client.get(lab_path(assessment_id))).json()["configured"] is False
    assert (await client.delete(lab_path(assessment_id))).status_code == 404


# --- authenticated scanning -----------------------------------------------------


@pytest.mark.anyio
async def test_authenticated_run_reaches_the_protected_surface(
    client: httpx.AsyncClient,
    lab: int,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    monkeypatch.setattr(settings, "runtime_probes_enabled", True)
    assessment_id = await web_target(client, lab)

    # Without a lab session: every page redirects to login, so nothing is found.
    anon = (await client.post(f"{URL}/{assessment_id}/analysis-runs")).json()
    anon_findings = (await client.get(f"{URL}/{assessment_id}/findings")).json()
    assert anon_findings == []
    anon_crawl = anon["analysis_metadata"]["crawl_inventory"]["pages"]
    assert all("xss_r" not in str(page) for page in anon_crawl)

    # Configure the lab session, then run again: the protected reflected-XSS
    # parameter is now crawled and probed.
    await client.post(lab_path(assessment_id), json={"username": "admin", "password": "password"})
    authed = (await client.post(f"{URL}/{assessment_id}/analysis-runs")).json()
    findings = (await client.get(f"{URL}/{assessment_id}/findings")).json()

    xss = [f for f in findings if f["category"] == "xss"]
    assert xss, authed["analysis_metadata"]["crawl_inventory"]
    assert {f["status"] for f in xss} <= {"potential", "inconclusive"}

    # The session cookie never appears in persisted findings/evidence.
    with session_factory() as session:
        cookie = session.scalar(select_lab(uuid.UUID(assessment_id))).cookie_header
    value = cookie.split("PHPSESSID=", 1)[1].split(";", 1)[0]
    assert value and value not in json.dumps(findings)


@pytest.mark.anyio
async def test_cookie_and_credentials_never_logged(
    client: httpx.AsyncClient,
    lab: int,
    caplog: pytest.LogCaptureFixture,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await web_target(client, lab)
    with caplog.at_level("DEBUG"):
        await client.post(
            lab_path(assessment_id), json={"username": "admin", "password": "password"}
        )
    with session_factory() as session:
        cookie = session.scalar(select_lab(uuid.UUID(assessment_id))).cookie_header
    value = cookie.split("PHPSESSID=", 1)[1].split(";", 1)[0]
    assert "password" not in caplog.text and value not in caplog.text


# --- containment: local-only, fail-closed ---------------------------------------


def test_non_local_target_is_refused() -> None:
    target = SimpleNamespace(canonical_target="http://93.184.216.34/")
    with pytest.raises(lab_session_mod.LabAuthError) as exc:
        lab_session_mod._require_local_target(target)  # type: ignore[arg-type]
    assert exc.value.code == "target_not_local"


def test_loopback_target_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])
    target = SimpleNamespace(canonical_target="http://127.0.0.1:8080/")
    lab_session_mod._require_local_target(target)  # type: ignore[arg-type]  # no raise


def test_production_forbids_the_feature() -> None:
    base = {
        "_env_file": None,
        "app_env": "production",
        "jwt_secret": TEST_SECRET,
        "email_backend": "smtp",
        **DEPLOYMENT_SETTINGS,
    }
    validate_security_configuration(Settings(**base))  # disabled: fine
    with pytest.raises(SecurityConfigurationError, match="WEB_AUTH_LAB_ENABLED"):
        validate_security_configuration(Settings(**base, web_auth_lab_enabled=True))
