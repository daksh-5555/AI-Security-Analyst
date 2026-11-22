"""Web-security analysis runs: authorized target, crawler, and metadata (M5)."""

from __future__ import annotations

import json

import httpx
import pytest
from crawl_fixtures import CSRF_VALUE, SiteHandler, fixture_site
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.analysis_run import AnalysisRun

URL = "/api/v1/assessments"
STATEMENT = "Local DVWA-style lab owned by the test team; authorized for crawling."

pytestmark = pytest.mark.usefixtures("assessment_client")


@pytest.fixture(autouse=True)
def lab_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["127.0.0.1"])
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])


async def web_assessment(client: httpx.AsyncClient, port: int | None) -> str:
    created = await client.post(URL, json={"assessment_type": "web_security"})
    assessment_id = created.json()["id"]
    if port is not None:
        registered = await client.post(
            f"{URL}/{assessment_id}/web-target",
            json={
                "base_url": f"http://127.0.0.1:{port}/",
                "authorization_statement": STATEMENT,
                "confirm_authorized": True,
            },
        )
        assert registered.status_code == 201, registered.text
    return assessment_id


@pytest.mark.anyio
async def test_web_run_crawls_the_authorized_target(client: httpx.AsyncClient) -> None:
    with fixture_site() as port:
        assessment_id = await web_assessment(client, port)
        response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
        log = list(SiteHandler.log)

    assert response.status_code == 201, response.text
    run = response.json()
    metadata = run["analysis_metadata"]
    assert run["status"] == "completed"
    assert metadata["target"] == {"type": "web_application", "url": f"http://127.0.0.1:{port}/"}
    tool = metadata["tools"][0]
    assert tool["stage"] == "web_crawl" and tool["status"] == "partial"
    # Probes are off by default and reported as skipped (disabled), not silently clean.
    assert metadata["completeness"]["incomplete_tools"] == ["web_crawl", "runtime_probes"]
    probes = metadata["tools"][1]
    assert probes["status"] == "skipped" and probes["error_code"] == "disabled"
    inventory = metadata["crawl_inventory"]
    assert {"/", "/about", "/login"} <= {p["path"] for p in inventory["pages"]}
    assert any(f["classification"] == "login" for f in inventory["forms"])
    assert all(f["submitted"] is False for f in inventory["forms"])
    assert ("/private", "http_401") in {
        (a["path"], a["signal"]) for a in inventory["auth_boundaries"]
    }
    assert run["findings_count"] == 0  # the crawler inventories; it does not report findings
    assert {method for method, _ in log} == {"GET"}
    assert "/logout" not in {path for _, path in log}
    assert CSRF_VALUE not in json.dumps(run)


@pytest.mark.anyio
async def test_web_run_without_target_is_404(client: httpx.AsyncClient) -> None:
    assessment_id = await web_assessment(client, None)
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert response.status_code == 404
    assert response.json() == {"detail": "Web target not found"}


@pytest.mark.anyio
async def test_revoked_web_target_blocks_the_run(
    client: httpx.AsyncClient, session_factory: sessionmaker[Session]
) -> None:
    with fixture_site() as port:
        assessment_id = await web_assessment(client, port)
        target = (await client.get(f"{URL}/{assessment_id}/targets")).json()[0]
        await client.post(f"{URL}/{assessment_id}/targets/{target['id']}/revoke")
        response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
        log = list(SiteHandler.log)
    assert response.status_code == 409
    assert log == []  # nothing was sent to the target
    with session_factory() as session:
        assert session.scalar(select(func.count(AnalysisRun.id))) == 0


@pytest.mark.anyio
async def test_unreachable_target_completes_with_a_failed_tool(client: httpx.AsyncClient) -> None:
    assessment_id = await web_assessment(client, 9)  # nothing listens on port 9
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    run = response.json()
    assert response.status_code == 201
    tool = run["analysis_metadata"]["tools"][0]
    assert tool["status"] == "failed" and tool["error_code"] == "unavailable"
    assert run["analysis_metadata"]["completeness"]["is_complete"] is False


@pytest.mark.anyio
async def test_target_removed_from_allowlist_is_not_contacted(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    with fixture_site() as port:
        assessment_id = await web_assessment(client, port)
        monkeypatch.setattr(settings, "web_target_allowed_hosts", [])
        response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
        log = list(SiteHandler.log)
    assert response.status_code == 409
    assert log == []
    with session_factory() as session:
        assert session.scalar(select(func.count(AnalysisRun.id))) == 0
