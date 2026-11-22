"""Opt-in end-to-end DVWA assessment (M15, ADR-0018).

Runs only when DVWA_URL points at a running local DVWA lab (for example
http://127.0.0.1:8080/ started with Docker; see docs/lab/dvwa.md). Without it
the test skips, exactly like the PostgreSQL tests. It never scans a public
target: the URL host must be an authorized local address.

Environment:
  DVWA_URL        base URL of the local lab (required to run)
  DVWA_USERNAME   default "admin"
  DVWA_PASSWORD   default "password"
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import httpx
import pytest

from app.core.config import settings

URL = "/api/v1/assessments"
DVWA_URL = os.environ.get("DVWA_URL")

pytestmark = [
    pytest.mark.skipif(not DVWA_URL, reason="set DVWA_URL to run the DVWA integration test"),
    pytest.mark.usefixtures("assessment_client"),
]


@pytest.fixture
def dvwa(monkeypatch: pytest.MonkeyPatch) -> str:
    assert DVWA_URL is not None
    host = urlsplit(DVWA_URL).hostname or ""
    monkeypatch.setattr(settings, "web_target_allowed_hosts", [host])
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8", "::1/128"])
    monkeypatch.setattr(settings, "web_auth_lab_enabled", True)
    monkeypatch.setattr(settings, "runtime_probes_enabled", True)
    monkeypatch.setattr(settings, "crawler_respect_robots", False)
    monkeypatch.setattr(settings, "web_target_max_requests_per_second", 10.0)
    return DVWA_URL


@pytest.mark.anyio
async def test_authenticated_dvwa_assessment_finds_reflected_xss(
    client: httpx.AsyncClient, dvwa: str
) -> None:
    assessment_id = (await client.post(URL, json={"assessment_type": "web_security"})).json()["id"]
    registered = await client.post(
        f"{URL}/{assessment_id}/web-target",
        json={
            "base_url": dvwa,
            "authorization_statement": "Local DVWA lab I own and authorize for testing.",
            "confirm_authorized": True,
        },
    )
    assert registered.status_code == 201, registered.text

    login = await client.post(
        f"{URL}/{assessment_id}/web-target/lab-credentials",
        json={
            "username": os.environ.get("DVWA_USERNAME", "admin"),
            "password": os.environ.get("DVWA_PASSWORD", "password"),
        },
    )
    assert login.status_code == 201, login.text

    run = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert run.status_code == 201, run.text
    findings = (await client.get(f"{URL}/{assessment_id}/findings")).json()
    categories = {f["category"] for f in findings}
    # DVWA's low-security pages expose reflected XSS and/or SQL injection.
    assert categories & {"xss", "sqli"}, findings
