"""JSON and HTML assessment reports (M12, ADR-0015). Offline; fake OSV server only."""

from __future__ import annotations

import html as html_module
import json
import re
import uuid
from pathlib import Path

import httpx
import pytest
from osv_fixtures import fake_osv_server, make_provider
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from test_dependency_audit import PINNED, make_repo
from test_explanations import FakeProvider, respond, valid_output

from app.api.dependencies import Principal, get_current_principal
from app.api.explanations import get_explanation_provider
from app.core.config import settings
from app.main import app
from app.models.assessment_finding import AssessmentFinding
from app.models.evidence_item import EvidenceItem
from app.services import analysis_execution
from app.services.dependencies import auditor as auditor_module
from app.services.reports.builder import AI_LABEL, REPORT_SCHEMA_VERSION
from app.services.reports.html import CONTENT_SECURITY_POLICY

pytestmark = pytest.mark.usefixtures("assessment_client")

URL = "/api/v1/assessments"
TOKEN = "ghp_" + "R5t6Y7u8I9" * 4
SOURCE = (
    "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/direct")\ndef handler():\n'
    '    cursor = sqlite3.connect("app.db").cursor()\n'
    '    cursor.execute(request.args.get("q"))\n    return "ok"\n'
)
XSS = '"><img src=x onerror=alert(1)><script>alert(2)</script>'


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "repositories"
    base.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [base])
    monkeypatch.setattr(
        settings, "evidence_fingerprint_key", SecretStr("test-only-fingerprint-key-" + "r" * 32)
    )
    return base


def full_repo(root: Path) -> Path:
    files = dict(PINNED)
    files["app.py"] = SOURCE
    files["settings.py"] = f'TOKEN = "{TOKEN}"\n'
    return make_repo(root, files)


async def new_assessment(client: httpx.AsyncClient, repo: Path | None) -> str:
    assessment_id = (await client.post(URL, json={"assessment_type": "repository"})).json()["id"]
    if repo is not None:
        response = await client.post(
            f"{URL}/{assessment_id}/repository",
            json={"source_kind": "local_path", "location": str(repo)},
        )
        assert response.status_code == 201
    return assessment_id


async def analysed(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, dict]:
    repo = full_repo(root)
    assessment_id = await new_assessment(client, repo)
    with fake_osv_server() as port:
        monkeypatch.setattr(auditor_module, "default_provider", lambda: make_provider(port))
        run = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert run.status_code == 201, run.text
    return assessment_id, run.json()


async def json_report(client: httpx.AsyncClient, assessment_id: str, **params) -> dict:
    response = await client.get(f"{URL}/{assessment_id}/reports/json", params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def html_report(client: httpx.AsyncClient, assessment_id: str, **params) -> httpx.Response:
    response = await client.get(f"{URL}/{assessment_id}/reports/html", params=params)
    assert response.status_code == 200, response.text
    return response


# --- content agrees with persisted data -----------------------------------------


@pytest.mark.anyio
async def test_reports_agree_with_persisted_findings(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id, run = await analysed(client, root, monkeypatch)
    persisted = (await client.get(f"{URL}/{assessment_id}/findings")).json()
    report = await json_report(client, assessment_id)

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["run"]["id"] == run["id"] and report["run"]["status"] == "completed"
    by_id = {item["id"]: item for item in persisted}
    assert {item["id"] for item in report["findings"]} == set(by_id)
    for item in report["findings"]:
        assert (item["status"], item["severity"]) == (
            by_id[item["id"]]["status"],
            by_id[item["id"]]["severity"],
        )
        assert [e["id"] for e in item["evidence"]] == by_id[item["id"]]["evidence_ids"]
        assert item["ai_explanation"] is None
    assert report["counts"]["total"] == len(persisted)
    assert sum(report["counts"]["by_status"].values()) == len(persisted)
    # Severity ordering is deterministic.
    order = ["critical", "high", "medium", "low", "unknown", "informational"]
    ranks = [order.index(item["severity"]) for item in report["findings"]]
    assert ranks == sorted(ranks)

    # Incomplete checks are explicit (the dependency audit is partial here).
    stages = {item["stage"] for item in report["checks_not_run"]}
    assert "dependency_audit" in stages
    assert any("Incomplete or skipped checks" in line for line in report["executive_summary"])
    advisory = next(a for a in report["advisories"] if a["advisory_id"] == "GHSA-test-0002")
    assert advisory["reference"] == "https://osv.dev/vulnerability/GHSA-test-0002"
    assert {t["stage"] for t in report["scope"]["tools"]} == {"secret_scan", "dependency_audit"}
    assert all(t["version"] for t in report["scope"]["tools"])
    assert report["scope"]["workflow"] is None
    assert report["target"]["display"] == "project"  # relative, never the host path

    html = (await html_report(client, assessment_id)).text
    for item in report["findings"]:
        assert item["id"] in html
    assert "Results are incomplete" in html


@pytest.mark.anyio
async def test_no_server_paths_or_secrets_in_reports(
    client: httpx.AsyncClient,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id, _run = await analysed(client, root, monkeypatch)
    with session_factory() as session:
        finding = session.scalars(
            select(AssessmentFinding).where(
                AssessmentFinding.assessment_id == uuid.UUID(assessment_id)
            )
        ).first()
        finding.summary = f"Leaked {TOKEN} via Authorization: Bearer abcdefghijklmnop0123"
        item = session.get(EvidenceItem, finding.evidence_ids[0])
        item.redacted_excerpt = "cookie: session=s3cr3tsessionvalue42"
        session.commit()
    text = json.dumps(await json_report(client, assessment_id))
    html = (await html_report(client, assessment_id)).text
    for blob in (text, html):
        assert str(root) not in blob and str(root.parent) not in blob
        assert TOKEN not in blob and TOKEN[4:] not in blob
        assert "abcdefghijklmnop0123" not in blob and "s3cr3tsessionvalue42" not in blob
        assert "fingerprint" not in blob and 'content_hash": "' not in blob.replace(
            '"content_hash": "', ""
        )


# --- HTML safety ------------------------------------------------------------------


@pytest.mark.anyio
async def test_html_escapes_malicious_titles_paths_and_evidence(
    client: httpx.AsyncClient,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id, _run = await analysed(client, root, monkeypatch)
    with session_factory() as session:
        finding = session.scalars(
            select(AssessmentFinding).where(
                AssessmentFinding.assessment_id == uuid.UUID(assessment_id)
            )
        ).first()
        finding.title = XSS
        finding.affected_component = "</td></tr></table><script>alert(3)</script>"
        item = session.get(EvidenceItem, finding.evidence_ids[0])
        item.location_path = "<svg onload=alert(4)>.py"
        item.redacted_excerpt = "</pre><iframe src=javascript:alert(5)>"
        session.commit()

    response = await html_report(client, assessment_id)
    html = response.text
    lowered = html.lower()
    # Every injected tag is escaped, so attribute payloads such as onerror= are
    # inert text inside an escaped string, never markup.
    for raw in ("<script", "<img", "<svg", "<iframe"):
        assert raw not in lowered, raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # advisory text (fake OSV)
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    # No remote resources, no scripts; only https links.
    tags = re.findall(r"<[a-z][^>]*>", lowered)  # real markup only (text is escaped)
    assert not [t for t in tags if t.startswith("<link") or re.search(r"\s(src|on\w+)=", t)]
    for href in re.findall(r'href="([^"]*)"', html):
        assert href.startswith("https://")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "script-src" not in CONTENT_SECURITY_POLICY and "default-src &#x27;none&#x27;" in html
    # The JSON keeps the raw (escaped-at-render) value as data.
    report = await json_report(client, assessment_id)
    assert any(item["title"] == XSS for item in report["findings"])


@pytest.mark.anyio
async def test_download_headers(client: httpx.AsyncClient, root: Path) -> None:
    assessment_id = await new_assessment(client, None)
    for kind, media in (("json", "application/json"), ("html", "text/html")):
        response = await client.get(f"{URL}/{assessment_id}/reports/{kind}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(media)
        disposition = response.headers["content-disposition"]
        assert disposition == f'attachment; filename="assessment-{assessment_id}-report.{kind}"'
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"


# --- empty, failed, selection, limits ----------------------------------------------


@pytest.mark.anyio
async def test_empty_assessment_report(client: httpx.AsyncClient) -> None:
    assessment_id = await new_assessment(client, None)
    report = await json_report(client, assessment_id)
    assert report["run"] is None and report["target"] is None
    assert report["counts"]["total"] == 0 and report["findings"] == []
    assert report["executive_summary"][0].startswith("No analysis run has finished")
    html = (await html_report(client, assessment_id)).text
    assert "No findings recorded." in html


@pytest.mark.anyio
async def test_failed_run_is_reported_as_not_clean(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id = await new_assessment(client, full_repo(root))

    def broken(*_args, **_kwargs):
        raise RuntimeError("analyzer bug")

    monkeypatch.setattr(analysis_execution, "collect_assessment_analysis", broken)
    assert (await client.post(f"{URL}/{assessment_id}/analysis-runs")).status_code == 500
    report = await json_report(client, assessment_id)
    assert report["run"]["status"] == "failed"
    assert report["run"]["error_message"] == "Assessment analysis failed."
    assert "not a clean result" in report["executive_summary"][0]
    assert "Results are incomplete" in (await html_report(client, assessment_id)).text


@pytest.mark.anyio
async def test_run_selection_and_boundaries(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id, first = await analysed(client, root, monkeypatch)
    second = (await client.post(f"{URL}/{assessment_id}/analysis-runs")).json()
    assert (await json_report(client, assessment_id))["run"]["id"] == second["id"]
    older = await json_report(client, assessment_id, analysis_run_id=first["id"])
    assert older["run"]["id"] == first["id"]
    unknown = await client.get(
        f"{URL}/{assessment_id}/reports/json", params={"analysis_run_id": str(uuid.uuid4())}
    )
    assert unknown.status_code == 404
    other = await new_assessment(client, None)
    foreign = await client.get(
        f"{URL}/{other}/reports/html", params={"analysis_run_id": first["id"]}
    )
    assert foreign.status_code == 404


@pytest.mark.anyio
async def test_deterministic_and_versioned(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id, _run = await analysed(client, root, monkeypatch)
    one = await client.get(f"{URL}/{assessment_id}/reports/json")
    two = await client.get(f"{URL}/{assessment_id}/reports/json")
    first, second = one.json(), two.json()
    assert first.pop("generated_at") and second.pop("generated_at")
    assert first == second and first["content_hash"] == second["content_hash"]
    assert one.text == json.dumps(one.json(), sort_keys=True, ensure_ascii=False, indent=2)
    assert first["generator"]["version"] == settings.app_version
    # A new run changes the content, so the hash changes.
    await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert (await json_report(client, assessment_id))["content_hash"] != first["content_hash"]


@pytest.mark.anyio
async def test_size_and_finding_limits(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id, _run = await analysed(client, root, monkeypatch)
    monkeypatch.setattr(settings, "report_max_findings", 1)
    report = await json_report(client, assessment_id)
    assert len(report["findings"]) == 1
    assert report["findings_omitted"] == report["counts"]["total"] - 1 > 0
    assert "more finding(s) omitted" in (await html_report(client, assessment_id)).text
    monkeypatch.setattr(settings, "report_max_bytes", 1000)
    too_big = await client.get(f"{URL}/{assessment_id}/reports/html")
    assert too_big.status_code == 413


# --- AI labelling and authorization -------------------------------------------------


@pytest.mark.anyio
async def test_ai_explanations_are_labelled_and_attributed(
    client: httpx.AsyncClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "llm_explanations_enabled", True)
    provider = FakeProvider(respond(lambda r: json.dumps(valid_output(r))))
    app.dependency_overrides[get_explanation_provider] = lambda: provider
    try:
        assessment_id, _run = await analysed(client, root, monkeypatch)
        findings = (await client.get(f"{URL}/{assessment_id}/findings")).json()
        target = next(f for f in findings if f["category"].startswith("input_to_"))
        created = await client.post(f"{URL}/{assessment_id}/findings/{target['id']}/explanations")
        assert created.json()["status"] == "available"
    finally:
        app.dependency_overrides.pop(get_explanation_provider, None)
    report = await json_report(client, assessment_id)
    explained = next(item for item in report["findings"] if item["id"] == target["id"])
    ai = explained["ai_explanation"]
    assert ai["label"] == AI_LABEL and ai["model"] == "fake-model-1@v"
    assert ai["source_references"] and ai["sources"][0]["license"]
    assert explained["status"] == target["status"]  # unchanged by the explanation
    others = [item for item in report["findings"] if item["id"] != target["id"]]
    assert all(item["ai_explanation"] is None for item in others)
    html = (await html_report(client, assessment_id)).text
    assert html_module.escape(AI_LABEL, quote=True) in html


@pytest.mark.anyio
async def test_report_access_follows_assessment_authorization(
    client: httpx.AsyncClient, make_assessment_principal
) -> None:

    from app.core.security import decode_access_token
    from app.schemas.enums import RoleName

    assessment_id = await new_assessment(client, None)
    original = app.dependency_overrides[get_current_principal]
    user_id, headers = make_assessment_principal()
    claims = decode_access_token(headers["Authorization"].removeprefix("Bearer "))
    stranger = Principal(
        user_id=user_id,
        email=f"other-{user_id.hex}@example.com",
        session_id=claims.sid,
        is_active=True,
        is_email_verified=True,
        roles=(RoleName.SECURITY_ANALYST.value,),
        claims=claims,
    )
    app.dependency_overrides[get_current_principal] = lambda: stranger
    try:
        for kind in ("json", "html"):
            denied = await client.get(f"{URL}/{assessment_id}/reports/{kind}")
            assert denied.status_code == 404
    finally:
        app.dependency_overrides[get_current_principal] = original
    app.dependency_overrides.pop(get_current_principal)
    try:
        anonymous = await client.get(f"{URL}/{assessment_id}/reports/json")
        assert anonymous.status_code == 401
    finally:
        app.dependency_overrides[get_current_principal] = original


@pytest.mark.anyio
async def test_workflow_report_step_matches_the_downloaded_report(
    client: httpx.AsyncClient, root: Path
) -> None:
    assessment_id = await new_assessment(client, full_repo(root))
    workflow = (await client.post(f"{URL}/{assessment_id}/workflows", json={})).json()
    assert workflow["status"] == "completed"
    step = next(e for e in workflow["events"] if e["node"] == "generate_report")
    report = await json_report(client, assessment_id)
    assert step["detail"]["content_hash"] == report["content_hash"]
    assert report["scope"]["workflow"]["id"] == workflow["id"]
    assert {c["check"] for c in report["scope"]["workflow"]["checks"]} >= {"secret_scan"}
