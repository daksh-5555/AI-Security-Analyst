"""Normalized evidence, finding identity, and retest across runs (M7, ADR-0010)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session, sessionmaker
from test_analysis_execution import make_relationship

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.schemas.enums import (
    AnalysisRunStatus,
    AssessmentStatus,
    AssessmentType,
    FindingSeverity,
    FindingStatus,
)
from app.schemas.finding import Finding
from app.schemas.input_operation_flow import InputOperationFlowResult
from app.services.finding_normalization import NormalizedFinding, static_normalized
from app.services.finding_policy import generate_findings
from app.services.findings import add_normalized_findings, list_findings
from app.services.tooling.adapters import flow_evidence_record

pytestmark = pytest.mark.usefixtures("assessment_client")

URL = "/api/v1/assessments"
TOKEN = "ghp_" + "N7m6B5v4C3" * 4
SOURCE = (
    "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/direct")\ndef handler():\n'
    '    cursor = sqlite3.connect("app.db").cursor()\n'
    '    cursor.execute(request.args.get("q"))\n    return "ok"\n'
)
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    repo = root / "project"
    repo.mkdir(parents=True)
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    monkeypatch.setattr(
        settings, "evidence_fingerprint_key", SecretStr("test-only-fingerprint-key-" + "q" * 32)
    )
    (repo / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (repo / "app.py").write_text(SOURCE, encoding="utf-8")
    (repo / "settings.py").write_text(f'TOKEN = "{TOKEN}"\n', encoding="utf-8")
    return repo


async def setup(client: httpx.AsyncClient, repository: Path) -> str:
    assessment_id = (await client.post(URL, json={"assessment_type": "repository"})).json()["id"]
    response = await client.post(
        f"{URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repository)},
    )
    assert response.status_code == 201
    return assessment_id


async def run(client: httpx.AsyncClient, assessment_id: str) -> dict:
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert response.status_code == 201, response.text
    return response.json()


async def findings(client: httpx.AsyncClient, assessment_id: str, run_id: str) -> list[dict]:
    response = await client.get(f"{URL}/{assessment_id}/findings?analysis_run_id={run_id}")
    return response.json()


@pytest.mark.anyio
async def test_every_new_finding_references_normalized_evidence(
    client: httpx.AsyncClient, repository: Path
) -> None:
    assessment_id = await setup(client, repository)
    first = await run(client, assessment_id)
    items = await findings(client, assessment_id, first["id"])

    categories = {item["category"] for item in items}
    assert "secret" in categories
    assert any(category.startswith("input_to_") for category in categories)
    for item in items:
        assert item["evidence_ids"], item["title"]
        assert item["rule_id"] and item["source_stage"]
        assert item["verification_method"] and item["status_rationale"]
        assert item["first_seen_at"] == item["last_seen_at"]
        assert item["previous_status"] is None
        evidence = await client.get(f"{URL}/{assessment_id}/evidence/{item['evidence_ids'][0]}")
        assert evidence.status_code == 200
        assert evidence.json()["analysis_run_id"] == first["id"]

    static = next(i for i in items if i["category"].startswith("input_to_"))
    secret = next(i for i in items if i["category"] == "secret")
    # Static suspicion and runtime/tool verification remain distinguishable.
    assert static["source_stage"] == "static_attack_surface" and static["status"] == "not_tested"
    assert static["rule_id"].startswith("static.input_to_")
    assert secret["source_stage"] == "secret_scan" and secret["cwe_ids"] == ["CWE-798"]
    static_evidence = (
        await client.get(f"{URL}/{assessment_id}/evidence/{static['evidence_ids'][0]}")
    ).json()
    assert static_evidence["source_type"] == "repository"
    assert static_evidence["location_path"] == "app.py"
    retest = first["analysis_metadata"]["retest"]
    assert retest["previous_run_id"] is None and retest["new"] == len(items)


@pytest.mark.anyio
async def test_evidence_never_contains_raw_secrets(
    client: httpx.AsyncClient, repository: Path
) -> None:
    assessment_id = await setup(client, repository)
    first = await run(client, assessment_id)
    listing = await client.get(f"{URL}/{assessment_id}/evidence?analysis_run_id={first['id']}")
    assert listing.status_code == 200 and listing.json()
    assert TOKEN not in json.dumps(listing.json())
    assert TOKEN[4:] not in json.dumps(listing.json())


@pytest.mark.anyio
async def test_recurring_findings_keep_first_seen_and_previous_status(
    client: httpx.AsyncClient, repository: Path
) -> None:
    assessment_id = await setup(client, repository)
    first = await run(client, assessment_id)
    second = await run(client, assessment_id)
    before = {i["title"]: i for i in await findings(client, assessment_id, first["id"])}
    after = {i["title"]: i for i in await findings(client, assessment_id, second["id"])}

    assert set(before) == set(after)
    for title, item in after.items():
        assert item["first_seen_at"] == before[title]["first_seen_at"]
        assert item["last_seen_at"] >= before[title]["last_seen_at"]
        assert item["previous_status"] == before[title]["status"]
        assert set(item["evidence_ids"]).isdisjoint(before[title]["evidence_ids"])
    retest = second["analysis_metadata"]["retest"]
    assert retest == {
        "previous_run_id": first["id"],
        "new": 0,
        "recurring": len(after),
        "not_reproduced": 0,
        "evidence_items": retest["evidence_items"],
    }


@pytest.mark.anyio
async def test_fixed_issue_is_reported_not_reproduced_with_earlier_evidence(
    client: httpx.AsyncClient, repository: Path
) -> None:
    assessment_id = await setup(client, repository)
    first = await run(client, assessment_id)
    earlier_secret = next(
        i for i in await findings(client, assessment_id, first["id"]) if i["category"] == "secret"
    )
    (repository / "settings.py").write_text('TOKEN = "${TOKEN_FROM_ENV}"\n', encoding="utf-8")

    second = await run(client, assessment_id)
    current = await findings(client, assessment_id, second["id"])
    secret = next(i for i in current if i["category"] == "secret")

    assert secret["status"] == "not_reproduced"
    assert secret["previous_status"] == "potential"
    assert secret["evidence_ids"] == earlier_secret["evidence_ids"]  # traceable to run 1
    assert secret["first_seen_at"] == earlier_secret["first_seen_at"]
    assert second["analysis_metadata"]["retest"]["not_reproduced"] == 1

    third = await run(client, assessment_id)  # not re-reported as not_reproduced again
    assert third["analysis_metadata"]["retest"]["not_reproduced"] == 0


@pytest.mark.anyio
async def test_no_not_reproduced_when_the_check_did_not_complete(
    client: httpx.AsyncClient, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id = await setup(client, repository)
    await run(client, assessment_id)
    (repository / "settings.py").write_text('TOKEN = "${TOKEN_FROM_ENV}"\n', encoding="utf-8")
    monkeypatch.setattr(settings, "secret_scan_max_files", 1)  # scan becomes partial

    second = await run(client, assessment_id)
    current = await findings(client, assessment_id, second["id"])
    assert not [i for i in current if i["category"] == "secret"]
    assert second["analysis_metadata"]["retest"]["not_reproduced"] == 0


@pytest.mark.anyio
async def test_evidence_endpoints_enforce_assessment_boundaries(
    client: httpx.AsyncClient, repository: Path
) -> None:
    assessment_id = await setup(client, repository)
    first = await run(client, assessment_id)
    evidence_id = (await findings(client, assessment_id, first["id"]))[0]["evidence_ids"][0]
    other = (await client.post(URL, json={"assessment_type": "repository"})).json()["id"]

    assert (await client.get(f"{URL}/{other}/evidence/{evidence_id}")).status_code == 404
    assert (await client.get(f"{URL}/{assessment_id}/evidence/{uuid.uuid4()}")).status_code == 404
    unknown_run = await client.get(f"{URL}/{assessment_id}/evidence?analysis_run_id={uuid.uuid4()}")
    assert unknown_run.status_code == 404
    paged = await client.get(f"{URL}/{assessment_id}/evidence?limit=1")
    assert len(paged.json()) == 1


def _run(session_factory: sessionmaker[Session]) -> tuple[uuid.UUID, uuid.UUID]:
    with session_factory() as session:
        assessment = AssessmentJob(
            assessment_type=AssessmentType.REPOSITORY,
            status=AssessmentStatus.QUEUED,
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(assessment)
        session.flush()
        run_row = AnalysisRun(
            assessment_id=assessment.id,
            status=AnalysisRunStatus.RUNNING,
            created_at=NOW,
            started_at=NOW,
        )
        session.add(run_row)
        session.commit()
        return assessment.id, run_row.id


def test_same_identity_within_a_run_is_merged(session_factory: sessionmaker[Session]) -> None:
    assessment_id, run_id = _run(session_factory)
    flow = InputOperationFlowResult.model_construct(relationships=[make_relationship()])
    generation = generate_findings(flow)
    item = static_normalized(generation, NOW)[0]
    other_record = flow_evidence_record(
        make_relationship().model_copy(update={"input_line_number": 21}), NOW
    )
    duplicate = NormalizedFinding(
        finding=item.finding,
        rule_id=item.rule_id,
        source_stage=item.source_stage,
        identity=item.identity,
        evidence=(other_record,),
        verification_method=item.verification_method,
        status_rationale=item.status_rationale,
    )
    with session_factory() as session:
        summary = add_normalized_findings(
            session,
            assessment_id,
            [item, duplicate],
            analysis_run_id=run_id,
            completed_stages=frozenset(),
        )
        session.commit()
        stored = list_findings(session, assessment_id)
    assert summary.findings == 1 and summary.evidence_items == 2
    assert len(stored) == 1 and len(stored[0].evidence_ids) == 2


def test_normalized_findings_require_evidence() -> None:
    finding = Finding(
        title="t",
        category="c",
        severity=FindingSeverity.LOW,
        status=FindingStatus.POTENTIAL,
        confidence=0.5,
        summary="s",
        evidence=[],
    )
    with pytest.raises(ValueError):
        NormalizedFinding(
            finding=finding,
            rule_id="r",
            source_stage="s",
            identity="i",
            evidence=(),
            verification_method="m",
            status_rationale="r",
        )
