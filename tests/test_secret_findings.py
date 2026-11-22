"""Secret scanning inside real analysis runs: findings, metadata, and redaction (M2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.schemas.enums import FindingSeverity, FindingStatus
from app.schemas.tooling import (
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSourceType,
    SafeErrorCode,
    ToolIdentity,
    ToolResult,
    ToolStatus,
)
from app.services.analysis_tools import secret_findings_from_result
from app.services.secret_scanning import SecretScannerTool

pytestmark = pytest.mark.usefixtures("assessment_client")

ASSESSMENTS_URL = "/api/v1/assessments"
GITHUB = "ghp_" + "Q9w8E7r6T5" * 4
STRIPE = "sk_live_" + "9fK2mN4pQ6rS8tU0vW2xY4zA"
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    target = root / "project"
    (target / "config").mkdir(parents=True)
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    monkeypatch.setattr(
        settings, "evidence_fingerprint_key", SecretStr("test-only-fingerprint-key-" + "y" * 32)
    )
    (target / "app.py").write_text(f'GITHUB_TOKEN = "{GITHUB}"\n', encoding="utf-8")
    (target / "config" / "billing.py").write_text(
        f'STRIPE_KEY = "{STRIPE}"\nCOPY = "{GITHUB}"\n', encoding="utf-8"
    )
    return target


async def run_analysis(client: httpx.AsyncClient, repository: Path) -> dict:
    created = await client.post(ASSESSMENTS_URL, json={"assessment_type": "repository"})
    assessment_id = created.json()["id"]
    registered = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repository)},
    )
    assert registered.status_code == 201
    response = await client.post(f"{ASSESSMENTS_URL}/{assessment_id}/analysis-runs")
    assert response.status_code == 201, response.text
    return response.json()


def _assert_no_raw_secret(payload: str) -> None:
    assert GITHUB not in payload
    assert STRIPE not in payload
    assert GITHUB[4:] not in payload


@pytest.mark.anyio
async def test_analysis_run_persists_redacted_potential_secret_findings(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    run = await run_analysis(client, repository)
    findings = (await client.get(f"{ASSESSMENTS_URL}/{run['assessment_id']}/findings")).json()

    secrets = [item for item in findings if item["category"] == "secret"]
    assert run["status"] == "completed"
    assert len(secrets) == 2  # the GitHub token in two files is one finding
    by_title = {item["title"]: item for item in secrets}
    github = by_title["Committed secret: GitHub token"]
    stripe = by_title["Committed secret: Stripe live secret key"]
    assert github["status"] == FindingStatus.POTENTIAL.value
    assert stripe["severity"] == FindingSeverity.CRITICAL.value
    assert len(github["evidence"]) == 2
    assert {e["details"]["path"] for e in github["evidence"]} == {"app.py", "config/billing.py"}
    assert all("********" in e["details"]["redacted_excerpt"] for e in github["evidence"])
    assert "validity was not tested" in github["summary"]
    assert github["remediation"]
    # Critical findings sort first.
    assert secrets[0]["title"] == "Committed secret: Stripe live secret key"

    _assert_no_raw_secret(json.dumps(findings))
    _assert_no_raw_secret(json.dumps(run))
    with session_factory() as session:
        dumped = json.dumps(
            [
                [str(value) for value in row]
                for table in (
                    "assessment_findings",
                    "finding_evidence",
                    "analysis_runs",
                    "audit_events",
                )
                for row in session.execute(text(f"SELECT * FROM {table}")).all()  # noqa: S608
            ]
        )
    _assert_no_raw_secret(dumped)


@pytest.mark.anyio
async def test_run_metadata_reports_the_secret_scanner(
    client: httpx.AsyncClient, repository: Path
) -> None:
    run = await run_analysis(client, repository)
    metadata = run["analysis_metadata"]
    tool = next(item for item in metadata["tools"] if item["stage"] == "secret_scan")

    assert tool["status"] == "completed"
    assert tool["rule_set_version"].startswith("secret-rules-")
    assert tool["counts"]["files_scanned"] == 2
    assert tool["evidence_count"] == 3
    assert metadata["finding_count"] == run["findings_count"]
    assert metadata["completeness"]["tools_are_complete"] is True
    assert metadata["completeness"]["incomplete_tools"] == []


@pytest.mark.anyio
async def test_disabled_scanner_is_reported_as_skipped_not_clean(
    client: httpx.AsyncClient, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "secret_scan_enabled", False)
    run = await run_analysis(client, repository)
    metadata = run["analysis_metadata"]
    tool = next(item for item in metadata["tools"] if item["stage"] == "secret_scan")

    assert tool["status"] == "skipped"
    assert tool["error_code"] == "disabled"
    assert metadata["completeness"]["is_complete"] is False
    assert metadata["completeness"]["incomplete_tools"] == ["secret_scan"]
    findings = (await client.get(f"{ASSESSMENTS_URL}/{run['assessment_id']}/findings")).json()
    assert not [item for item in findings if item["category"] == "secret"]


@pytest.mark.anyio
async def test_scanner_failure_is_contained_and_visible(
    client: httpx.AsyncClient, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: SecretScannerTool, _context: object) -> ToolResult:
        raise RuntimeError(f"failure while reading {GITHUB}")

    monkeypatch.setattr(SecretScannerTool, "run", explode)
    run = await run_analysis(client, repository)
    tool = next(
        item for item in run["analysis_metadata"]["tools"] if item["stage"] == "secret_scan"
    )

    assert run["status"] == "completed"
    assert tool["status"] == "failed"
    assert tool["error_code"] == SafeErrorCode.TOOL_ERROR.value
    assert run["analysis_metadata"]["completeness"]["is_complete"] is False
    _assert_no_raw_secret(json.dumps(run))


def _record(path: str, line: int, fingerprint: str, severity: str, title: str) -> EvidenceRecord:
    tool = ToolIdentity(name="secret_scanner", version="1.0.0", rule_set_version="r1")
    return EvidenceRecord(
        evidence_key=f"secret_scanner:secret.x:{path.replace('/', '.')}{line}",
        source_type=EvidenceSourceType.REPOSITORY,
        provenance=EvidenceProvenance(
            tool=tool, rule_id="secret.x", observed_at=NOW, method="unit"
        ),
        location=EvidenceLocation(path=path, line=line),
        summary="s",
        redacted_excerpt="k = ********",
        fingerprint=fingerprint,
        metadata={"severity": severity, "confidence": 0.9, "rule_title": title, "remediation": "r"},
    )


def test_conversion_groups_by_fingerprint_and_orders_deterministically() -> None:
    result = ToolResult(
        tool=ToolIdentity(name="secret_scanner", version="1.0.0", rule_set_version="r1"),
        stage="secret_scan",
        status=ToolStatus.COMPLETED,
        started_at=NOW,
        finished_at=NOW,
        evidence=[
            _record("b.py", 3, "a" * 64, "medium", "Token"),
            _record("a.py", 1, "a" * 64, "medium", "Token"),
            _record("z.py", 9, "b" * 64, "critical", "Key"),
        ],
    )
    findings = secret_findings_from_result(result)

    assert [finding.title for finding in findings] == [
        "Committed secret: Key",
        "Committed secret: Token",
    ]
    assert findings[1].affected_component == "a.py:1"
    assert [e.details["path"] for e in findings[1].evidence] == ["a.py", "b.py"]
    assert all(finding.status is FindingStatus.POTENTIAL for finding in findings)


def test_failed_or_skipped_results_produce_no_findings() -> None:
    for status, code in [
        (ToolStatus.FAILED, SafeErrorCode.TOOL_ERROR),
        (ToolStatus.SKIPPED, SafeErrorCode.DISABLED),
    ]:
        result = ToolResult(
            tool=ToolIdentity(name="secret_scanner", version="1.0.0"),
            stage="secret_scan",
            status=status,
            started_at=NOW,
            finished_at=NOW,
            error_code=code,
        )
        assert secret_findings_from_result(result) == []
