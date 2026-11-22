"""Dependency audit tool, findings, and analysis-run integration (M3)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from osv_fixtures import FakeOsvHandler, fake_osv_server, make_provider

from app.core.config import settings
from app.schemas.enums import FindingStatus
from app.schemas.tooling import ToolStatus
from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.analysis_tools import dependency_findings_from_result
from app.services.dependencies import auditor as auditor_module
from app.services.dependencies.auditor import DependencyAuditTool
from app.services.repository_discovery import discover_repository
from app.services.tooling import ToolContext

ASSESSMENTS_URL = "/api/v1/assessments"


@pytest.fixture
def allowed_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


def make_repo(root: Path, files: dict[str, str]) -> Path:
    repo = root / "project"
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return repo


PINNED = {
    "requirements.txt": "demo-http==2.0.1\nsafe-lib==1.0.0\nunpinned-lib>=1\n",
    "web/package.json": json.dumps({"dependencies": {"demo-merge": "^1.0.0"}}),
    "web/package-lock.json": json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"demo-merge": "^1.0.0"}},
                "node_modules/demo-merge": {"version": "1.1.0"},
            },
        }
    ),
}


def audit(repo: Path, provider) -> object:  # noqa: ANN001
    context = ToolContext(
        execution=AnalysisExecutionContext(60), discovery=discover_repository(repo)
    )
    return DependencyAuditTool(provider=provider).run(context)


def test_matches_are_verified_locally_and_explained(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, PINNED)
    with fake_osv_server() as port:
        result = audit(repo, make_provider(port))

    assert result.status is ToolStatus.PARTIAL  # unpinned-lib could not be checked
    assert {item.code for item in result.limitations} == {"unresolved_versions"}
    by_package = {record.metadata["package"]: record for record in result.evidence}
    http = by_package["demo-http"]
    assert http.metadata["range_check"] == "affected"
    assert http.metadata["match_explanation"] == (
        "version 2.0.1 is within the affected range (introduced 0, fixed 2.0.3)"
    )
    assert http.metadata["cve_ids"] == ["CVE-2099-0001"]
    assert http.metadata["fixed_versions"] == ["2.0.3"]
    assert http.metadata["freshness"] == "fresh"
    assert http.metadata["source"] == "osv"
    assert http.location.path == "requirements.txt"
    assert by_package["demo-merge"].location.path == "web/package-lock.json"
    assert by_package["demo-merge"].metadata["relationship"] == "direct"
    assert result.counts["packages_checked"] == 3
    assert result.counts["unresolved_versions"] == 1


def test_provider_match_outside_local_range_is_not_confirmed(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, {"requirements.txt": "demo-http==9.9.9\n"})
    with fake_osv_server() as port:
        result = audit(repo, make_provider(port))
    record = result.evidence[0]
    assert record.metadata["range_check"] == "not_affected"
    assert "range_check_disagreement" in {item.code for item in result.limitations}
    finding = dependency_findings_from_result(result)[0]
    assert finding.status is FindingStatus.INCONCLUSIVE


def test_offline_without_cache_reports_unchecked_not_clean(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, {"requirements.txt": "demo-http==2.0.1\n"})
    result = audit(repo, make_provider(None, mode="offline"))
    assert result.status is ToolStatus.PARTIAL
    assert result.evidence == []
    assert result.counts["packages_unchecked"] == 1
    assert "advisory_data_unavailable" in {item.code for item in result.limitations}
    assert not result.is_clean


def test_packages_beyond_the_budget_are_unchecked(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "advisory_max_packages", 1)
    repo = make_repo(allowed_root, {"requirements.txt": "a-lib==1.0\nb-lib==1.0\n"})
    with fake_osv_server() as port:
        result = audit(repo, make_provider(port))
    assert "max_packages" in {item.code for item in result.limitations}
    assert result.counts["packages_unchecked"] == 1


def test_findings_are_grouped_confirmed_and_ordered(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, PINNED)
    with fake_osv_server() as port:
        result = audit(repo, make_provider(port))
    findings = dependency_findings_from_result(result)

    assert [finding.title for finding in findings] == [
        "Vulnerable dependency: demo-http 2.0.1 (GHSA-test-0001)",
        "Vulnerable dependency: demo-merge 1.1.0 (GHSA-test-0002)",
    ]
    http = findings[0]
    assert http.status is FindingStatus.CONFIRMED
    assert http.severity.value == "high"
    assert http.category == "dependency"
    assert "Upgrade demo-http to a fixed version (2.0.3)" in (http.remediation or "")
    assert "Exploitability in this application was not assessed" in http.summary
    assert findings[1].severity.value == "medium"  # GHSA MODERATE
    assert http.evidence[0].details["source_url"].startswith("https://osv.dev/vulnerability/")


def test_tool_is_not_applicable_without_dependency_files(allowed_root: Path) -> None:
    repo = make_repo(allowed_root, {"app.py": "x = 1\n"})
    context = ToolContext(
        execution=AnalysisExecutionContext(60), discovery=discover_repository(repo)
    )
    assert (
        DependencyAuditTool(provider=make_provider(None, mode="offline")).applies_to(context)
        is False
    )


def test_no_repository_code_or_package_manager_is_executed(
    allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("subprocess execution attempted")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    repo = make_repo(
        allowed_root,
        {
            "setup.py": "raise SystemExit('setup.py must never run')\n",
            "requirements.txt": "demo-http==2.0.1\n",
            "package.json": json.dumps({"scripts": {"preinstall": "rm -rf /"}, "dependencies": {}}),
        },
    )
    with fake_osv_server() as port:
        result = audit(repo, make_provider(port))
    assert result.evidence


# --- analysis-run integration -------------------------------------------------


async def run_analysis(client: httpx.AsyncClient, repo: Path) -> dict:
    created = await client.post(ASSESSMENTS_URL, json={"assessment_type": "repository"})
    assessment_id = created.json()["id"]
    registered = await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repo)},
    )
    assert registered.status_code == 201
    response = await client.post(f"{ASSESSMENTS_URL}/{assessment_id}/analysis-runs")
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.anyio
@pytest.mark.usefixtures("assessment_client")
async def test_analysis_run_persists_dependency_findings(
    client: httpx.AsyncClient, allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(allowed_root, PINNED)
    with fake_osv_server() as port:
        monkeypatch.setattr(auditor_module, "default_provider", lambda: make_provider(port))
        run = await run_analysis(client, repo)
        requests_seen = list(FakeOsvHandler.requests)

    assert requests_seen  # the provider was used (through the guarded client)
    tool = next(t for t in run["analysis_metadata"]["tools"] if t["stage"] == "dependency_audit")
    assert tool["status"] == "partial"
    assert run["analysis_metadata"]["completeness"]["is_complete"] is False
    findings = (await client.get(f"{ASSESSMENTS_URL}/{run['assessment_id']}/findings")).json()
    dependency = [item for item in findings if item["category"] == "dependency"]
    assert {item["status"] for item in dependency} == {"confirmed"}
    assert len(dependency) == 2
    # Untrusted advisory text is stored as data (control characters stripped);
    # HTML escaping is the responsibility of report rendering (M12).
    merge = next(item for item in dependency if "demo-merge" in item["title"])
    assert "\x07" not in merge["summary"]
    assert merge["evidence"][0]["details"]["advisory_id"] == "GHSA-test-0002"


@pytest.mark.anyio
@pytest.mark.usefixtures("assessment_client")
async def test_disabled_dependency_audit_is_reported(
    client: httpx.AsyncClient, allowed_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "dependency_audit_mode", "disabled")
    run = await run_analysis(client, make_repo(allowed_root, PINNED))
    tool = next(t for t in run["analysis_metadata"]["tools"] if t["stage"] == "dependency_audit")
    assert tool["status"] == "skipped" and tool["error_code"] == "disabled"
    assert "dependency_audit" in run["analysis_metadata"]["completeness"]["incomplete_tools"]


def test_default_provider_limits_egress_to_the_configured_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "dependency_audit_mode", "online")
    provider = auditor_module.default_provider()
    client = provider._client  # noqa: SLF001
    assert client is not None
    assert client._allowed_hosts == frozenset({"api.osv.dev"})  # noqa: SLF001
    assert client.policy.allowed_schemes == frozenset({"https"})
    assert client.policy.allowed_local_networks == ()
