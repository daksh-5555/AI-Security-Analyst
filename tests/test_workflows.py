"""Bounded, approval-gated assessment workflows (M10, ADR-0013). No external network."""

from __future__ import annotations

import json
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from probe_fixtures import ProbeHandler, probe_site
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from test_explanations import FakeProvider, good, respond

from app.api.explanations import get_explanation_provider
from app.core.config import settings
from app.main import app
from app.models.analysis_run import AnalysisRun
from app.models.audit_event import AuditEvent
from app.models.workflow import AssessmentWorkflow
from app.schemas.enums import AssessmentType, AuditAction
from app.services.analysis_execution import ActiveAnalysisRunError
from app.services.analysis_tools import tool_pipeline_config, web_tool_pipeline_config
from app.services.explanations.provider import ProviderError, ProviderErrorCode
from app.services.workflow import engine
from app.services.workflow.plan import (
    NODE_SEQUENCE,
    TOOL_CHECKS,
    config_snapshot,
    excluded_tool_stages,
    plan_checks,
)

pytestmark = pytest.mark.usefixtures("assessment_client")

URL = "/api/v1/assessments"
SOURCE = (
    "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/direct")\ndef handler():\n'
    '    cursor = sqlite3.connect("app.db").cursor()\n'
    '    cursor.execute(request.args.get("q"))\n    return "ok"\n'
)
PROBE_VALUE = re.compile(r"aisa[0-9a-f]{6,}| AND ")


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    repo = root / "project"
    repo.mkdir(parents=True)
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    monkeypatch.setattr(
        settings, "evidence_fingerprint_key", SecretStr("test-only-fingerprint-key-" + "g" * 32)
    )
    (repo / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (repo / "app.py").write_text(SOURCE, encoding="utf-8")
    (repo / "settings.py").write_text('TOKEN = "ghp_' + "Q1w2E3r4T5" * 4 + '"\n', encoding="utf-8")
    return repo


@pytest.fixture
def fake_provider():
    holder = {"provider": FakeProvider(respond(good))}
    app.dependency_overrides[get_explanation_provider] = lambda: holder["provider"]
    yield holder
    app.dependency_overrides.pop(get_explanation_provider, None)


async def repo_assessment(client: httpx.AsyncClient, repo: Path) -> str:
    assessment_id = (await client.post(URL, json={"assessment_type": "repository"})).json()["id"]
    response = await client.post(
        f"{URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repo)},
    )
    assert response.status_code == 201
    return assessment_id


async def start(client: httpx.AsyncClient, assessment_id: str, **body) -> httpx.Response:
    return await client.post(f"{URL}/{assessment_id}/workflows", json=body)


def outcomes(workflow: dict) -> list[tuple[str, str]]:
    return [(event["node"], event["outcome"]) for event in workflow["events"]]


def audit_actions(session_factory: sessionmaker[Session], workflow_id: str) -> list[AuditAction]:
    with session_factory() as session:
        return list(
            session.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.resource_id == uuid.UUID(workflow_id))
                .order_by(AuditEvent.occurred_at, AuditEvent.id)
            )
        )


def run_count(session_factory: sessionmaker[Session], assessment_id: str) -> int:
    with session_factory() as session:
        return session.scalar(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.assessment_id == uuid.UUID(assessment_id)
            )
        )


# --- repository workflows -------------------------------------------------------


@pytest.mark.anyio
async def test_repository_workflow_runs_every_node_in_order(
    client: httpx.AsyncClient,
    repository: Path,
    fake_provider,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await repo_assessment(client, repository)
    response = await start(client, assessment_id)
    assert response.status_code == 201, response.text
    workflow = response.json()

    assert workflow["status"] == "completed" and workflow["error_code"] is None
    assert outcomes(workflow) == [
        ("load_assessment", "completed"),
        ("validate_authorization", "completed"),
        ("plan_enabled_checks", "completed"),
        ("approval_gate", "completed"),
        ("run_analysis", "completed"),
        ("explain_findings", "skipped"),
        ("generate_report", "completed"),  # M12: built from persisted results
        ("finalize_run", "completed"),
    ]
    assert workflow["step_count"] == len(NODE_SEQUENCE) and workflow["pending_approvals"] == []
    checks = {item["check"]: item for item in workflow["plan"]["checks"]}
    assert checks["secret_scan"]["decision"] == "run"
    assert checks["explain_findings"]["reason"] == "not_requested"
    assert workflow["plan"]["config"] == config_snapshot()

    run = (
        await client.get(f"{URL}/{assessment_id}/analysis-runs/{workflow['analysis_run_id']}")
    ).json()
    assert run["status"] == "completed" and run["findings_count"] > 0
    run_event = workflow["events"][4]["detail"]
    assert run_event["analysis_run_id"] == workflow["analysis_run_id"]
    assert {tool["stage"] for tool in run_event["tools"]} == {"secret_scan", "dependency_audit"}
    assert audit_actions(session_factory, workflow["id"]) == [
        AuditAction.WORKFLOW_STARTED,
        AuditAction.WORKFLOW_FINISHED,
    ]
    assert fake_provider["provider"].requests == []  # AI not involved

    detail = await client.get(f"{URL}/{assessment_id}/workflows/{workflow['id']}")
    assert detail.json() == workflow
    listing = await client.get(f"{URL}/{assessment_id}/workflows")
    assert [item["id"] for item in listing.json()] == [workflow["id"]]


@pytest.mark.anyio
async def test_requested_explanations_are_skipped_while_ai_is_disabled(
    client: httpx.AsyncClient, repository: Path, fake_provider
) -> None:
    assessment_id = await repo_assessment(client, repository)
    workflow = (await start(client, assessment_id, explain_findings=True)).json()
    assert workflow["status"] == "completed"
    explain = next(e for e in workflow["events"] if e["node"] == "explain_findings")
    assert explain["outcome"] == "skipped"
    assert explain["detail"]["reason"] == "disabled_by_configuration"
    assert fake_provider["provider"].requests == []


@pytest.mark.anyio
async def test_explanations_are_bounded_and_advisory(
    client: httpx.AsyncClient,
    repository: Path,
    fake_provider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_explanations_enabled", True)
    monkeypatch.setattr(settings, "workflow_max_explanations", 1)
    assessment_id = await repo_assessment(client, repository)
    workflow = (await start(client, assessment_id, explain_findings=True)).json()
    explain = next(e for e in workflow["events"] if e["node"] == "explain_findings")
    assert explain["outcome"] == "completed"
    assert (explain["detail"]["requested"], explain["detail"]["available"]) == (1, 1)
    assert len(fake_provider["provider"].requests) == 1
    findings = (await client.get(f"{URL}/{assessment_id}/findings")).json()
    # The highest-severity finding was chosen.
    severities = ["critical", "high", "medium", "low", "unknown", "informational"]
    best = min(severities.index(f["severity"]) for f in findings)
    explained = fake_provider["provider"].requests[0].user
    assert any(f["id"] in explained and severities.index(f["severity"]) == best for f in findings)


@pytest.mark.anyio
async def test_explanation_failure_never_fails_the_workflow(
    client: httpx.AsyncClient,
    repository: Path,
    fake_provider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_explanations_enabled", True)

    def outage(_request):
        raise ProviderError(ProviderErrorCode.UNAVAILABLE)

    fake_provider["provider"] = FakeProvider(outage)
    assessment_id = await repo_assessment(client, repository)
    workflow = (await start(client, assessment_id, explain_findings=True)).json()
    assert workflow["status"] == "completed"
    explain = next(e for e in workflow["events"] if e["node"] == "explain_findings")
    assert explain["detail"]["unavailable"] == explain["detail"]["requested"] > 0


@pytest.mark.anyio
async def test_invalid_target_fails_before_any_analysis(
    client: httpx.AsyncClient, repository: Path, session_factory: sessionmaker[Session]
) -> None:
    assessment_id = await repo_assessment(client, repository)
    for path in sorted(repository.rglob("*"), reverse=True):
        path.unlink()
    repository.rmdir()
    workflow = (await start(client, assessment_id)).json()
    assert workflow["status"] == "failed"
    assert workflow["error_code"] == "target_not_authorized"
    assert outcomes(workflow)[-1] == ("validate_authorization", "failed")
    assert run_count(session_factory, assessment_id) == 0


# --- web workflows: approval gate -----------------------------------------------


@pytest.fixture
def web_lab(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["127.0.0.1"])
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])
    monkeypatch.setattr(settings, "web_target_max_requests_per_second", 50.0)
    monkeypatch.setattr(settings, "crawler_respect_robots", False)
    with probe_site() as port:
        ProbeHandler.log.clear()
        yield port


async def web_assessment(client: httpx.AsyncClient, port: int) -> str:
    assessment_id = (await client.post(URL, json={"assessment_type": "web_security"})).json()["id"]
    response = await client.post(
        f"{URL}/{assessment_id}/web-target",
        json={
            "base_url": f"http://127.0.0.1:{port}/",
            "authorization_statement": "Local deliberately vulnerable lab owned by the test.",
            "confirm_authorized": True,
        },
    )
    assert response.status_code == 201, response.text
    return assessment_id


def probe_requests() -> list[str]:
    return [
        json.dumps(entry) for entry in ProbeHandler.log if PROBE_VALUE.search(json.dumps(entry))
    ]


async def approve(client, assessment_id, workflow_id, decision="approve", check="runtime_probes"):
    return await client.post(
        f"{URL}/{assessment_id}/workflows/{workflow_id}/approvals",
        json={"check": check, "decision": decision, "reason": "Lab owned by the test team."},
    )


@pytest.mark.anyio
async def test_high_risk_check_waits_for_approval_then_runs(
    client: httpx.AsyncClient,
    web_lab: int,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    monkeypatch.setattr(settings, "runtime_probes_enabled", True)
    assessment_id = await web_assessment(client, web_lab)
    paused = (await start(client, assessment_id)).json()

    assert paused["status"] == "awaiting_approval"
    assert paused["pending_approvals"] == ["runtime_probes"]
    assert paused["current_node"] == "approval_gate"
    assert run_count(session_factory, assessment_id) == 0
    assert ProbeHandler.log == []  # nothing sent to the target yet
    # Another workflow cannot start while this one waits.
    assert (await start(client, assessment_id)).status_code == 409

    response = await approve(client, assessment_id, paused["id"])
    assert response.status_code == 200, response.text
    done = response.json()
    assert done["status"] == "completed"
    assert done["approvals"]["runtime_probes"]["decision"] == "approved"
    assert done["approvals"]["runtime_probes"]["by"] is not None
    run_event = next(e for e in done["events"] if e["node"] == "run_analysis")
    tools = {tool["stage"]: tool["status"] for tool in run_event["detail"]["tools"]}
    assert tools["runtime_probes"] in {"completed", "partial"}
    assert run_event["detail"]["excluded_checks"] == []
    assert probe_requests()
    assert ("approval_gate", "approval_recorded") in outcomes(done)
    assert AuditAction.WORKFLOW_APPROVAL_RECORDED in audit_actions(session_factory, done["id"])
    # The decision cannot be made twice.
    assert (await approve(client, assessment_id, done["id"])).status_code == 409


@pytest.mark.anyio
async def test_denied_check_is_never_executed(
    client: httpx.AsyncClient, web_lab: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "runtime_probes_enabled", True)
    assessment_id = await web_assessment(client, web_lab)
    paused = (await start(client, assessment_id)).json()
    done = (await approve(client, assessment_id, paused["id"], decision="deny")).json()

    assert done["status"] == "completed"
    run_event = next(e for e in done["events"] if e["node"] == "run_analysis")
    assert run_event["detail"]["excluded_checks"] == ["runtime_probes"]
    tools = {tool["stage"]: tool["status"] for tool in run_event["detail"]["tools"]}
    assert tools["runtime_probes"] == "skipped" and tools["web_crawl"] != "skipped"
    assert run_event["detail"]["is_complete"] is False  # honestly incomplete
    assert ProbeHandler.log and probe_requests() == []  # crawled, never probed


@pytest.mark.anyio
async def test_configuration_disabled_checks_need_no_approval_and_stay_off(
    client: httpx.AsyncClient, web_lab: int
) -> None:
    assessment_id = await web_assessment(client, web_lab)  # probes disabled by default
    workflow = (await start(client, assessment_id)).json()
    assert workflow["status"] == "completed"
    probes = next(c for c in workflow["plan"]["checks"] if c["check"] == "runtime_probes")
    assert (probes["decision"], probes["reason"]) == ("skip", "disabled_by_configuration")
    assert probe_requests() == []


@pytest.mark.anyio
async def test_approval_request_validation(
    client: httpx.AsyncClient, web_lab: int, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "runtime_probes_enabled", True)
    assessment_id = await web_assessment(client, web_lab)
    paused = (await start(client, assessment_id)).json()
    # Only allowlisted checks can be named; there is no way to add a target or URL.
    bad = await approve(client, assessment_id, paused["id"], check="https://evil.example/")
    assert bad.status_code == 422
    other = await repo_assessment(client, repository)
    foreign = await approve(client, other, paused["id"])
    assert foreign.status_code == 404

    cancelled = await client.post(f"{URL}/{assessment_id}/workflows/{paused['id']}/cancel")
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert (await approve(client, assessment_id, paused["id"])).status_code == 409
    again = await client.post(f"{URL}/{assessment_id}/workflows/{paused['id']}/cancel")
    assert again.status_code == 409
    assert (await start(client, assessment_id)).json()["status"] == "awaiting_approval"


# --- retries, recovery, budgets -------------------------------------------------


@pytest.mark.anyio
async def test_retryable_error_then_resume(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await repo_assessment(client, repository)
    real = engine.execute_assessment_analysis
    calls = {"count": 0}

    def flaky(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ActiveAnalysisRunError
        return real(*args, **kwargs)

    monkeypatch.setattr(engine, "execute_assessment_analysis", flaky)
    stuck = (await start(client, assessment_id)).json()
    assert stuck["status"] == "running" and stuck["error_code"] == "active_run_conflict"
    assert stuck["current_node"] == "run_analysis"

    resumed = await client.post(f"{URL}/{assessment_id}/workflows/{stuck['id']}/resume")
    assert resumed.status_code == 200
    done = resumed.json()
    assert done["status"] == "completed" and done["error_code"] is None
    attempts = [e["attempt"] for e in done["events"] if e["node"] == "run_analysis"]
    assert attempts == [1, 2]
    finished = await client.post(f"{URL}/{assessment_id}/workflows/{stuck['id']}/resume")
    assert finished.status_code == 409


@pytest.mark.anyio
async def test_node_attempts_are_bounded(
    client: httpx.AsyncClient, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id = await repo_assessment(client, repository)

    def always_busy(*_args, **_kwargs):
        raise ActiveAnalysisRunError

    monkeypatch.setattr(engine, "execute_assessment_analysis", always_busy)
    workflow = (await start(client, assessment_id)).json()
    url = f"{URL}/{assessment_id}/workflows/{workflow['id']}/resume"
    second = (await client.post(url)).json()
    assert second["status"] == "running"
    third = (await client.post(url)).json()
    assert third["status"] == "failed" and third["error_code"] == "node_attempts_exhausted"


@pytest.mark.anyio
async def test_step_budget_is_enforced(
    client: httpx.AsyncClient, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "workflow_max_steps", 3)
    assessment_id = await repo_assessment(client, repository)
    workflow = (await start(client, assessment_id)).json()
    assert workflow["status"] == "failed" and workflow["error_code"] == "step_budget_exhausted"
    assert workflow["step_count"] == 3 and workflow["analysis_run_id"] is None


@pytest.mark.anyio
async def test_interrupted_analysis_is_adopted_not_repeated(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await repo_assessment(client, repository)
    real = engine.execute_assessment_analysis

    def completes_then_connection_drops(*args, **kwargs):
        real(*args, **kwargs)
        raise ActiveAnalysisRunError  # the run finished, but the node never saw it

    monkeypatch.setattr(engine, "execute_assessment_analysis", completes_then_connection_drops)
    stuck = (await start(client, assessment_id)).json()
    assert stuck["status"] == "running"
    monkeypatch.setattr(engine, "execute_assessment_analysis", real)
    done = (await client.post(f"{URL}/{assessment_id}/workflows/{stuck['id']}/resume")).json()
    assert done["status"] == "completed" and done["analysis_run_id"]
    assert run_count(session_factory, assessment_id) == 1  # no second analysis


@pytest.mark.anyio
async def test_a_running_step_cannot_be_advanced_twice(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await repo_assessment(client, repository)
    real = engine.execute_assessment_analysis
    errors: list[BaseException] = []

    def concurrent_resume(db, requested_id, **kwargs):
        workflow_id = db.scalar(
            select(AssessmentWorkflow.id).where(AssessmentWorkflow.assessment_id == requested_id)
        )
        db.rollback()

        def other_request() -> None:
            with session_factory() as other:
                try:
                    engine.advance(other, workflow_id, actor_user_id=None)
                except engine.WorkflowStateError as exc:
                    errors.append(exc)

        thread = threading.Thread(target=other_request)
        thread.start()
        thread.join(timeout=30)
        return real(db, requested_id, **kwargs)

    monkeypatch.setattr(engine, "execute_assessment_analysis", concurrent_resume)
    workflow = (await start(client, assessment_id)).json()
    assert workflow["status"] == "completed"
    assert len(errors) == 1
    assert [e["node"] for e in workflow["events"]].count("run_analysis") == 1
    assert run_count(session_factory, assessment_id) == 1


@pytest.mark.anyio
async def test_stale_step_marker_allows_recovery(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await repo_assessment(client, repository)
    with session_factory() as session:
        workflow = engine.start_workflow(session, uuid.UUID(assessment_id), actor_user_id=None)
        # Simulate a process that died mid-step long ago.
        stale = datetime.now(UTC) - timedelta(seconds=settings.analysis_stale_after_seconds + 5)
        row = session.get(AssessmentWorkflow, workflow.id)
        row.status = engine.WorkflowStatus.RUNNING
        row.current_node = "finalize_run"
        row.state = {
            **row.state,
            "running_step": {"node": "finalize_run", "step": 9, "started_at": stale.isoformat()},
        }
        row.completed_at = None
        session.commit()
        fresh = datetime.now(UTC).isoformat()
        row.state = {
            **row.state,
            "running_step": {"node": "finalize_run", "step": 9, "started_at": fresh},
        }
        session.commit()
        with pytest.raises(engine.WorkflowStateError):
            engine.advance(session, workflow.id, actor_user_id=None)
        row.state = {
            **row.state,
            "running_step": {"node": "finalize_run", "step": 9, "started_at": stale.isoformat()},
        }
        session.commit()
        finished = engine.advance(session, workflow.id, actor_user_id=None)
        assert finished.status is engine.WorkflowStatus.COMPLETED


# --- graph governance (static) -------------------------------------------------


def test_graph_is_a_fixed_allowlist() -> None:
    assert tuple(engine.NODE_HANDLERS) == NODE_SEQUENCE
    for kind in AssessmentType:
        for explain in (False, True):
            snapshot = {
                "secret_scan_enabled": True,
                "dependency_audit_mode": "offline",
                "runtime_probes_enabled": True,
                "llm_explanations_enabled": True,
                "workflow_max_explanations": 5,
            }
            plan = plan_checks(kind, {"explain_findings": explain}, snapshot)
            assert plan == plan_checks(kind, {"explain_findings": explain}, snapshot)  # replayable
            for check in plan["checks"]:
                if check["kind"] == "tool":
                    assert check["check"] in TOOL_CHECKS


def test_exclusions_only_narrow_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "runtime_probes_enabled", False)
    assert web_tool_pipeline_config().enabled_stages == {"web_crawl"}
    # Even an "approved" probe cannot be enabled when configuration disables it.
    snapshot = config_snapshot()
    plan = plan_checks(AssessmentType.WEB_SECURITY, {}, snapshot)
    approvals = {"runtime_probes": {"decision": "approved"}}
    assert "runtime_probes" in excluded_tool_stages(plan, approvals)
    assert web_tool_pipeline_config(frozenset({"web_crawl"})).enabled_stages == frozenset()
    assert tool_pipeline_config(frozenset({"secret_scan"})).enabled_stages <= (
        tool_pipeline_config().enabled_stages
    )
