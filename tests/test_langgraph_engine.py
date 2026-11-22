"""LangGraph orchestration engine (M14, ADR-0017).

These tests pin the LangGraph-specific behaviour. The behavioural parity with the
built-in engine is proven by running the whole workflow suite under
``TEST_WORKFLOW_ENGINE=langgraph``; here we assert the graph shape, that the
driver is genuinely used, that it stays bounded and offline, and that the
security guarantees (approval gate, denied checks) still hold under LangGraph.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import httpx
import pytest
from probe_fixtures import ProbeHandler, probe_site
from pydantic import SecretStr
from test_workflows import outcomes, repo_assessment, start, web_assessment

from app.core.config import SecurityConfigurationError, Settings, validate_security_configuration
from app.core.config import settings as app_settings
from app.services.workflow import engine, langgraph_engine
from app.services.workflow.plan import NODE_SEQUENCE

pytestmark = pytest.mark.usefixtures("assessment_client")

URL = "/api/v1/assessments"


@pytest.fixture(autouse=True)
def _force_langgraph(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_settings, "workflow_engine", "langgraph")


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    repo = root / "project"
    repo.mkdir(parents=True)
    monkeypatch.setattr(app_settings, "repository_allowed_roots", [root])
    monkeypatch.setattr(
        app_settings, "evidence_fingerprint_key", SecretStr("test-only-fingerprint-key-" + "l" * 32)
    )
    (repo / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (repo / "app.py").write_text(
        "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
        '@app.route("/d")\ndef h():\n'
        '    sqlite3.connect("a.db").cursor().execute(request.args.get("q"))\n    return "ok"\n',
        encoding="utf-8",
    )
    return repo


# --- graph structure ------------------------------------------------------------


def test_graph_nodes_are_exactly_the_allowlisted_sequence() -> None:
    compiled = langgraph_engine.build_graph()
    drawn = compiled.get_graph()
    nodes = {n for n in drawn.nodes if n not in ("__start__", "__end__")}
    assert nodes == set(NODE_SEQUENCE)
    assert "__start__" in drawn.nodes and "__end__" in drawn.nodes
    # Compiled once and cached.
    assert langgraph_engine.build_graph() is compiled


def test_importing_langgraph_emits_no_warning() -> None:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        langgraph_engine.build_graph.cache_clear()
        langgraph_engine.build_graph()


# --- the driver is genuinely used ----------------------------------------------


@pytest.mark.anyio
async def test_workflow_runs_through_the_langgraph_driver(
    client: httpx.AsyncClient, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[uuid.UUID] = []
    real_drive = langgraph_engine.drive

    def spy(db, workflow_id, **kwargs):  # noqa: ANN001, ANN202
        calls.append(workflow_id)
        return real_drive(db, workflow_id, **kwargs)

    monkeypatch.setattr(langgraph_engine, "drive", spy)
    assessment_id = await repo_assessment(client, repository)
    workflow = (await start(client, assessment_id)).json()

    assert workflow["status"] == "completed"
    assert calls and str(calls[0]) == workflow["id"]  # LangGraph drove it
    assert [node for node, _ in outcomes(workflow)] == list(NODE_SEQUENCE)
    assert ("generate_report", "completed") in outcomes(workflow)


@pytest.mark.anyio
async def test_no_network_is_opened_by_orchestration(
    client: httpx.AsyncClient, repository: Path
) -> None:
    # The autouse offline guard fails any non-loopback connection; a repository
    # workflow reaches no network at all, so completing proves the orchestration
    # layer (which pulls in requests/urllib3) opened nothing.
    assessment_id = await repo_assessment(client, repository)
    workflow = (await start(client, assessment_id)).json()
    assert workflow["status"] == "completed"


# --- security parity under LangGraph -------------------------------------------


@pytest.fixture
def web_lab(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_settings, "web_target_allowed_hosts", ["127.0.0.1"])
    monkeypatch.setattr(app_settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])
    monkeypatch.setattr(app_settings, "web_target_max_requests_per_second", 50.0)
    monkeypatch.setattr(app_settings, "crawler_respect_robots", False)
    with probe_site() as port:
        ProbeHandler.log.clear()
        yield port


@pytest.mark.anyio
async def test_approval_gate_still_pauses_under_langgraph(
    client: httpx.AsyncClient, web_lab: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_settings, "runtime_probes_enabled", True)
    assessment_id = await web_assessment(client, web_lab)
    paused = (await start(client, assessment_id)).json()
    assert paused["status"] == "awaiting_approval"
    assert paused["pending_approvals"] == ["runtime_probes"]
    assert ProbeHandler.log == []  # LangGraph did not let the probe node run


# --- fail-closed configuration --------------------------------------------------


def test_config_fails_closed_when_langgraph_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    real = importlib.util.find_spec

    def missing(name: str, *a, **k):  # noqa: ANN002, ANN003, ANN202
        return None if name == "langgraph" else real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", missing)
    config = Settings(_env_file=None, workflow_engine="langgraph")
    with pytest.raises(SecurityConfigurationError, match="orchestration"):
        validate_security_configuration(config)
    # The built-in engine needs nothing extra.
    validate_security_configuration(Settings(_env_file=None, workflow_engine="builtin"))


def test_engine_default_is_builtin() -> None:
    assert Settings(_env_file=None).workflow_engine == "builtin"
    assert engine.run_step_for_node is not None  # shared step exported
