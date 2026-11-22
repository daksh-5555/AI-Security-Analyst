"""The existing static pipeline fits the tool contract unchanged (M1)."""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest
from disclosure_helpers import assert_no_path_disclosure

from app.core.config import settings
from app.schemas.tooling import EvidenceSourceType, ToolStatus
from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.attack_surface_reporting import analyze_discovered_repository
from app.services.repository_discovery import discover_repository
from app.services.tooling import PipelineConfig, StageRegistry, ToolContext, run_stages
from app.services.tooling.adapters import STATIC_STAGE, StaticAttackSurfaceTool

SOURCE = textwrap.dedent(
    """
    import sqlite3

    from flask import Flask, request

    app = Flask(__name__)


    @app.route("/direct")
    def handler():
        cursor = sqlite3.connect("app.db").cursor()
        cursor.execute(request.args.get("q"))
        return "ok"
    """
).lstrip()

FIXED = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    target = root / "project"
    target.mkdir(parents=True)
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    (target / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (target / "app.py").write_text(SOURCE, encoding="utf-8")
    return target


def _context(repository: Path, *, max_files: int | None = None) -> ToolContext:
    discovery = (
        discover_repository(repository)
        if max_files is None
        else discover_repository(repository, max_file_count=max_files)
    )
    return ToolContext(
        execution=AnalysisExecutionContext(60),
        repository_root=repository.resolve(),
        discovery=discovery,
        clock=lambda: FIXED,
    )


def test_adapter_matches_existing_pipeline_completeness(repository: Path) -> None:
    context = _context(repository)
    expected = analyze_discovered_repository(context.discovery).summary.summary

    result = StaticAttackSurfaceTool().run(context)

    assert result.stage == STATIC_STAGE
    assert (result.status is ToolStatus.COMPLETED) == expected.is_complete
    assert result.counts["routes"] == expected.route_count
    assert result.counts["issues"] == expected.issue_count
    assert result.counts["resolved_flow_relationships"] >= 1
    assert all(record.source_type is EvidenceSourceType.REPOSITORY for record in result.evidence)
    assert {record.location.path for record in result.evidence} == {"app.py"}
    assert all(
        record.provenance.rule_id.startswith("static.input_to_") for record in result.evidence
    )


def test_adapter_output_never_contains_absolute_paths(repository: Path) -> None:
    result = StaticAttackSurfaceTool().run(_context(repository))
    payload = json.loads(result.model_dump_json())
    assert_no_path_disclosure(payload, repository, repository.parent)


def test_adapter_is_deterministic(repository: Path) -> None:
    first = StaticAttackSurfaceTool().run(_context(repository))
    second = StaticAttackSurfaceTool().run(_context(repository))
    assert first.model_dump_json() == second.model_dump_json()


def test_truncated_discovery_becomes_partial_with_limitations(repository: Path) -> None:
    (repository / "extra.py").write_text("x = 1\n", encoding="utf-8")
    result = StaticAttackSurfaceTool().run(_context(repository, max_files=1))

    assert result.status is ToolStatus.PARTIAL
    assert any(item.code.startswith("discovery_truncated.") for item in result.limitations)
    assert not result.is_clean


def test_adapter_runs_through_the_registry_and_executor(repository: Path) -> None:
    registry = StageRegistry()
    registry.register(STATIC_STAGE, StaticAttackSurfaceTool(), order=100)

    outcome = run_stages(registry, _context(repository))
    assert outcome.results[0].stage == STATIC_STAGE
    assert outcome.results[0].evidence

    disabled = run_stages(
        registry, _context(repository), PipelineConfig(enabled_stages=frozenset())
    )
    assert disabled.results[0].status is ToolStatus.SKIPPED
    assert not disabled.is_clean


def test_adapter_is_skipped_without_a_discovery_inventory() -> None:
    registry = StageRegistry()
    registry.register(STATIC_STAGE, StaticAttackSurfaceTool(), order=100)
    outcome = run_stages(registry, ToolContext(execution=AnalysisExecutionContext(60)))
    assert outcome.results[0].status is ToolStatus.SKIPPED
