"""Deterministic tests for cooperative analysis execution limits."""

import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.services import attack_surface_reporting
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
    AnalysisExecutionContext,
)
from app.services.repository_discovery import discover_repository


class FakeMonotonicClock:
    """Return scripted monotonic values, then stay beyond the deadline."""

    def __init__(self, values: list[float]) -> None:
        self._values = list(values)

    def __call__(self) -> float:
        if self._values:
            return self._values.pop(0)
        return float("inf")


def test_context_uses_the_injected_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wall_clock = [0.0]
    monkeypatch.setattr(time, "time", lambda: wall_clock[0])

    context = AnalysisExecutionContext(100, clock=lambda: 0.0)
    wall_clock[0] += 10_000

    context.check()
    assert context.should_continue() is True


def test_context_expires_on_monotonic_deadline() -> None:
    clock = FakeMonotonicClock([0.0, 99.0, 99.5, 100.0])
    context = AnalysisExecutionContext(100, clock=clock)

    context.check()
    assert context.should_continue() is True

    with pytest.raises(AnalysisDeadlineExceededError, match="Analysis timed out"):
        context.check()


def test_abort_is_distinct_from_deadline_expiration() -> None:
    context = AnalysisExecutionContext(100, clock=lambda: 0.0)
    context.request_abort()

    with pytest.raises(AnalysisExecutionAbortedError, match="execution aborted"):
        context.check()
    assert context.should_continue() is False


def test_pipeline_checks_between_stages_and_stops_on_abort(
    session_factory: sessionmaker[Session],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = SimpleNamespace(root=str(tmp_path))
    calls: list[str] = []
    stages = {
        "technologies": "detect_technologies",
        "attack_surface": "identify_attack_surface",
        "auth_controls": "identify_auth_controls",
        "input_sources": "identify_input_sources",
        "sensitive_operations": "identify_sensitive_operations",
        "correlation": "correlate_attack_surface",
        "handler_calls": "analyze_handler_calls",
        "input_operation_flow": "analyze_input_operation_flow",
        "summary": "summarize_attack_surface",
    }
    context = AnalysisExecutionContext(100, clock=lambda: 0.0)

    def stage(name: str):
        def run(*_args: object) -> object:
            calls.append(name)
            if name == "technologies":
                context.request_abort()
            return object()

        return run

    monkeypatch.setattr(
        attack_surface_reporting,
        "discover_registered_repository",
        lambda _db, _assessment_id, **_kwargs: discovery,
    )
    for attribute, function_name in stages.items():
        monkeypatch.setattr(
            attack_surface_reporting,
            function_name,
            stage(attribute),
        )

    with session_factory() as session:
        with pytest.raises(AnalysisExecutionAbortedError):
            attack_surface_reporting.collect_assessment_analysis(
                session,
                uuid.uuid4(),
                execution_context=context,
            )

    assert calls == ["technologies"]


def test_pipeline_deadline_expires_at_a_stage_boundary(
    session_factory: sessionmaker[Session],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = SimpleNamespace(root=str(tmp_path))
    calls: list[str] = []
    stages = {
        "technologies": "detect_technologies",
        "attack_surface": "identify_attack_surface",
        "auth_controls": "identify_auth_controls",
        "input_sources": "identify_input_sources",
        "sensitive_operations": "identify_sensitive_operations",
        "correlation": "correlate_attack_surface",
        "handler_calls": "analyze_handler_calls",
        "input_operation_flow": "analyze_input_operation_flow",
        "summary": "summarize_attack_surface",
    }

    def stage(name: str):
        def run(*_args: object) -> object:
            calls.append(name)
            return object()

        return run

    monkeypatch.setattr(
        attack_surface_reporting,
        "discover_registered_repository",
        lambda _db, _assessment_id, **_kwargs: discovery,
    )
    for attribute, function_name in stages.items():
        monkeypatch.setattr(
            attack_surface_reporting,
            function_name,
            stage(attribute),
        )

    # init, initial check, post-discovery check, then expiry after the first
    # real stage.
    context = AnalysisExecutionContext(
        10,
        clock=FakeMonotonicClock([0.0, 0.0, 0.0, 10.0]),
    )

    with session_factory() as session:
        with pytest.raises(AnalysisDeadlineExceededError):
            attack_surface_reporting.collect_assessment_analysis(
                session,
                uuid.uuid4(),
                execution_context=context,
            )

    assert calls == ["technologies"]


def test_deadline_expires_during_repository_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repositories"
    root.mkdir()
    repository = root / "project"
    repository.mkdir()
    (repository / "a.py").write_text("value = 1\n", encoding="utf-8")
    (repository / "b.py").write_text("value = 2\n", encoding="utf-8")
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])

    # init, initial walk check, then expiry at the first directory entry.
    context = AnalysisExecutionContext(
        10,
        clock=FakeMonotonicClock([0.0, 0.0, 10.0]),
    )

    with pytest.raises(AnalysisDeadlineExceededError):
        discover_repository(repository, execution_context=context)
