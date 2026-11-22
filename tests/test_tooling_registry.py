"""Registry and executor tests: tools are consumed only through typed results (M1)."""

from __future__ import annotations

import ast
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

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
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
    AnalysisExecutionContext,
)
from app.services.tooling import (
    AnalysisTool,
    PipelineConfig,
    RegistryError,
    StageRegistry,
    ToolBudget,
    ToolContext,
    run_stages,
)

FIXED = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
SECRET_MESSAGE = "boom at /srv/secret/path token=abc123"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class FakeTool:
    """Configurable tool used only by these tests."""

    def __init__(
        self,
        name: str,
        *,
        behaviour: Callable[[ToolContext], ToolResult | None] | None = None,
        applies: bool = True,
        evidence: bool = False,
    ) -> None:
        self._identity = ToolIdentity(name=name, version="1.0")
        self._behaviour = behaviour
        self._applies = applies
        self._evidence = evidence
        self.seen_contexts: list[ToolContext] = []

    @property
    def identity(self) -> ToolIdentity:
        return self._identity

    def applies_to(self, context: ToolContext) -> bool:
        return self._applies

    def run(self, context: ToolContext) -> ToolResult:
        self.seen_contexts.append(context)
        if self._behaviour is not None:
            outcome = self._behaviour(context)
            if outcome is not None:
                return outcome
        evidence = []
        if self._evidence:
            location = EvidenceLocation(path="app.py", line=1)
            evidence.append(
                EvidenceRecord(
                    evidence_key=f"{self._identity.name}:rule:1",
                    source_type=EvidenceSourceType.REPOSITORY,
                    provenance=EvidenceProvenance(
                        tool=self._identity, rule_id="rule", observed_at=FIXED, method="fake"
                    ),
                    location=location,
                    summary="fake observation",
                )
            )
        return ToolResult(
            tool=self._identity,
            stage=context.options.get("stage_name", self._identity.name),
            status=ToolStatus.COMPLETED,
            started_at=FIXED,
            finished_at=FIXED,
            evidence=evidence,
        )


def make_context(clock: FakeClock | None = None, timeout: float = 100.0) -> ToolContext:
    execution = AnalysisExecutionContext(timeout, clock=clock or FakeClock())
    return ToolContext(execution=execution, clock=lambda: FIXED)


def registry_with(*tools: FakeTool) -> StageRegistry:
    registry = StageRegistry()
    for index, tool in enumerate(tools):
        registry.register(tool.identity.name, tool, order=index * 10)
    return registry


def test_fake_tools_satisfy_the_protocol() -> None:
    assert isinstance(FakeTool("alpha"), AnalysisTool)


def test_registry_orders_deterministically_and_rejects_duplicates() -> None:
    registry = StageRegistry()
    registry.register("zeta", FakeTool("zeta"), order=1)
    registry.register("alpha", FakeTool("alpha"), order=1)
    registry.register("first", FakeTool("first"), order=0)
    assert registry.stages() == ("first", "alpha", "zeta")

    with pytest.raises(RegistryError):
        registry.register("alpha", FakeTool("other"), order=5)
    with pytest.raises(RegistryError):
        registry.register("another", FakeTool("alpha"), order=5)
    with pytest.raises(RegistryError):
        registry.register("Bad-Name", FakeTool("bad"), order=5)
    with pytest.raises(RegistryError):
        registry.register("notatool", object(), order=5)  # type: ignore[arg-type]


def test_executor_consumes_two_tools_through_typed_results() -> None:
    first, second = FakeTool("first", evidence=True), FakeTool("second")
    outcome = run_stages(registry_with(first, second), make_context())

    assert [result.stage for result in outcome.results] == ["first", "second"]
    assert [result.status for result in outcome.results] == [ToolStatus.COMPLETED] * 2
    assert outcome.is_complete
    assert not outcome.is_clean  # the first tool produced evidence
    # Later stages receive earlier typed results without importing the tool.
    assert set(second.seen_contexts[0].prior_results) == {"first"}
    assert second.seen_contexts[0].prior_results["first"].evidence


def test_executor_module_never_imports_concrete_tools() -> None:
    import app.services.tooling.executor as executor_module

    tree = ast.parse(Path(executor_module.__file__).read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not any("adapters" in module or "tools." in module for module in imported)
    assert "app.services.attack_surface_reporting" not in imported


def test_disabled_and_inapplicable_tools_are_skipped_not_omitted() -> None:
    enabled, disabled, inapplicable = FakeTool("on"), FakeTool("off"), FakeTool("na", applies=False)
    outcome = run_stages(
        registry_with(enabled, disabled, inapplicable),
        make_context(),
        PipelineConfig(enabled_stages=frozenset({"on", "na"})),
    )

    statuses = {result.stage: (result.status, result.error_code) for result in outcome.results}
    assert statuses["off"] == (ToolStatus.SKIPPED, SafeErrorCode.DISABLED)
    assert statuses["na"] == (ToolStatus.SKIPPED, SafeErrorCode.NOT_APPLICABLE)
    assert disabled.seen_contexts == []
    assert not outcome.is_clean
    assert set(outcome.incomplete_stages) == {"off", "na"}


def test_tool_exception_becomes_failed_without_leaking_its_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def explode(_context: ToolContext) -> None:
        raise RuntimeError(SECRET_MESSAGE)

    caplog.set_level(logging.DEBUG)
    later = FakeTool("later")
    outcome = run_stages(
        registry_with(FakeTool("broken", behaviour=explode), later), make_context()
    )

    broken = outcome.result_for("broken")
    assert broken is not None
    assert broken.status is ToolStatus.FAILED
    assert broken.error_code is SafeErrorCode.TOOL_ERROR
    assert outcome.result_for("later").status is ToolStatus.COMPLETED
    assert SECRET_MESSAGE not in outcome.results[0].model_dump_json()
    for record in caplog.records:
        assert SECRET_MESSAGE not in record.getMessage()
        assert SECRET_MESSAGE not in str(vars(record))
    assert not outcome.is_clean


def test_mislabelled_result_is_rejected() -> None:
    def wrong_stage(context: ToolContext) -> ToolResult:
        return ToolResult(
            tool=ToolIdentity(name="liar", version="1.0"),
            stage="somewhere_else",
            status=ToolStatus.COMPLETED,
            started_at=FIXED,
            finished_at=FIXED,
        )

    outcome = run_stages(registry_with(FakeTool("liar", behaviour=wrong_stage)), make_context())
    assert outcome.results[0].status is ToolStatus.FAILED


def test_cancellation_marks_current_and_remaining_stages_cancelled() -> None:
    context = make_context()

    def abort(ctx: ToolContext) -> None:
        ctx.execution.request_abort()
        ctx.execution.check()

    outcome = run_stages(
        registry_with(FakeTool("before"), FakeTool("aborting", behaviour=abort), FakeTool("after")),
        context,
    )
    assert [(r.stage, r.status) for r in outcome.results] == [
        ("before", ToolStatus.COMPLETED),
        ("aborting", ToolStatus.CANCELLED),
        ("after", ToolStatus.CANCELLED),
    ]
    assert outcome.results[2].error_code is SafeErrorCode.CANCELLED


def test_cancelled_before_start_runs_nothing() -> None:
    context = make_context()
    context.execution.request_abort()
    tool = FakeTool("never")
    outcome = run_stages(registry_with(tool), context)
    assert outcome.results[0].status is ToolStatus.CANCELLED
    assert tool.seen_contexts == []


def test_stage_budget_failure_does_not_stop_later_stages() -> None:
    clock = FakeClock()

    def slow(ctx: ToolContext) -> None:
        clock.now += 5  # exceeds the 2-second stage budget
        ctx.execution.check()

    outcome = run_stages(
        registry_with(FakeTool("slow", behaviour=slow), FakeTool("next")),
        make_context(clock, timeout=100),
        PipelineConfig(budgets={"slow": ToolBudget(max_seconds=2)}),
    )
    assert outcome.results[0].status is ToolStatus.FAILED
    assert outcome.results[0].error_code is SafeErrorCode.BUDGET_EXHAUSTED
    assert outcome.results[1].status is ToolStatus.COMPLETED


def test_run_deadline_cancels_remaining_stages_with_timeout() -> None:
    clock = FakeClock()

    def overrun(ctx: ToolContext) -> None:
        clock.now += 50
        ctx.execution.check()

    outcome = run_stages(
        registry_with(FakeTool("overrun", behaviour=overrun), FakeTool("next")),
        make_context(clock, timeout=10),
    )
    assert [(r.status, r.error_code) for r in outcome.results] == [
        (ToolStatus.CANCELLED, SafeErrorCode.TIMEOUT),
        (ToolStatus.CANCELLED, SafeErrorCode.TIMEOUT),
    ]


def test_child_context_never_outlives_parent_and_shares_abort() -> None:
    clock = FakeClock()
    parent = AnalysisExecutionContext(10, clock=clock)
    child = parent.child(100)
    assert child.remaining_seconds() == pytest.approx(10)
    assert parent.child(3).remaining_seconds() == pytest.approx(3)
    clock.now = 11
    with pytest.raises(AnalysisDeadlineExceededError):
        child.check()
    parent.request_abort()
    assert child.abort_event.is_set()
    with pytest.raises(AnalysisExecutionAbortedError):
        child.check()


def test_options_are_scoped_per_stage_and_read_only() -> None:
    tool = FakeTool("configured")
    run_stages(
        registry_with(tool),
        make_context(),
        PipelineConfig(options={"configured": {"max_files": 3}}),
    )
    options = tool.seen_contexts[0].options
    assert options["max_files"] == 3
    with pytest.raises(TypeError):
        options["max_files"] = 4  # type: ignore[index]


def test_empty_registry_is_never_clean() -> None:
    outcome = run_stages(StageRegistry(), make_context())
    assert outcome.results == ()
    assert not outcome.is_clean
    assert not outcome.is_complete
