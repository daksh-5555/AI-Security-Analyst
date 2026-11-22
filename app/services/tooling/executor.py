"""Run registered tools in order and collect their typed results.

The executor never imports a concrete tool. Its guarantees (ADR-0001):

- every registered stage appears in the outcome exactly once;
- disabled or inapplicable stages are ``skipped`` with a reason code;
- an exception becomes a ``failed`` result with a safe error code; exception
  text is neither stored nor logged;
- cancellation and run-deadline expiry become ``cancelled`` for the current and
  every remaining stage;
- a per-stage budget that runs out fails only that stage;
- the outcome is never "clean" unless every stage completed without evidence.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, replace

from app.schemas.tooling import SafeErrorCode, ToolIdentity, ToolResult, ToolStatus
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
)
from app.services.tooling.protocol import ToolContext
from app.services.tooling.registry import PipelineConfig, StageRegistry

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PipelineOutcome:
    """Results of every registered stage, in plan order."""

    results: tuple[ToolResult, ...]

    @property
    def is_clean(self) -> bool:
        """True only when at least one stage ran and all completed with no evidence."""
        return bool(self.results) and all(result.is_clean for result in self.results)

    @property
    def is_complete(self) -> bool:
        return bool(self.results) and all(
            result.status is ToolStatus.COMPLETED for result in self.results
        )

    @property
    def incomplete_stages(self) -> tuple[str, ...]:
        return tuple(
            result.stage for result in self.results if result.status is not ToolStatus.COMPLETED
        )

    def result_for(self, stage: str) -> ToolResult | None:
        return next((result for result in self.results if result.stage == stage), None)


def _synthetic(
    identity: ToolIdentity,
    stage: str,
    status: ToolStatus,
    code: SafeErrorCode,
    context: ToolContext,
) -> ToolResult:
    now = context.clock()
    return ToolResult(
        tool=identity,
        stage=stage,
        status=status,
        started_at=now,
        finished_at=now,
        error_code=code,
    )


def _log_failure(
    stage: str, identity: ToolIdentity, code: SafeErrorCode, exc: BaseException
) -> None:
    # Only the exception type is logged: messages can contain paths or values.
    logger.warning(
        "Analysis tool did not complete.",
        extra={
            "stage": stage,
            "tool": identity.name,
            "error_code": code.value,
            "error_type": type(exc).__name__,
        },
    )


def run_stages(
    registry: StageRegistry,
    context: ToolContext,
    config: PipelineConfig | None = None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> PipelineOutcome:
    """Execute every registered stage and return their results in plan order."""
    pipeline = config or PipelineConfig()
    results: list[ToolResult] = []
    prior: dict[str, ToolResult] = {}
    stop_code: SafeErrorCode | None = None

    for registration in registry.plan():
        stage, tool = registration.stage, registration.tool
        identity = tool.identity

        if stop_code is not None:
            results.append(_synthetic(identity, stage, ToolStatus.CANCELLED, stop_code, context))
            continue
        if not pipeline.is_enabled(stage):
            results.append(
                _synthetic(identity, stage, ToolStatus.SKIPPED, SafeErrorCode.DISABLED, context)
            )
            continue
        if context.execution.abort_event.is_set():
            stop_code = SafeErrorCode.CANCELLED
        elif context.execution.remaining_seconds() <= 0:
            stop_code = SafeErrorCode.TIMEOUT
        if stop_code is not None:
            results.append(_synthetic(identity, stage, ToolStatus.CANCELLED, stop_code, context))
            continue

        stage_context = replace(
            context,
            execution=context.execution.child(pipeline.budget_for(stage).max_seconds),
            options=pipeline.options_for(stage),
            prior_results=dict(prior),
        )
        try:
            if not tool.applies_to(stage_context):
                results.append(
                    _synthetic(
                        identity, stage, ToolStatus.SKIPPED, SafeErrorCode.NOT_APPLICABLE, context
                    )
                )
                continue
            started = monotonic()
            result = tool.run(stage_context)
            elapsed = monotonic() - started
        except AnalysisExecutionAbortedError as exc:
            stop_code = SafeErrorCode.CANCELLED
            _log_failure(stage, identity, stop_code, exc)
            results.append(_synthetic(identity, stage, ToolStatus.CANCELLED, stop_code, context))
            continue
        except AnalysisDeadlineExceededError as exc:
            if context.execution.should_continue():
                # Only this stage's budget ran out; later stages may still run.
                code = SafeErrorCode.BUDGET_EXHAUSTED
                _log_failure(stage, identity, code, exc)
                results.append(_synthetic(identity, stage, ToolStatus.FAILED, code, context))
                continue
            stop_code = (
                SafeErrorCode.CANCELLED
                if context.execution.abort_event.is_set()
                else SafeErrorCode.TIMEOUT
            )
            _log_failure(stage, identity, stop_code, exc)
            results.append(_synthetic(identity, stage, ToolStatus.CANCELLED, stop_code, context))
            continue
        except Exception as exc:  # every tool failure is contained
            _log_failure(stage, identity, SafeErrorCode.TOOL_ERROR, exc)
            results.append(
                _synthetic(identity, stage, ToolStatus.FAILED, SafeErrorCode.TOOL_ERROR, context)
            )
            continue

        if not isinstance(result, ToolResult) or result.stage != stage or result.tool != identity:
            # A tool that mislabels its output cannot be trusted as evidence.
            logger.warning(
                "Analysis tool returned an invalid result.",
                extra={"stage": stage, "tool": identity.name},
            )
            results.append(
                _synthetic(identity, stage, ToolStatus.FAILED, SafeErrorCode.TOOL_ERROR, context)
            )
            continue

        usage = result.usage
        if usage.wall_time_seconds == 0.0 and elapsed > 0:
            result = result.model_copy(
                update={"usage": usage.model_copy(update={"wall_time_seconds": elapsed})}
            )
        results.append(result)
        prior[stage] = result

    return PipelineOutcome(results=tuple(results))


__all__ = ["PipelineOutcome", "run_stages"]
