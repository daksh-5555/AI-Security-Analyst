"""Stage registry and pipeline configuration.

The registry is the only place that knows which tools exist. The executor
consumes the registry's plan and the tools' typed results, so adding a scanner
means registering it, not editing the executor.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from app.services.tooling.protocol import AnalysisTool

_STAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]*$")


class RegistryError(ValueError):
    """Raised for invalid or conflicting registrations."""


@dataclass(frozen=True, slots=True)
class StageRegistration:
    """One tool bound to a named stage at a position in the plan."""

    stage: str
    order: int
    tool: AnalysisTool


@dataclass(frozen=True, slots=True)
class ToolBudget:
    """Per-stage limits. ``max_seconds`` is enforced cooperatively."""

    max_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.max_seconds is not None and self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive")


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Which stages run and with which budgets and options.

    ``enabled_stages=None`` enables every registered stage. Stages that are
    registered but not enabled are reported as ``skipped``; they are never
    silently omitted from the outcome.
    """

    enabled_stages: frozenset[str] | None = None
    budgets: Mapping[str, ToolBudget] = field(default_factory=dict)
    options: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.enabled_stages is not None:
            object.__setattr__(self, "enabled_stages", frozenset(self.enabled_stages))
        object.__setattr__(self, "budgets", MappingProxyType(dict(self.budgets)))
        object.__setattr__(
            self,
            "options",
            MappingProxyType(
                {key: MappingProxyType(dict(value)) for key, value in self.options.items()}
            ),
        )

    def is_enabled(self, stage: str) -> bool:
        return self.enabled_stages is None or stage in self.enabled_stages

    def budget_for(self, stage: str) -> ToolBudget:
        return self.budgets.get(stage, ToolBudget())

    def options_for(self, stage: str) -> Mapping[str, Any]:
        return self.options.get(stage, MappingProxyType({}))


class StageRegistry:
    """Ordered, duplicate-free mapping of stage names to tools."""

    def __init__(self, registrations: Iterable[StageRegistration] = ()) -> None:
        self._by_stage: dict[str, StageRegistration] = {}
        for registration in registrations:
            self.register(registration.stage, registration.tool, order=registration.order)

    def register(self, stage: str, tool: AnalysisTool, *, order: int) -> None:
        if not _STAGE_PATTERN.fullmatch(stage):
            raise RegistryError("stage names must be lowercase letters, digits, or '_'")
        if not isinstance(tool, AnalysisTool):
            raise RegistryError("tool does not implement the AnalysisTool protocol")
        if stage in self._by_stage:
            raise RegistryError(f"stage '{stage}' is already registered")
        name = tool.identity.name
        if any(existing.tool.identity.name == name for existing in self._by_stage.values()):
            raise RegistryError(f"tool '{name}' is already registered")
        self._by_stage[stage] = StageRegistration(stage=stage, order=order, tool=tool)

    def plan(self) -> tuple[StageRegistration, ...]:
        """Registrations in deterministic execution order (order, then stage name)."""
        return tuple(sorted(self._by_stage.values(), key=lambda item: (item.order, item.stage)))

    def stages(self) -> tuple[str, ...]:
        return tuple(registration.stage for registration in self.plan())

    def __contains__(self, stage: object) -> bool:
        return stage in self._by_stage

    def __len__(self) -> int:
        return len(self._by_stage)


__all__ = [
    "PipelineConfig",
    "RegistryError",
    "StageRegistration",
    "StageRegistry",
    "ToolBudget",
]
