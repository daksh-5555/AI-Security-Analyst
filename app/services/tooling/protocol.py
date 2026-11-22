"""The protocol every analysis tool implements, and the context it receives.

Tools are deterministic analyzers or probes. They receive a read-only
``ToolContext`` and return a typed ``ToolResult``. They must not write to the
database, call FastAPI request objects, or open network connections except
through the guarded client introduced in M4 (ADR-0001, ADR-0004).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.tooling import ToolIdentity, ToolResult
from app.services.analysis_execution_context import AnalysisExecutionContext

if TYPE_CHECKING:
    from app.services.net import GuardedHttpClient


def utc_now() -> datetime:
    return datetime.now(UTC)


def _frozen(mapping: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return MappingProxyType(dict(mapping or {}))


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Immutable inputs for one tool invocation.

    ``repository_root`` is the already-validated resolved root. Tools must still
    revalidate it before reading files, exactly as the existing analyzers do.
    ``web_target_url`` and ``http_client`` are set only for web assessments.
    ``prior_results`` holds results of earlier stages in the same run, keyed by
    stage name, so a tool can consume typed outputs without importing the tool
    that produced them.
    """

    execution: AnalysisExecutionContext
    assessment_id: uuid.UUID | None = None
    analysis_run_id: uuid.UUID | None = None
    repository_root: Path | None = None
    discovery: RepositoryDiscoveryResult | None = None
    # Web tools: the authorized target's canonical base URL and the guarded client
    # bound to that target (from ``build_target_client``). Tools never build their
    # own clients.
    web_target_url: str | None = None
    http_client: GuardedHttpClient | None = None
    options: Mapping[str, Any] = field(default_factory=lambda: _frozen(None))
    prior_results: Mapping[str, ToolResult] = field(default_factory=lambda: _frozen(None))
    clock: Callable[[], datetime] = utc_now

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", _frozen(self.options))
        object.__setattr__(self, "prior_results", _frozen(self.prior_results))


@runtime_checkable
class AnalysisTool(Protocol):
    """A deterministic analysis tool that can be registered with the pipeline."""

    @property
    def identity(self) -> ToolIdentity:
        """Stable tool name, version, and rule-set version."""

    def applies_to(self, context: ToolContext) -> bool:
        """Return False when the tool has nothing to analyse in this context."""

    def run(self, context: ToolContext) -> ToolResult:
        """Execute the tool. Raise only for genuine failures or cancellation."""


__all__ = ["AnalysisTool", "ToolContext", "utc_now"]
