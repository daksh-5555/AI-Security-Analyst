"""Extension seam for analysis tools (ADR-0001).

Concrete tools are registered in a ``StageRegistry`` and executed by
``run_stages``; the executor consumes only the typed ``ToolResult`` contract.
"""

from app.services.tooling.executor import PipelineOutcome, run_stages
from app.services.tooling.protocol import AnalysisTool, ToolContext
from app.services.tooling.registry import (
    PipelineConfig,
    RegistryError,
    StageRegistration,
    StageRegistry,
    ToolBudget,
)

__all__ = [
    "AnalysisTool",
    "PipelineConfig",
    "PipelineOutcome",
    "RegistryError",
    "StageRegistration",
    "StageRegistry",
    "ToolBudget",
    "ToolContext",
    "run_stages",
]
