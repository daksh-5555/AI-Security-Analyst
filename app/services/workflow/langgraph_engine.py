"""LangGraph-backed orchestration for assessment workflows (M14, ADR-0017).

LangGraph supplies the graph structure and drives traversal between the fixed,
allowlisted workflow nodes. It owns none of the security-critical state: the
authoritative workflow row, the per-step conditional-UPDATE claim, the step and
per-node budgets, the human-approval gate, crash recovery, and every audit event
stay in :mod:`app.services.workflow.engine`. Each LangGraph node runs exactly one
:func:`~app.services.workflow.engine.run_step_for_node`, so this driver and the
built-in driver are behaviourally identical and neither can bypass a control.

This layer makes no LLM, tool, shell, or network call; provider telemetry is
disabled. Traversal is bounded twice over: our ``WORKFLOW_MAX_STEPS`` budget
fails the run first, and LangGraph's ``recursion_limit`` is a hard backstop.
"""

from __future__ import annotations

import os
import uuid
import warnings
from functools import lru_cache
from typing import Any, TypedDict

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.workflow import AssessmentWorkflow
from app.schemas.enums import WorkflowStatus
from app.services.workflow.engine import ProviderFactory, run_step_for_node

# Keep the orchestration layer offline and quiet before LangGraph is imported.
os.environ.setdefault("LANGSMITH_TRACING", "false")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGCHAIN_ENDPOINT", "")

_RECURSION_BUFFER = 5


class _GraphState(TypedDict):
    # ``next`` is the node LangGraph should run next, or the END sentinel. The
    # runtime objects (db, ids, provider factory) travel in the invoke config,
    # never in the graph state.
    next: str
    stop: bool


@lru_cache(maxsize=1)
def build_graph() -> Any:
    """Compile the workflow StateGraph once per process.

    Nodes are the fixed workflow stages; every edge is conditional and routes
    either to the node the step advanced to or to END. The graph cannot reach
    any node outside this allowlist.
    """
    with warnings.catch_warnings():
        # LangChain's import runs surface_langchain_deprecation_warnings(), which
        # inserts its own "default" filter at the front of the list and so beats
        # an earlier simplefilter("ignore"). Import it first, then re-assert a
        # blanket ignore at the front before the checkpoint module (which warns)
        # loads. Scoped to this one-time, third-party build + compile.
        warnings.simplefilter("ignore")
        try:
            import langchain_core  # noqa: F401  (triggers its filter side effect first)
        except ImportError:
            pass
        warnings.filterwarnings("ignore")
        from langgraph.graph import END, StateGraph

        from app.services.workflow.plan import NODE_SEQUENCE

        path_map = {name: name for name in NODE_SEQUENCE}
        path_map["__end__"] = END

        builder = StateGraph(_GraphState)
        for name in NODE_SEQUENCE:
            builder.add_node(name, _make_node(name))
        builder.set_conditional_entry_point(_route, path_map=path_map)
        for name in NODE_SEQUENCE:
            builder.add_conditional_edges(name, _route, path_map=path_map)
        return builder.compile()


def _make_node(name: str):  # noqa: ANN202 - returns a LangGraph node callable
    def node(_state: _GraphState, config: dict[str, Any]) -> _GraphState:
        runtime = config["configurable"]
        db: Session = runtime["db"]
        workflow_id: uuid.UUID = runtime["workflow_id"]
        cont = run_step_for_node(
            db,
            workflow_id,
            actor_user_id=runtime["actor_user_id"],
            provider_factory=runtime["provider_factory"],
        )
        status, current = _status(db, workflow_id)
        if cont and status is WorkflowStatus.RUNNING and current is not None:
            return {"next": current, "stop": False}
        return {"next": "__end__", "stop": True}

    node.__name__ = f"node_{name}"
    return node


def _route(state: _GraphState) -> str:
    return "__end__" if state.get("stop") else state["next"]


def _status(db: Session, workflow_id: uuid.UUID) -> tuple[WorkflowStatus | None, str | None]:
    db.expire_all()
    workflow = db.get(AssessmentWorkflow, workflow_id)
    if workflow is None:
        return None, None
    return workflow.status, workflow.current_node


def drive(
    db: Session,
    workflow_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None,
    provider_factory: ProviderFactory,
) -> None:
    """Advance one workflow to its next stopping point via LangGraph.

    Returns once the workflow pauses for approval, errors, fails, or completes.
    Exceptions from the shared step function (for example a concurrent-advance
    conflict) propagate unchanged, matching the built-in driver.
    """
    status, current = _status(db, workflow_id)
    if status is not WorkflowStatus.RUNNING or current is None:
        return
    graph = build_graph()
    with warnings.catch_warnings():
        # LangGraph emits an upstream pending-deprecation notice from its
        # checkpoint serializer the first time a graph runs; it is third-party
        # and category/message filters do not reach it, so suppress here.
        warnings.simplefilter("ignore")
        graph.invoke(
            {"next": current, "stop": False},
            config={
                "recursion_limit": settings.workflow_max_steps + _RECURSION_BUFFER,
                "configurable": {
                    "db": db,
                    "workflow_id": workflow_id,
                    "actor_user_id": actor_user_id,
                    "provider_factory": provider_factory,
                },
            },
        )


__all__ = ["build_graph", "drive"]
