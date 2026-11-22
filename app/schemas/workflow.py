"""Schemas for bounded assessment workflows (M10)."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import WorkflowStatus


class WorkflowCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explain_findings: bool = Field(
        default=False,
        description="Also request advisory LLM explanations (needs LLM_EXPLANATIONS_ENABLED).",
    )


class WorkflowApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check: Literal["runtime_probes"] = Field(description="The pending high-risk check.")
    decision: Literal["approve", "deny"]
    reason: str = Field(min_length=1, max_length=500, description="Why, for the audit record.")


class WorkflowEventRead(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    sequence: int
    node: str
    outcome: str
    attempt: int
    detail: dict[str, Any] | None = None
    actor_user_id: uuid.UUID | None = None
    occurred_at: datetime


class WorkflowRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    assessment_id: uuid.UUID
    status: WorkflowStatus
    graph_version: str
    current_node: str
    step_count: int
    max_steps: int
    options: dict[str, Any]
    plan: dict[str, Any] | None = Field(
        default=None, description="Checks with risk, decision, reason, and the config snapshot."
    )
    approvals: dict[str, Any]
    pending_approvals: list[str]
    analysis_run_id: uuid.UUID | None = None
    error_code: str | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None


class WorkflowDetail(WorkflowRead):
    events: list[WorkflowEventRead]
