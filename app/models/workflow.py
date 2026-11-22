"""Persisted state of bounded assessment workflows (M10, ADR-0013)."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, UniqueConstraint, Uuid, text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import WorkflowStatus


def _now() -> datetime:
    return datetime.now(UTC)


class AssessmentWorkflow(Base):
    """One workflow: its plan, approvals, current node, and step budget."""

    __tablename__ = "assessment_workflows"
    __table_args__ = (
        Index("ix_assessment_workflows_assessment_id_created_at", "assessment_id", "created_at"),
        Index(
            "uq_assessment_workflows_active_assessment",
            "assessment_id",
            unique=True,
            sqlite_where=text("status IN ('running', 'awaiting_approval')"),
            postgresql_where=text("status IN ('running', 'awaiting_approval')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_jobs.id", name="fk_assessment_workflows_assessment_id", ondelete="CASCADE"
        ),
        nullable=False,
    )
    status: Mapped[WorkflowStatus] = mapped_column(
        SAEnum(
            WorkflowStatus,
            name="workflow_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    graph_version: Mapped[str] = mapped_column(String(50), nullable=False)
    current_node: Mapped[str] = mapped_column(String(64), nullable=False)
    step_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    plan: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    analysis_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "analysis_runs.id", name="fk_assessment_workflows_analysis_run_id", ondelete="SET NULL"
        ),
        nullable=True,
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id", name="fk_assessment_workflows_requested_by_user_id", ondelete="SET NULL"
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class WorkflowEvent(Base):
    """Append-only record of each node outcome and approval decision."""

    __tablename__ = "workflow_events"
    __table_args__ = (
        UniqueConstraint("workflow_id", "sequence", name="uq_workflow_events_workflow_id_sequence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_workflows.id", name="fk_workflow_events_workflow_id", ondelete="CASCADE"
        ),
        nullable=False,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    node: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", name="fk_workflow_events_actor_user_id", ondelete="SET NULL"),
        nullable=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_now)
