"""bounded assessment workflows and their event log

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-16

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0020"
down_revision: str | Sequence[str] | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_INDEX = "uq_assessment_workflows_active_assessment"
_ACTIVE = sa.text("status IN ('running', 'awaiting_approval')")
_ACTIONS_V5 = (
    "assessment.created",
    "assessment.access_denied",
    "assessment.lifecycle_changed",
    "assessment.lifecycle_denied",
    "repository_target.created",
    "analysis_run.started",
    "analysis_run.completed",
    "analysis_run.failed",
    "assessment_target.authorized",
    "assessment_target.revoked",
    "analysis_run.queued",
    "analysis_run.cancelled",
    "finding_explanation.created",
)
_NEW_ACTIONS = ("workflow.started", "workflow.approval_recorded", "workflow.finished")
_ACTIONS_V6 = (*_ACTIONS_V5, *_NEW_ACTIONS)
_RESOURCES_V3 = (
    "assessment",
    "repository_target",
    "analysis_run",
    "assessment_target",
    "finding_explanation",
)
_RESOURCES_V4 = (*_RESOURCES_V3, "workflow")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _replace_audit_constraints(actions: tuple[str, ...], resources: tuple[str, ...]) -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint("audit_action", type_="check")
        batch_op.create_check_constraint("audit_action", f"action IN ({_values(actions)})")
        batch_op.drop_constraint("audit_resource_type", type_="check")
        batch_op.create_check_constraint(
            "audit_resource_type", f"resource_type IN ({_values(resources)})"
        )


def upgrade() -> None:
    op.create_table(
        "assessment_workflows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "running",
                "awaiting_approval",
                "completed",
                "failed",
                "cancelled",
                name="workflow_status",
                native_enum=False,
                create_constraint=True,
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("graph_version", sa.String(length=50), nullable=False),
        sa.Column("current_node", sa.String(length=64), nullable=False),
        sa.Column("step_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=True),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_assessment_workflows"),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_assessment_workflows_assessment_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["analysis_runs.id"],
            name="fk_assessment_workflows_analysis_run_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name="fk_assessment_workflows_requested_by_user_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_assessment_workflows_assessment_id_created_at",
        "assessment_workflows",
        ["assessment_id", "created_at"],
    )
    op.create_index(
        ACTIVE_INDEX,
        "assessment_workflows",
        ["assessment_id"],
        unique=True,
        sqlite_where=_ACTIVE,
        postgresql_where=_ACTIVE,
    )
    op.create_table(
        "workflow_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("node", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_workflow_events"),
        sa.ForeignKeyConstraint(
            ["workflow_id"],
            ["assessment_workflows.id"],
            name="fk_workflow_events_workflow_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_workflow_events_actor_user_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "workflow_id", "sequence", name="uq_workflow_events_workflow_id_sequence"
        ),
    )
    _replace_audit_constraints(_ACTIONS_V6, _RESOURCES_V4)


def downgrade() -> None:
    if not op.get_context().as_sql:
        bind = op.get_bind()
        rows = bind.execute(text("SELECT COUNT(*) FROM assessment_workflows")).scalar_one()
        events = bind.execute(
            text("SELECT COUNT(*) FROM audit_events WHERE action IN (:a, :b, :c)"),
            dict(zip(("a", "b", "c"), _NEW_ACTIONS, strict=True)),
        ).scalar_one()
        if rows or events:
            raise RuntimeError(
                "Cannot downgrade migration 0020 while workflows "
                f"({rows} row(s)) or workflow audit events ({events} row(s)) exist; that "
                "would require deleting workflow or audit history."
            )
    _replace_audit_constraints(_ACTIONS_V5, _RESOURCES_V3)
    op.drop_table("workflow_events")
    op.drop_index(ACTIVE_INDEX, table_name="assessment_workflows")
    op.drop_index(
        "ix_assessment_workflows_assessment_id_created_at", table_name="assessment_workflows"
    )
    op.drop_table("assessment_workflows")
