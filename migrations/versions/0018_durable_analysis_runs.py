"""durable background analysis runs: queued/cancelled states, lease, progress

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-16

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0018"
down_revision: str | Sequence[str] | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_RUN_INDEX = "uq_analysis_runs_active_assessment"
QUEUE_INDEX = "ix_analysis_runs_status_created_at"
REQUESTER_FOREIGN_KEY = "fk_analysis_runs_requested_by_user_id"
_RUNNING_ONLY = sa.text("status = 'running'")
_QUEUED_OR_RUNNING = sa.text("status IN ('queued', 'running')")

_STATUSES_V1 = ("running", "completed", "failed")
_STATUSES_V2 = ("queued", "running", "completed", "failed", "cancelled")
_ACTIONS_V3 = (
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
)
_NEW_ACTIONS = ("analysis_run.queued", "analysis_run.cancelled")
_ACTIONS_V4 = (*_ACTIONS_V3, *_NEW_ACTIONS)


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _run_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("lease_owner", sa.String(length=200), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stage", sa.String(length=64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("summary_snapshot", sa.JSON(), nullable=True),
    )


def _create_active_index(predicate: sa.TextClause) -> None:
    op.create_index(
        ACTIVE_RUN_INDEX,
        "analysis_runs",
        ["assessment_id"],
        unique=True,
        sqlite_where=predicate,
        postgresql_where=predicate,
    )


def _replace_audit_actions(actions: tuple[str, ...]) -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint("audit_action", type_="check")
        batch_op.create_check_constraint("audit_action", f"action IN ({_values(actions)})")


def upgrade() -> None:
    # SQLite batch mode rebuilds the table and does not reliably keep the
    # partial-index predicate, so the index is dropped and recreated explicitly.
    op.drop_index(ACTIVE_RUN_INDEX, table_name="analysis_runs")
    with op.batch_alter_table("analysis_runs") as batch_op:
        batch_op.drop_constraint("analysis_run_status", type_="check")
        batch_op.create_check_constraint(
            "analysis_run_status", f"status IN ({_values(_STATUSES_V2)})"
        )
        for column in _run_columns():
            batch_op.add_column(column)
        batch_op.create_foreign_key(
            REQUESTER_FOREIGN_KEY,
            "users",
            ["requested_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(QUEUE_INDEX, ["status", "created_at"])
    # One active (queued or running) run per assessment.
    _create_active_index(_QUEUED_OR_RUNNING)
    _replace_audit_actions(_ACTIONS_V4)


def _refuse_lossy_downgrade() -> None:
    if op.get_context().as_sql:
        return
    bind = op.get_bind()
    runs = bind.execute(
        text("SELECT COUNT(*) FROM analysis_runs WHERE status IN ('queued', 'cancelled')")
    ).scalar_one()
    events = bind.execute(
        text("SELECT COUNT(*) FROM audit_events WHERE action IN (:a, :b)"),
        {"a": _NEW_ACTIONS[0], "b": _NEW_ACTIONS[1]},
    ).scalar_one()
    if runs or events:
        raise RuntimeError(
            "Cannot downgrade migration 0018 while queued or cancelled analysis runs "
            f"({runs} row(s)) or queue/cancel audit events ({events} row(s)) exist; "
            "that would require deleting run or audit history."
        )


def downgrade() -> None:
    _refuse_lossy_downgrade()
    _replace_audit_actions(_ACTIONS_V3)
    op.drop_index(ACTIVE_RUN_INDEX, table_name="analysis_runs")
    with op.batch_alter_table("analysis_runs") as batch_op:
        batch_op.drop_index(QUEUE_INDEX)
        batch_op.drop_constraint(REQUESTER_FOREIGN_KEY, type_="foreignkey")
        for column in reversed(_run_columns()):
            batch_op.drop_column(column.name)
        batch_op.drop_constraint("analysis_run_status", type_="check")
        batch_op.create_check_constraint(
            "analysis_run_status", f"status IN ({_values(_STATUSES_V1)})"
        )
    _create_active_index(_RUNNING_ONLY)
