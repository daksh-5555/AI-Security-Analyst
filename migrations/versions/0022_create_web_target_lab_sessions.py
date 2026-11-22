"""authenticated local lab sessions for web targets

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-17

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0022"
down_revision: str | Sequence[str] | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIONS_V6 = (
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
    "workflow.started",
    "workflow.approval_recorded",
    "workflow.finished",
)
_NEW_ACTIONS = ("web_target.lab_session_established", "web_target.lab_session_cleared")
_ACTIONS_V7 = (*_ACTIONS_V6, *_NEW_ACTIONS)


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _set_audit_actions(actions: tuple[str, ...]) -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint("audit_action", type_="check")
        batch_op.create_check_constraint("audit_action", f"action IN ({_values(actions)})")


def upgrade() -> None:
    op.create_table(
        "web_target_lab_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=200), nullable=False),
        sa.Column("login_path", sa.String(length=300), nullable=False),
        # The established lab session cookie, stored to replay against the local
        # lab only. Never returned by the API, logged, or placed in evidence.
        sa.Column("cookie_header", sa.Text(), nullable=False),
        sa.Column("established_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("established_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_web_target_lab_sessions"),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_web_target_lab_sessions_assessment_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["established_by_user_id"],
            ["users.id"],
            name="fk_web_target_lab_sessions_established_by_user_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("assessment_id", name="uq_web_target_lab_sessions_assessment_id"),
    )
    _set_audit_actions(_ACTIONS_V7)


def downgrade() -> None:
    if not op.get_context().as_sql:
        bind = op.get_bind()
        rows = bind.execute(text("SELECT COUNT(*) FROM web_target_lab_sessions")).scalar_one()
        events = bind.execute(
            text("SELECT COUNT(*) FROM audit_events WHERE action IN (:a, :b)"),
            {"a": _NEW_ACTIONS[0], "b": _NEW_ACTIONS[1]},
        ).scalar_one()
        if rows or events:
            raise RuntimeError(
                "Cannot downgrade migration 0022 while lab sessions "
                f"({rows} row(s)) or lab-session audit events ({events} row(s)) exist."
            )
    _set_audit_actions(_ACTIONS_V6)
    op.drop_table("web_target_lab_sessions")
