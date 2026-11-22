"""add analysis run terminal audit values

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-12

"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0013"
down_revision: str | Sequence[str] | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_AUDIT_ACTIONS_V1 = (
    "assessment.created",
    "assessment.access_denied",
    "assessment.lifecycle_changed",
    "assessment.lifecycle_denied",
    "repository_target.created",
    "analysis_run.started",
)
_AUDIT_ACTIONS_V2 = (
    *_AUDIT_ACTIONS_V1,
    "analysis_run.completed",
    "analysis_run.failed",
)
_AUDIT_OUTCOMES_V1 = ("success", "denied")
_AUDIT_OUTCOMES_V2 = ("success", "failure", "denied")
_TERMINAL_ACTIONS = ("analysis_run.completed", "analysis_run.failed")


def _check_values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _replace_constraints(
    *,
    actions: tuple[str, ...],
    outcomes: tuple[str, ...],
) -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint("audit_action", type_="check")
        batch_op.create_check_constraint(
            "audit_action",
            f"action IN ({_check_values(actions)})",
        )
        batch_op.drop_constraint("audit_outcome", type_="check")
        batch_op.create_check_constraint(
            "audit_outcome",
            f"outcome IN ({_check_values(outcomes)})",
        )


def _assert_terminal_audit_rows_are_absent() -> None:
    """Refuse a downgrade that would require deleting terminal audit history."""
    if op.get_context().as_sql:
        # Offline SQL generation cannot inspect existing rows.
        return

    bind = op.get_bind()
    terminal_count = bind.execute(
        text(
            "SELECT COUNT(*) FROM audit_events "
            "WHERE action IN (:completed, :failed) OR outcome = 'failure'"
        ),
        {"completed": _TERMINAL_ACTIONS[0], "failed": _TERMINAL_ACTIONS[1]},
    ).scalar_one()
    if terminal_count:
        raise RuntimeError(
            "Cannot downgrade migration 0013 while terminal analysis-run audit "
            f"events exist ({terminal_count} row(s)). Downgrading would require "
            "deleting or rewriting durable audit history, which this migration "
            "will not do. Retain or resolve those rows through the approved "
            "audit-retention process, then retry the downgrade."
        )


def upgrade() -> None:
    _replace_constraints(
        actions=_AUDIT_ACTIONS_V2,
        outcomes=_AUDIT_OUTCOMES_V2,
    )


def downgrade() -> None:
    # Reverting fails loudly if terminal analysis-run audit rows still exist,
    # rather than silently rewriting durable audit history. The check must run
    # before batch DDL so SQLite does not leave a temporary table behind.
    _assert_terminal_audit_rows_are_absent()
    _replace_constraints(
        actions=_AUDIT_ACTIONS_V1,
        outcomes=_AUDIT_OUTCOMES_V1,
    )
