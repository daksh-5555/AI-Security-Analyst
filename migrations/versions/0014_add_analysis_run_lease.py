"""add analysis run lease foundation

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-14

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_RUN_INDEX = "uq_analysis_runs_active_assessment"
CANCEL_ACTOR_FOREIGN_KEY = "fk_analysis_runs_cancel_requested_by_user_id"
RUNNING_PREDICATE = sa.text("status = 'running'")
BACKFILL_RUNNING_HEARTBEATS = sa.text(
    "UPDATE analysis_runs SET heartbeat_at = started_at "
    "WHERE status = 'running' AND heartbeat_at IS NULL"
)


def _create_active_run_index() -> None:
    op.create_index(
        ACTIVE_RUN_INDEX,
        "analysis_runs",
        ["assessment_id"],
        unique=True,
        sqlite_where=RUNNING_PREDICATE,
        postgresql_where=RUNNING_PREDICATE,
    )


def upgrade() -> None:
    # SQLite batch mode rebuilds the table, which does not reliably retain the
    # partial-index predicate. Recreate the index explicitly around the rebuild
    # so `WHERE status = 'running'` remains the exact uniqueness scope.
    op.drop_index(ACTIVE_RUN_INDEX, table_name="analysis_runs")

    with op.batch_alter_table("analysis_runs") as batch_op:
        batch_op.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("cancel_requested_by_user_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            CANCEL_ACTOR_FOREIGN_KEY,
            "users",
            ["cancel_requested_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )

    _create_active_run_index()

    # Running runs need a lease baseline. The NULL guard keeps this idempotent
    # and prevents a second pass from overwriting a newer heartbeat.
    op.execute(BACKFILL_RUNNING_HEARTBEATS)


def downgrade() -> None:
    # Drop the partial index before the rebuild and restore it afterwards, for
    # the same reason as the upgrade. Only lease columns are removed; run,
    # finding, and audit rows are left intact.
    op.drop_index(ACTIVE_RUN_INDEX, table_name="analysis_runs")

    with op.batch_alter_table("analysis_runs") as batch_op:
        batch_op.drop_constraint(CANCEL_ACTOR_FOREIGN_KEY, type_="foreignkey")
        batch_op.drop_column("cancel_requested_by_user_id")
        batch_op.drop_column("cancel_requested_at")
        batch_op.drop_column("heartbeat_at")

    _create_active_run_index()
