"""create assessment status history

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-26

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

assessment_previous_status = sa.Enum(
    "queued",
    "running",
    "completed",
    "failed",
    name="assessment_previous_status",
    native_enum=False,
    create_constraint=True,
    length=20,
)
assessment_new_status = sa.Enum(
    "queued",
    "running",
    "completed",
    "failed",
    name="assessment_new_status",
    native_enum=False,
    create_constraint=True,
    length=20,
)


def upgrade() -> None:
    op.create_table(
        "assessment_status_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("previous_status", assessment_previous_status, nullable=False),
        sa.Column("new_status", assessment_new_status, nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "previous_status <> new_status",
            name="ck_assessment_status_history_status_change",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_assessment_status_history_assessment_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assessment_status_history"),
    )
    op.create_index(
        "ix_assessment_status_history_assessment_id_changed_at",
        "assessment_status_history",
        ["assessment_id", "changed_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_assessment_status_history_assessment_id_changed_at",
        table_name="assessment_status_history",
    )
    op.drop_table("assessment_status_history")
