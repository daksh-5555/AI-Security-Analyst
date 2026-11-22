"""create analysis runs and link findings to runs

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-06

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

analysis_run_status = sa.Enum(
    "running",
    "completed",
    "failed",
    name="analysis_run_status",
    native_enum=False,
    create_constraint=True,
    length=20,
)


def upgrade() -> None:
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("status", analysis_run_status, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_analysis_runs_assessment_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_analysis_runs"),
    )
    op.create_index(
        "ix_analysis_runs_assessment_id_created_at",
        "analysis_runs",
        ["assessment_id", "created_at"],
        unique=False,
    )

    with op.batch_alter_table("assessment_findings") as batch_op:
        batch_op.add_column(sa.Column("analysis_run_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_assessment_findings_analysis_run_id",
            "analysis_runs",
            ["analysis_run_id"],
            ["id"],
            ondelete="CASCADE",
        )

    op.create_index(
        "ix_assessment_findings_analysis_run_id",
        "assessment_findings",
        ["analysis_run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_assessment_findings_analysis_run_id",
        table_name="assessment_findings",
    )

    with op.batch_alter_table("assessment_findings") as batch_op:
        batch_op.drop_column("analysis_run_id")

    op.drop_index(
        "ix_analysis_runs_assessment_id_created_at",
        table_name="analysis_runs",
    )
    op.drop_table("analysis_runs")
