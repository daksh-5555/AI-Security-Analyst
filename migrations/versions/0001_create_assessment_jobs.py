"""create assessment jobs

Revision ID: 0001
Revises:
Create Date: 2026-10-26

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

assessment_type = sa.Enum(
    "repository",
    "web_security",
    "performance",
    name="assessment_type",
    native_enum=False,
    create_constraint=True,
    length=20,
)
assessment_status = sa.Enum(
    "queued",
    "running",
    "completed",
    "failed",
    name="assessment_status",
    native_enum=False,
    create_constraint=True,
    length=20,
)


def upgrade() -> None:
    op.create_table(
        "assessment_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_type", assessment_type, nullable=False),
        sa.Column("status", assessment_status, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_assessment_jobs_created_at",
        "assessment_jobs",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_assessment_jobs_created_at", table_name="assessment_jobs")
    op.drop_table("assessment_jobs")
