"""create repository targets

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-02

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

repository_source_kind = sa.Enum(
    "local_path",
    name="repository_source_kind",
    native_enum=False,
    create_constraint=True,
    length=20,
)


def upgrade() -> None:
    op.create_table(
        "repository_targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("source_kind", repository_source_kind, nullable=False),
        sa.Column("location", sa.String(length=4096), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_repository_targets_assessment_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_repository_targets"),
        sa.UniqueConstraint(
            "assessment_id",
            name="uq_repository_targets_assessment_id",
        ),
    )


def downgrade() -> None:
    op.drop_table("repository_targets")
