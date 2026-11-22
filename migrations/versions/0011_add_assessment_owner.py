"""add nullable assessment owner

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-10

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OWNER_FOREIGN_KEY = "fk_assessment_jobs_owner_id"
OWNER_INDEX = "ix_assessment_jobs_owner_id"


def upgrade() -> None:
    with op.batch_alter_table("assessment_jobs") as batch_op:
        batch_op.add_column(sa.Column("owner_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            OWNER_FOREIGN_KEY,
            "users",
            ["owner_id"],
            ["id"],
            ondelete="RESTRICT",
        )

    op.create_index(
        OWNER_INDEX,
        "assessment_jobs",
        ["owner_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(OWNER_INDEX, table_name="assessment_jobs")

    with op.batch_alter_table("assessment_jobs") as batch_op:
        batch_op.drop_constraint(OWNER_FOREIGN_KEY, type_="foreignkey")
        batch_op.drop_column("owner_id")
