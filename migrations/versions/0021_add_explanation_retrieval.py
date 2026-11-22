"""record knowledge retrieval used by explanations

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-17

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | Sequence[str] | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("finding_explanations") as batch_op:
        batch_op.add_column(sa.Column("retrieval", sa.JSON(), nullable=True))


def downgrade() -> None:
    # Dropping only removes retrieval provenance; explanations themselves remain.
    with op.batch_alter_table("finding_explanations") as batch_op:
        batch_op.drop_column("retrieval")
