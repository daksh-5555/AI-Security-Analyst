"""enforce one running analysis run per assessment

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-07

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_RUN_INDEX = "uq_analysis_runs_active_assessment"
RUNNING_PREDICATE = sa.text("status = 'running'")


def upgrade() -> None:
    dialect = op.get_context().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError(
            "uq_analysis_runs_active_assessment requires partial unique index support; "
            f"dialect '{dialect}' is not supported"
        )

    op.create_index(
        ACTIVE_RUN_INDEX,
        "analysis_runs",
        ["assessment_id"],
        unique=True,
        sqlite_where=RUNNING_PREDICATE,
        postgresql_where=RUNNING_PREDICATE,
    )


def downgrade() -> None:
    op.drop_index(ACTIVE_RUN_INDEX, table_name="analysis_runs")
