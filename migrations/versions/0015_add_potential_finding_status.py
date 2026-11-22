"""add potential finding status

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-16

"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES_V1 = ("confirmed", "not_reproduced", "inconclusive", "not_tested")
_STATUSES_V2 = ("confirmed", "potential", "not_reproduced", "inconclusive", "not_tested")


def _check_values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _replace_status_constraint(statuses: tuple[str, ...]) -> None:
    # SQLite batch mode rebuilds the table. migrations/env.py disables foreign-key
    # enforcement on migration connections so dependent finding_evidence rows are
    # preserved, then re-checks integrity afterwards.
    with op.batch_alter_table("assessment_findings") as batch_op:
        batch_op.drop_constraint("finding_status", type_="check")
        batch_op.create_check_constraint(
            "finding_status",
            f"status IN ({_check_values(statuses)})",
        )


def upgrade() -> None:
    _replace_status_constraint(_STATUSES_V2)


def downgrade() -> None:
    if not op.get_context().as_sql:
        count = (
            op.get_bind()
            .execute(text("SELECT COUNT(*) FROM assessment_findings WHERE status = 'potential'"))
            .scalar_one()
        )
        if count:
            raise RuntimeError(
                "Cannot downgrade migration 0015 while findings with status 'potential' "
                f"exist ({count} row(s)). Downgrading would require deleting or "
                "rewriting findings, which this migration will not do."
            )
    _replace_status_constraint(_STATUSES_V1)
