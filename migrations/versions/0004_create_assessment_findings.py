"""create assessment findings and finding evidence

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-02

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

finding_severity = sa.Enum(
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "unknown",
    name="finding_severity",
    native_enum=False,
    create_constraint=True,
    length=20,
)
finding_status = sa.Enum(
    "confirmed",
    "not_reproduced",
    "inconclusive",
    "not_tested",
    name="finding_status",
    native_enum=False,
    create_constraint=True,
    length=20,
)


def upgrade() -> None:
    op.create_table(
        "assessment_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("affected_component", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_assessment_findings_confidence_range",
        ),
        sa.CheckConstraint(
            "position >= 0",
            name="ck_assessment_findings_position_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_assessment_findings_assessment_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assessment_findings"),
        sa.UniqueConstraint(
            "assessment_id",
            "position",
            name="uq_assessment_findings_assessment_id_position",
        ),
    )

    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "position >= 0",
            name="ck_finding_evidence_position_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["assessment_findings.id"],
            name="fk_finding_evidence_finding_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_evidence"),
        sa.UniqueConstraint(
            "finding_id",
            "position",
            name="uq_finding_evidence_finding_id_position",
        ),
    )


def downgrade() -> None:
    op.drop_table("finding_evidence")
    op.drop_table("assessment_findings")
