"""normalize evidence and add finding identity and retest fields

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-16

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0017"
down_revision: str | Sequence[str] | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _finding_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("rule_id", sa.String(length=200), nullable=True),
        sa.Column("source_stage", sa.String(length=100), nullable=True),
        sa.Column("identity_key", sa.String(length=64), nullable=True),
        sa.Column("verification_method", sa.Text(), nullable=True),
        sa.Column("status_rationale", sa.Text(), nullable=True),
        sa.Column("cwe_ids", sa.JSON(), nullable=True),
        sa.Column("cve_ids", sa.JSON(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("previous_status", sa.String(length=20), nullable=True),
        sa.Column("previous_finding_id", sa.Uuid(), nullable=True),
    )


def upgrade() -> None:
    with op.batch_alter_table("assessment_findings") as batch_op:
        for column in _finding_columns():
            batch_op.add_column(column)
        batch_op.create_foreign_key(
            "fk_assessment_findings_previous_finding_id",
            "assessment_findings",
            ["previous_finding_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_assessment_findings_assessment_id_identity_key",
            ["assessment_id", "identity_key"],
        )

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_key", sa.String(length=300), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("tool_name", sa.String(length=200), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=False),
        sa.Column("rule_set_version", sa.String(length=64), nullable=True),
        sa.Column("rule_id", sa.String(length=200), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("location_path", sa.Text(), nullable=True),
        sa.Column("location_line", sa.Integer(), nullable=True),
        sa.Column("url_path", sa.Text(), nullable=True),
        sa.Column("parameter", sa.String(length=200), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("redacted_excerpt", sa.Text(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=True),
        sa.Column("request_summary", sa.JSON(), nullable=True),
        sa.Column("response_summary", sa.JSON(), nullable=True),
        sa.Column("limitations", sa.JSON(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_evidence_items"),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_evidence_items_assessment_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["analysis_runs.id"],
            name="fk_evidence_items_analysis_run_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "analysis_run_id",
            "evidence_key",
            name="uq_evidence_items_analysis_run_id_evidence_key",
        ),
    )
    op.create_index("ix_evidence_items_assessment_id", "evidence_items", ["assessment_id"])
    op.create_table(
        "finding_evidence_links",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_item_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("finding_id", "evidence_item_id", name="pk_finding_evidence_links"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["assessment_findings.id"],
            name="fk_finding_evidence_links_finding_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_item_id"],
            ["evidence_items.id"],
            name="fk_finding_evidence_links_evidence_item_id",
            ondelete="CASCADE",
        ),
    )
    # Existing findings were seen exactly when they were created.
    op.execute(
        text(
            "UPDATE assessment_findings SET first_seen_at = created_at, "
            "last_seen_at = created_at WHERE first_seen_at IS NULL"
        )
    )


def downgrade() -> None:
    if not op.get_context().as_sql:
        count = op.get_bind().execute(text("SELECT COUNT(*) FROM evidence_items")).scalar_one()
        if count:
            raise RuntimeError(
                "Cannot downgrade migration 0017 while normalized evidence exists "
                f"({count} row(s)); that would delete evidence referenced by findings."
            )
    op.drop_table("finding_evidence_links")
    op.drop_index("ix_evidence_items_assessment_id", table_name="evidence_items")
    op.drop_table("evidence_items")
    with op.batch_alter_table("assessment_findings") as batch_op:
        batch_op.drop_index("ix_assessment_findings_assessment_id_identity_key")
        batch_op.drop_constraint("fk_assessment_findings_previous_finding_id", type_="foreignkey")
        for column in reversed(_finding_columns()):
            batch_op.drop_column(column.name)
