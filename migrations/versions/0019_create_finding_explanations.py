"""advisory LLM finding explanations

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-16

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0019"
down_revision: str | Sequence[str] | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIONS_V4 = (
    "assessment.created",
    "assessment.access_denied",
    "assessment.lifecycle_changed",
    "assessment.lifecycle_denied",
    "repository_target.created",
    "analysis_run.started",
    "analysis_run.completed",
    "analysis_run.failed",
    "assessment_target.authorized",
    "assessment_target.revoked",
    "analysis_run.queued",
    "analysis_run.cancelled",
)
_ACTIONS_V5 = (*_ACTIONS_V4, "finding_explanation.created")
_RESOURCES_V2 = ("assessment", "repository_target", "analysis_run", "assessment_target")
_RESOURCES_V3 = (*_RESOURCES_V2, "finding_explanation")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _replace_audit_constraints(actions: tuple[str, ...], resources: tuple[str, ...]) -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint("audit_action", type_="check")
        batch_op.create_check_constraint("audit_action", f"action IN ({_values(actions)})")
        batch_op.drop_constraint("audit_resource_type", type_="check")
        batch_op.create_check_constraint(
            "audit_resource_type", f"resource_type IN ({_values(resources)})"
        )


def upgrade() -> None:
    op.create_table(
        "finding_explanations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "available",
                "unavailable",
                name="finding_explanation_status",
                native_enum=False,
                create_constraint=True,
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("prompt_template_version", sa.String(length=50), nullable=False),
        sa.Column("output", sa.JSON(), nullable=True),
        sa.Column("supplied_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_finding_explanations"),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_finding_explanations_assessment_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["assessment_findings.id"],
            name="fk_finding_explanations_finding_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name="fk_finding_explanations_requested_by_user_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_finding_explanations_finding_id_created_at",
        "finding_explanations",
        ["finding_id", "created_at"],
    )
    op.create_index(
        "ix_finding_explanations_assessment_id", "finding_explanations", ["assessment_id"]
    )
    _replace_audit_constraints(_ACTIONS_V5, _RESOURCES_V3)


def downgrade() -> None:
    if not op.get_context().as_sql:
        bind = op.get_bind()
        rows = bind.execute(text("SELECT COUNT(*) FROM finding_explanations")).scalar_one()
        events = bind.execute(
            text("SELECT COUNT(*) FROM audit_events WHERE action = 'finding_explanation.created'")
        ).scalar_one()
        if rows or events:
            raise RuntimeError(
                "Cannot downgrade migration 0019 while finding explanations "
                f"({rows} row(s)) or their audit events ({events} row(s)) exist; that "
                "would require deleting explanation or audit history."
            )
    _replace_audit_constraints(_ACTIONS_V4, _RESOURCES_V2)
    op.drop_index("ix_finding_explanations_assessment_id", table_name="finding_explanations")
    op.drop_index(
        "ix_finding_explanations_finding_id_created_at", table_name="finding_explanations"
    )
    op.drop_table("finding_explanations")
