"""create audit events

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-11

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

audit_action = sa.Enum(
    "assessment.created",
    "assessment.access_denied",
    "assessment.lifecycle_changed",
    "assessment.lifecycle_denied",
    "repository_target.created",
    "analysis_run.started",
    name="audit_action",
    native_enum=False,
    create_constraint=True,
    length=64,
)
audit_outcome = sa.Enum(
    "success",
    "denied",
    name="audit_outcome",
    native_enum=False,
    create_constraint=True,
    length=16,
)
audit_resource_type = sa.Enum(
    "assessment",
    "repository_target",
    "analysis_run",
    name="audit_resource_type",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("assessment_id", sa.Uuid(), nullable=True),
        sa.Column("resource_type", audit_resource_type, nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=True),
        sa.Column("action", audit_action, nullable=False),
        sa.Column("outcome", audit_outcome, nullable=False),
        sa.Column("context", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_audit_events_actor_user_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_audit_events_assessment_id",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )
    op.create_index(
        "ix_audit_events_assessment_id_occurred_at",
        "audit_events",
        ["assessment_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_actor_user_id_occurred_at",
        "audit_events",
        ["actor_user_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_action_occurred_at",
        "audit_events",
        ["action", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_occurred_at",
        "audit_events",
        ["occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.drop_index("ix_audit_events_action_occurred_at", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_user_id_occurred_at", table_name="audit_events")
    op.drop_index("ix_audit_events_assessment_id_occurred_at", table_name="audit_events")
    op.drop_table("audit_events")
