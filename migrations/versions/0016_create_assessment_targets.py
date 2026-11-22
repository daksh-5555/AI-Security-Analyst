"""create assessment targets and target authorization audit values

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-16

"""

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0016"
down_revision: str | Sequence[str] | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIONS_V2 = (
    "assessment.created",
    "assessment.access_denied",
    "assessment.lifecycle_changed",
    "assessment.lifecycle_denied",
    "repository_target.created",
    "analysis_run.started",
    "analysis_run.completed",
    "analysis_run.failed",
)
_ACTIONS_V3 = (*_ACTIONS_V2, "assessment_target.authorized", "assessment_target.revoked")
_RESOURCES_V1 = ("assessment", "repository_target", "analysis_run")
_RESOURCES_V2 = (*_RESOURCES_V1, "assessment_target")
_NEW_ACTIONS = ("assessment_target.authorized", "assessment_target.revoked")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=32)


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
        "assessment_targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column(
            "target_type",
            _enum("assessment_target_type", "repository", "web_application"),
            nullable=False,
        ),
        sa.Column("repository_target_id", sa.Uuid(), nullable=True),
        sa.Column("canonical_target", sa.Text(), nullable=False),
        sa.Column(
            "status",
            _enum("assessment_target_status", "pending_authorization", "authorized", "revoked"),
            nullable=False,
        ),
        sa.Column(
            "authorization_basis",
            _enum(
                "assessment_target_authorization_basis",
                "owner_registration",
                "explicit_confirmation",
                "legacy_backfill",
            ),
            nullable=True,
        ),
        sa.Column("authorization_statement", sa.Text(), nullable=True),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("authorized_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("policy_snapshot", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_assessment_targets"),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessment_jobs.id"],
            name="fk_assessment_targets_assessment_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["repository_target_id"],
            ["repository_targets.id"],
            name="fk_assessment_targets_repository_target_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_assessment_targets_created_by",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_by_user_id"],
            ["users.id"],
            name="fk_assessment_targets_authorized_by",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_user_id"],
            ["users.id"],
            name="fk_assessment_targets_revoked_by",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "assessment_id",
            "target_type",
            name="uq_assessment_targets_assessment_id_target_type",
        ),
        sa.UniqueConstraint(
            "repository_target_id",
            name="uq_assessment_targets_repository_target_id",
        ),
    )
    _replace_audit_constraints(_ACTIONS_V3, _RESOURCES_V2)
    _backfill_repository_targets()


def _backfill_repository_targets() -> None:
    """Create one target row per existing repository target.

    Targets whose assessment has an owner keep working (``legacy_backfill``,
    authorized by registration under the previous policy). Ownerless legacy rows
    become ``pending_authorization`` and are blocked from analysis until someone
    who can manage the assessment confirms them. No existing row is modified.
    """
    if op.get_context().as_sql:
        return
    bind = op.get_bind()
    rows = bind.execute(
        text(
            "SELECT rt.id, rt.assessment_id, rt.location, a.owner_id "
            "FROM repository_targets rt JOIN assessment_jobs a ON a.id = rt.assessment_id"
        )
    ).fetchall()
    if not rows:
        return
    now = datetime.now(UTC)
    table = sa.table(
        "assessment_targets",
        sa.column("id", sa.Uuid()),
        sa.column("assessment_id", sa.Uuid()),
        sa.column("target_type", sa.String()),
        sa.column("repository_target_id", sa.Uuid()),
        sa.column("canonical_target", sa.Text()),
        sa.column("status", sa.String()),
        sa.column("authorization_basis", sa.String()),
        sa.column("authorization_statement", sa.Text()),
        sa.column("created_by_user_id", sa.Uuid()),
        sa.column("authorized_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )

    def as_uuid(value: object) -> uuid.UUID | None:
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))

    records = []
    for target_id, assessment_id, location, owner_id in rows:
        owned = owner_id is not None
        records.append(
            {
                "id": uuid.uuid4(),
                "assessment_id": as_uuid(assessment_id),
                "target_type": "repository",
                "repository_target_id": as_uuid(target_id),
                "canonical_target": location,
                "status": "authorized" if owned else "pending_authorization",
                "authorization_basis": "legacy_backfill" if owned else None,
                "authorization_statement": (
                    "Registered by the assessment owner before explicit target "
                    "authorization existed (migration 0016)."
                    if owned
                    else None
                ),
                "created_by_user_id": as_uuid(owner_id),
                "authorized_at": now if owned else None,
                "created_at": now,
                "updated_at": now,
            }
        )
    op.bulk_insert(table, records)


def downgrade() -> None:
    if not op.get_context().as_sql:
        count = (
            op.get_bind()
            .execute(
                text(
                    "SELECT COUNT(*) FROM audit_events WHERE action IN (:a, :b) "
                    "OR resource_type = 'assessment_target'"
                ),
                {"a": _NEW_ACTIONS[0], "b": _NEW_ACTIONS[1]},
            )
            .scalar_one()
        )
        if count:
            raise RuntimeError(
                "Cannot downgrade migration 0016 while target-authorization audit events "
                f"exist ({count} row(s)); that would require deleting audit history."
            )
    _replace_audit_constraints(_ACTIONS_V2, _RESOURCES_V1)
    op.drop_table("assessment_targets")
