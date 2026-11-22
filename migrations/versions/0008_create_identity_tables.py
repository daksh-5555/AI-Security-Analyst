"""create identity tables and seed canonical roles

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-07

"""

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE_ADMIN_ID = uuid.UUID("d4cb62aa-d7fe-5173-b863-db5f6f51332c")
ROLE_SECURITY_ANALYST_ID = uuid.UUID("e6fbed1f-2a57-5880-ab46-48a50e432747")
ROLE_VIEWER_ID = uuid.UUID("1ccf37b3-3921-5a91-ab87-3192b3a4bba1")

ROLE_NAMES = (
    "Admin",
    "Security Analyst",
    "Viewer",
)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_email_verified", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint(
            "email_normalized",
            name="uq_users_email_normalized",
        ),
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_roles_user_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_user_roles_role_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"),
    )

    op.create_index(
        "ix_user_roles_role_id",
        "user_roles",
        ["role_id"],
        unique=False,
    )

    roles_table = sa.table(
        "roles",
        sa.column("id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    seeded_at = datetime.now(UTC)
    op.bulk_insert(
        roles_table,
        [
            {
                "id": ROLE_ADMIN_ID,
                "name": ROLE_NAMES[0],
                "created_at": seeded_at,
            },
            {
                "id": ROLE_SECURITY_ANALYST_ID,
                "name": ROLE_NAMES[1],
                "created_at": seeded_at,
            },
            {
                "id": ROLE_VIEWER_ID,
                "name": ROLE_NAMES[2],
                "created_at": seeded_at,
            },
        ],
    )


def downgrade() -> None:
    # Destructive only for the identity tables introduced by this revision.
    op.drop_index("ix_user_roles_role_id", table_name="user_roles")
    op.drop_table("user_roles")
    op.drop_table("users")
    op.drop_table("roles")
