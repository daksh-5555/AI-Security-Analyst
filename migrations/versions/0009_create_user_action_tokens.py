"""create user action tokens

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-07

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_TOKEN_INDEX = "uq_user_action_tokens_active_user_purpose"
ACTIVE_TOKEN_PREDICATE = sa.text("consumed_at IS NULL")

user_action_token_purpose = sa.Enum(
    "email_verification",
    "password_reset",
    name="user_action_token_purpose",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade() -> None:
    dialect = op.get_context().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError(
            f"{ACTIVE_TOKEN_INDEX} requires partial unique index support; "
            f"dialect '{dialect}' is not supported"
        )

    op.create_table(
        "user_action_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", user_action_token_purpose, nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_action_tokens_user_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_action_tokens"),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_user_action_tokens_token_hash",
        ),
    )
    op.create_index(
        "ix_user_action_tokens_user_id_purpose",
        "user_action_tokens",
        ["user_id", "purpose"],
        unique=False,
    )
    op.create_index(
        "ix_user_action_tokens_expires_at",
        "user_action_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        ACTIVE_TOKEN_INDEX,
        "user_action_tokens",
        ["user_id", "purpose"],
        unique=True,
        sqlite_where=ACTIVE_TOKEN_PREDICATE,
        postgresql_where=ACTIVE_TOKEN_PREDICATE,
    )


def downgrade() -> None:
    op.drop_index(ACTIVE_TOKEN_INDEX, table_name="user_action_tokens")
    op.drop_index("ix_user_action_tokens_expires_at", table_name="user_action_tokens")
    op.drop_index("ix_user_action_tokens_user_id_purpose", table_name="user_action_tokens")
    op.drop_table("user_action_tokens")
