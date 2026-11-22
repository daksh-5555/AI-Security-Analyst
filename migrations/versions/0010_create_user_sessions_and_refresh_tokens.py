"""create user sessions and refresh tokens

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-07

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE_REFRESH_TOKEN_INDEX = "uq_refresh_tokens_active_session"
ACTIVE_REFRESH_TOKEN_PREDICATE = sa.text("consumed_at IS NULL AND revoked_at IS NULL")

session_revocation_reason = sa.Enum(
    "logout",
    "password_reset",
    "refresh_reuse",
    "expired",
    "user_deactivated",
    "admin",
    name="session_revocation_reason",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade() -> None:
    dialect = op.get_context().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError(
            f"{ACTIVE_REFRESH_TOKEN_INDEX} requires partial unique index support; "
            f"dialect '{dialect}' is not supported"
        )

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_refreshed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", session_revocation_reason, nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_sessions_user_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_sessions"),
    )
    op.create_index(
        "ix_user_sessions_user_id",
        "user_sessions",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_user_sessions_absolute_expires_at",
        "user_sessions",
        ["absolute_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_user_sessions_idle_expires_at",
        "user_sessions",
        ["idle_expires_at"],
        unique=False,
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["user_sessions.id"],
            name="fk_refresh_tokens_session_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by_id"],
            ["refresh_tokens.id"],
            name="fk_refresh_tokens_replaced_by_id",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_refresh_tokens_token_hash",
        ),
    )
    op.create_index(
        "ix_refresh_tokens_session_id",
        "refresh_tokens",
        ["session_id"],
        unique=False,
    )
    op.create_index(
        "ix_refresh_tokens_expires_at",
        "refresh_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        ACTIVE_REFRESH_TOKEN_INDEX,
        "refresh_tokens",
        ["session_id"],
        unique=True,
        sqlite_where=ACTIVE_REFRESH_TOKEN_PREDICATE,
        postgresql_where=ACTIVE_REFRESH_TOKEN_PREDICATE,
    )


def downgrade() -> None:
    op.drop_index(ACTIVE_REFRESH_TOKEN_INDEX, table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_session_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_user_sessions_idle_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_absolute_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
