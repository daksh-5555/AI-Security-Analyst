import io
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.core.emails import normalize_email
from app.core.security import generate_opaque_token, hash_opaque_token
from app.db.session import create_db_engine
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_INDEX = "uq_refresh_tokens_active_session"


def make_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def make_user(email: str = "migration-session-user@example.com") -> User:
    now = datetime.now(UTC)
    normalized = normalize_email(email)
    return User(
        email=normalized,
        email_normalized=normalized,
        password_hash="argon2id-placeholder-hash",
        created_at=now,
        updated_at=now,
    )


def make_session(user_id: uuid.UUID) -> UserSession:
    now = datetime.now(UTC)
    return UserSession(
        user_id=user_id,
        created_at=now,
        last_refreshed_at=now,
        absolute_expires_at=now + timedelta(days=30),
        idle_expires_at=now + timedelta(hours=1),
    )


def make_refresh_token(session_id: uuid.UUID) -> RefreshToken:
    now = datetime.now(UTC)
    return RefreshToken(
        session_id=session_id,
        token_hash=hash_opaque_token(generate_opaque_token("refresh")),
        created_at=now,
        expires_at=now + timedelta(days=30),
    )


def test_migration_0010_follows_0009() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))

    revision = script.get_revision("0010")

    assert revision is not None
    assert revision.down_revision == "0009"
    assert script.get_heads() == ["0022"]


def test_migration_0010_round_trip_preserves_identity_data(tmp_path: Path) -> None:
    database_path = tmp_path / "sessions-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)
    session_factory = sessionmaker(expire_on_commit=False)

    command.upgrade(config, "0009")
    engine = create_db_engine(database_url)
    session_factory.configure(bind=engine)
    try:
        with session_factory() as session:
            user = make_user()
            session.add(user)
            session.commit()
            user_id = user.id
    finally:
        engine.dispose()

    command.upgrade(config, "0010")

    engine = create_db_engine(database_url)
    session_factory.configure(bind=engine)
    try:
        inspector = inspect(engine)

        tables = set(inspector.get_table_names())
        assert "user_sessions" in tables
        assert "refresh_tokens" in tables

        session_columns = {column["name"] for column in inspector.get_columns("user_sessions")}
        assert session_columns == {
            "id",
            "user_id",
            "created_at",
            "last_refreshed_at",
            "absolute_expires_at",
            "idle_expires_at",
            "revoked_at",
            "revocation_reason",
        }
        token_columns = {column["name"] for column in inspector.get_columns("refresh_tokens")}
        assert token_columns == {
            "id",
            "session_id",
            "token_hash",
            "created_at",
            "expires_at",
            "consumed_at",
            "revoked_at",
            "replaced_by_id",
        }

        session_foreign_keys = inspector.get_foreign_keys("user_sessions")
        assert len(session_foreign_keys) == 1
        assert session_foreign_keys[0]["referred_table"] == "users"
        assert session_foreign_keys[0]["options"].get("ondelete") == "CASCADE"

        token_foreign_keys = {
            foreign_key["referred_table"]: foreign_key
            for foreign_key in inspector.get_foreign_keys("refresh_tokens")
        }
        assert token_foreign_keys["user_sessions"]["options"].get("ondelete") == "CASCADE"
        assert token_foreign_keys["refresh_tokens"]["options"].get("ondelete") == "SET NULL"

        token_uniques = inspector.get_unique_constraints("refresh_tokens")
        assert any(constraint["column_names"] == ["token_hash"] for constraint in token_uniques)

        session_indexes = {index["name"]: index for index in inspector.get_indexes("user_sessions")}
        assert session_indexes["ix_user_sessions_user_id"]["column_names"] == ["user_id"]
        assert session_indexes["ix_user_sessions_absolute_expires_at"]["column_names"] == [
            "absolute_expires_at"
        ]
        assert session_indexes["ix_user_sessions_idle_expires_at"]["column_names"] == [
            "idle_expires_at"
        ]

        token_indexes = {index["name"]: index for index in inspector.get_indexes("refresh_tokens")}
        assert token_indexes["ix_refresh_tokens_session_id"]["column_names"] == ["session_id"]
        assert token_indexes["ix_refresh_tokens_expires_at"]["column_names"] == ["expires_at"]
        assert token_indexes[ACTIVE_INDEX]["column_names"] == ["session_id"]
        assert token_indexes[ACTIVE_INDEX]["unique"] == 1

        with engine.connect() as connection:
            active_index_sql = connection.execute(
                text("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = :name"),
                {"name": ACTIVE_INDEX},
            ).scalar_one()
            session_table_sql = connection.execute(
                text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = :name"),
                {"name": "user_sessions"},
            ).scalar_one()

            stored_user_count = connection.execute(
                text("SELECT COUNT(*) FROM users WHERE email_normalized = :email"),
                {"email": "migration-session-user@example.com"},
            ).scalar_one()
            stored_role_count = connection.execute(text("SELECT COUNT(*) FROM roles")).scalar_one()

        assert "consumed_at IS NULL" in active_index_sql
        assert "revoked_at IS NULL" in active_index_sql
        assert stored_user_count == 1
        assert stored_role_count == 3
        for reason in (
            "logout",
            "password_reset",
            "refresh_reuse",
            "expired",
            "user_deactivated",
            "admin",
        ):
            assert reason in session_table_sql

        with session_factory() as session:
            user_session = make_session(user_id)
            session.add(user_session)
            session.flush()
            first_token = make_refresh_token(user_session.id)
            session.add(first_token)
            session.commit()

            session.add(make_refresh_token(user_session.id))
            with pytest.raises(IntegrityError):
                session.commit()
            session.rollback()

            assert session.scalar(select(func.count()).select_from(RefreshToken)) == 1

            first_token.consumed_at = datetime.now(UTC)
            session.commit()
            session.add(make_refresh_token(user_session.id))
            session.commit()

            assert session.scalar(select(func.count()).select_from(RefreshToken)) == 2
    finally:
        engine.dispose()

    command.downgrade(config, "0009")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "user_sessions" not in tables
        assert "refresh_tokens" not in tables
        assert "users" in tables

        with engine.connect() as connection:
            stored_user_count = connection.execute(
                text("SELECT COUNT(*) FROM users WHERE email_normalized = :email"),
                {"email": "migration-session-user@example.com"},
            ).scalar_one()
        assert stored_user_count == 1
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert "user_sessions" in tables
        assert "refresh_tokens" in tables
        with engine.connect() as connection:
            stored_user_count = connection.execute(
                text("SELECT COUNT(*) FROM users WHERE email_normalized = :email"),
                {"email": "migration-session-user@example.com"},
            ).scalar_one()
        assert stored_user_count == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("database_url", ["sqlite://", "postgresql://"])
def test_migration_0010_offline_sql(database_url: str) -> None:
    config = make_config(database_url)
    output = io.StringIO()
    config.output_buffer = output

    command.upgrade(config, "0009:0010", sql=True)

    sql = output.getvalue()
    assert "CREATE TABLE user_sessions" in sql
    assert "CREATE TABLE refresh_tokens" in sql
    assert "uq_refresh_tokens_token_hash" in sql
    assert ACTIVE_INDEX in sql
    assert "consumed_at IS NULL AND revoked_at IS NULL" in sql
    assert "ON DELETE CASCADE" in sql
    assert "ON DELETE SET NULL" in sql
