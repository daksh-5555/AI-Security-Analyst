import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.emails import normalize_email
from app.core.roles import DEFAULT_ROLE_ID, DEFAULT_ROLE_NAME, ROLE_IDS
from app.core.security import generate_opaque_token, hash_opaque_token
from app.db.base import Base
from app.db.session import create_db_engine
from app.models.role import Role
from app.models.user import User
from app.models.user_action_token import UserActionToken
from app.schemas.enums import RoleName, UserActionTokenPurpose
from app.services import user_action_tokens as token_service

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_user(email: str = "token-user@example.com") -> User:
    now = datetime.now(UTC)
    normalized = normalize_email(email)
    return User(
        email=normalized,
        email_normalized=normalized,
        password_hash="argon2id-placeholder-hash",
        created_at=now,
        updated_at=now,
    )


def make_token(
    user_id: uuid.UUID,
    *,
    purpose: UserActionTokenPurpose = UserActionTokenPurpose.EMAIL_VERIFICATION,
    token_hash: str | None = None,
    expires_at: datetime | None = None,
    consumed_at: datetime | None = None,
) -> UserActionToken:
    now = datetime.now(UTC)
    return UserActionToken(
        user_id=user_id,
        purpose=purpose,
        token_hash=token_hash or hash_opaque_token(generate_opaque_token("test")),
        created_at=now,
        expires_at=expires_at or now + timedelta(hours=1),
        consumed_at=consumed_at,
    )


def test_user_action_token_model_is_registered() -> None:
    assert "user_action_tokens" in Base.metadata.tables


def test_role_constants_match_seeded_roles(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        roles = {
            role.id: role.name
            for role in session.scalars(
                select(Role).where(Role.id.in_(tuple(ROLE_IDS.values())))
            ).all()
        }

    assert roles == {
        ROLE_IDS[RoleName.ADMIN]: RoleName.ADMIN.value,
        ROLE_IDS[RoleName.SECURITY_ANALYST]: RoleName.SECURITY_ANALYST.value,
        ROLE_IDS[RoleName.VIEWER]: RoleName.VIEWER.value,
    }
    assert DEFAULT_ROLE_ID == ROLE_IDS[DEFAULT_ROLE_NAME]


def test_duplicate_token_hash_is_rejected(session_factory: sessionmaker[Session]) -> None:
    shared_hash = hash_opaque_token(generate_opaque_token("test"))
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        session.add(make_token(user.id, token_hash=shared_hash))
        session.commit()

        second_user = make_user("other-user@example.com")
        session.add(second_user)
        session.flush()
        session.add(make_token(second_user.id, token_hash=shared_hash))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 1


def test_only_one_unconsumed_token_per_user_and_purpose(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        session.add(make_token(user.id))
        session.commit()

        session.add(make_token(user.id))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 1


def test_consumed_token_allows_a_replacement(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        original = make_token(user.id)
        session.add(original)
        session.commit()

        original.consumed_at = datetime.now(UTC)
        session.commit()

        session.add(make_token(user.id))
        session.commit()

        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 2


def test_different_purposes_may_each_have_one_active_token(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        session.add(make_token(user.id, purpose=UserActionTokenPurpose.EMAIL_VERIFICATION))
        session.add(make_token(user.id, purpose=UserActionTokenPurpose.PASSWORD_RESET))
        session.commit()

        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 2


def test_user_deletion_cascades_action_tokens(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        session.add(make_token(user.id))
        session.commit()
        user_id = user.id

    with session_factory() as session:
        session.execute(delete(User).where(User.id == user_id))
        session.commit()

    with session_factory() as session:
        assert session.get(User, user_id) is None
        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 0


def test_issue_action_token_invalidates_previous_tokens(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.commit()

        first = token_service.issue_action_token(
            session,
            user_id=user.id,
            purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        )
        session.commit()
        second = token_service.issue_action_token(
            session,
            user_id=user.id,
            purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        )
        session.commit()

        tokens = list(
            session.scalars(select(UserActionToken).order_by(UserActionToken.created_at)).all()
        )

    assert first is not None and second is not None
    assert first != second
    assert len(tokens) == 2
    assert sum(token.consumed_at is not None for token in tokens) == 1
    assert sum(token.consumed_at is None for token in tokens) == 1
    stored_hashes = {token.token_hash for token in tokens}
    assert stored_hashes == {hash_opaque_token(first), hash_opaque_token(second)}


def test_issue_action_token_returns_none_on_concurrent_issuance(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        session.add(make_token(user.id))
        session.commit()

        # Simulate losing the race: invalidation runs, but a concurrent token
        # is already active when the new insert executes.
        monkeypatch.setattr(token_service, "invalidate_tokens", lambda *args, **kwargs: 0)
        issued = token_service.issue_action_token(
            session,
            user_id=user.id,
            purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        )
        session.rollback()

        assert issued is None
        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 1


def test_consume_token_is_single_use(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        token = make_token(user.id)
        session.add(token)
        session.commit()

        assert token_service.consume_token(session, token) is True
        session.commit()
        assert token_service.consume_token(session, token) is False

        session.refresh(token)
        assert token.consumed_at is not None


def test_consume_token_rejects_expired_tokens(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        token = make_token(user.id, expires_at=datetime.now(UTC) - timedelta(seconds=1))
        session.add(token)
        session.commit()

        assert token_service.consume_token(session, token) is False


def test_hash_presented_token_rejects_malformed_values() -> None:
    assert token_service.hash_presented_token("not a token") is None
    assert token_service.hash_presented_token("") is None
    assert token_service.hash_presented_token("verify_" + "a" * 600) is None
    assert token_service.hash_presented_token(123) is None  # type: ignore[arg-type]


def test_cooldown_is_tracked_per_user_and_purpose(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(token_service.settings, "auth_token_request_cooldown_seconds", 60)
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()

        assert (
            token_service.cooldown_active(
                session,
                user_id=user.id,
                purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
            )
            is False
        )

        token_service.issue_action_token(
            session,
            user_id=user.id,
            purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        )
        session.commit()

        assert token_service.cooldown_active(
            session,
            user_id=user.id,
            purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        )
        assert (
            token_service.cooldown_active(
                session,
                user_id=user.id,
                purpose=UserActionTokenPurpose.PASSWORD_RESET,
            )
            is False
        )


def test_migration_creates_tokens_table_with_partial_unique_index(tmp_path: Path) -> None:
    database_path = tmp_path / "action-tokens.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "user_action_tokens" in inspector.get_table_names()
        columns = {column["name"] for column in inspector.get_columns("user_action_tokens")}
        assert columns == {
            "id",
            "user_id",
            "purpose",
            "token_hash",
            "created_at",
            "expires_at",
            "consumed_at",
        }

        unique_constraints = inspector.get_unique_constraints("user_action_tokens")
        assert any(
            constraint["column_names"] == ["token_hash"] for constraint in unique_constraints
        )

        indexes = {index["name"]: index for index in inspector.get_indexes("user_action_tokens")}
        assert indexes["ix_user_action_tokens_user_id_purpose"]["column_names"] == [
            "user_id",
            "purpose",
        ]
        assert indexes["ix_user_action_tokens_expires_at"]["column_names"] == ["expires_at"]
        assert indexes["uq_user_action_tokens_active_user_purpose"]["unique"] == 1

        foreign_keys = inspector.get_foreign_keys("user_action_tokens")
        assert len(foreign_keys) == 1
        assert foreign_keys[0]["referred_table"] == "users"
        assert foreign_keys[0]["options"].get("ondelete") == "CASCADE"

        with engine.connect() as connection:
            index_sql = connection.execute(
                text("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = :name"),
                {"name": "uq_user_action_tokens_active_user_purpose"},
            ).scalar_one()
        assert "consumed_at IS NULL" in index_sql
    finally:
        engine.dispose()

    command.downgrade(config, "0008")

    engine = create_db_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert "user_action_tokens" not in tables
        assert {"users", "roles", "user_roles"} <= tables
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert "user_action_tokens" in inspect(engine).get_table_names()
    finally:
        engine.dispose()
