import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.emails import normalize_email
from app.core.security import generate_opaque_token, hash_opaque_token
from app.db.base import Base
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_user(email: str = "session-user@example.com") -> User:
    now = datetime.now(UTC)
    normalized = normalize_email(email)
    return User(
        email=normalized,
        email_normalized=normalized,
        password_hash="argon2id-placeholder-hash",
        created_at=now,
        updated_at=now,
    )


def make_session(
    user_id: uuid.UUID,
    *,
    revoked_at: datetime | None = None,
    revocation_reason: SessionRevocationReason | None = None,
) -> UserSession:
    now = datetime.now(UTC)
    return UserSession(
        user_id=user_id,
        created_at=now,
        last_refreshed_at=now,
        absolute_expires_at=now + timedelta(days=30),
        idle_expires_at=now + timedelta(hours=1),
        revoked_at=revoked_at,
        revocation_reason=revocation_reason,
    )


def make_refresh_token(
    session_id: uuid.UUID,
    *,
    token_hash: str | None = None,
    consumed_at: datetime | None = None,
    revoked_at: datetime | None = None,
    replaced_by_id: uuid.UUID | None = None,
) -> RefreshToken:
    now = datetime.now(UTC)
    return RefreshToken(
        session_id=session_id,
        token_hash=token_hash or hash_opaque_token(generate_opaque_token("refresh")),
        created_at=now,
        expires_at=now + timedelta(days=30),
        consumed_at=consumed_at,
        revoked_at=revoked_at,
        replaced_by_id=replaced_by_id,
    )


def test_session_models_are_registered() -> None:
    assert "user_sessions" in Base.metadata.tables
    assert "refresh_tokens" in Base.metadata.tables


def test_revocation_reason_values() -> None:
    assert {reason.value for reason in SessionRevocationReason} == {
        "logout",
        "password_reset",
        "refresh_reuse",
        "expired",
        "user_deactivated",
        "admin",
    }


def test_session_creation_and_user_relationship(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.commit()
        user_id = user.id
        session_id = user_session.id

    with session_factory() as session:
        stored = session.get(UserSession, session_id)

        assert stored is not None
        assert stored.user_id == user_id
        assert stored.user.id == user_id
        assert stored.created_at.tzinfo is not None
        assert stored.last_refreshed_at.tzinfo is not None
        assert stored.absolute_expires_at.tzinfo is not None
        assert stored.idle_expires_at.tzinfo is not None
        assert stored.revoked_at is None
        assert stored.revocation_reason is None
        assert stored.refresh_tokens == []

        user = session.get(User, user_id)
        assert user is not None
        assert [candidate.id for candidate in user.sessions] == [session_id]


def test_revocation_reason_round_trips(
    session_factory: sessionmaker[Session],
) -> None:
    now = datetime.now(UTC)
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(
            user.id,
            revoked_at=now,
            revocation_reason=SessionRevocationReason.PASSWORD_RESET,
        )
        session.add(user_session)
        session.commit()
        session_id = user_session.id

    with session_factory() as session:
        stored = session.get(UserSession, session_id)

    assert stored is not None
    assert stored.revoked_at is not None
    assert stored.revocation_reason is SessionRevocationReason.PASSWORD_RESET


def test_refresh_token_creation_and_session_relationship(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        refresh_token = make_refresh_token(user_session.id)
        session.add(refresh_token)
        session.commit()
        session_id = user_session.id
        token_id = refresh_token.id

    with session_factory() as session:
        stored = session.get(RefreshToken, token_id)

        assert stored is not None
        assert stored.session_id == session_id
        assert stored.session.id == session_id
        assert stored.created_at.tzinfo is not None
        assert stored.expires_at.tzinfo is not None
        assert stored.consumed_at is None
        assert stored.revoked_at is None
        assert stored.replaced_by_id is None
        assert [candidate.id for candidate in stored.session.refresh_tokens] == [token_id]


def test_duplicate_token_hash_is_rejected(
    session_factory: sessionmaker[Session],
) -> None:
    shared_hash = hash_opaque_token(generate_opaque_token("refresh"))
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        first_session = make_session(user.id)
        second_session = make_session(user.id)
        session.add_all([first_session, second_session])
        session.flush()

        session.add(make_refresh_token(first_session.id, token_hash=shared_hash))
        session.commit()

        session.add(make_refresh_token(second_session.id, token_hash=shared_hash))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 1


def test_only_one_active_refresh_token_per_session(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        session.add(make_refresh_token(user_session.id))
        session.commit()

        session.add(make_refresh_token(user_session.id))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 1


def test_consumed_token_allows_a_replacement(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        original = make_refresh_token(user_session.id)
        session.add(original)
        session.commit()

        original.consumed_at = datetime.now(UTC)
        session.commit()

        session.add(make_refresh_token(user_session.id))
        session.commit()

        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 2


def test_revoked_token_allows_a_replacement(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        original = make_refresh_token(user_session.id)
        session.add(original)
        session.commit()

        original.revoked_at = datetime.now(UTC)
        session.commit()

        session.add(make_refresh_token(user_session.id))
        session.commit()

        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 2


def test_multiple_sessions_per_user_are_allowed(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        session.add_all([make_session(user.id), make_session(user.id)])
        session.commit()

        assert session.scalar(select(func.count()).select_from(UserSession)) == 2


def test_user_deletion_cascades_sessions_and_refresh_tokens(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        session.add(make_refresh_token(user_session.id))
        session.commit()
        user_id = user.id

    with session_factory() as session:
        session.execute(delete(User).where(User.id == user_id))
        session.commit()

    with session_factory() as session:
        assert session.get(User, user_id) is None
        assert session.scalar(select(func.count()).select_from(UserSession)) == 0
        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 0


def test_session_deletion_cascades_refresh_tokens(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        session.add(make_refresh_token(user_session.id))
        session.commit()
        session_id = user_session.id

    with session_factory() as session:
        session.execute(delete(UserSession).where(UserSession.id == session_id))
        session.commit()

    with session_factory() as session:
        assert session.get(UserSession, session_id) is None
        assert session.scalar(select(func.count()).select_from(RefreshToken)) == 0


def test_replacement_token_self_reference(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        user = make_user()
        session.add(user)
        session.flush()
        user_session = make_session(user.id)
        session.add(user_session)
        session.flush()
        original = make_refresh_token(user_session.id, consumed_at=datetime.now(UTC))
        replacement = make_refresh_token(user_session.id)
        session.add_all([original, replacement])
        session.commit()

        original.replaced_by_id = replacement.id
        session.commit()
        original_id = original.id
        replacement_id = replacement.id

    with session_factory() as session:
        stored = session.get(RefreshToken, original_id)

        assert stored is not None
        assert stored.replaced_by is not None
        assert stored.replaced_by.id == replacement_id

    with session_factory() as session:
        session.execute(delete(RefreshToken).where(RefreshToken.id == replacement_id))
        session.commit()

    with session_factory() as session:
        stored = session.get(RefreshToken, original_id)

        assert stored is not None
        assert stored.replaced_by_id is None
        assert stored.replaced_by is None
