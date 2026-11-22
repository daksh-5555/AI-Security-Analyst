"""Shared helpers for identity lifecycle API tests."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.emails import normalize_email
from app.core.roles import ROLE_IDS
from app.core.security import generate_opaque_token, hash_opaque_token, hash_password
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_action_token import UserActionToken
from app.models.user_role import UserRole
from app.models.user_session import UserSession
from app.schemas.enums import RoleName, UserActionTokenPurpose

# No trailing ``\b``: base64url tokens can end with ``-``, which is a non-word
# character, so a trailing word boundary would silently drop it and produce an
# invalid token roughly once every 64 generated values.
TOKEN_PATTERN = re.compile(r"\b(?:verify|reset)_[A-Za-z0-9_-]+")
DEFAULT_PASSWORD = "correct horse battery staple"


def extract_action_token(body: str) -> str:
    match = TOKEN_PATTERN.search(body)
    assert match is not None, "email body did not contain an action token"
    return match.group(0)


def assert_validation_errors_hide_input(response) -> None:
    """Assert a validation response never serializes submitted values."""
    detail = response.json()["detail"]
    if isinstance(detail, list):
        for error in detail:
            assert "input" not in error


def create_user(
    session_factory: sessionmaker[Session],
    *,
    email: str = "existing@example.com",
    password: str = DEFAULT_PASSWORD,
    is_active: bool = True,
    is_email_verified: bool = False,
) -> uuid.UUID:
    normalized = normalize_email(email)
    now = datetime.now(UTC)
    with session_factory() as session:
        user = User(
            email=normalized,
            email_normalized=normalized,
            password_hash=hash_password(password),
            is_active=is_active,
            is_email_verified=is_email_verified,
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        session.commit()
        return user.id


def get_user(session_factory: sessionmaker[Session], user_id: uuid.UUID) -> User | None:
    with session_factory() as session:
        return session.get(User, user_id)


def role_ids_for(session_factory: sessionmaker[Session], user_id: uuid.UUID) -> set[uuid.UUID]:
    with session_factory() as session:
        return set(
            session.scalars(select(UserRole.role_id).where(UserRole.user_id == user_id)).all()
        )


def tokens_for(
    session_factory: sessionmaker[Session],
    user_id: uuid.UUID,
    *,
    purpose: UserActionTokenPurpose | None = None,
) -> list[UserActionToken]:
    with session_factory() as session:
        statement = select(UserActionToken).where(UserActionToken.user_id == user_id)
        if purpose is not None:
            statement = statement.where(UserActionToken.purpose == purpose)
        return list(session.scalars(statement).all())


def expire_tokens(
    session_factory: sessionmaker[Session],
    user_id: uuid.UUID,
    *,
    purpose: UserActionTokenPurpose,
) -> None:
    """Force outstanding tokens of a purpose to be expired."""
    with session_factory() as session:
        for token in session.scalars(
            select(UserActionToken).where(
                UserActionToken.user_id == user_id,
                UserActionToken.purpose == purpose,
                UserActionToken.consumed_at.is_(None),
            )
        ).all():
            token.expires_at = datetime.now(UTC) - timedelta(seconds=60)
        session.commit()


def create_session(
    session_factory: sessionmaker[Session],
    user_id: uuid.UUID,
    *,
    revoked_at: datetime | None = None,
    idle_expires_at: datetime | None = None,
    absolute_expires_at: datetime | None = None,
) -> uuid.UUID:
    """Persist an active or partially expired session for principal tests."""
    now = datetime.now(UTC)
    with session_factory() as session:
        user_session = UserSession(
            user_id=user_id,
            created_at=now,
            last_refreshed_at=now,
            absolute_expires_at=absolute_expires_at or (now + timedelta(days=30)),
            idle_expires_at=idle_expires_at or (now + timedelta(days=14)),
            revoked_at=revoked_at,
            revocation_reason=None,
        )
        session.add(user_session)
        session.commit()
        return user_session.id


def create_refresh_token(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
    *,
    consumed_at: datetime | None = None,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> uuid.UUID:
    now = datetime.now(UTC)
    with session_factory() as session:
        refresh_token = RefreshToken(
            session_id=session_id,
            token_hash=hash_opaque_token(generate_opaque_token("refresh")),
            created_at=now,
            expires_at=expires_at or (now + timedelta(days=14)),
            consumed_at=consumed_at,
            revoked_at=revoked_at,
        )
        session.add(refresh_token)
        session.commit()
        return refresh_token.id


def assign_role(
    session_factory: sessionmaker[Session],
    user_id: uuid.UUID,
    role_name: RoleName,
) -> None:
    with session_factory() as session:
        session.add(UserRole(user_id=user_id, role_id=ROLE_IDS[role_name]))
        session.commit()


def remove_role(
    session_factory: sessionmaker[Session],
    user_id: uuid.UUID,
    role_name: RoleName,
) -> None:
    with session_factory() as session:
        session.execute(
            delete(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == ROLE_IDS[role_name],
            )
        )
        session.commit()
