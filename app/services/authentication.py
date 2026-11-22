"""Password authentication and persisted session creation.

The service owns the login transaction boundary. It deliberately returns the
same generic credential error for every unusable identity so callers cannot
enumerate accounts, and it never grants roles during login.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.emails import normalize_and_validate_email
from app.core.security import (
    create_access_token,
    dummy_password_hash,
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession


class AuthenticationError(RuntimeError):
    """Base error for authentication operations."""


class InvalidCredentialsError(AuthenticationError):
    """Raised for every malformed, unknown, or unusable credential."""

    def __init__(self) -> None:
        super().__init__("Invalid email or password.")


class LoginPersistenceError(AuthenticationError):
    """Raised when the login transaction cannot be committed."""

    def __init__(self) -> None:
        super().__init__("Login could not be persisted.")


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Successful login data; raw tokens exist only in this result and response."""

    user_id: uuid.UUID
    email: str
    access_token: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int
    session_id: uuid.UUID


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(UTC)


def _try_normalize_email(email: str) -> str | None:
    try:
        return normalize_and_validate_email(email)
    except (TypeError, ValueError):
        return None


def _read_user_by_email(db: Session, normalized_email: str) -> User | None:
    return db.execute(
        select(User).where(User.email_normalized == normalized_email)
    ).scalar_one_or_none()


def _lock_user_for_login(db: Session, normalized_email: str) -> User | None:
    """Acquire the user-row synchronization point and re-read the user.

    Password reset updates the user row before it revokes sessions. Taking the
    same row first makes login and reset serialize completely: whichever commits
    first wins, and the loser observes the committed password and sessions.

    PostgreSQL row-locks the matching user with ``SELECT ... FOR UPDATE``. SQLite
    has no row locks and ignores ``FOR UPDATE``, so a no-op ``UPDATE`` is issued
    first to take the database write lock. Doing the write before the read also
    avoids SQLite's read-then-write lock-upgrade failure. The no-op explicitly
    assigns ``updated_at`` to itself so SQLAlchemy does not fire its ``onupdate``
    and change audit data on every login.

    ``populate_existing`` refreshes any identity-map instance with the values read
    under the lock, so a session cannot return a stale pre-reset password.
    """
    statement = (
        select(User)
        .where(User.email_normalized == normalized_email)
        .execution_options(populate_existing=True)
    )

    if db.get_bind().dialect.name == "sqlite":
        db.execute(
            update(User)
            .where(User.email_normalized == normalized_email)
            .values(password_hash=User.password_hash, updated_at=User.updated_at)
            .execution_options(synchronize_session=False)
        )
    else:
        statement = statement.with_for_update()

    return db.execute(statement).scalar_one_or_none()


def login(
    db: Session,
    *,
    email: str,
    password: str,
    now: datetime | None = None,
) -> LoginResult:
    """Verify credentials and create one persisted session and refresh token.

    Password verification is optimistic: the hash is read and checked without a
    write lock, then the user row is locked and the hash is revalidated. If reset
    committed in between, the revalidation sees the new hash and the old password
    fails. If this login acquires the lock first, a concurrent reset waits and
    then revokes the session this login creates.

    Malformed and unknown identities still perform an Argon2 verification
    against a cached dummy hash. Account state is checked only after password
    verification. The optional rehash, session row, and initial refresh token
    commit atomically; a signing failure occurs before any row is added.
    """
    current = _utc_now(now)

    normalized = _try_normalize_email(email)

    user: User | None = None
    if normalized is not None:
        try:
            user = _read_user_by_email(db, normalized)
        except SQLAlchemyError:
            db.rollback()
            raise LoginPersistenceError() from None

    candidate_hash = user.password_hash if user is not None else dummy_password_hash()
    # Close the advisory read before the slow verification. On SQLite this
    # releases the shared lock, so a concurrent reset can commit instead of
    # deadlocking against a read-then-write lock upgrade.
    db.rollback()

    password_ok = verify_password(password, candidate_hash)
    if user is None or not password_ok or normalized is None:
        raise InvalidCredentialsError()

    try:
        locked_user = _lock_user_for_login(db, normalized)
    except SQLAlchemyError:
        db.rollback()
        raise LoginPersistenceError() from None

    if locked_user is None:
        db.rollback()
        raise InvalidCredentialsError()

    if locked_user.password_hash != candidate_hash and not verify_password(
        password, locked_user.password_hash
    ):
        # Password reset committed while the optimistic verification was running.
        db.rollback()
        raise InvalidCredentialsError()

    if not locked_user.is_active or not locked_user.is_email_verified:
        db.rollback()
        raise InvalidCredentialsError()

    user = locked_user

    # Everything from the rehash assignment onward mutates the session. Any
    # failure must roll the pending mutation back before it propagates.
    try:
        if password_needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            user.updated_at = current

        session_id = uuid.uuid4()
        absolute_expires_at = current + timedelta(seconds=settings.absolute_session_ttl_seconds)
        idle_expires_at = min(
            current + timedelta(seconds=settings.refresh_token_ttl_seconds),
            absolute_expires_at,
        )

        # Build tokens before persisting so signing/configuration failures cannot
        # leave an orphan session row behind.
        access_token = create_access_token(
            user_id=user.id,
            session_id=session_id,
            now=current,
        )
        raw_refresh_token = generate_opaque_token("refresh")

        user_session = UserSession(
            id=session_id,
            user_id=user.id,
            created_at=current,
            last_refreshed_at=current,
            absolute_expires_at=absolute_expires_at,
            idle_expires_at=idle_expires_at,
            revoked_at=None,
            revocation_reason=None,
        )
        refresh_token = RefreshToken(
            session_id=session_id,
            token_hash=hash_opaque_token(raw_refresh_token),
            created_at=current,
            expires_at=idle_expires_at,
            consumed_at=None,
            revoked_at=None,
            replaced_by_id=None,
        )
        db.add_all([user_session, refresh_token])

        db.commit()
    except LoginPersistenceError:
        db.rollback()
        raise
    except SQLAlchemyError:
        db.rollback()
        raise LoginPersistenceError() from None
    except Exception:
        db.rollback()
        raise

    return LoginResult(
        user_id=user.id,
        email=user.email,
        access_token=access_token,
        refresh_token=raw_refresh_token,
        expires_in=settings.access_token_ttl_seconds,
        refresh_expires_in=int((idle_expires_at - current).total_seconds()),
        session_id=session_id,
    )


__all__ = [
    "AuthenticationError",
    "InvalidCredentialsError",
    "LoginPersistenceError",
    "LoginResult",
    "login",
]
