"""Refresh-token rotation, replay detection, and session-family revocation.

Raw refresh tokens are high-entropy opaque secrets; only their SHA-256 digests are
persisted. Rotation locks the session row first and consumes the presented token
with one conditional ``UPDATE`` so that exactly one concurrent request can win.
Replaying an already-consumed token is treated as reuse and revokes the whole
session family.

The ``user_sessions`` row is the serialization point for refresh and logout. Both
operations update it before touching ``refresh_tokens``, so they cannot interleave
in a way that leaves a usable replacement token for a revoked session.

Idle expiry slides forward on each rotation, but never past the session's absolute
expiry. Session identifiers (the JWT ``sid``) stay stable across rotations.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token, generate_opaque_token, hash_opaque_token
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason
from app.services import sessions

logger = logging.getLogger(__name__)


class RefreshTokenError(RuntimeError):
    """Base error for refresh-token operations."""


class InvalidRefreshTokenError(RefreshTokenError):
    """Raised when a presented refresh token cannot be used."""

    def __init__(self) -> None:
        super().__init__("Invalid or expired refresh token.")


class RefreshTokenReuseError(InvalidRefreshTokenError):
    """Raised after a consumed token is replayed and its family is revoked."""


class RefreshPersistenceError(RefreshTokenError):
    """Raised when a rotation cannot be committed."""

    def __init__(self) -> None:
        super().__init__("Refresh could not be persisted.")


@dataclass(frozen=True, slots=True)
class RefreshResult:
    """Successful rotation data; raw tokens exist only in this result and response."""

    user_id: uuid.UUID
    session_id: uuid.UUID
    access_token: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(UTC)


def _token_hash(presented_token: str) -> str | None:
    try:
        return hash_opaque_token(presented_token)
    except (TypeError, ValueError):
        return None


def _revoke_family_for_reuse(
    db: Session,
    *,
    session_id: uuid.UUID,
    now: datetime,
) -> None:
    """Revoke a session family after a consumed token is replayed.

    Reuse is fail-closed: the session row is revoked before its refresh tokens, in
    the same order used by logout, so the two operations serialize on the session
    row. The security event records identifiers only; it never includes a raw token
    or token hash. This function always raises.
    """
    try:
        user_id = db.scalar(select(UserSession.user_id).where(UserSession.id == session_id))
        sessions.revoke_session_family(
            db,
            session_id=session_id,
            reason=SessionRevocationReason.REFRESH_REUSE,
            now=now,
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error("Refresh token reuse revocation failed.")
        raise RefreshPersistenceError() from None

    logger.warning(
        "Refresh token reuse detected; session family revoked.",
        extra={
            "security_event": "refresh_token_reuse",
            "user_id": str(user_id) if user_id is not None else None,
            "session_id": str(session_id),
        },
    )
    raise RefreshTokenReuseError()


def rotate(
    db: Session,
    *,
    presented_token: str,
    now: datetime | None = None,
) -> RefreshResult:
    """Consume one refresh token and issue a replacement pair.

    Steps, in order:

    1. Look up the token hash (an advisory read).
    2. Reject unknown, revoked, or expired tokens without touching the session.
    3. Lock and revalidate the session with one conditional ``UPDATE``. The row
       lock is held until commit and is shared with logout, which updates the same
       row first.
    4. Consume the token with one conditional ``UPDATE`` and require one affected
       row.
    5. Insert the replacement token and extend idle expiry, then commit.

    Because the session row is locked before the token row, a refresh that starts
    while logout is in flight either commits first (and logout then revokes the new
    token) or observes the revoked session and fails. A refresh can never create a
    usable replacement token for an already-revoked session.
    """
    current = _utc_now(now)
    token_hash = _token_hash(presented_token)
    if token_hash is None:
        raise InvalidRefreshTokenError()

    try:
        token = db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        ).scalar_one_or_none()
    except SQLAlchemyError:
        db.rollback()
        raise RefreshPersistenceError() from None

    if token is None:
        db.rollback()
        raise InvalidRefreshTokenError()

    if token.consumed_at is not None:
        # Confirmed reuse of a previously consumed token.
        _revoke_family_for_reuse(db, session_id=token.session_id, now=current)

    if token.revoked_at is not None or token.expires_at <= current:
        # Revoked or expired tokens are not confirmed reuse.
        db.rollback()
        raise InvalidRefreshTokenError()

    session_id = token.session_id
    try:
        session_info = db.execute(
            select(UserSession.user_id, UserSession.absolute_expires_at).where(
                UserSession.id == session_id
            )
        ).one_or_none()
    except SQLAlchemyError:
        db.rollback()
        raise RefreshPersistenceError() from None

    if session_info is None:
        db.rollback()
        raise InvalidRefreshTokenError()

    user_id, absolute_expires_at = session_info
    new_idle_expires_at = min(
        current + timedelta(seconds=settings.refresh_token_ttl_seconds),
        absolute_expires_at,
    )
    if new_idle_expires_at <= current:
        db.rollback()
        raise InvalidRefreshTokenError()

    try:
        lock_result = db.execute(
            update(UserSession)
            .where(
                UserSession.id == session_id,
                UserSession.revoked_at.is_(None),
                UserSession.idle_expires_at > current,
                UserSession.absolute_expires_at > current,
            )
            .values(last_refreshed_at=current, idle_expires_at=new_idle_expires_at)
            .execution_options(synchronize_session=False)
        )
    except SQLAlchemyError:
        db.rollback()
        raise RefreshPersistenceError() from None

    if (lock_result.rowcount or 0) != 1:
        # Unknown, revoked, or expired session: never refresh it.
        db.rollback()
        raise InvalidRefreshTokenError()

    try:
        consumed_result = db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.id == token.id,
                RefreshToken.consumed_at.is_(None),
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > current,
            )
            .values(consumed_at=current)
            .execution_options(synchronize_session=False)
        )
    except SQLAlchemyError:
        db.rollback()
        raise RefreshPersistenceError() from None

    if (consumed_result.rowcount or 0) != 1:
        # A request that lost a race observes a consumed token and is treated as
        # reuse. The session lock usually prevents this branch, but a token can
        # also be revoked by an out-of-band path; re-read to classify it correctly.
        try:
            # Read columns instead of the ORM entity so the identity map cannot
            # return the stale, pre-consume ``consumed_at`` value.
            fresh = db.execute(
                select(RefreshToken.session_id, RefreshToken.consumed_at).where(
                    RefreshToken.id == token.id
                )
            ).one_or_none()
        except SQLAlchemyError:
            db.rollback()
            raise RefreshPersistenceError() from None

        if fresh is None:
            db.rollback()
            raise InvalidRefreshTokenError()
        if fresh.consumed_at is not None:
            _revoke_family_for_reuse(db, session_id=fresh.session_id, now=current)
        db.rollback()
        raise InvalidRefreshTokenError()

    try:
        user = db.get(User, user_id)
        if user is None or not user.is_active or not user.is_email_verified:
            raise InvalidRefreshTokenError()

        raw_refresh_token = generate_opaque_token("refresh")
        replacement = RefreshToken(
            session_id=session_id,
            token_hash=hash_opaque_token(raw_refresh_token),
            created_at=current,
            expires_at=new_idle_expires_at,
            consumed_at=None,
            revoked_at=None,
            replaced_by_id=None,
        )
        db.add(replacement)
        db.flush()

        token.replaced_by_id = replacement.id

        # Sign before committing so a signing/configuration failure rolls the
        # consumption, replacement row, and expiry extension back together.
        access_token = create_access_token(
            user_id=user.id,
            session_id=session_id,
            now=current,
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise RefreshPersistenceError() from None
    except Exception:
        db.rollback()
        raise

    return RefreshResult(
        user_id=user_id,
        session_id=session_id,
        access_token=access_token,
        refresh_token=raw_refresh_token,
        expires_in=settings.access_token_ttl_seconds,
        refresh_expires_in=int((new_idle_expires_at - current).total_seconds()),
    )


__all__ = [
    "InvalidRefreshTokenError",
    "RefreshPersistenceError",
    "RefreshResult",
    "RefreshTokenError",
    "RefreshTokenReuseError",
    "rotate",
]
