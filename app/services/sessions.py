"""Current-session revocation shared by logout and refresh replay handling.

Revocation updates the ``user_sessions`` row first and its ``refresh_tokens``
rows second, in one transaction. Refresh rotation uses the same order, so the two
operations serialize on the session row instead of deadlocking and a logout
cannot miss a replacement token committed by a concurrent rotation.

These helpers do not decide whether the caller is authorized; they only perform
the database mutation. Logout authorization comes from the verified access token.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason


class SessionRevocationError(RuntimeError):
    """Base error for session revocation."""


class SessionPersistenceError(SessionRevocationError):
    """Raised when session revocation cannot be committed."""

    def __init__(self) -> None:
        super().__init__("Session revocation could not be persisted.")


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(UTC)


def revoke_session_family(
    db: Session,
    *,
    session_id: uuid.UUID,
    reason: SessionRevocationReason,
    now: datetime,
    include_consumed: bool = True,
) -> None:
    """Revoke one session and every refresh token in its family.

    The session row is updated first so it becomes the serialization point shared
    with refresh rotation, logout, and password reset. Existing history is
    preserved: ``consumed_at`` and ``replaced_by_id`` are never cleared, and
    already-revoked rows are untouched. The caller owns the transaction boundary.

    ``include_consumed`` defaults to true so logout and reuse revocation also mark
    consumed tokens as revoked. Password reset passes false to leave
    consumed/replaced token history exactly as it was.
    """
    db.execute(
        update(UserSession)
        .where(
            UserSession.id == session_id,
            UserSession.revoked_at.is_(None),
        )
        .values(
            revoked_at=now,
            revocation_reason=reason,
        )
        .execution_options(synchronize_session=False)
    )
    token_statement = update(RefreshToken).where(
        RefreshToken.session_id == session_id,
        RefreshToken.revoked_at.is_(None),
    )
    if not include_consumed:
        token_statement = token_statement.where(RefreshToken.consumed_at.is_(None))
    db.execute(token_statement.values(revoked_at=now).execution_options(synchronize_session=False))


def revoke_session(
    db: Session,
    *,
    session_id: uuid.UUID,
    now: datetime | None = None,
) -> None:
    """Revoke the current session family with the ``logout`` reason.

    Session and refresh-token changes commit together. Any failure rolls both
    back, so a partially revoked family is never committed.
    """
    current = _utc_now(now)
    try:
        revoke_session_family(
            db,
            session_id=session_id,
            reason=SessionRevocationReason.LOGOUT,
            now=current,
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise SessionPersistenceError() from None


__all__ = [
    "SessionPersistenceError",
    "SessionRevocationError",
    "revoke_session",
    "revoke_session_family",
]
