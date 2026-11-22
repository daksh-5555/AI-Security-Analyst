"""Issue, validate, and consume hashed single-use user action tokens.

Only SHA-256 digests are persisted. Raw tokens exist in memory long enough to be
placed in an outbound email and are never written to the database or logs.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import generate_opaque_token, hash_opaque_token
from app.db.integrity import ACTIVE_ACTION_TOKEN, log_unexpected_integrity_error, violates
from app.models.user_action_token import UserActionToken
from app.schemas.enums import UserActionTokenPurpose

logger = logging.getLogger(__name__)

TOKEN_PREFIXES: dict[UserActionTokenPurpose, str] = {
    UserActionTokenPurpose.EMAIL_VERIFICATION: "verify",
    UserActionTokenPurpose.PASSWORD_RESET: "reset",
}


class ActionTokenError(RuntimeError):
    """Base error for action-token operations."""


class InvalidActionTokenError(ActionTokenError):
    """Raised when a presented token is unusable for any reason."""

    def __init__(self) -> None:
        super().__init__("Invalid or expired token.")


def _ttl_seconds(purpose: UserActionTokenPurpose) -> int:
    if purpose is UserActionTokenPurpose.EMAIL_VERIFICATION:
        return settings.email_verification_token_ttl_seconds
    return settings.password_reset_token_ttl_seconds


def token_expiry(purpose: UserActionTokenPurpose, *, now: datetime | None = None) -> datetime:
    """Return the expiry timestamp for a newly issued token."""
    issued_at = datetime.now(UTC) if now is None else now
    return issued_at + timedelta(seconds=_ttl_seconds(purpose))


def hash_presented_token(raw_token: str) -> str | None:
    """Return the SHA-256 digest of a presentable token, or None if malformed."""
    if not isinstance(raw_token, str):
        return None
    try:
        return hash_opaque_token(raw_token)
    except (TypeError, ValueError):
        return None


def latest_token_created_at(
    db: Session,
    *,
    user_id: uuid.UUID,
    purpose: UserActionTokenPurpose,
) -> datetime | None:
    """Return when a token of this purpose was last issued to the user."""
    created_at = db.execute(
        select(func.max(UserActionToken.created_at)).where(
            UserActionToken.user_id == user_id,
            UserActionToken.purpose == purpose,
        )
    ).scalar_one()
    return created_at


def cooldown_active(
    db: Session,
    *,
    user_id: uuid.UUID,
    purpose: UserActionTokenPurpose,
    now: datetime | None = None,
) -> bool:
    """Report whether the per-account issuance cooldown is still in effect."""
    cooldown = settings.auth_token_request_cooldown_seconds
    if cooldown <= 0:
        return False
    last_issued = latest_token_created_at(db, user_id=user_id, purpose=purpose)
    if last_issued is None:
        return False
    reference = datetime.now(UTC) if now is None else now
    return reference - last_issued < timedelta(seconds=cooldown)


def invalidate_tokens(
    db: Session,
    *,
    user_id: uuid.UUID,
    purpose: UserActionTokenPurpose,
    except_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> int:
    """Mark every outstanding token of a purpose as consumed.

    Expired-but-unconsumed rows are included so the partial unique index never
    blocks a replacement. Returns the number of rows changed.
    """
    consumed_at = datetime.now(UTC) if now is None else now
    statement = (
        update(UserActionToken)
        .where(
            UserActionToken.user_id == user_id,
            UserActionToken.purpose == purpose,
            UserActionToken.consumed_at.is_(None),
        )
        .values(consumed_at=consumed_at)
        .execution_options(synchronize_session=False)
    )
    if except_id is not None:
        statement = statement.where(UserActionToken.id != except_id)
    result = db.execute(statement)
    return result.rowcount or 0


def issue_action_token(
    db: Session,
    *,
    user_id: uuid.UUID,
    purpose: UserActionTokenPurpose,
    now: datetime | None = None,
) -> str | None:
    """Invalidate prior tokens and insert a new one within the caller's transaction.

    Returns the raw token, or ``None`` when a concurrent issuance won the race
    for the single active slot. The caller decides whether to commit; on
    ``None`` no email should be sent.
    """
    issued_at = datetime.now(UTC) if now is None else now
    invalidate_tokens(db, user_id=user_id, purpose=purpose, now=issued_at)

    raw_token = generate_opaque_token(TOKEN_PREFIXES[purpose])
    token = UserActionToken(
        user_id=user_id,
        purpose=purpose,
        token_hash=hash_opaque_token(raw_token),
        created_at=issued_at,
        expires_at=token_expiry(purpose, now=issued_at),
        consumed_at=None,
    )
    try:
        with db.begin_nested():
            db.add(token)
            db.flush()
    except IntegrityError as exc:
        # Expected: a concurrent request inserted its own token after our
        # invalidation. Its message will be delivered, so this request stays
        # silent. Any other violation is logged; both fail closed (no token).
        if not violates(exc, ACTIVE_ACTION_TOKEN):
            log_unexpected_integrity_error(logger, "action token issuance", exc)
        return None
    return raw_token


def find_token_by_presented_value(db: Session, raw_token: str) -> UserActionToken | None:
    """Look up a token row by digest without revealing whether it is usable."""
    token_hash = hash_presented_token(raw_token)
    if token_hash is None:
        return None
    return db.execute(
        select(UserActionToken).where(UserActionToken.token_hash == token_hash)
    ).scalar_one_or_none()


def consume_token(
    db: Session,
    token: UserActionToken,
    *,
    now: datetime | None = None,
) -> bool:
    """Atomically consume a token if it is still unconsumed and unexpired."""
    consumed_at = datetime.now(UTC) if now is None else now
    result = db.execute(
        update(UserActionToken)
        .where(
            UserActionToken.id == token.id,
            UserActionToken.consumed_at.is_(None),
            UserActionToken.expires_at > consumed_at,
        )
        .values(consumed_at=consumed_at)
        .execution_options(synchronize_session=False)
    )
    return (result.rowcount or 0) == 1


def is_expired(token: UserActionToken, *, now: datetime | None = None) -> bool:
    """Report whether a token's expiry has passed."""
    reference = datetime.now(UTC) if now is None else now
    return token.expires_at <= reference
