"""Identity lifecycle orchestration: registration, verification, and reset.

Services own their transaction boundaries, matching the rest of the codebase.
Raw tokens are returned to the caller only so the API layer can enqueue a single
email; they are never persisted or logged here.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.emails import normalize_and_validate_email
from app.core.security import (
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    validate_password_policy,
)
from app.db.integrity import (
    ACTIVE_ACTION_TOKEN,
    USERS_EMAIL_NORMALIZED,
    log_unexpected_integrity_error,
    violates,
)
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason, UserActionTokenPurpose
from app.services import sessions
from app.services import user_action_tokens as token_service
from app.services.roles import RoleConfigurationError, assign_default_role_if_unassigned

logger = logging.getLogger(__name__)


class IdentityError(RuntimeError):
    """Base error for identity lifecycle operations."""


class InvalidEmailError(ValueError):
    """Raised when registration input contains a malformed email address."""


class InvalidPasswordError(ValueError):
    """Raised when a supplied password violates the application policy."""


class InvalidIdentityTokenError(IdentityError):
    """Generic failure for unusable verification or reset tokens.

    The message is intentionally uniform so callers cannot distinguish an
    unknown token from an expired, consumed, or wrong-purpose one.
    """

    def __init__(self) -> None:
        super().__init__("Invalid or expired token.")


class PasswordResetPersistenceError(IdentityError):
    """Raised when the password-reset transaction cannot be persisted."""

    def __init__(self) -> None:
        super().__init__("Password reset could not be persisted.")


def _try_normalize_email(value: str) -> str | None:
    try:
        return normalize_and_validate_email(value)
    except (TypeError, ValueError):
        return None


def _require_normalized_email(value: str) -> str:
    try:
        return normalize_and_validate_email(value)
    except (TypeError, ValueError) as exc:
        raise InvalidEmailError("A valid email address is required.") from exc


def _enforce_password_policy(password: str) -> None:
    try:
        validate_password_policy(password)
    except (TypeError, ValueError) as exc:
        raise InvalidPasswordError(str(exc)) from exc


def _find_user_by_email(db: Session, normalized_email: str) -> User | None:
    return db.execute(
        select(User).where(User.email_normalized == normalized_email)
    ).scalar_one_or_none()


def register_user(db: Session, *, email: str, password: str) -> tuple[str, User] | None:
    """Create an unverified user and return a raw verification token.

    Returns ``None`` when the normalized address already exists. The password is
    hashed before the duplicate check so both paths perform comparable work.
    """
    normalized = _require_normalized_email(email)
    _enforce_password_policy(password)
    password_hash = hash_password(password)

    now = datetime.now(UTC)
    user = User(
        email=normalized,
        email_normalized=normalized,
        password_hash=password_hash,
        is_active=True,
        is_email_verified=False,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        _classify_registration_conflict(exc)
        return None

    raw_token = token_service.issue_action_token(
        db,
        user_id=user.id,
        purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        now=now,
    )
    if raw_token is None:
        db.rollback()
        return None

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _classify_registration_conflict(exc)
        return None
    return raw_token, user


def _classify_registration_conflict(exc: IntegrityError) -> None:
    """Log any registration integrity failure other than a duplicate address.

    The response stays the generic acknowledgement either way, so accounts
    cannot be enumerated, but unexpected failures are no longer indistinguishable
    from the expected duplicate-address race in the logs.
    """
    if not violates(exc, USERS_EMAIL_NORMALIZED) and not violates(exc, ACTIVE_ACTION_TOKEN):
        log_unexpected_integrity_error(logger, "registration", exc)


def _classify_token_issuance_conflict(exc: IntegrityError, operation: str) -> None:
    """Log any token-issuance integrity failure other than the active-token race."""
    if not violates(exc, ACTIVE_ACTION_TOKEN):
        log_unexpected_integrity_error(logger, operation, exc)


def resend_verification_email(db: Session, *, email: str) -> tuple[str, User] | None:
    """Issue a replacement verification token when allowed.

    Returns ``None`` for malformed, unknown, inactive, or already-verified
    accounts, and while the per-account cooldown is active. Callers must still
    return a generic acknowledgement in every case.
    """
    normalized = _try_normalize_email(email)
    if normalized is None:
        return None

    user = _find_user_by_email(db, normalized)
    if user is None or not user.is_active or user.is_email_verified:
        return None
    if token_service.cooldown_active(
        db,
        user_id=user.id,
        purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
    ):
        return None

    now = datetime.now(UTC)
    raw_token = token_service.issue_action_token(
        db,
        user_id=user.id,
        purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
        now=now,
    )
    if raw_token is None:
        db.rollback()
        return None

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _classify_token_issuance_conflict(exc, "verification resend")
        return None
    return raw_token, user


def verify_email(db: Session, *, token: str) -> None:
    """Consume a verification token and grant the default role if unassigned.

    Repeated verification for an already-verified account succeeds without
    creating a second role assignment.
    """
    action_token = token_service.find_token_by_presented_value(db, token)
    if (
        action_token is None
        or action_token.purpose is not UserActionTokenPurpose.EMAIL_VERIFICATION
    ):
        raise InvalidIdentityTokenError()

    user = db.get(User, action_token.user_id)
    if user is None or not user.is_active:
        raise InvalidIdentityTokenError()

    now = datetime.now(UTC)

    if user.is_email_verified:
        if action_token.consumed_at is None and not token_service.is_expired(action_token, now=now):
            token_service.consume_token(db, action_token, now=now)
            db.commit()
        return

    if action_token.consumed_at is not None or token_service.is_expired(action_token, now=now):
        raise InvalidIdentityTokenError()

    if not token_service.consume_token(db, action_token, now=now):
        # A concurrent request consumed the token. Report success only if that
        # request also completed verification.
        db.rollback()
        refreshed = db.get(User, action_token.user_id)
        if refreshed is not None and refreshed.is_email_verified:
            return
        raise InvalidIdentityTokenError()

    user.is_email_verified = True
    user.updated_at = now

    try:
        assign_default_role_if_unassigned(db, user_id=user.id)
    except RoleConfigurationError:
        db.rollback()
        raise

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        # No integrity race is expected here: role-assignment races are absorbed
        # inside ``assign_default_role_if_unassigned``. Keep the generic 400.
        log_unexpected_integrity_error(logger, "email verification", exc)
        raise InvalidIdentityTokenError() from None


def request_password_reset(db: Session, *, email: str) -> tuple[str, User] | None:
    """Issue a reset token for an eligible account, otherwise do nothing.

    Token generation and hashing run even for malformed or unknown addresses so
    the work performed is comparable across both branches.
    """
    dummy_token = generate_opaque_token("reset")
    hash_opaque_token(dummy_token)

    normalized = _try_normalize_email(email)
    if normalized is None:
        return None

    user = _find_user_by_email(db, normalized)
    if user is None or not user.is_active:
        return None
    if token_service.cooldown_active(
        db,
        user_id=user.id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    ):
        return None

    now = datetime.now(UTC)
    raw_token = token_service.issue_action_token(
        db,
        user_id=user.id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
        now=now,
    )
    if raw_token is None:
        db.rollback()
        return None

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _classify_token_issuance_conflict(exc, "password reset request")
        return None
    return raw_token, user


def _revoke_sessions_for_password_reset(
    db: Session,
    *,
    user_id: uuid.UUID,
    now: datetime,
) -> None:
    """Revoke every currently active session and its active refresh tokens.

    Sessions are locked in ascending identifier order and each session is revoked
    before its tokens. That matches refresh rotation, logout, and reuse revocation,
    which all take the session row before the token rows, and removes the previous
    token-then-session cycle. Only active (unconsumed, unrevoked) refresh tokens are
    revoked; consumed/replaced history is left exactly as it was. The caller owns
    the transaction boundary.
    """
    active_session_ids = list(
        db.scalars(
            select(UserSession.id)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
            )
            .order_by(UserSession.id)
        ).all()
    )

    for session_id in active_session_ids:
        sessions.revoke_session_family(
            db,
            session_id=session_id,
            reason=SessionRevocationReason.PASSWORD_RESET,
            now=now,
            include_consumed=False,
        )


def confirm_password_reset(db: Session, *, token: str, new_password: str) -> None:
    """Replace a user's password using a single-use reset token.

    The email-verification flag is intentionally left unchanged. Lock order is the
    presented reset token, the user row, then the user's active sessions in
    ascending identifier order, each session before its active refresh tokens. The
    password update, token consumption, and all revocations commit atomically.
    """
    _enforce_password_policy(new_password)

    action_token = token_service.find_token_by_presented_value(db, token)
    if action_token is None or action_token.purpose is not UserActionTokenPurpose.PASSWORD_RESET:
        raise InvalidIdentityTokenError()

    user = db.get(User, action_token.user_id)
    if user is None or not user.is_active:
        raise InvalidIdentityTokenError()

    now = datetime.now(UTC)
    if action_token.consumed_at is not None or token_service.is_expired(action_token, now=now):
        raise InvalidIdentityTokenError()

    new_password_hash = hash_password(new_password)

    try:
        if not token_service.consume_token(db, action_token, now=now):
            db.rollback()
            raise InvalidIdentityTokenError()

        user.password_hash = new_password_hash
        user.updated_at = now
        token_service.invalidate_tokens(
            db,
            user_id=user.id,
            purpose=UserActionTokenPurpose.PASSWORD_RESET,
            except_id=action_token.id,
            now=now,
        )
        # ``autoflush`` is disabled, so flush explicitly to acquire the user row
        # before any session row. Canonical order: reset token -> user ->
        # session(s) in ascending id -> refresh token(s).
        db.flush()

        _revoke_sessions_for_password_reset(db, user_id=user.id, now=now)

        db.commit()
    except InvalidIdentityTokenError:
        raise
    except IntegrityError as exc:
        db.rollback()
        log_unexpected_integrity_error(logger, "password reset confirmation", exc)
        raise InvalidIdentityTokenError() from None
    except SQLAlchemyError:
        db.rollback()
        raise PasswordResetPersistenceError() from None


__all__ = [
    "IdentityError",
    "InvalidEmailError",
    "InvalidIdentityTokenError",
    "InvalidPasswordError",
    "PasswordResetPersistenceError",
    "confirm_password_reset",
    "register_user",
    "request_password_reset",
    "resend_verification_email",
    "verify_email",
]
