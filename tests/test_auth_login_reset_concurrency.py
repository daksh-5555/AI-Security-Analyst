"""Login and password-reset serialization tests.

Password reset and login both use the ``users`` row as their synchronization
point. These tests cover the two serialized orders and a real two-thread race on
file-backed SQLite. PostgreSQL row-lock behavior is reasoned about in the service
docstring and README; it is not executed by this environment.
"""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from auth_helpers import DEFAULT_PASSWORD, create_user, get_user
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import password_needs_rehash, verify_password
from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason
from app.services import authentication, identity
from app.services.authentication import InvalidCredentialsError, LoginPersistenceError

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

NEW_PASSWORD = "a completely new passphrase"


def _login(
    session_factory: sessionmaker[Session],
    email: str,
    password: str = DEFAULT_PASSWORD,
) -> authentication.LoginResult:
    with session_factory() as db:
        return authentication.login(db, email=email, password=password)


def _issue_reset(session_factory: sessionmaker[Session], email: str) -> str:
    with session_factory() as db:
        issued = identity.request_password_reset(db, email=email)
    assert issued is not None
    return issued[0]


def _confirm_reset(
    session_factory: sessionmaker[Session],
    token: str,
    password: str = NEW_PASSWORD,
) -> None:
    with session_factory() as db:
        identity.confirm_password_reset(db, token=token, new_password=password)


def _session_and_token(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
) -> tuple[UserSession | None, RefreshToken | None]:
    with session_factory() as db:
        user_session = db.get(UserSession, session_id)
        refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.session_id == session_id))
        return user_session, refresh_token


def test_login_that_commits_first_is_revoked_by_a_later_reset(
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="login-first@example.com",
        is_email_verified=True,
    )
    other_user_id = create_user(
        session_factory,
        email="login-bystander@example.com",
        is_email_verified=True,
    )
    assert user_id != other_user_id

    first = _login(session_factory, "login-first@example.com")
    second = _login(session_factory, "login-first@example.com")
    bystander = _login(session_factory, "login-bystander@example.com")

    raw_reset = _issue_reset(session_factory, "login-first@example.com")
    _confirm_reset(session_factory, raw_reset)

    for result in (first, second):
        user_session, refresh_token = _session_and_token(session_factory, result.session_id)
        assert user_session is not None
        assert user_session.revoked_at is not None
        assert user_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET
        assert refresh_token is not None
        assert refresh_token.revoked_at is not None
        assert refresh_token.consumed_at is None

    bystander_session, bystander_token = _session_and_token(session_factory, bystander.session_id)
    assert bystander_session is not None
    assert bystander_session.revoked_at is None
    assert bystander_token is not None
    assert bystander_token.revoked_at is None
    assert bystander_token.consumed_at is None

    with session_factory() as db:
        active_sessions = list(
            db.scalars(
                select(UserSession).where(
                    UserSession.user_id == user_id,
                    UserSession.revoked_at.is_(None),
                )
            ).all()
        )
        active_tokens = list(
            db.scalars(
                select(RefreshToken).where(
                    RefreshToken.session_id.in_(
                        select(UserSession.id).where(UserSession.user_id == user_id)
                    ),
                    RefreshToken.consumed_at.is_(None),
                    RefreshToken.revoked_at.is_(None),
                )
            ).all()
        )
    assert active_sessions == []
    assert active_tokens == []

    with pytest.raises(InvalidCredentialsError):
        _login(session_factory, "login-first@example.com")


def test_reset_that_commits_first_rejects_the_old_password(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="reset-first@example.com",
        is_email_verified=True,
    )
    raw_reset = _issue_reset(session_factory, "reset-first@example.com")
    _confirm_reset(session_factory, raw_reset)

    with pytest.raises(InvalidCredentialsError):
        _login(session_factory, "reset-first@example.com")

    with session_factory() as db:
        assert db.scalar(select(func.count()).select_from(UserSession)) == 0
        assert db.scalar(select(func.count()).select_from(RefreshToken)) == 0

    result = _login(session_factory, "reset-first@example.com", NEW_PASSWORD)
    assert result.session_id is not None
    user_session, refresh_token = _session_and_token(session_factory, result.session_id)
    assert user_session is not None
    assert user_session.revoked_at is None
    assert refresh_token is not None
    assert refresh_token.revoked_at is None


def test_rehash_login_cannot_overwrite_a_reset_that_commits_first(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(
        session_factory,
        email="rehash-reset@example.com",
        is_email_verified=True,
    )
    monkeypatch.setattr(settings, "argon2_time_cost", 2)
    original = get_user(session_factory, user_id)
    assert original is not None
    assert password_needs_rehash(original.password_hash) is True

    raw_reset = _issue_reset(session_factory, "rehash-reset@example.com")
    _confirm_reset(session_factory, raw_reset)

    with pytest.raises(InvalidCredentialsError):
        _login(session_factory, "rehash-reset@example.com")

    updated = get_user(session_factory, user_id)
    assert updated is not None
    assert verify_password(NEW_PASSWORD, updated.password_hash) is True
    assert verify_password(DEFAULT_PASSWORD, updated.password_hash) is False


def test_concurrent_login_and_reset_leave_no_active_old_password_session(
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="login-reset-race@example.com",
        is_email_verified=True,
    )
    raw_reset = _issue_reset(session_factory, "login-reset-race@example.com")
    barrier = threading.Barrier(2)

    def attempt_login() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                return (
                    "ok",
                    authentication.login(
                        db,
                        email="login-reset-race@example.com",
                        password=DEFAULT_PASSWORD,
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - outcome is asserted below
                return "error", exc

    def attempt_reset() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                identity.confirm_password_reset(
                    db,
                    token=raw_reset,
                    new_password=NEW_PASSWORD,
                )
                return "ok", None
            except Exception as exc:  # noqa: BLE001 - outcome is asserted below
                return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        login_future = pool.submit(attempt_login)
        reset_future = pool.submit(attempt_reset)
        login_status, login_payload = login_future.result(timeout=60)
        reset_status, reset_payload = reset_future.result(timeout=60)

    assert reset_status == "ok", reset_payload

    with session_factory() as db:
        active_sessions = list(
            db.scalars(
                select(UserSession).where(
                    UserSession.user_id == user_id,
                    UserSession.revoked_at.is_(None),
                )
            ).all()
        )
        active_tokens = list(
            db.scalars(
                select(RefreshToken).where(
                    RefreshToken.session_id.in_(
                        select(UserSession.id).where(UserSession.user_id == user_id)
                    ),
                    RefreshToken.consumed_at.is_(None),
                    RefreshToken.revoked_at.is_(None),
                )
            ).all()
        )
    assert active_sessions == []
    assert active_tokens == []

    if login_status == "ok":
        result = login_payload
        assert isinstance(result, authentication.LoginResult)
        user_session, refresh_token = _session_and_token(session_factory, result.session_id)
        assert user_session is not None
        assert user_session.revoked_at is not None
        assert user_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET
        assert refresh_token is not None
        assert refresh_token.revoked_at is not None
    else:
        assert isinstance(login_payload, (InvalidCredentialsError, LoginPersistenceError))

    # The new password still works; a login that commits after reset starts a
    # fresh session with the committed hash.
    after_reset = _login(session_factory, "login-reset-race@example.com", NEW_PASSWORD)
    assert after_reset.session_id is not None
