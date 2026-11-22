from datetime import UTC, datetime, timedelta

import pytest
from auth_helpers import DEFAULT_PASSWORD, create_user, get_user
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import SecurityConfigurationError, settings
from app.core.security import (
    clear_dummy_password_hash_cache,
    decode_access_token,
    dummy_password_hash,
    hash_opaque_token,
    password_needs_rehash,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user_role import UserRole
from app.models.user_session import UserSession
from app.services import authentication
from app.services.authentication import InvalidCredentialsError, LoginPersistenceError

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

FIXED_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _count(session_factory: sessionmaker[Session], model: type) -> int:
    with session_factory() as session:
        return session.scalar(select(func.count()).select_from(model)) or 0


def _decode(token: str, *, now: datetime | None = None):
    return decode_access_token(token, now=now)


def _login(
    session_factory: sessionmaker[Session],
    *,
    email: str,
    password: str = DEFAULT_PASSWORD,
    now: datetime | None = None,
):
    with session_factory() as db:
        return authentication.login(
            db,
            email=email,
            password=password,
            now=now,
        )


def test_login_uses_injected_now_for_exact_expiry_math(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "refresh_token_ttl_seconds", 3_600)
    monkeypatch.setattr(settings, "absolute_session_ttl_seconds", 7_200)
    user_id = create_user(
        session_factory,
        email="math@example.com",
        is_email_verified=True,
    )

    result = _login(session_factory, email="math@example.com", now=FIXED_NOW)

    assert result.user_id == user_id
    assert result.email == "math@example.com"
    assert result.expires_in == settings.access_token_ttl_seconds
    assert result.refresh_expires_in == 3_600
    assert result.session_id == _decode(result.access_token, now=FIXED_NOW).sid

    with session_factory() as session:
        stored = session.get(UserSession, result.session_id)
        assert stored is not None
        refresh = session.scalar(
            select(RefreshToken).where(RefreshToken.session_id == result.session_id)
        )
        assert refresh is not None

        assert stored.absolute_expires_at == FIXED_NOW + timedelta(seconds=7_200)
        assert stored.idle_expires_at == FIXED_NOW + timedelta(seconds=3_600)
        assert stored.created_at == FIXED_NOW
        assert stored.last_refreshed_at == FIXED_NOW
        assert stored.revoked_at is None
        assert refresh.expires_at == stored.idle_expires_at
        assert refresh.expires_at == FIXED_NOW + timedelta(seconds=3_600)


def test_login_jwt_identity_matches_persisted_rows(
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="claims@example.com",
        is_email_verified=True,
    )

    result = _login(session_factory, email="claims@example.com")
    claims = _decode(result.access_token)

    assert claims.sub == user_id
    assert claims.sid == result.session_id
    assert claims.typ == "access"
    assert claims.iss == settings.jwt_issuer
    assert claims.aud == settings.jwt_audience
    assert not hasattr(claims, "roles")
    assert not hasattr(claims, "permissions")

    with session_factory() as session:
        stored = session.get(UserSession, claims.sid)
        assert stored is not None
        assert stored.user_id == claims.sub


def test_only_the_refresh_hash_is_persisted(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="hash@example.com",
        is_email_verified=True,
    )

    result = _login(session_factory, email="hash@example.com")

    with session_factory() as session:
        refresh = session.scalar(select(RefreshToken))
        assert refresh is not None
        assert refresh.token_hash == hash_opaque_token(result.refresh_token)
        assert refresh.token_hash != result.refresh_token
        assert len(refresh.token_hash) == 64
        assert refresh.consumed_at is None
        assert refresh.revoked_at is None
        assert refresh.replaced_by_id is None


def test_login_never_assigns_a_role(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="roleless@example.com",
        is_email_verified=True,
    )

    _login(session_factory, email="roleless@example.com")

    assert _count(session_factory, UserRole) == 0


@pytest.mark.parametrize("case", ["malformed", "unknown"])
def test_unusable_identities_verify_against_the_dummy_hash(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    calls: list[tuple[str, str]] = []

    def fake_verify(password: str, password_hash: str) -> bool:
        calls.append((password, password_hash))
        return False

    monkeypatch.setattr(authentication, "verify_password", fake_verify)
    submitted = "not-an-email" if case == "malformed" else "missing@example.com"

    with pytest.raises(InvalidCredentialsError):
        _login(session_factory, email=submitted, password="candidate")

    assert calls == [("candidate", dummy_password_hash())]
    assert _count(session_factory, UserSession) == 0
    assert _count(session_factory, RefreshToken) == 0


def test_existing_identity_verifies_against_its_real_hash(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(
        session_factory,
        email="real-hash@example.com",
        is_email_verified=True,
    )
    user = get_user(session_factory, user_id)
    assert user is not None
    calls: list[str] = []

    real_verify = authentication.verify_password

    def recording_verify(password: str, password_hash: str) -> bool:
        calls.append(password_hash)
        return real_verify(password, password_hash)

    monkeypatch.setattr(authentication, "verify_password", recording_verify)

    _login(session_factory, email="real-hash@example.com")

    assert calls == [user.password_hash]
    assert calls[0] != dummy_password_hash()


def test_dummy_hash_cache_does_not_hold_credentials(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_dummy_password_hash_cache()
    monkeypatch.setattr(
        authentication,
        "verify_password",
        lambda _password, _hash: False,
    )

    with pytest.raises(InvalidCredentialsError):
        _login(session_factory, email="nobody@example.com", password="secret-value")

    from app.core import security as security_module

    assert "secret-value" not in str(security_module._dummy_hash_cache)


def test_commit_failure_rolls_back_session_refresh_and_rehash(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(
        session_factory,
        email="rollback@example.com",
        is_email_verified=True,
    )
    original = get_user(session_factory, user_id)
    assert original is not None
    original_hash = original.password_hash

    # Force the successful-verification path to rehash the stored password.
    monkeypatch.setattr(settings, "argon2_time_cost", 2)
    assert password_needs_rehash(original_hash) is True

    with session_factory() as db:
        real_commit = db.commit

        def failing_commit() -> None:
            raise SQLAlchemyError("simulated commit failure")

        monkeypatch.setattr(db, "commit", failing_commit)

        with pytest.raises(LoginPersistenceError):
            authentication.login(
                db,
                email="rollback@example.com",
                password=DEFAULT_PASSWORD,
                now=FIXED_NOW,
            )

        monkeypatch.setattr(db, "commit", real_commit)

    assert _count(session_factory, UserSession) == 0
    assert _count(session_factory, RefreshToken) == 0
    unchanged = get_user(session_factory, user_id)
    assert unchanged is not None
    assert unchanged.password_hash == original_hash
    assert verify_password(DEFAULT_PASSWORD, unchanged.password_hash) is True


def test_jwt_failure_after_rehash_assignment_rolls_back_pending_mutation(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(
        session_factory,
        email="jwt-failure@example.com",
        is_email_verified=True,
    )
    original = get_user(session_factory, user_id)
    assert original is not None
    original_hash = original.password_hash
    original_updated_at = original.updated_at

    # Force the successful-verification path to assign a rehash before JWT creation.
    monkeypatch.setattr(settings, "argon2_time_cost", 2)
    assert password_needs_rehash(original_hash) is True
    monkeypatch.setattr(settings, "jwt_secret", None)

    with session_factory() as db:
        with pytest.raises(SecurityConfigurationError):
            authentication.login(
                db,
                email="jwt-failure@example.com",
                password=DEFAULT_PASSWORD,
                now=FIXED_NOW,
            )

        # The service must roll back its pending ORM mutation; committing this
        # same session afterwards must not persist the rehash or any rows.
        db.commit()

    unchanged = get_user(session_factory, user_id)
    assert unchanged is not None
    assert unchanged.password_hash == original_hash
    assert unchanged.updated_at == original_updated_at
    assert _count(session_factory, UserSession) == 0
    assert _count(session_factory, RefreshToken) == 0


def test_missing_jwt_secret_persists_nothing(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_user(
        session_factory,
        email="no-secret@example.com",
        is_email_verified=True,
    )
    monkeypatch.setattr(settings, "jwt_secret", None)

    with pytest.raises(SecurityConfigurationError):
        _login(session_factory, email="no-secret@example.com", now=FIXED_NOW)

    assert _count(session_factory, UserSession) == 0
    assert _count(session_factory, RefreshToken) == 0


def test_inactive_and_unverified_users_fail_after_password_verification(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_user(
        session_factory,
        email="inactive-service@example.com",
        is_active=False,
        is_email_verified=True,
    )
    calls: list[str] = []
    real_verify = authentication.verify_password

    def recording_verify(password: str, password_hash: str) -> bool:
        calls.append(password_hash)
        return real_verify(password, password_hash)

    monkeypatch.setattr(authentication, "verify_password", recording_verify)

    with pytest.raises(InvalidCredentialsError):
        _login(session_factory, email="inactive-service@example.com")

    assert len(calls) == 1
    assert calls[0] != dummy_password_hash()
    assert _count(session_factory, UserSession) == 0


def test_login_rejects_naive_now(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="naive-now@example.com",
        is_email_verified=True,
    )

    with pytest.raises(ValueError):
        _login(
            session_factory,
            email="naive-now@example.com",
            now=datetime(2026, 1, 2, 3, 4, 5),
        )

    assert _count(session_factory, UserSession) == 0


def test_login_stores_the_submitted_email_shape_for_lookup(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="MixedCase@Example.com",
        is_email_verified=True,
    )

    result = _login(session_factory, email="  mixedcase@example.com  ")

    assert result.email == "mixedcase@example.com"
    stored = get_user(session_factory, result.user_id)
    assert stored is not None
    assert stored.email == "mixedcase@example.com"
