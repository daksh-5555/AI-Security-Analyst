import uuid

import jwt
import pytest
from auth_helpers import (
    DEFAULT_PASSWORD,
    assert_validation_errors_hide_input,
    create_user,
    extract_action_token,
    get_user,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import hash_opaque_token, password_needs_rehash, verify_password
from app.models.refresh_token import RefreshToken
from app.models.user_role import UserRole
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason
from app.services import authentication
from app.services.authentication import LoginPersistenceError

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

LOGIN_URL = "/api/v1/auth/login"
RESET_REQUEST_URL = "/api/v1/auth/password-reset/request"
RESET_CONFIRM_URL = "/api/v1/auth/password-reset/confirm"
GENERIC_DETAIL = "Invalid email or password"
NEW_PASSWORD = "a completely new passphrase"


async def login(client, email: str, password: str = DEFAULT_PASSWORD):
    return await client.post(LOGIN_URL, json={"email": email, "password": password})


async def request_and_confirm_reset(client, mailer, email: str) -> None:
    requested = await client.post(RESET_REQUEST_URL, json={"email": email})
    assert requested.status_code == 202
    token = extract_action_token(mailer.messages[-1].body)
    confirmed = await client.post(
        RESET_CONFIRM_URL,
        json={"token": token, "new_password": NEW_PASSWORD},
    )
    assert confirmed.status_code == 204


def _count(session_factory: sessionmaker[Session], model: type) -> int:
    with session_factory() as session:
        return session.scalar(select(func.count()).select_from(model)) or 0


def _decode(token: str) -> dict:
    secret = settings.jwt_secret
    assert secret is not None
    return jwt.decode(
        token,
        secret.get_secret_value(),
        algorithms=["HS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )


@pytest.mark.anyio
async def test_successful_login_returns_tokens_and_persists_session(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="login@example.com",
        is_email_verified=True,
    )

    response = await login(client, "login@example.com")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "refresh_expires_in",
        "session_id",
    }
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.access_token_ttl_seconds
    assert body["refresh_expires_in"] == settings.refresh_token_ttl_seconds
    assert body["refresh_token"].startswith("refresh_")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    session_id = uuid.UUID(body["session_id"])
    claims = _decode(body["access_token"])
    assert claims["sub"] == str(user_id)
    assert claims["sid"] == str(session_id)
    assert claims["typ"] == "access"
    assert "roles" not in claims
    assert "permissions" not in claims

    with session_factory() as session:
        sessions = list(session.scalars(select(UserSession)).all())
        refresh_tokens = list(session.scalars(select(RefreshToken)).all())

    assert len(sessions) == 1
    stored_session = sessions[0]
    assert stored_session.id == session_id
    assert stored_session.user_id == user_id
    assert stored_session.revoked_at is None

    assert len(refresh_tokens) == 1
    stored_token = refresh_tokens[0]
    assert stored_token.session_id == session_id
    assert stored_token.token_hash == hash_opaque_token(body["refresh_token"])
    assert stored_token.token_hash != body["refresh_token"]
    assert stored_token.expires_at == stored_session.idle_expires_at
    assert stored_token.consumed_at is None
    assert stored_token.revoked_at is None

    assert _count(session_factory, UserRole) == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("case", "is_active", "is_email_verified", "submitted_email", "submitted_password"),
    [
        ("malformed", True, True, "not-an-address", DEFAULT_PASSWORD),
        ("unknown", True, True, "unknown@example.com", DEFAULT_PASSWORD),
        ("wrong_password", True, True, None, "definitely the wrong password"),
        ("inactive", False, True, None, DEFAULT_PASSWORD),
        ("unverified", True, False, None, DEFAULT_PASSWORD),
    ],
)
async def test_invalid_credentials_are_indistinguishable(
    client,
    session_factory: sessionmaker[Session],
    case: str,
    is_active: bool,
    is_email_verified: bool,
    submitted_email: str | None,
    submitted_password: str,
) -> None:
    email = f"{case.replace('_', '-')}@example.com"
    if case not in {"malformed", "unknown"}:
        create_user(
            session_factory,
            email=email,
            is_active=is_active,
            is_email_verified=is_email_verified,
        )

    response = await login(client, submitted_email or email, submitted_password)

    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_DETAIL}
    assert _count(session_factory, UserSession) == 0
    assert _count(session_factory, RefreshToken) == 0


@pytest.mark.anyio
async def test_empty_credentials_use_generic_failure(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    response = await login(client, "", "")

    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_DETAIL}
    assert _count(session_factory, UserSession) == 0


@pytest.mark.anyio
async def test_short_legacy_password_can_log_in(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="legacy@example.com",
        password="short",
        is_email_verified=True,
    )

    response = await login(client, "legacy@example.com", "short")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_oversized_password_is_rejected_without_echoing_input(
    client,
) -> None:
    oversized = "a" * 1025

    response = await login(client, "someone@example.com", oversized)

    assert response.status_code == 422
    assert oversized not in response.text
    assert_validation_errors_hide_input(response)


@pytest.mark.anyio
async def test_oversized_multibyte_password_is_rejected(client) -> None:
    # 600 two-byte characters exceed the 1024-byte limit without being 1024 chars.
    oversized = "\u00e9" * 600
    assert len(oversized) < 1024
    assert len(oversized.encode("utf-8")) > 1024

    response = await login(client, "someone@example.com", oversized)

    assert response.status_code == 422
    assert oversized not in response.text
    assert_validation_errors_hide_input(response)


@pytest.mark.anyio
async def test_extra_fields_are_forbidden(client) -> None:
    response = await client.post(
        LOGIN_URL,
        json={
            "email": "someone@example.com",
            "password": DEFAULT_PASSWORD,
            "role": "Admin",
        },
    )

    assert response.status_code == 422
    assert DEFAULT_PASSWORD not in response.text
    assert_validation_errors_hide_input(response)


@pytest.mark.anyio
async def test_password_rehash_is_persisted(
    client,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(
        session_factory,
        email="rehash@example.com",
        is_email_verified=True,
    )
    user = get_user(session_factory, user_id)
    assert user is not None
    original_hash = user.password_hash

    monkeypatch.setattr(settings, "argon2_time_cost", 2)
    assert password_needs_rehash(original_hash) is True

    response = await login(client, "rehash@example.com")

    assert response.status_code == 200
    updated = get_user(session_factory, user_id)
    assert updated is not None
    assert updated.password_hash != original_hash
    assert password_needs_rehash(updated.password_hash) is False
    assert verify_password(DEFAULT_PASSWORD, updated.password_hash) is True


@pytest.mark.anyio
async def test_login_after_completed_reset_requires_the_new_password(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="reset-then-login@example.com",
        is_email_verified=True,
    )

    await request_and_confirm_reset(auth_client, mailer, "reset-then-login@example.com")

    old_password = await login(auth_client, "reset-then-login@example.com")
    assert old_password.status_code == 401
    assert old_password.json() == {"detail": GENERIC_DETAIL}
    assert _count(session_factory, UserSession) == 0
    assert _count(session_factory, RefreshToken) == 0

    new_password = await login(auth_client, "reset-then-login@example.com", NEW_PASSWORD)
    assert new_password.status_code == 200
    assert _count(session_factory, UserSession) == 1
    assert _count(session_factory, RefreshToken) == 1


@pytest.mark.anyio
async def test_reset_revokes_a_session_and_refresh_token_created_by_login(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="login-then-reset@example.com",
        is_email_verified=True,
    )
    other_user_id = create_user(
        session_factory,
        email="bystander-login@example.com",
        is_email_verified=True,
    )
    assert user_id != other_user_id

    logged_in = await login(auth_client, "login-then-reset@example.com")
    assert logged_in.status_code == 200
    body = logged_in.json()
    bystander = await login(auth_client, "bystander-login@example.com")
    assert bystander.status_code == 200
    bystander_body = bystander.json()

    await request_and_confirm_reset(auth_client, mailer, "login-then-reset@example.com")

    session_id = uuid.UUID(body["session_id"])
    with session_factory() as session:
        stored_session = session.get(UserSession, session_id)
        assert stored_session is not None
        assert stored_session.revoked_at is not None
        assert stored_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET
        stored_token = session.scalar(
            select(RefreshToken).where(RefreshToken.session_id == session_id)
        )
        assert stored_token is not None
        assert stored_token.revoked_at is not None
        assert stored_token.consumed_at is None

        bystander_session = session.get(UserSession, uuid.UUID(bystander_body["session_id"]))
        assert bystander_session is not None
        assert bystander_session.revoked_at is None
        bystander_token = session.scalar(
            select(RefreshToken).where(RefreshToken.session_id == bystander_session.id)
        )
        assert bystander_token is not None
        assert bystander_token.revoked_at is None
        assert bystander_token.consumed_at is None

    old_password = await login(auth_client, "login-then-reset@example.com")
    assert old_password.status_code == 401


@pytest.mark.anyio
async def test_login_without_rehash_does_not_change_updated_at(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="no-audit-change@example.com",
        is_email_verified=True,
    )
    before = get_user(session_factory, user_id)
    assert before is not None
    original_updated_at = before.updated_at

    response = await login(client, "no-audit-change@example.com")

    assert response.status_code == 200
    after = get_user(session_factory, user_id)
    assert after is not None
    assert after.updated_at == original_updated_at


@pytest.mark.anyio
async def test_login_rate_limit_is_independent_of_other_auth_buckets(
    client,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_rate_limit_max_requests", 1)
    create_user(
        session_factory,
        email="limited@example.com",
        is_email_verified=True,
    )

    first = await login(client, "limited@example.com")
    second = await login(client, "limited@example.com")

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == {"detail": "Too many requests"}
    assert "Retry-After" in second.headers

    other_bucket = await client.post(
        RESET_REQUEST_URL,
        json={"email": "unknown-reset@example.com"},
    )
    assert other_bucket.status_code == 202


@pytest.mark.anyio
async def test_persistence_failure_returns_generic_server_error(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_login(*_args, **_kwargs):
        raise LoginPersistenceError()

    monkeypatch.setattr(authentication, "login", fail_login)

    response = await login(client, "someone@example.com")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal Server Error"}


@pytest.mark.anyio
async def test_openapi_schemas_expose_only_safe_login_fields(client) -> None:
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    schemas = response.json()["components"]["schemas"]

    assert set(schemas["LoginRequest"]["properties"]) == {"email", "password"}
    assert set(schemas["LoginResponse"]["properties"]) == {
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "refresh_expires_in",
        "session_id",
    }
    assert set(schemas["CurrentUserResponse"]["properties"]) == {
        "id",
        "email",
        "is_active",
        "is_email_verified",
        "roles",
    }
    assert "password_hash" not in str(schemas)
    assert "token_hash" not in str(schemas)
