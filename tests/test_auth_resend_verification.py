import pytest
from auth_helpers import (
    DEFAULT_PASSWORD,
    create_user,
    extract_action_token,
    get_user,
    role_ids_for,
    tokens_for,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.roles import ROLE_IDS
from app.models.user import User
from app.models.user_action_token import UserActionToken
from app.schemas.enums import RoleName, UserActionTokenPurpose

pytestmark = pytest.mark.usefixtures("low_cost_argon2")

REGISTER_URL = "/api/v1/auth/register"
RESEND_URL = "/api/v1/auth/resend-verification"
VERIFY_URL = "/api/v1/auth/verify-email"
GENERIC_MESSAGE = "If the account requires verification, a verification email has been sent."


async def resend(client, email: str):
    return await client.post(RESEND_URL, json={"email": email})


async def register(client, mailer, email: str = "resend@example.com") -> str:
    response = await client.post(
        REGISTER_URL,
        json={"email": email, "password": DEFAULT_PASSWORD},
    )
    assert response.status_code == 202
    return extract_action_token(mailer.messages[-1].body)


@pytest.mark.anyio
async def test_resend_issues_a_replacement_token(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 0)
    first_token = await register(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    response = await resend(auth_client, "resend@example.com")

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert response.headers["Cache-Control"] == "no-store"
    assert len(mailer.messages) == 2
    second_token = extract_action_token(mailer.messages[-1].body)
    assert second_token != first_token

    tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
    )
    assert len(tokens) == 2
    assert sum(token.consumed_at is not None for token in tokens) == 1


@pytest.mark.anyio
async def test_resend_invalidates_the_previous_token(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 0)
    first_token = await register(auth_client, mailer)
    await resend(auth_client, "resend@example.com")
    second_token = extract_action_token(mailer.messages[-1].body)

    stale_response = await auth_client.post(VERIFY_URL, json={"token": first_token})
    fresh_response = await auth_client.post(VERIFY_URL, json={"token": second_token})

    assert stale_response.status_code == 400
    assert fresh_response.status_code == 204

    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None
    assert role_ids_for(session_factory, user_id) == {ROLE_IDS[RoleName.SECURITY_ANALYST]}


@pytest.mark.anyio
@pytest.mark.parametrize(
    "email",
    ["unknown@example.com", "not-an-address", "missing-domain@"],
)
async def test_resend_for_unknown_or_malformed_address_is_generic(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    email: str,
) -> None:
    response = await resend(auth_client, email)

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert mailer.messages == []
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 0


@pytest.mark.anyio
async def test_resend_for_inactive_user_is_generic(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="inactive@example.com",
        is_active=False,
    )

    response = await resend(auth_client, "inactive@example.com")

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert mailer.messages == []
    assert tokens_for(session_factory, user_id) == []


@pytest.mark.anyio
async def test_resend_for_verified_user_sends_nothing(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="verified@example.com",
        is_email_verified=True,
    )

    response = await resend(auth_client, "verified@example.com")

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert mailer.messages == []
    assert tokens_for(session_factory, user_id) == []


@pytest.mark.anyio
async def test_resend_cooldown_suppresses_email(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 3600)
    await register(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    response = await resend(auth_client, "resend@example.com")

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert len(mailer.messages) == 1
    assert len(tokens_for(session_factory, user_id)) == 1


@pytest.mark.anyio
async def test_resend_response_matches_registration_shape(
    auth_client,
    mailer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 0)
    await register(auth_client, mailer)

    existing = await resend(auth_client, "resend@example.com")
    missing = await resend(auth_client, "unknown@example.com")

    assert existing.status_code == missing.status_code == 202
    assert existing.json() == missing.json() == {"message": GENERIC_MESSAGE}


@pytest.mark.anyio
async def test_resend_validation_errors_hide_email_input(auth_client) -> None:
    email = "sensitive-input@example.com"

    response = await auth_client.post(
        RESEND_URL,
        json={"email": email, "role": "Admin"},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert all("input" not in error for error in detail)


@pytest.mark.anyio
async def test_resend_does_not_assign_roles(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 0)
    await register(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    response = await resend(auth_client, "resend@example.com")

    assert response.status_code == 202
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False
    assert role_ids_for(session_factory, user_id) == set()
