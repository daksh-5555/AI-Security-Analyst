import pytest
from auth_helpers import DEFAULT_PASSWORD, extract_action_token
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import hash_opaque_token, verify_password
from app.models.user import User
from app.models.user_action_token import UserActionToken
from app.models.user_role import UserRole
from app.schemas.enums import UserActionTokenPurpose

pytestmark = pytest.mark.usefixtures("low_cost_argon2")

REGISTER_URL = "/api/v1/auth/register"
GENERIC_MESSAGE = "If the address can be registered, a verification email has been sent."


def _count(session_factory: sessionmaker[Session], model: type) -> int:
    with session_factory() as session:
        return session.scalar(select(func.count()).select_from(model)) or 0


@pytest.mark.anyio
async def test_registration_creates_unverified_user_without_role(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    response = await auth_client.post(
        REGISTER_URL,
        json={"email": "  Analyst@Example.COM ", "password": DEFAULT_PASSWORD},
    )

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert DEFAULT_PASSWORD not in response.text
    assert "password_hash" not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    with session_factory() as session:
        user = session.scalar(select(User))
        assert user is not None
        assert user.email == "analyst@example.com"
        assert user.email_normalized == "analyst@example.com"
        assert user.is_active is True
        assert user.is_email_verified is False
        assert verify_password(DEFAULT_PASSWORD, user.password_hash)

        token = session.scalar(select(UserActionToken))
        assert token is not None
        assert token.user_id == user.id
        assert token.purpose is UserActionTokenPurpose.EMAIL_VERIFICATION
        assert token.consumed_at is None
        assert token.expires_at > token.created_at
        token_hash = token.token_hash

    assert _count(session_factory, UserRole) == 0
    assert len(mailer.messages) == 1
    message = mailer.messages[0]
    assert message.to == "analyst@example.com"
    assert "Verify your email address" in message.subject

    raw_token = extract_action_token(message.body)
    assert raw_token.startswith("verify_")
    assert hash_opaque_token(raw_token) == token_hash
    assert raw_token not in repr(token_hash)

    response_json = response.json()
    assert "id" not in response_json
    assert "token" not in response_json


@pytest.mark.anyio
@pytest.mark.parametrize(
    "duplicate_email",
    ["analyst@example.com", "ANALYST@EXAMPLE.COM", "  Analyst@Example.com  "],
)
async def test_duplicate_registration_is_indistinguishable(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    duplicate_email: str,
) -> None:
    first = await auth_client.post(
        REGISTER_URL,
        json={"email": "analyst@example.com", "password": DEFAULT_PASSWORD},
    )
    second = await auth_client.post(
        REGISTER_URL,
        json={"email": duplicate_email, "password": "a different valid passphrase"},
    )

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json() == second.json()
    assert _count(session_factory, User) == 1
    assert _count(session_factory, UserActionToken) == 1
    assert len(mailer.messages) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "email",
    ["not-an-address", "missing-domain@", "@missing-local.com", "a b@example.com", "a@b"],
)
async def test_invalid_email_is_rejected(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    email: str,
) -> None:
    response = await auth_client.post(
        REGISTER_URL,
        json={"email": email, "password": DEFAULT_PASSWORD},
    )

    assert response.status_code == 422
    assert _count(session_factory, User) == 0
    assert _count(session_factory, UserActionToken) == 0
    assert mailer.messages == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "password",
    [
        "short",
        "elevenchars",
        " " * 12,
        "a" * 1025,
    ],
)
async def test_password_policy_is_enforced(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    password: str,
) -> None:
    response = await auth_client.post(
        REGISTER_URL,
        json={"email": "policy@example.com", "password": password},
    )

    assert response.status_code == 422
    assert password not in response.text
    assert _count(session_factory, User) == 0
    assert mailer.messages == []


@pytest.mark.anyio
async def test_twelve_character_password_is_accepted(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    response = await auth_client.post(
        REGISTER_URL,
        json={"email": "boundary@example.com", "password": "twelvechars!"},
    )

    assert response.status_code == 202
    assert _count(session_factory, User) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "extra_field",
    ["role", "role_id", "roles", "is_active", "is_email_verified", "password_hash"],
)
async def test_role_and_state_fields_are_forbidden(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    extra_field: str,
) -> None:
    payload = {"email": "extra@example.com", "password": DEFAULT_PASSWORD}
    payload[extra_field] = "Admin" if extra_field != "roles" else ["Admin"]

    response = await auth_client.post(REGISTER_URL, json=payload)

    assert response.status_code == 422
    assert _count(session_factory, User) == 0
    assert mailer.messages == []


@pytest.mark.anyio
async def test_validation_errors_do_not_echo_sensitive_input(
    auth_client,
    session_factory: sessionmaker[Session],
) -> None:
    password = "elevenchars"
    response = await auth_client.post(
        REGISTER_URL,
        json={"email": "echo@example.com", "password": password},
    )

    assert response.status_code == 422
    assert password not in response.text


@pytest.mark.anyio
async def test_registration_does_not_accept_missing_fields(
    auth_client,
    session_factory: sessionmaker[Session],
) -> None:
    response = await auth_client.post(REGISTER_URL, json={"email": "missing@example.com"})

    assert response.status_code == 422
    assert _count(session_factory, User) == 0


def test_registration_response_schema_has_no_token_fields() -> None:
    from app.main import app

    schema = app.openapi()
    register_operation = schema["paths"][REGISTER_URL]["post"]
    response_schema = register_operation["responses"]["202"]["content"]["application/json"][
        "schema"
    ]
    assert response_schema["$ref"].endswith("/AuthMessageResponse")

    message_schema = schema["components"]["schemas"]["AuthMessageResponse"]
    assert set(message_schema["properties"]) == {"message"}
