import pytest
from auth_helpers import (
    DEFAULT_PASSWORD,
    assert_validation_errors_hide_input,
    create_user,
    expire_tokens,
    extract_action_token,
    get_user,
    role_ids_for,
    tokens_for,
)
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.roles import ROLE_IDS
from app.models.role import Role
from app.models.user import User
from app.models.user_role import UserRole
from app.schemas.enums import RoleName, UserActionTokenPurpose

pytestmark = pytest.mark.usefixtures("low_cost_argon2")

REGISTER_URL = "/api/v1/auth/register"
VERIFY_URL = "/api/v1/auth/verify-email"
RESET_REQUEST_URL = "/api/v1/auth/password-reset/request"


async def register_and_get_token(
    client,
    mailer,
    *,
    email: str = "verify@example.com",
    password: str = DEFAULT_PASSWORD,
) -> str:
    response = await client.post(REGISTER_URL, json={"email": email, "password": password})
    assert response.status_code == 202
    return extract_action_token(mailer.messages[-1].body)


async def verify(client, token: str):
    return await client.post(VERIFY_URL, json={"token": token})


def assign_role(
    session_factory: sessionmaker[Session],
    user_id,
    role_name: RoleName,
) -> None:
    with session_factory() as session:
        session.add(UserRole(user_id=user_id, role_id=ROLE_IDS[role_name]))
        session.commit()


@pytest.mark.anyio
async def test_valid_token_verifies_email_and_assigns_default_role(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    response = await verify(auth_client, token)

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["Cache-Control"] == "no-store"

    user = get_user(session_factory, user_id)
    assert user is not None
    assert user.is_email_verified is True
    assert role_ids_for(session_factory, user_id) == {ROLE_IDS[RoleName.SECURITY_ANALYST]}

    tokens = tokens_for(session_factory, user_id)
    assert len(tokens) == 1
    assert tokens[0].consumed_at is not None


@pytest.mark.anyio
async def test_repeated_verification_is_idempotent(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    first = await verify(auth_client, token)
    second = await verify(auth_client, token)

    assert first.status_code == 204
    assert second.status_code == 204
    assert role_ids_for(session_factory, user_id) == {ROLE_IDS[RoleName.SECURITY_ANALYST]}
    with session_factory() as session:
        assert len(session.scalars(select(UserRole)).all()) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "existing_role",
    [RoleName.VIEWER, RoleName.ADMIN],
)
async def test_existing_explicit_role_is_preserved(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    existing_role: RoleName,
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    assign_role(session_factory, user_id, existing_role)

    response = await verify(auth_client, token)

    assert response.status_code == 204
    assert role_ids_for(session_factory, user_id) == {ROLE_IDS[existing_role]}
    assert ROLE_IDS[RoleName.SECURITY_ANALYST] not in role_ids_for(session_factory, user_id)


@pytest.mark.anyio
async def test_expired_token_is_rejected(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None
    expire_tokens(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.EMAIL_VERIFICATION,
    )

    response = await verify(auth_client, token)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired token"}
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False
    assert role_ids_for(session_factory, user_id) == set()
    assert tokens_for(session_factory, user_id)[0].consumed_at is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "token",
    [
        "verify_" + "A" * 64,
        "not-a-token",
        "reset_" + "A" * 64,
        "",
    ],
)
async def test_unknown_or_malformed_token_is_rejected(
    auth_client,
    session_factory: sessionmaker[Session],
    token: str,
) -> None:
    response = await verify(auth_client, token)

    assert response.status_code in {400, 422}
    assert_validation_errors_hide_input(response)


@pytest.mark.anyio
async def test_token_cannot_cross_purposes(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    reset_response = await auth_client.post(
        RESET_REQUEST_URL,
        json={"email": "verify@example.com"},
    )
    assert reset_response.status_code == 202
    reset_token = extract_action_token(mailer.messages[-1].body)
    assert reset_token.startswith("reset_")

    response = await verify(auth_client, reset_token)

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False
    assert role_ids_for(session_factory, user_id) == set()


@pytest.mark.anyio
async def test_inactive_user_cannot_verify(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user = session.scalar(select(User))
        assert user is not None
        user.is_active = False
        session.commit()
        user_id = user.id

    response = await verify(auth_client, token)

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False
    assert role_ids_for(session_factory, user_id) == set()


@pytest.mark.anyio
async def test_already_verified_user_stays_idempotent_when_token_unconsumed(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user = session.scalar(select(User))
        assert user is not None
        user.is_email_verified = True
        session.commit()
        user_id = user.id

    response = await verify(auth_client, token)

    assert response.status_code == 204
    assert role_ids_for(session_factory, user_id) == set()
    assert tokens_for(session_factory, user_id)[0].consumed_at is not None


@pytest.mark.anyio
async def test_missing_default_role_rolls_back_verification(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    with session_factory() as session:
        session.execute(delete(Role).where(Role.id == ROLE_IDS[RoleName.SECURITY_ANALYST]))
        session.commit()

    response = await verify(auth_client, token)

    assert response.status_code == 500
    assert token not in response.text
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False
    assert role_ids_for(session_factory, user_id) == set()
    assert tokens_for(session_factory, user_id)[0].consumed_at is None


@pytest.mark.anyio
async def test_verification_validation_errors_hide_the_token(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)

    response = await auth_client.post(
        VERIFY_URL,
        json={"token": token, "role": "Admin"},
    )

    assert response.status_code == 422
    assert token not in response.text
    assert_validation_errors_hide_input(response)

    with session_factory() as session:
        user = session.scalar(select(User))
    assert user is not None and user.is_email_verified is False


@pytest.mark.anyio
async def test_verification_does_not_change_password(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    token = await register_and_get_token(auth_client, mailer)
    with session_factory() as session:
        user = session.scalar(select(User))
        assert user is not None
        original_hash = user.password_hash
        user_id = user.id

    response = await verify(auth_client, token)

    assert response.status_code == 204
    user = get_user(session_factory, user_id)
    assert user is not None and user.password_hash == original_hash


@pytest.mark.anyio
async def test_verification_for_unregistered_token_is_generic(
    auth_client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="unrelated@example.com")

    response = await verify(auth_client, "verify_" + "B" * 64)

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False
    assert role_ids_for(session_factory, user_id) == set()


@pytest.mark.anyio
async def test_token_is_bound_to_its_user(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    first_token = await register_and_get_token(auth_client, mailer, email="first@example.com")
    second_token = await register_and_get_token(auth_client, mailer, email="second@example.com")

    assert first_token != second_token
    with session_factory() as session:
        users = {user.email: user.id for user in session.scalars(select(User)).all()}

    response = await verify(auth_client, first_token)

    assert response.status_code == 204
    first = get_user(session_factory, users["first@example.com"])
    second = get_user(session_factory, users["second@example.com"])
    assert first is not None and first.is_email_verified is True
    assert second is not None and second.is_email_verified is False
    assert role_ids_for(session_factory, users["second@example.com"]) == set()
