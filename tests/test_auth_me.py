import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from auth_helpers import (
    DEFAULT_PASSWORD,
    assign_role,
    create_session,
    create_user,
    get_user,
    remove_role,
)
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.role import Role
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.enums import RoleName

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

LOGIN_URL = "/api/v1/auth/login"
ME_URL = "/api/v1/auth/me"
GENERIC_DETAIL = "Invalid or expired access token"
BEARER_CHALLENGE = "Bearer"


def _secret() -> str:
    secret = settings.jwt_secret
    assert secret is not None
    return secret.get_secret_value()


async def login(client, email: str, password: str = DEFAULT_PASSWORD):
    return await client.post(LOGIN_URL, json={"email": email, "password": password})


async def login_tokens(client, *, email: str = "me@example.com") -> dict:
    response = await login(client, email)
    assert response.status_code == 200
    return response.json()


def _claims(**overrides) -> dict:
    now = datetime.now(UTC)
    payload = {
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + settings.access_token_ttl_seconds,
        "jti": str(uuid.uuid4()),
        "typ": "access",
    }
    payload.update(overrides)
    return payload


def _token(payload: dict, *, secret: str | None = None) -> str:
    return jwt.encode(payload, secret or _secret(), algorithm="HS256")


def _assert_unauthorized(response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_DETAIL}
    assert response.headers.get("WWW-Authenticate") == BEARER_CHALLENGE


@pytest.mark.anyio
async def test_me_returns_only_safe_identity_fields(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="me@example.com",
        is_email_verified=True,
    )
    tokens = await login_tokens(client)

    response = await client.get(
        ME_URL,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"id", "email", "is_active", "is_email_verified", "roles"}
    assert body == {
        "id": str(user_id),
        "email": "me@example.com",
        "is_active": True,
        "is_email_verified": True,
        "roles": [],
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    user = get_user(session_factory, user_id)
    assert user is not None
    assert user.password_hash not in response.text
    assert tokens["refresh_token"] not in response.text
    assert "token_hash" not in response.text


@pytest.mark.anyio
async def test_roles_are_resolved_freshly_on_every_request(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="roles@example.com",
        is_email_verified=True,
    )
    tokens = await login_tokens(client, email="roles@example.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    assign_role(session_factory, user_id, RoleName.VIEWER)
    added = await client.get(ME_URL, headers=headers)

    assert added.status_code == 200
    assert added.json()["roles"] == [RoleName.VIEWER.value]

    remove_role(session_factory, user_id, RoleName.VIEWER)
    removed = await client.get(ME_URL, headers=headers)

    assert removed.status_code == 200
    assert removed.json()["roles"] == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Token abc"},
    ],
    ids=["missing", "basic", "scheme-only", "empty", "malformed", "wrong-scheme"],
)
async def test_malformed_authorization_headers_are_generic_401(
    client,
    headers: dict[str, str],
) -> None:
    response = await client.get(ME_URL, headers=headers)

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_duplicate_authorization_headers_are_rejected(client) -> None:
    response = await client.get(
        ME_URL,
        headers=[
            ("Authorization", "Bearer first"),
            ("Authorization", "Bearer second"),
        ],
    )

    _assert_unauthorized(response)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "unexpected-issuer"},
        {"aud": "unexpected-audience"},
        {"typ": "refresh"},
        {"jti": ""},
        {"sub": "not-a-uuid"},
        {"sid": "not-a-uuid"},
    ],
    ids=["issuer", "audience", "type", "jti", "subject", "session"],
)
async def test_invalid_claim_values_are_generic_401(
    client,
    overrides: dict[str, object],
) -> None:
    token = _token(_claims(**overrides))

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_invalid_signature_is_generic_401(client) -> None:
    token = _token(_claims(), secret="wrong-secret-" + "x" * 40)

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_expired_token_is_generic_401(client) -> None:
    now = datetime.now(UTC) - timedelta(hours=1)
    token = _token(
        _claims(
            iat=int(now.timestamp()),
            exp=int(now.timestamp()) + settings.access_token_ttl_seconds,
        )
    )

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_unknown_session_is_generic_401(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="unknown-session@example.com",
        is_email_verified=True,
    )
    token = _token(_claims(sub=str(user_id), sid=str(uuid.uuid4())))

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_subject_and_session_mismatch_is_generic_401(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    owner_id = create_user(
        session_factory,
        email="owner@example.com",
        is_email_verified=True,
    )
    other_id = create_user(
        session_factory,
        email="other@example.com",
        is_email_verified=True,
    )
    session_id = create_session(session_factory, owner_id)
    token = _token(_claims(sub=str(other_id), sid=str(session_id)))

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_revoked_session_is_generic_401(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="revoked@example.com",
        is_email_verified=True,
    )
    session_id = create_session(
        session_factory,
        user_id,
        revoked_at=datetime.now(UTC),
    )
    token = _token(_claims(sub=str(user_id), sid=str(session_id)))

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
@pytest.mark.parametrize("expiry_field", ["idle_expires_at", "absolute_expires_at"])
async def test_expired_sessions_are_generic_401(
    client,
    session_factory: sessionmaker[Session],
    expiry_field: str,
) -> None:
    user_id = create_user(
        session_factory,
        email=f"expired-{expiry_field}@example.com",
        is_email_verified=True,
    )
    expired_at = datetime.now(UTC) - timedelta(seconds=60)
    session_id = create_session(
        session_factory,
        user_id,
        **{expiry_field: expired_at},
    )
    token = _token(_claims(sub=str(user_id), sid=str(session_id)))

    response = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    _assert_unauthorized(response)


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["inactive", "unverified", "deleted"])
async def test_unusable_users_are_generic_401(
    client,
    session_factory: sessionmaker[Session],
    state: str,
) -> None:
    user_id = create_user(
        session_factory,
        email=f"{state}-user@example.com",
        is_email_verified=True,
    )
    tokens = await login_tokens(client, email=f"{state}-user@example.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    with session_factory() as session:
        user = session.get(User, user_id)
        assert user is not None
        if state == "inactive":
            user.is_active = False
        elif state == "unverified":
            user.is_email_verified = False
        else:
            session.delete(user)
        session.commit()

    response = await client.get(ME_URL, headers=headers)

    _assert_unauthorized(response)


@pytest.mark.anyio
async def test_all_client_failures_share_the_same_response(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="distinct@example.com",
        is_email_verified=True,
    )
    session_id = create_session(session_factory, user_id)

    unknown_session_token = _token(_claims(sub=str(user_id), sid=str(uuid.uuid4())))
    mismatched_subject_token = _token(_claims(sub=str(uuid.uuid4()), sid=str(session_id)))

    responses = [
        await client.get(ME_URL),
        await client.get(
            ME_URL,
            headers={"Authorization": "Basic abc"},
        ),
        await client.get(
            ME_URL,
            headers={"Authorization": "Bearer malformed"},
        ),
        await client.get(
            ME_URL,
            headers={"Authorization": f"Bearer {unknown_session_token}"},
        ),
        await client.get(
            ME_URL,
            headers={"Authorization": f"Bearer {mismatched_subject_token}"},
        ),
    ]

    for response in responses:
        _assert_unauthorized(response)


@pytest.mark.anyio
async def test_role_names_come_from_database_not_jwt(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="db-roles@example.com",
        is_email_verified=True,
    )
    assign_role(session_factory, user_id, RoleName.ADMIN)
    tokens = await login_tokens(client, email="db-roles@example.com")

    decoded = jwt.decode(
        tokens["access_token"],
        _secret(),
        algorithms=["HS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    assert "roles" not in decoded
    assert "permissions" not in decoded

    response = await client.get(
        ME_URL,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    assert response.json()["roles"] == [RoleName.ADMIN.value]

    with session_factory() as session:
        role_names = set(session.scalars(select(Role.name)).all())
    assert RoleName.ADMIN.value in role_names


@pytest.mark.anyio
async def test_session_rows_are_not_mutated_by_me(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="immutable-session@example.com",
        is_email_verified=True,
    )
    tokens = await login_tokens(client, email="immutable-session@example.com")

    with session_factory() as session:
        before = session.get(UserSession, uuid.UUID(tokens["session_id"]))
        assert before is not None
        snapshot = (
            before.id,
            before.user_id,
            before.absolute_expires_at,
            before.idle_expires_at,
            before.revoked_at,
            before.last_refreshed_at,
        )
        assert before.user_id == user_id

    response = await client.get(
        ME_URL,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 200

    with session_factory() as session:
        after = session.get(UserSession, uuid.UUID(tokens["session_id"]))
        assert after is not None
        assert (
            after.id,
            after.user_id,
            after.absolute_expires_at,
            after.idle_expires_at,
            after.revoked_at,
            after.last_refreshed_at,
        ) == snapshot
