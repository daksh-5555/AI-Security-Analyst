import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from auth_helpers import (
    DEFAULT_PASSWORD,
    assert_validation_errors_hide_input,
    create_user,
    expire_tokens,
    extract_action_token,
    get_user,
    tokens_for,
)
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import (
    generate_opaque_token,
    hash_opaque_token,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_action_token import UserActionToken
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason, UserActionTokenPurpose
from app.services import authentication, identity, refresh_tokens, sessions
from app.services.refresh_tokens import InvalidRefreshTokenError

pytestmark = pytest.mark.usefixtures("low_cost_argon2")

REGISTER_URL = "/api/v1/auth/register"
VERIFY_URL = "/api/v1/auth/verify-email"
LOGIN_URL = "/api/v1/auth/login"
ME_URL = "/api/v1/auth/me"
REFRESH_URL = "/api/v1/auth/refresh"
LOGOUT_URL = "/api/v1/auth/logout"
RESET_REQUEST_URL = "/api/v1/auth/password-reset/request"
RESET_CONFIRM_URL = "/api/v1/auth/password-reset/confirm"
GENERIC_MESSAGE = "If an account exists for that address, a password reset email has been sent."
NEW_PASSWORD = "a completely new passphrase"


async def request_reset(client, email: str):
    return await client.post(RESET_REQUEST_URL, json={"email": email})


async def confirm_reset(client, token: str, new_password: str = NEW_PASSWORD):
    return await client.post(
        RESET_CONFIRM_URL,
        json={"token": token, "new_password": new_password},
    )


def create_session(
    session_factory: sessionmaker[Session],
    user_id: uuid.UUID,
    *,
    revoked_at: datetime | None = None,
    revocation_reason: SessionRevocationReason | None = None,
) -> uuid.UUID:
    now = datetime.now(UTC)
    with session_factory() as session:
        user_session = UserSession(
            user_id=user_id,
            created_at=now,
            last_refreshed_at=now,
            absolute_expires_at=now + timedelta(days=30),
            idle_expires_at=now + timedelta(days=14),
            revoked_at=revoked_at,
            revocation_reason=revocation_reason,
        )
        session.add(user_session)
        session.commit()
        return user_session.id


def create_refresh_token(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
    *,
    consumed_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> uuid.UUID:
    now = datetime.now(UTC)
    with session_factory() as session:
        refresh_token = RefreshToken(
            session_id=session_id,
            token_hash=hash_opaque_token(generate_opaque_token("refresh")),
            created_at=now,
            expires_at=now + timedelta(days=14),
            consumed_at=consumed_at,
            revoked_at=revoked_at,
        )
        session.add(refresh_token)
        session.commit()
        return refresh_token.id


def get_session(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
) -> UserSession | None:
    with session_factory() as session:
        return session.get(UserSession, session_id)


def get_refresh_token(
    session_factory: sessionmaker[Session],
    token_id: uuid.UUID,
) -> RefreshToken | None:
    with session_factory() as session:
        return session.get(RefreshToken, token_id)


def get_refresh_token_by_hash(
    session_factory: sessionmaker[Session],
    raw_token: str,
) -> RefreshToken | None:
    with session_factory() as session:
        return session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw_token))
        )


def tokens_for_session(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
) -> list[RefreshToken]:
    with session_factory() as session:
        return list(
            session.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all()
        )


async def login_tokens(client, email: str, password: str = DEFAULT_PASSWORD) -> dict:
    response = await client.post(LOGIN_URL, json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()


def issue_reset_token_service(
    session_factory: sessionmaker[Session],
    email: str,
) -> str:
    with session_factory() as db:
        issued = identity.request_password_reset(db, email=email)
    assert issued is not None
    return issued[0]


def login_service(
    session_factory: sessionmaker[Session],
    email: str,
) -> authentication.LoginResult:
    with session_factory() as db:
        return authentication.login(db, email=email, password=DEFAULT_PASSWORD)


@pytest.mark.anyio
async def test_request_for_existing_user_sends_one_reset_email(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="reset@example.com")

    response = await request_reset(auth_client, "reset@example.com")

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert response.headers["Cache-Control"] == "no-store"
    assert len(mailer.messages) == 1
    message = mailer.messages[0]
    assert message.to == "reset@example.com"
    assert "Reset your password" in message.subject

    raw_token = extract_action_token(message.body)
    assert raw_token.startswith("reset_")

    tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(tokens) == 1
    assert tokens[0].consumed_at is None
    assert tokens[0].token_hash == hash_opaque_token(raw_token)
    assert raw_token not in tokens[0].token_hash

    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False


@pytest.mark.anyio
@pytest.mark.parametrize(
    "email",
    [
        "unknown@example.com",
        "not-an-address",
        "missing-domain@",
    ],
)
async def test_unknown_or_malformed_request_is_indistinguishable(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    email: str,
) -> None:
    response = await request_reset(auth_client, email)

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert mailer.messages == []
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(UserActionToken)) == 0


@pytest.mark.anyio
async def test_inactive_user_request_is_indistinguishable(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="inactive@example.com",
        is_active=False,
    )

    response = await request_reset(auth_client, "inactive@example.com")

    assert response.status_code == 202
    assert response.json() == {"message": GENERIC_MESSAGE}
    assert mailer.messages == []
    assert tokens_for(session_factory, user_id) == []


@pytest.mark.anyio
async def test_repeated_requests_invalidate_the_previous_token(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 0)
    user_id = create_user(session_factory, email="repeat@example.com")

    first = await request_reset(auth_client, "repeat@example.com")
    second = await request_reset(auth_client, "repeat@example.com")

    assert first.status_code == 202
    assert second.status_code == 202
    assert len(mailer.messages) == 2
    first_token = extract_action_token(mailer.messages[0].body)
    second_token = extract_action_token(mailer.messages[1].body)
    assert first_token != second_token

    tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(tokens) == 2
    assert sum(token.consumed_at is not None for token in tokens) == 1

    stale_response = await confirm_reset(auth_client, first_token)
    assert stale_response.status_code == 400

    fresh_response = await confirm_reset(auth_client, second_token)
    assert fresh_response.status_code == 204


@pytest.mark.anyio
async def test_cooldown_suppresses_repeated_email(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 3600)
    user_id = create_user(session_factory, email="cooldown@example.com")

    first = await request_reset(auth_client, "cooldown@example.com")
    second = await request_reset(auth_client, "cooldown@example.com")

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json() == second.json()
    assert len(mailer.messages) == 1
    assert len(tokens_for(session_factory, user_id)) == 1


@pytest.mark.anyio
async def test_confirmation_updates_password_and_consumes_token(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="confirm@example.com")
    await request_reset(auth_client, "confirm@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    before = get_user(session_factory, user_id)
    assert before is not None
    before_updated_at = before.updated_at

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    assert response.content == b""
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(NEW_PASSWORD, user.password_hash) is True
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is False
    assert user.updated_at > before_updated_at
    assert user.is_email_verified is False

    tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(tokens) == 1
    assert tokens[0].consumed_at is not None


@pytest.mark.anyio
async def test_reset_preserves_email_verification_state(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="verified@example.com",
        is_email_verified=True,
    )
    await request_reset(auth_client, "verified@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is True


@pytest.mark.anyio
async def test_reset_token_is_single_use(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="replay@example.com")
    await request_reset(auth_client, "replay@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    first = await confirm_reset(auth_client, token)
    second = await confirm_reset(auth_client, token, "another new passphrase")

    assert first.status_code == 204
    assert second.status_code == 400
    assert second.json() == {"detail": "Invalid or expired token"}
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(NEW_PASSWORD, user.password_hash) is True


@pytest.mark.anyio
async def test_expired_reset_token_is_rejected(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="expired@example.com")
    await request_reset(auth_client, "expired@example.com")
    token = extract_action_token(mailer.messages[-1].body)
    expire_tokens(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True
    assert tokens_for(session_factory, user_id)[0].consumed_at is None


@pytest.mark.anyio
async def test_verification_token_cannot_reset_password(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    register_response = await auth_client.post(
        REGISTER_URL,
        json={"email": "cross@example.com", "password": DEFAULT_PASSWORD},
    )
    assert register_response.status_code == 202
    verification_token = extract_action_token(mailer.messages[-1].body)
    with session_factory() as session:
        user_id = session.scalar(select(User.id))
    assert user_id is not None

    response = await confirm_reset(auth_client, verification_token)

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True
    assert user.is_email_verified is False


@pytest.mark.anyio
async def test_reset_token_cannot_verify_email(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="cross2@example.com")
    await request_reset(auth_client, "cross2@example.com")
    reset_token = extract_action_token(mailer.messages[-1].body)

    response = await auth_client.post(VERIFY_URL, json={"token": reset_token})

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None and user.is_email_verified is False


@pytest.mark.anyio
@pytest.mark.parametrize(
    "token",
    ["reset_" + "C" * 64, "not-a-token", "", "verify_" + "C" * 64],
)
async def test_unknown_or_malformed_reset_token_is_rejected(
    auth_client,
    session_factory: sessionmaker[Session],
    token: str,
) -> None:
    response = await confirm_reset(auth_client, token)

    assert response.status_code in {400, 422}
    assert_validation_errors_hide_input(response)


@pytest.mark.anyio
async def test_password_policy_failure_keeps_token_usable(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="policy@example.com")
    await request_reset(auth_client, "policy@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token, "too-short")

    assert response.status_code == 422
    assert "too-short" not in response.text
    assert_validation_errors_hide_input(response)
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True
    assert tokens_for(session_factory, user_id)[0].consumed_at is None


@pytest.mark.anyio
async def test_confirmation_extra_fields_are_forbidden_and_hidden(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="extra@example.com")
    await request_reset(auth_client, "extra@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await auth_client.post(
        RESET_CONFIRM_URL,
        json={"token": token, "new_password": NEW_PASSWORD, "role": "Admin"},
    )

    assert response.status_code == 422
    assert token not in response.text
    assert NEW_PASSWORD not in response.text
    assert_validation_errors_hide_input(response)
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True


@pytest.mark.anyio
async def test_inactive_user_cannot_confirm_reset(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="inactive-reset@example.com")
    await request_reset(auth_client, "inactive-reset@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    with session_factory() as session:
        user = session.get(User, user_id)
        assert user is not None
        user.is_active = False
        session.commit()

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 400
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True


@pytest.mark.anyio
async def test_confirmation_invalidates_all_outstanding_reset_tokens(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_token_request_cooldown_seconds", 0)
    user_id = create_user(session_factory, email="invalidate@example.com")

    await request_reset(auth_client, "invalidate@example.com")
    await request_reset(auth_client, "invalidate@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(tokens) == 2
    assert all(token.consumed_at is not None for token in tokens)


@pytest.mark.anyio
async def test_reset_revokes_every_active_session(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="sessions@example.com")
    session_ids = [
        create_session(session_factory, user_id),
        create_session(session_factory, user_id),
    ]
    await request_reset(auth_client, "sessions@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    for session_id in session_ids:
        user_session = get_session(session_factory, session_id)
        assert user_session is not None
        assert user_session.revoked_at is not None
        assert user_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET

    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(NEW_PASSWORD, user.password_hash) is True
    reset_tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(reset_tokens) == 1
    assert reset_tokens[0].consumed_at is not None


@pytest.mark.anyio
async def test_reset_revokes_active_refresh_tokens_for_sessions(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="refresh@example.com")
    session_ids = [
        create_session(session_factory, user_id),
        create_session(session_factory, user_id),
    ]
    token_ids = [create_refresh_token(session_factory, session_id) for session_id in session_ids]
    await request_reset(auth_client, "refresh@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    for token_id in token_ids:
        refresh_token = get_refresh_token(session_factory, token_id)
        assert refresh_token is not None
        assert refresh_token.revoked_at is not None
        assert refresh_token.consumed_at is None


@pytest.mark.anyio
async def test_reset_leaves_other_users_sessions_and_tokens_unchanged(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="owner@example.com")
    other_user_id = create_user(session_factory, email="other@example.com")
    own_session_id = create_session(session_factory, user_id)
    other_session_id = create_session(session_factory, other_user_id)
    own_token_id = create_refresh_token(session_factory, own_session_id)
    other_token_id = create_refresh_token(session_factory, other_session_id)
    await request_reset(auth_client, "owner@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    own_session = get_session(session_factory, own_session_id)
    assert own_session is not None
    assert own_session.revoked_at is not None
    own_token = get_refresh_token(session_factory, own_token_id)
    assert own_token is not None
    assert own_token.revoked_at is not None

    other_session = get_session(session_factory, other_session_id)
    assert other_session is not None
    assert other_session.revoked_at is None
    assert other_session.revocation_reason is None
    other_token = get_refresh_token(session_factory, other_token_id)
    assert other_token is not None
    assert other_token.revoked_at is None
    assert other_token.consumed_at is None


@pytest.mark.anyio
async def test_reset_preserves_already_revoked_session_state(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="revoked-session@example.com")
    revoked_at = datetime.now(UTC) - timedelta(days=1)
    session_id = create_session(
        session_factory,
        user_id,
        revoked_at=revoked_at,
        revocation_reason=SessionRevocationReason.LOGOUT,
    )
    await request_reset(auth_client, "revoked-session@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    user_session = get_session(session_factory, session_id)
    assert user_session is not None
    assert user_session.revoked_at == revoked_at
    assert user_session.revocation_reason is SessionRevocationReason.LOGOUT


@pytest.mark.anyio
async def test_reset_preserves_consumed_and_revoked_refresh_token_state(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="inactive-tokens@example.com")
    session_id = create_session(session_factory, user_id)
    consumed_at = datetime.now(UTC) - timedelta(hours=1)
    revoked_at = datetime.now(UTC) - timedelta(hours=2)
    consumed_token_id = create_refresh_token(
        session_factory,
        session_id,
        consumed_at=consumed_at,
    )
    revoked_token_id = create_refresh_token(
        session_factory,
        session_id,
        revoked_at=revoked_at,
    )
    await request_reset(auth_client, "inactive-tokens@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    consumed_token = get_refresh_token(session_factory, consumed_token_id)
    assert consumed_token is not None
    assert consumed_token.consumed_at == consumed_at
    assert consumed_token.revoked_at is None

    revoked_token = get_refresh_token(session_factory, revoked_token_id)
    assert revoked_token is not None
    assert revoked_token.consumed_at is None
    assert revoked_token.revoked_at == revoked_at


@pytest.mark.anyio
async def test_reset_succeeds_when_user_has_no_sessions(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(session_factory, email="no-sessions@example.com")
    await request_reset(auth_client, "no-sessions@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    response = await confirm_reset(auth_client, token)

    assert response.status_code == 204
    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(NEW_PASSWORD, user.password_hash) is True
    reset_tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(reset_tokens) == 1
    assert reset_tokens[0].consumed_at is not None


@pytest.mark.anyio
async def test_commit_failure_rolls_back_password_tokens_and_revocations(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(session_factory, email="rollback@example.com")
    session_id = create_session(session_factory, user_id)
    refresh_token_id = create_refresh_token(session_factory, session_id)
    await request_reset(auth_client, "rollback@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    def fail_commit(_self: Session) -> None:
        raise IntegrityError("UPDATE", {}, RuntimeError("simulated commit failure"))

    monkeypatch.setattr(Session, "commit", fail_commit)
    response = await confirm_reset(auth_client, token)
    monkeypatch.undo()

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired token"}

    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True
    assert verify_password(NEW_PASSWORD, user.password_hash) is False

    reset_tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(reset_tokens) == 1
    assert reset_tokens[0].consumed_at is None

    user_session = get_session(session_factory, session_id)
    assert user_session is not None
    assert user_session.revoked_at is None
    assert user_session.revocation_reason is None

    refresh_token = get_refresh_token(session_factory, refresh_token_id)
    assert refresh_token is not None
    assert refresh_token.revoked_at is None
    assert refresh_token.consumed_at is None


@pytest.mark.anyio
@pytest.mark.usefixtures("configure_jwt")
async def test_reset_invalidates_access_and_refresh_tokens_for_every_session(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="reauth@example.com",
        is_email_verified=True,
    )
    other_user_id = create_user(
        session_factory,
        email="other-auth@example.com",
        is_email_verified=True,
    )
    first = await login_tokens(auth_client, "reauth@example.com")
    second = await login_tokens(auth_client, "reauth@example.com")
    other = await login_tokens(auth_client, "other-auth@example.com")
    assert user_id != other_user_id

    await request_reset(auth_client, "reauth@example.com")
    token = extract_action_token(mailer.messages[-1].body)
    response = await confirm_reset(auth_client, token)
    assert response.status_code == 204

    for issued in (first, second):
        session_id = uuid.UUID(issued["session_id"])
        stored_session = get_session(session_factory, session_id)
        assert stored_session is not None
        assert stored_session.revoked_at is not None
        assert stored_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET

        stored_token = get_refresh_token_by_hash(session_factory, issued["refresh_token"])
        assert stored_token is not None
        assert stored_token.revoked_at is not None
        assert stored_token.consumed_at is None

        me = await auth_client.get(
            ME_URL,
            headers={"Authorization": f"Bearer {issued['access_token']}"},
        )
        assert me.status_code == 401
        assert me.json() == {"detail": "Invalid or expired access token"}

        refreshed = await auth_client.post(
            REFRESH_URL,
            json={"refresh_token": issued["refresh_token"]},
        )
        assert refreshed.status_code == 401
        assert refreshed.json() == {"detail": "Invalid or expired refresh token"}

    other_me = await auth_client.get(
        ME_URL,
        headers={"Authorization": f"Bearer {other['access_token']}"},
    )
    assert other_me.status_code == 200
    assert other_me.json()["id"] == str(other_user_id)

    old_password = await auth_client.post(
        LOGIN_URL,
        json={"email": "reauth@example.com", "password": DEFAULT_PASSWORD},
    )
    assert old_password.status_code == 401
    new_password = await auth_client.post(
        LOGIN_URL,
        json={"email": "reauth@example.com", "password": NEW_PASSWORD},
    )
    assert new_password.status_code == 200


@pytest.mark.anyio
@pytest.mark.usefixtures("configure_jwt")
async def test_expired_or_invalid_reset_token_does_not_revoke_sessions(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="no-revoke@example.com",
        is_email_verified=True,
    )
    issued = await login_tokens(auth_client, "no-revoke@example.com")
    await request_reset(auth_client, "no-revoke@example.com")
    valid_token = extract_action_token(mailer.messages[-1].body)
    expire_tokens(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )

    expired = await confirm_reset(auth_client, valid_token)
    assert expired.status_code == 400
    unknown = await confirm_reset(auth_client, "reset_" + "D" * 64)
    assert unknown.status_code == 400

    stored_session = get_session(session_factory, uuid.UUID(issued["session_id"]))
    assert stored_session is not None
    assert stored_session.revoked_at is None
    stored_token = get_refresh_token_by_hash(session_factory, issued["refresh_token"])
    assert stored_token is not None
    assert stored_token.revoked_at is None
    assert stored_token.consumed_at is None

    me = await auth_client.get(
        ME_URL,
        headers={"Authorization": f"Bearer {issued['access_token']}"},
    )
    assert me.status_code == 200


@pytest.mark.anyio
@pytest.mark.usefixtures("configure_jwt")
async def test_reset_preserves_consumed_and_replaced_token_history(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="history@example.com",
        is_email_verified=True,
    )
    original = await login_tokens(auth_client, "history@example.com")
    rotated_response = await auth_client.post(
        REFRESH_URL,
        json={"refresh_token": original["refresh_token"]},
    )
    assert rotated_response.status_code == 200
    replacement = rotated_response.json()
    session_id = uuid.UUID(original["session_id"])

    await request_reset(auth_client, "history@example.com")
    token = extract_action_token(mailer.messages[-1].body)
    response = await confirm_reset(auth_client, token)
    assert response.status_code == 204

    old = get_refresh_token_by_hash(session_factory, original["refresh_token"])
    new = get_refresh_token_by_hash(session_factory, replacement["refresh_token"])
    assert old is not None and new is not None
    assert old.consumed_at is not None
    assert old.revoked_at is None
    assert old.replaced_by_id == new.id
    assert new.consumed_at is None
    assert new.revoked_at is not None

    stored_session = get_session(session_factory, session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET


@pytest.mark.anyio
@pytest.mark.usefixtures("configure_jwt")
async def test_reset_persistence_failure_during_revocation_rolls_back_everything(
    auth_client,
    mailer,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = create_user(
        session_factory,
        email="reset-rollback@example.com",
        is_email_verified=True,
    )
    issued = await login_tokens(auth_client, "reset-rollback@example.com")
    session_id = uuid.UUID(issued["session_id"])
    await request_reset(auth_client, "reset-rollback@example.com")
    token = extract_action_token(mailer.messages[-1].body)

    def fail_after_partial_update(
        db: Session,
        *,
        session_id: uuid.UUID,
        reason: SessionRevocationReason,
        now: datetime,
        include_consumed: bool = True,
    ) -> None:
        db.execute(
            update(UserSession)
            .where(UserSession.id == session_id)
            .values(revoked_at=now, revocation_reason=reason)
        )
        raise SQLAlchemyError("simulated persistence failure")

    monkeypatch.setattr(sessions, "revoke_session_family", fail_after_partial_update)

    response = await confirm_reset(auth_client, token)
    monkeypatch.undo()

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal Server Error"}

    user = get_user(session_factory, user_id)
    assert user is not None
    assert verify_password(DEFAULT_PASSWORD, user.password_hash) is True
    assert verify_password(NEW_PASSWORD, user.password_hash) is False

    reset_tokens = tokens_for(
        session_factory,
        user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(reset_tokens) == 1
    assert reset_tokens[0].consumed_at is None

    stored_session = get_session(session_factory, session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is None
    assert stored_session.revocation_reason is None

    stored_token = get_refresh_token_by_hash(session_factory, issued["refresh_token"])
    assert stored_token is not None
    assert stored_token.revoked_at is None
    assert stored_token.consumed_at is None


@pytest.mark.usefixtures("configure_jwt")
def test_concurrent_password_reset_and_refresh_leave_no_active_tokens(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="race-refresh@example.com",
        is_email_verified=True,
    )
    issued = login_service(session_factory, "race-refresh@example.com")
    raw_reset = issue_reset_token_service(session_factory, "race-refresh@example.com")
    barrier = threading.Barrier(2)

    def attempt_reset() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                identity.confirm_password_reset(
                    db,
                    token=raw_reset,
                    new_password=NEW_PASSWORD,
                )
                return "success", None
            except Exception as exc:
                return "error", exc

    def attempt_refresh() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                return "success", refresh_tokens.rotate(
                    db,
                    presented_token=issued.refresh_token,
                )
            except Exception as exc:
                return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(attempt_reset), pool.submit(attempt_refresh))
        outcomes = [future.result(timeout=30) for future in futures]

    reset_outcome, refresh_outcome = outcomes
    assert reset_outcome[0] == "success", reset_outcome[1]
    if refresh_outcome[0] == "error":
        assert isinstance(refresh_outcome[1], InvalidRefreshTokenError)

    stored_session = get_session(session_factory, issued.session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET

    tokens = tokens_for_session(session_factory, issued.session_id)
    assert all(token.revoked_at is not None for token in tokens if token.consumed_at is None)
    assert [
        token for token in tokens if token.consumed_at is None and token.revoked_at is None
    ] == []

    user = get_user(session_factory, issued.user_id)
    assert user is not None
    assert verify_password(NEW_PASSWORD, user.password_hash) is True


@pytest.mark.usefixtures("configure_jwt")
def test_concurrent_password_reset_and_logout_complete_safely(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="race-logout@example.com",
        is_email_verified=True,
    )
    issued = login_service(session_factory, "race-logout@example.com")
    raw_reset = issue_reset_token_service(session_factory, "race-logout@example.com")
    barrier = threading.Barrier(2)

    def attempt_reset() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                identity.confirm_password_reset(
                    db,
                    token=raw_reset,
                    new_password=NEW_PASSWORD,
                )
                return "success", None
            except Exception as exc:
                return "error", exc

    def attempt_logout() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                sessions.revoke_session(db, session_id=issued.session_id)
                return "success", None
            except Exception as exc:
                return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(attempt_reset), pool.submit(attempt_logout))
        outcomes = [future.result(timeout=30) for future in futures]

    for outcome in outcomes:
        assert outcome[0] == "success", outcome[1]

    stored_session = get_session(session_factory, issued.session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason in {
        SessionRevocationReason.PASSWORD_RESET,
        SessionRevocationReason.LOGOUT,
    }
    tokens = tokens_for_session(session_factory, issued.session_id)
    assert [
        token for token in tokens if token.consumed_at is None and token.revoked_at is None
    ] == []

    user = get_user(session_factory, issued.user_id)
    assert user is not None
    assert verify_password(NEW_PASSWORD, user.password_hash) is True


@pytest.mark.usefixtures("configure_jwt")
def test_concurrent_password_reset_attempts_only_one_succeeds(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="race-reset@example.com",
        is_email_verified=True,
    )
    issued = login_service(session_factory, "race-reset@example.com")
    raw_reset = issue_reset_token_service(session_factory, "race-reset@example.com")
    passwords = ("first replacement passphrase", "second replacement passphrase")
    barrier = threading.Barrier(2)

    def attempt_reset(password: str) -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                identity.confirm_password_reset(
                    db,
                    token=raw_reset,
                    new_password=password,
                )
                return "success", password
            except Exception as exc:
                return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (
            pool.submit(attempt_reset, passwords[0]),
            pool.submit(attempt_reset, passwords[1]),
        )
        outcomes = [future.result(timeout=30) for future in futures]

    successes = [payload for status, payload in outcomes if status == "success"]
    failures = [payload for status, payload in outcomes if status == "error"]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], identity.InvalidIdentityTokenError)

    user = get_user(session_factory, issued.user_id)
    assert user is not None
    assert verify_password(successes[0], user.password_hash) is True

    stored_session = get_session(session_factory, issued.session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.PASSWORD_RESET

    reset_tokens = tokens_for(
        session_factory,
        issued.user_id,
        purpose=UserActionTokenPurpose.PASSWORD_RESET,
    )
    assert len(reset_tokens) == 1
    assert reset_tokens[0].consumed_at is not None
