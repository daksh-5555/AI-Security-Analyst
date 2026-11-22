"""Current-session logout and refresh/logout race tests."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest
from auth_helpers import DEFAULT_PASSWORD, create_user
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import hash_opaque_token
from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason
from app.services import authentication, refresh_tokens, sessions
from app.services.refresh_tokens import InvalidRefreshTokenError

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

LOGIN_URL = "/api/v1/auth/login"
LOGOUT_URL = "/api/v1/auth/logout"
REFRESH_URL = "/api/v1/auth/refresh"
ME_URL = "/api/v1/auth/me"
GENERIC_ACCESS_DETAIL = "Invalid or expired access token"
GENERIC_REFRESH_DETAIL = "Invalid or expired refresh token"
INTERNAL_DETAIL = "Internal Server Error"


async def login(client, email: str = "logout@example.com") -> dict:
    response = await client.post(
        LOGIN_URL,
        json={"email": email, "password": DEFAULT_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _stored_session(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
) -> UserSession | None:
    with session_factory() as session:
        return session.get(UserSession, session_id)


def _stored_tokens(
    session_factory: sessionmaker[Session],
    session_id: uuid.UUID,
) -> list[RefreshToken]:
    with session_factory() as session:
        return list(
            session.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all()
        )


def _active_tokens(tokens: list[RefreshToken]) -> list[RefreshToken]:
    return [token for token in tokens if token.consumed_at is None and token.revoked_at is None]


def _assert_access_rejected(response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_ACCESS_DETAIL}
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def _assert_refresh_rejected(response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_REFRESH_DETAIL}


@pytest.mark.anyio
async def test_logout_revokes_current_session_and_all_active_refresh_tokens(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    tokens = await login(client)
    session_id = uuid.UUID(tokens["session_id"])

    response = await client.post(LOGOUT_URL, headers=_auth(tokens["access_token"]))

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert tokens["refresh_token"] not in response.text
    assert hash_opaque_token(tokens["refresh_token"]) not in response.text

    stored_session = _stored_session(session_factory, session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.LOGOUT

    stored_tokens = _stored_tokens(session_factory, session_id)
    assert len(stored_tokens) == 1
    assert stored_tokens[0].revoked_at is not None
    assert stored_tokens[0].consumed_at is None
    assert stored_tokens[0].replaced_by_id is None
    assert _active_tokens(stored_tokens) == []

    _assert_access_rejected(await client.get(ME_URL, headers=_auth(tokens["access_token"])))
    _assert_refresh_rejected(
        await client.post(REFRESH_URL, json={"refresh_token": tokens["refresh_token"]})
    )


@pytest.mark.anyio
async def test_logout_preserves_other_sessions_of_the_same_user(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    first = await login(client)
    second = await login(client)
    first_sid = uuid.UUID(first["session_id"])
    second_sid = uuid.UUID(second["session_id"])
    assert first_sid != second_sid

    response = await client.post(LOGOUT_URL, headers=_auth(first["access_token"]))
    assert response.status_code == 204

    first_session = _stored_session(session_factory, first_sid)
    second_session = _stored_session(session_factory, second_sid)
    assert first_session is not None and first_session.revoked_at is not None
    assert second_session is not None
    assert second_session.user_id == user_id
    assert second_session.revoked_at is None
    assert all(token.revoked_at is not None for token in _stored_tokens(session_factory, first_sid))
    second_tokens = _stored_tokens(session_factory, second_sid)
    assert len(_active_tokens(second_tokens)) == 1

    me = await client.get(ME_URL, headers=_auth(second["access_token"]))
    assert me.status_code == 200
    assert me.json()["id"] == str(user_id)

    rotated = await client.post(
        REFRESH_URL,
        json={"refresh_token": second["refresh_token"]},
    )
    assert rotated.status_code == 200
    assert uuid.UUID(rotated.json()["session_id"]) == second_sid


@pytest.mark.anyio
async def test_logout_revokes_only_the_authenticated_users_session(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_a = create_user(session_factory, email="a@example.com", is_email_verified=True)
    user_b = create_user(session_factory, email="b@example.com", is_email_verified=True)
    tokens_a = await login(client, "a@example.com")
    tokens_b = await login(client, "b@example.com")
    sid_a = uuid.UUID(tokens_a["session_id"])
    sid_b = uuid.UUID(tokens_b["session_id"])

    # Logging out B cannot select A's session: only B's verified sid is used.
    response = await client.post(LOGOUT_URL, headers=_auth(tokens_b["access_token"]))
    assert response.status_code == 204

    session_a = _stored_session(session_factory, sid_a)
    session_b = _stored_session(session_factory, sid_b)
    assert session_a is not None and session_a.user_id == user_a
    assert session_a.revoked_at is None
    assert session_b is not None and session_b.user_id == user_b
    assert session_b.revoked_at is not None
    assert session_b.revocation_reason is SessionRevocationReason.LOGOUT
    assert len(_active_tokens(_stored_tokens(session_factory, sid_a))) == 1
    assert _active_tokens(_stored_tokens(session_factory, sid_b)) == []

    me_a = await client.get(ME_URL, headers=_auth(tokens_a["access_token"]))
    assert me_a.status_code == 200
    refresh_a = await client.post(
        REFRESH_URL,
        json={"refresh_token": tokens_a["refresh_token"]},
    )
    assert refresh_a.status_code == 200

    _assert_access_rejected(await client.get(ME_URL, headers=_auth(tokens_b["access_token"])))


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
async def test_unauthenticated_logout_is_rejected(
    client,
    session_factory: sessionmaker[Session],
    headers: dict[str, str],
) -> None:
    create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    tokens = await login(client)
    session_id = uuid.UUID(tokens["session_id"])

    response = await client.post(LOGOUT_URL, headers=headers)

    _assert_access_rejected(response)

    stored_session = _stored_session(session_factory, session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is None
    assert len(_active_tokens(_stored_tokens(session_factory, session_id))) == 1


@pytest.mark.anyio
async def test_repeated_logout_returns_generic_401(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    tokens = await login(client)

    first = await client.post(LOGOUT_URL, headers=_auth(tokens["access_token"]))
    second = await client.post(LOGOUT_URL, headers=_auth(tokens["access_token"]))

    assert first.status_code == 204
    _assert_access_rejected(second)
    assert second.headers["Cache-Control"] == "no-store"


@pytest.mark.anyio
async def test_logout_revokes_rotated_family_and_preserves_history(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    session_id = uuid.UUID(original["session_id"])

    rotated = await client.post(
        REFRESH_URL,
        json={"refresh_token": original["refresh_token"]},
    )
    assert rotated.status_code == 200
    replacement = rotated.json()
    assert uuid.UUID(replacement["session_id"]) == session_id

    response = await client.post(LOGOUT_URL, headers=_auth(replacement["access_token"]))
    assert response.status_code == 204

    stored_session = _stored_session(session_factory, session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.LOGOUT

    tokens = _stored_tokens(session_factory, session_id)
    assert len(tokens) == 2
    old = next(
        token
        for token in tokens
        if token.token_hash == hash_opaque_token(original["refresh_token"])
    )
    new = next(
        token
        for token in tokens
        if token.token_hash == hash_opaque_token(replacement["refresh_token"])
    )
    assert old.consumed_at is not None
    assert old.replaced_by_id == new.id
    assert old.revoked_at is not None
    assert new.consumed_at is None
    assert new.revoked_at is not None
    assert _active_tokens(tokens) == []

    for access_token in (original["access_token"], replacement["access_token"]):
        _assert_access_rejected(await client.get(ME_URL, headers=_auth(access_token)))
    _assert_refresh_rejected(
        await client.post(
            REFRESH_URL,
            json={"refresh_token": replacement["refresh_token"]},
        )
    )


@pytest.mark.anyio
async def test_logout_persistence_failure_rolls_back_session_and_tokens(
    client,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    tokens = await login(client)
    session_id = uuid.UUID(tokens["session_id"])

    def fail_after_partial_update(
        db: Session,
        *,
        session_id: uuid.UUID,
        reason: SessionRevocationReason,
        now: datetime,
    ) -> None:
        db.execute(
            update(UserSession)
            .where(UserSession.id == session_id)
            .values(revoked_at=now, revocation_reason=reason)
        )
        db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id == session_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        raise SQLAlchemyError("simulated persistence failure")

    monkeypatch.setattr(sessions, "revoke_session_family", fail_after_partial_update)

    response = await client.post(LOGOUT_URL, headers=_auth(tokens["access_token"]))

    assert response.status_code == 500
    assert response.json() == {"detail": INTERNAL_DETAIL}

    stored_session = _stored_session(session_factory, session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is None
    assert stored_session.revocation_reason is None
    stored_tokens = _stored_tokens(session_factory, session_id)
    assert len(stored_tokens) == 1
    assert stored_tokens[0].revoked_at is None
    assert len(_active_tokens(stored_tokens)) == 1

    # The access token still works, proving the failed mutation was rolled back.
    me = await client.get(ME_URL, headers=_auth(tokens["access_token"]))
    assert me.status_code == 200


def test_refresh_racing_logout_cannot_leave_a_usable_token(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="logout@example.com",
        is_email_verified=True,
    )
    with session_factory() as db:
        issued = authentication.login(
            db,
            email="logout@example.com",
            password=DEFAULT_PASSWORD,
        )

    barrier = threading.Barrier(2)

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

    def attempt_logout() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                sessions.revoke_session(db, session_id=issued.session_id)
                return "success", None
            except Exception as exc:
                return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(attempt_refresh), pool.submit(attempt_logout))
        outcomes = [future.result(timeout=30) for future in futures]

    refresh_outcome, logout_outcome = outcomes
    assert logout_outcome[0] == "success", logout_outcome[1]
    if refresh_outcome[0] == "error":
        assert isinstance(refresh_outcome[1], InvalidRefreshTokenError)

    stored_session = _stored_session(session_factory, issued.session_id)
    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.LOGOUT

    tokens = _stored_tokens(session_factory, issued.session_id)
    assert _active_tokens(tokens) == []
    assert all(token.revoked_at is not None for token in tokens)
