"""Refresh-token rotation, reuse detection, and session-family revocation tests."""

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from auth_helpers import DEFAULT_PASSWORD, create_user
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import (
    decode_access_token,
    generate_opaque_token,
    hash_opaque_token,
)
from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession
from app.schemas.enums import SessionRevocationReason
from app.services import authentication, refresh_tokens
from app.services.refresh_tokens import (
    InvalidRefreshTokenError,
    RefreshTokenReuseError,
)

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
ME_URL = "/api/v1/auth/me"
GENERIC_REFRESH_DETAIL = "Invalid or expired refresh token"
GENERIC_ACCESS_DETAIL = "Invalid or expired access token"


async def login(client, email: str = "refresh@example.com") -> dict:
    response = await client.post(
        LOGIN_URL,
        json={"email": email, "password": DEFAULT_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()


async def refresh(client, raw_token: str):
    return await client.post(REFRESH_URL, json={"refresh_token": raw_token})


def _assert_refresh_rejected(response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_REFRESH_DETAIL}


def _assert_access_rejected(response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_ACCESS_DETAIL}
    assert response.headers.get("WWW-Authenticate") == "Bearer"


@pytest.mark.anyio
async def test_successful_refresh_rotates_tokens_and_keeps_session_family(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    original_sid = uuid.UUID(original["session_id"])
    original_claims = decode_access_token(original["access_token"])

    with session_factory() as session:
        before = session.get(UserSession, original_sid)
        assert before is not None
        before_snapshot = {
            "created_at": before.created_at,
            "last_refreshed_at": before.last_refreshed_at,
            "idle_expires_at": before.idle_expires_at,
            "absolute_expires_at": before.absolute_expires_at,
        }

    response = await refresh(client, original["refresh_token"])

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
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
    assert body["refresh_token"] != original["refresh_token"]
    assert body["refresh_token"].startswith("refresh_")
    assert uuid.UUID(body["session_id"]) == original_sid

    claims = decode_access_token(body["access_token"])
    assert claims.sub == user_id
    assert claims.sid == original_sid
    assert claims.sid == original_claims.sid
    assert claims.typ == "access"

    with session_factory() as session:
        sessions = list(session.scalars(select(UserSession)).all())
        tokens = list(session.scalars(select(RefreshToken)).all())
        stored_session = session.get(UserSession, original_sid)
        old = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(original["refresh_token"])
            )
        )
        new = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(body["refresh_token"])
            )
        )

        assert len(sessions) == 1
        assert len(tokens) == 2
        assert stored_session is not None
        assert old is not None
        assert new is not None
        assert old.id != new.id
        assert old.consumed_at is not None
        assert old.revoked_at is None
        assert old.replaced_by_id == new.id
        assert new.consumed_at is None
        assert new.revoked_at is None
        assert new.replaced_by_id is None
        assert new.expires_at == stored_session.idle_expires_at
        assert stored_session.created_at == before_snapshot["created_at"]
        assert stored_session.absolute_expires_at == before_snapshot["absolute_expires_at"]
        assert stored_session.idle_expires_at > before_snapshot["idle_expires_at"]
        assert stored_session.last_refreshed_at >= before_snapshot["last_refreshed_at"]
        assert stored_session.revoked_at is None

    assert "token_hash" not in response.text
    assert hash_opaque_token(body["refresh_token"]) not in response.text


@pytest.mark.anyio
async def test_consumed_refresh_token_cannot_be_used_again(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    rotated = await refresh(client, original["refresh_token"])
    assert rotated.status_code == 200

    replay = await refresh(client, original["refresh_token"])
    _assert_refresh_rejected(replay)

    # Replay revokes the family, so the replacement token is no longer usable.
    replacement_attempt = await refresh(client, rotated.json()["refresh_token"])
    _assert_refresh_rejected(replacement_attempt)

    session_id = uuid.UUID(original["session_id"])
    with session_factory() as session:
        stored_session = session.get(UserSession, session_id)
        tokens = list(
            session.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all()
        )

    assert stored_session is not None
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.REFRESH_REUSE
    assert len(tokens) == 2
    assert all(token.revoked_at is not None for token in tokens)
    old = next(
        token
        for token in tokens
        if token.token_hash == hash_opaque_token(original["refresh_token"])
    )
    assert old.consumed_at is not None
    assert old.replaced_by_id is not None


@pytest.mark.anyio
async def test_unknown_or_malformed_token_is_rejected_without_revoking_session(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    session_id = uuid.UUID(original["session_id"])

    for candidate in (generate_opaque_token("refresh"), "not-a-refresh-token"):
        _assert_refresh_rejected(await refresh(client, candidate))

    with session_factory() as session:
        stored_session = session.get(UserSession, session_id)
        original_row = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(original["refresh_token"])
            )
        )

    assert stored_session is not None
    assert stored_session.revoked_at is None
    assert original_row is not None
    assert original_row.consumed_at is None
    assert original_row.revoked_at is None

    # An unknown token is not confirmed reuse: the real token still rotates.
    accepted = await refresh(client, original["refresh_token"])
    assert accepted.status_code == 200


@pytest.mark.anyio
async def test_expired_refresh_token_is_rejected(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    session_id = uuid.UUID(original["session_id"])

    with session_factory() as session:
        token_row = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(original["refresh_token"])
            )
        )
        assert token_row is not None
        token_row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    _assert_refresh_rejected(await refresh(client, original["refresh_token"]))

    with session_factory() as session:
        stored_session = session.get(UserSession, session_id)
        token_row = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(original["refresh_token"])
            )
        )

    assert stored_session is not None
    assert stored_session.revoked_at is None
    assert token_row is not None
    assert token_row.consumed_at is None


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["idle", "absolute", "revoked"])
async def test_expired_or_revoked_session_cannot_be_refreshed(
    client,
    session_factory: sessionmaker[Session],
    state: str,
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    session_id = uuid.UUID(original["session_id"])
    now = datetime.now(UTC)

    with session_factory() as session:
        stored_session = session.get(UserSession, session_id)
        assert stored_session is not None
        if state == "idle":
            stored_session.idle_expires_at = now - timedelta(seconds=1)
        elif state == "absolute":
            stored_session.absolute_expires_at = now - timedelta(seconds=1)
        else:
            stored_session.revoked_at = now
            stored_session.revocation_reason = SessionRevocationReason.ADMIN
        session.commit()

    _assert_refresh_rejected(await refresh(client, original["refresh_token"]))

    # The conditional consume is rolled back when the session is unusable.
    with session_factory() as session:
        token_row = session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(original["refresh_token"])
            )
        )

    assert token_row is not None
    assert token_row.consumed_at is None


@pytest.mark.anyio
async def test_reuse_detection_revokes_family_and_invalidates_access_tokens(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    user_id = create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    rotated = await refresh(client, original["refresh_token"])
    assert rotated.status_code == 200
    replacement = rotated.json()
    session_id = uuid.UUID(original["session_id"])

    replay = await refresh(client, original["refresh_token"])
    _assert_refresh_rejected(replay)

    with session_factory() as session:
        stored_session = session.get(UserSession, session_id)
        tokens = list(
            session.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all()
        )

    assert stored_session is not None
    assert stored_session.user_id == user_id
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.REFRESH_REUSE
    assert len(tokens) == 2
    assert all(token.revoked_at is not None for token in tokens)

    for access_token in (original["access_token"], replacement["access_token"]):
        response = await client.get(
            ME_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        _assert_access_rejected(response)


@pytest.mark.anyio
async def test_reuse_detection_records_structured_event_without_secrets(
    client,
    session_factory: sessionmaker[Session],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    user_id = create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    original = await login(client)
    rotated = await refresh(client, original["refresh_token"])
    assert rotated.status_code == 200
    replacement = rotated.json()

    _assert_refresh_rejected(await refresh(client, original["refresh_token"]))

    events = [
        record
        for record in caplog.records
        if getattr(record, "security_event", None) == "refresh_token_reuse"
    ]
    assert len(events) == 1
    event = events[0]
    assert event.user_id == str(user_id)
    assert event.session_id == original["session_id"]
    assert event.levelno == logging.WARNING

    for raw_token in (original["refresh_token"], replacement["refresh_token"]):
        assert raw_token not in caplog.text
        assert hash_opaque_token(raw_token) not in caplog.text


@pytest.mark.anyio
async def test_raw_refresh_tokens_are_never_persisted_or_exposed(
    client,
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    login_response = await client.post(
        LOGIN_URL,
        json={"email": "refresh@example.com", "password": DEFAULT_PASSWORD},
    )
    assert login_response.status_code == 200
    original = login_response.json()
    rotated_response = await refresh(client, original["refresh_token"])
    assert rotated_response.status_code == 200
    replacement = rotated_response.json()

    raw_tokens = [original["refresh_token"], replacement["refresh_token"]]
    expected_hashes = {hash_opaque_token(token) for token in raw_tokens}

    with session_factory() as session:
        stored_hashes = set(session.scalars(select(RefreshToken.token_hash)).all())

    assert stored_hashes == expected_hashes
    for raw_token in raw_tokens:
        assert raw_token not in stored_hashes
    assert original["refresh_token"] not in rotated_response.text

    for response in (login_response, rotated_response):
        assert "token_hash" not in response.text
        for expected_hash in expected_hashes:
            assert expected_hash not in response.text


def test_concurrent_refresh_attempts_cannot_both_succeed(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    with session_factory() as db:
        issued = authentication.login(
            db,
            email="refresh@example.com",
            password=DEFAULT_PASSWORD,
        )
    raw_token = issued.refresh_token
    barrier = threading.Barrier(2)

    def attempt() -> tuple[str, object]:
        with session_factory() as db:
            barrier.wait(timeout=10)
            try:
                return "success", refresh_tokens.rotate(db, presented_token=raw_token)
            except Exception as exc:
                return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(attempt), pool.submit(attempt))
        outcomes = [future.result(timeout=30) for future in futures]

    successes = [payload for status, payload in outcomes if status == "success"]
    failures = [payload for status, payload in outcomes if status == "error"]

    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], InvalidRefreshTokenError)
    assert isinstance(failures[0], RefreshTokenReuseError)

    with session_factory() as session:
        stored_session = session.get(UserSession, issued.session_id)
        tokens = list(
            session.scalars(
                select(RefreshToken).where(RefreshToken.session_id == issued.session_id)
            ).all()
        )

    assert stored_session is not None
    assert len(tokens) == 2
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason is SessionRevocationReason.REFRESH_REUSE
    assert sum(token.consumed_at is not None for token in tokens) == 1
    assert all(token.revoked_at is not None for token in tokens)


def test_rotation_rejects_naive_now(
    session_factory: sessionmaker[Session],
) -> None:
    create_user(
        session_factory,
        email="refresh@example.com",
        is_email_verified=True,
    )
    with session_factory() as db:
        issued = authentication.login(
            db,
            email="refresh@example.com",
            password=DEFAULT_PASSWORD,
        )

    with session_factory() as db:
        with pytest.raises(ValueError):
            refresh_tokens.rotate(
                db,
                presented_token=issued.refresh_token,
                now=datetime(2026, 1, 2, 3, 4, 5),
            )
