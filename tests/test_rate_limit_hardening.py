"""Regression tests for bounded rate limiting, login throttling, and audit budgets."""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from auth_helpers import DEFAULT_PASSWORD, create_user
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.rate_limit import (
    OVERFLOW_IDENTITY,
    AuthRateLimiter,
    auth_rate_limiter,
    login_failure_limiter,
)
from app.main import app
from app.models.audit_event import AuditEvent
from app.schemas.enums import AuditAction

LOGIN_URL = "/api/v1/auth/login"
ATTACKER = "203.0.113.10"
VICTIM = "198.51.100.20"


@asynccontextmanager
async def client_from(address: str) -> AsyncIterator[httpx.AsyncClient]:
    """Client whose direct peer address is ``address`` (uses existing overrides)."""
    transport = httpx.ASGITransport(app=app, client=(address, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# --- B9: bounded limiter memory without evicting active entries ---------------


def test_limiter_memory_is_bounded_under_identity_flood() -> None:
    limiter = AuthRateLimiter(max_tracked_keys=50)
    for index in range(5_000):
        limiter.check("scope", f"client-{index}", max_requests=5, window_seconds=60, now=1.0)

    assert limiter.tracked_key_count <= 50


def test_identity_flood_cannot_reset_an_active_limited_identity() -> None:
    limiter = AuthRateLimiter(max_tracked_keys=10)
    for _ in range(3):
        assert limiter.check(
            "scope", "attacker", max_requests=3, window_seconds=60, now=1.0
        ).allowed
    assert not limiter.check(
        "scope", "attacker", max_requests=3, window_seconds=60, now=1.0
    ).allowed

    # Flood with new identities while the attacker's window is still active.
    for index in range(1_000):
        limiter.check("scope", f"flood-{index}", max_requests=3, window_seconds=60, now=2.0)

    assert not limiter.check(
        "scope", "attacker", max_requests=3, window_seconds=60, now=3.0
    ).allowed


def test_new_identities_share_overflow_bucket_when_full() -> None:
    limiter = AuthRateLimiter(max_tracked_keys=2)
    limiter.check("scope", "a", max_requests=2, window_seconds=60, now=1.0)
    limiter.check("scope", "b", max_requests=2, window_seconds=60, now=1.0)

    # The table is full of active keys, so every new identity shares one budget.
    assert limiter.check("scope", "c", max_requests=2, window_seconds=60, now=1.0).allowed
    assert limiter.check("scope", "d", max_requests=2, window_seconds=60, now=1.0).allowed
    assert not limiter.check("scope", "e", max_requests=2, window_seconds=60, now=1.0).allowed
    assert not limiter.check(
        "scope", OVERFLOW_IDENTITY, max_requests=2, window_seconds=60, now=1.0
    ).allowed


def test_expired_keys_are_pruned_to_admit_new_identities() -> None:
    limiter = AuthRateLimiter(max_tracked_keys=2)
    limiter.check("scope", "a", max_requests=1, window_seconds=10, now=1.0)
    limiter.check("scope", "b", max_requests=1, window_seconds=10, now=1.0)

    assert limiter.check("scope", "c", max_requests=1, window_seconds=10, now=20.0).allowed
    # "c" received its own key, so a different new identity is not blocked by it.
    assert limiter.check("scope", "d", max_requests=1, window_seconds=10, now=20.0).allowed


def test_pruning_respects_each_keys_own_window() -> None:
    limiter = AuthRateLimiter(max_tracked_keys=2)
    limiter.check("long", "x", max_requests=1, window_seconds=1_000, now=1.0)
    limiter.check("short", "y", max_requests=1, window_seconds=1, now=1.0)

    # At t=50 the short key is stale but the long-window key is still active.
    limiter.check("short", "z", max_requests=1, window_seconds=1, now=50.0)

    assert not limiter.check("long", "x", max_requests=1, window_seconds=1_000, now=50.0).allowed


def test_record_and_is_limited_count_only_recorded_events() -> None:
    limiter = AuthRateLimiter()
    assert limiter.is_limited("s", "k", max_requests=2, window_seconds=60, now=1.0).allowed
    assert limiter.record("s", "k", window_seconds=60, now=1.0) == 1
    assert limiter.record("s", "k", window_seconds=60, now=2.0) == 2
    decision = limiter.is_limited("s", "k", max_requests=2, window_seconds=60, now=3.0)
    assert not decision.allowed and decision.retry_after_seconds >= 1
    limiter.clear("s", "k")
    assert limiter.is_limited("s", "k", max_requests=2, window_seconds=60, now=3.0).allowed


# --- B6: per-account failed-login throttling ----------------------------------


@pytest.fixture
def login_user(
    session_factory: sessionmaker[Session],
    configure_jwt: None,
    low_cost_argon2: None,
    auth_client: httpx.AsyncClient,
) -> str:
    email = "throttle@example.com"
    create_user(session_factory, email=email, is_email_verified=True)
    return email


def _bad(email: str) -> dict[str, str]:
    return {"email": email, "password": "definitely-the-wrong-password"}


def _good(email: str) -> dict[str, str]:
    return {"email": email, "password": DEFAULT_PASSWORD}


@pytest.mark.anyio
async def test_repeated_failures_from_one_address_are_throttled(login_user: str) -> None:
    attempts = settings.auth_login_failure_max_attempts
    async with client_from(ATTACKER) as attacker:
        for _ in range(attempts):
            assert (await attacker.post(LOGIN_URL, json=_bad(login_user))).status_code == 401
        throttled = await attacker.post(LOGIN_URL, json=_good(login_user))

    # Even the correct password is refused, so throttled guesses reveal nothing.
    assert throttled.status_code == 429
    assert int(throttled.headers["Retry-After"]) >= 1
    assert "access_token" not in throttled.text


@pytest.mark.anyio
async def test_attacker_cannot_lock_victim_out_from_another_address(login_user: str) -> None:
    async with client_from(ATTACKER) as attacker:
        for _ in range(settings.auth_login_failure_max_attempts + 3):
            await attacker.post(LOGIN_URL, json=_bad(login_user))

    async with client_from(VICTIM) as victim:
        response = await victim.post(LOGIN_URL, json=_good(login_user))

    assert response.status_code == 200
    assert response.json()["access_token"]


@pytest.mark.anyio
async def test_throttle_is_identical_for_unknown_accounts(login_user: str) -> None:
    statuses: dict[str, list[int]] = {}
    for email in (login_user, "nobody-here@example.com"):
        # Isolate the per-account throttle from the per-address endpoint limit.
        auth_rate_limiter.reset()
        async with client_from(ATTACKER) as attacker:
            statuses[email] = [
                (await attacker.post(LOGIN_URL, json=_bad(email))).status_code
                for _ in range(settings.auth_login_failure_max_attempts + 1)
            ]

    assert statuses[login_user] == statuses["nobody-here@example.com"]
    assert statuses[login_user][-1] == 429


@pytest.mark.anyio
async def test_successful_login_clears_failures_for_that_address(login_user: str) -> None:
    async with client_from(VICTIM) as victim:
        for _ in range(settings.auth_login_failure_max_attempts - 1):
            await victim.post(LOGIN_URL, json=_bad(login_user))
        assert (await victim.post(LOGIN_URL, json=_good(login_user))).status_code == 200
        # The counter restarted, so one more mistake is not throttled.
        assert (await victim.post(LOGIN_URL, json=_bad(login_user))).status_code == 401


@pytest.mark.anyio
async def test_forwarded_headers_do_not_change_the_throttled_identity(login_user: str) -> None:
    async with client_from(ATTACKER) as attacker:
        for index in range(settings.auth_login_failure_max_attempts):
            await attacker.post(
                LOGIN_URL,
                json=_bad(login_user),
                headers={
                    "X-Forwarded-For": f"192.0.2.{index}",
                    "Forwarded": f"for=192.0.2.{index}",
                },
            )
        spoofed = await attacker.post(
            LOGIN_URL,
            json=_good(login_user),
            headers={"X-Forwarded-For": VICTIM, "Forwarded": f"for={VICTIM}"},
        )

    assert spoofed.status_code == 429


@pytest.mark.anyio
async def test_distributed_failures_raise_one_alert_without_blocking(
    login_user: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(settings, "auth_login_account_alert_threshold", 3)
    caplog.set_level(logging.WARNING, logger="app.api.auth")

    for index in range(5):
        async with client_from(f"192.0.2.{index}") as client:
            assert (await client.post(LOGIN_URL, json=_bad(login_user))).status_code == 401

    alerts = [
        record
        for record in caplog.records
        if getattr(record, "security_event", None) == "login_failure_threshold"
    ]
    assert len(alerts) == 1
    assert login_user not in alerts[0].getMessage()
    assert login_user not in str(vars(alerts[0]))
    # Alert only: a correct login from a fresh address still succeeds.
    async with client_from(VICTIM) as victim:
        assert (await victim.post(LOGIN_URL, json=_good(login_user))).status_code == 200


def test_login_failure_limiter_never_stores_raw_email() -> None:
    from app.api.auth import _login_account_key

    key = _login_account_key("  Person@Example.COM ")
    assert key == _login_account_key("person@example.com")
    assert "example" not in key and len(key) == 64
    assert login_failure_limiter.tracked_key_count == 0


# --- B4: bounded unauthenticated audit writes ---------------------------------


def _unauthenticated_denials(session_factory: sessionmaker[Session]) -> int:
    with session_factory() as session:
        return session.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == AuditAction.ASSESSMENT_ACCESS_DENIED,
                AuditEvent.actor_user_id.is_(None),
            )
        )


async def _flood(address: str, count: int) -> list[int]:
    async with client_from(address) as client:
        return [
            (await client.get(f"/api/v1/assessments/{uuid.uuid4()}")).status_code
            for _ in range(count)
        ]


@pytest.mark.anyio
async def test_unauthenticated_flood_is_bounded_per_client(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "audit_unauthenticated_denials_per_client", 7)

    statuses = await _flood(ATTACKER, 40)

    assert set(statuses) == {401}
    assert _unauthenticated_denials(session_factory) == 7


@pytest.mark.anyio
async def test_unauthenticated_flood_is_bounded_globally(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "audit_unauthenticated_denials_per_client", 100)
    monkeypatch.setattr(settings, "audit_unauthenticated_denials_global", 9)

    statuses: list[int] = []
    for index in range(6):
        statuses += await _flood(f"192.0.2.{index}", 5)

    assert set(statuses) == {401}
    assert _unauthenticated_denials(session_factory) == 9


@pytest.mark.anyio
async def test_each_client_keeps_its_own_audit_budget(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "audit_unauthenticated_denials_per_client", 3)

    await _flood(ATTACKER, 20)
    await _flood(VICTIM, 2)

    # The attacker's flood did not consume the second client's audit budget.
    assert _unauthenticated_denials(session_factory) == 5
