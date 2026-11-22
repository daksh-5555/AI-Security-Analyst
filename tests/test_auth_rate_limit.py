import pytest

from app.core.config import settings
from app.core.rate_limit import AuthRateLimiter, auth_rate_limiter
from app.services.analysis_admission import analysis_rate_limiter

VERIFY_URL = "/api/v1/auth/verify-email"
REGISTER_URL = "/api/v1/auth/register"
RESET_REQUEST_URL = "/api/v1/auth/password-reset/request"

pytestmark = pytest.mark.usefixtures("low_cost_argon2")


def test_limiter_allows_requests_up_to_the_limit() -> None:
    limiter = AuthRateLimiter()

    decisions = [
        limiter.check("scope", "client", max_requests=3, window_seconds=10, now=float(index))
        for index in range(3)
    ]

    assert all(decision.allowed for decision in decisions)
    assert decisions[0].retry_after_seconds == 0


def test_limiter_rejects_requests_over_the_limit() -> None:
    limiter = AuthRateLimiter()
    for index in range(3):
        assert limiter.check(
            "scope",
            "client",
            max_requests=3,
            window_seconds=10,
            now=float(index),
        ).allowed

    decision = limiter.check(
        "scope",
        "client",
        max_requests=3,
        window_seconds=10,
        now=3.0,
    )

    assert decision.allowed is False
    assert decision.retry_after_seconds == 7


def test_limiter_window_expiry_restores_allowance() -> None:
    limiter = AuthRateLimiter()
    assert limiter.check("scope", "client", max_requests=1, window_seconds=10, now=0.0).allowed
    assert not limiter.check("scope", "client", max_requests=1, window_seconds=10, now=5.0).allowed
    assert limiter.check("scope", "client", max_requests=1, window_seconds=10, now=10.0).allowed


def test_limiter_is_isolated_by_scope_and_identity() -> None:
    limiter = AuthRateLimiter()
    assert limiter.check("a", "one", max_requests=1, window_seconds=10, now=0.0).allowed
    assert limiter.check("b", "one", max_requests=1, window_seconds=10, now=0.0).allowed
    assert limiter.check("a", "two", max_requests=1, window_seconds=10, now=0.0).allowed
    assert not limiter.check("a", "one", max_requests=1, window_seconds=10, now=0.0).allowed


def test_limiter_reset_clears_state() -> None:
    limiter = AuthRateLimiter()
    assert limiter.check("scope", "client", max_requests=1, window_seconds=10, now=0.0).allowed
    assert not limiter.check("scope", "client", max_requests=1, window_seconds=10, now=0.0).allowed

    limiter.reset()

    assert limiter.check("scope", "client", max_requests=1, window_seconds=10, now=0.0).allowed


@pytest.mark.anyio
async def test_api_returns_429_with_retry_after(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_rate_limit_max_requests", 1)
    monkeypatch.setattr(settings, "auth_rate_limit_window_seconds", 60)

    first = await client.post(VERIFY_URL, json={"token": "verify_" + "E" * 64})
    second = await client.post(VERIFY_URL, json={"token": "verify_" + "E" * 64})

    assert first.status_code == 400
    assert second.status_code == 429
    assert second.json() == {"detail": "Too many requests"}
    assert int(second.headers["Retry-After"]) > 0


@pytest.mark.anyio
async def test_rate_limit_is_scoped_per_endpoint(
    auth_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_rate_limit_max_requests", 1)
    monkeypatch.setattr(settings, "auth_rate_limit_window_seconds", 60)

    register_response = await auth_client.post(
        REGISTER_URL,
        json={"email": "scope@example.com", "password": "correct horse battery staple"},
    )
    reset_response = await auth_client.post(
        RESET_REQUEST_URL,
        json={"email": "scope@example.com"},
    )
    repeated_register = await auth_client.post(
        REGISTER_URL,
        json={"email": "scope@example.com", "password": "correct horse battery staple"},
    )

    assert register_response.status_code == 202
    assert reset_response.status_code == 202
    assert repeated_register.status_code == 429


def test_analysis_rate_limiter_is_separate_from_the_auth_limiter() -> None:
    assert isinstance(analysis_rate_limiter, AuthRateLimiter)
    assert analysis_rate_limiter is not auth_rate_limiter
