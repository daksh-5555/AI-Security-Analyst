"""Regression tests: blocking authentication work must not run on the event loop."""

import asyncio
import inspect
import threading

import httpx
import pytest
from fastapi.routing import APIRoute

from app.api import auth as auth_api


def _auth_routes() -> list[APIRoute]:
    # Inspect the auth router itself: newer FastAPI versions wrap included
    # routers, so ``app.routes`` no longer lists their APIRoute objects directly.
    return [route for route in auth_api.router.routes if isinstance(route, APIRoute)]


def test_every_auth_route_handler_is_synchronous() -> None:
    routes = _auth_routes()
    assert {route.path for route in routes} >= {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/password-reset/confirm",
    }
    coroutine_handlers = [
        route.path for route in routes if inspect.iscoroutinefunction(route.endpoint)
    ]
    assert coroutine_handlers == []


@pytest.mark.anyio
async def test_slow_login_does_not_block_the_event_loop(
    auth_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A login blocked in the service layer must not stall other requests."""
    entered = threading.Event()
    release = threading.Event()
    released_by_test: list[bool] = []

    def blocking_login(*_args: object, **_kwargs: object) -> object:
        entered.set()
        # Simulates Argon2 or a SQLite busy wait. On the event loop this would
        # freeze the test itself, so ``release`` could only end by timing out.
        released_by_test.append(release.wait(timeout=3))
        raise auth_api.InvalidCredentialsError()

    monkeypatch.setattr(auth_api.authentication, "login", blocking_login)

    login_task = asyncio.create_task(
        auth_client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "x" * 16},
        )
    )
    try:
        for _ in range(500):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert entered.is_set()

        health = await asyncio.wait_for(auth_client.get("/health"), timeout=2)
        assert health.status_code == 200
        assert not login_task.done()
    finally:
        release.set()

    response = await login_task
    assert response.status_code == 401
    # The handler must have been released by this coroutine, proving the event
    # loop kept running while the login was blocked in a worker thread.
    assert released_by_test == [True]
