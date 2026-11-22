"""Browser refresh-cookie flow: HttpOnly cookie delivery, double-submit CSRF, and
backward compatibility with the existing header/body refresh contract.

Every test here is offline and deterministic. ``auth_cookie_secure`` is turned off
for the round-trip tests because the ASGI transport speaks plain http, and a
browser cookie jar refuses to return a Secure cookie over http — exactly the
reason the setting exists for local same-origin dev. The attribute assertions run
with the secure default so the production cookie shape is what is checked.
"""

from __future__ import annotations

import httpx
import pytest
from auth_helpers import DEFAULT_PASSWORD, create_user
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

pytestmark = pytest.mark.usefixtures("low_cost_argon2", "configure_jwt")

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
LOGOUT_URL = "/api/v1/auth/logout"
GENERIC_REFRESH_DETAIL = "Invalid or expired refresh token"


def _set_cookie_header(response: httpx.Response, name: str) -> str | None:
    for raw in response.headers.get_list("set-cookie"):
        if raw.startswith(f"{name}="):
            return raw
    return None


async def _login(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    *,
    email: str = "cookie@example.com",
) -> httpx.Response:
    create_user(session_factory, email=email, is_email_verified=True)
    response = await client.post(
        LOGIN_URL,
        json={"email": email, "password": DEFAULT_PASSWORD},
    )
    assert response.status_code == 200
    return response


@pytest.mark.anyio
async def test_login_sets_httponly_refresh_and_readable_csrf_cookies(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    response = await _login(client, session_factory)

    refresh_cookie = _set_cookie_header(response, settings.auth_refresh_cookie_name)
    csrf_cookie = _set_cookie_header(response, settings.auth_csrf_cookie_name)
    assert refresh_cookie is not None and csrf_cookie is not None

    # Refresh cookie: HttpOnly, Secure (default), SameSite=strict, auth-scoped path.
    assert "HttpOnly" in refresh_cookie
    assert "Secure" in refresh_cookie
    assert "SameSite=strict" in refresh_cookie
    assert "Path=/api/v1/auth" in refresh_cookie

    # CSRF cookie: deliberately readable (not HttpOnly) and site-wide (Path=/) so a
    # single-page app served at "/" can read it to echo in the X-CSRF-Token header.
    assert "HttpOnly" not in csrf_cookie
    assert "Path=/" in csrf_cookie
    assert "Path=/api/v1/auth" not in csrf_cookie

    # The body contract is unchanged by default.
    assert response.json()["refresh_token"]


@pytest.mark.anyio
async def test_refresh_via_cookie_with_csrf_header_rotates(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    await _login(client, session_factory)
    csrf = client.cookies.get(settings.auth_csrf_cookie_name)
    assert csrf

    response = await client.post(REFRESH_URL, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    assert response.json()["access_token"]


@pytest.mark.anyio
async def test_refresh_via_cookie_without_csrf_header_is_forbidden(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    await _login(client, session_factory)

    response = await client.post(REFRESH_URL)

    assert response.status_code == 403


@pytest.mark.anyio
async def test_refresh_via_cookie_with_wrong_csrf_header_is_forbidden(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    await _login(client, session_factory)

    response = await client.post(REFRESH_URL, headers={"X-CSRF-Token": "not-the-value"})

    assert response.status_code == 403


@pytest.mark.anyio
async def test_body_token_takes_precedence_and_skips_csrf(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cookie and CSRF cookie are both present, but a body token must still work
    # with no CSRF header: the body path is not a CSRF vector.
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    login = await _login(client, session_factory)
    body_token = login.json()["refresh_token"]

    response = await client.post(REFRESH_URL, json={"refresh_token": body_token})

    assert response.status_code == 200
    assert response.json()["access_token"]


@pytest.mark.anyio
async def test_refresh_without_token_or_cookie_is_unauthorized(
    client: httpx.AsyncClient,
) -> None:
    # No login, so no cookie and no body token: the generic 401, never a 403.
    response = await client.post(REFRESH_URL)

    assert response.status_code == 401
    assert response.json() == {"detail": GENERIC_REFRESH_DETAIL}


@pytest.mark.anyio
async def test_cookie_refresh_rotates_the_cookie_value(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    await _login(client, session_factory)
    first = client.cookies.get(settings.auth_refresh_cookie_name)
    csrf = client.cookies.get(settings.auth_csrf_cookie_name)

    response = await client.post(REFRESH_URL, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200

    second = client.cookies.get(settings.auth_refresh_cookie_name)
    assert first and second and second != first


@pytest.mark.anyio
async def test_logout_clears_the_auth_cookies(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    login = await _login(client, session_factory)
    access_token = login.json()["access_token"]

    response = await client.post(
        LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 204
    refresh_clear = _set_cookie_header(response, settings.auth_refresh_cookie_name)
    csrf_clear = _set_cookie_header(response, settings.auth_csrf_cookie_name)
    assert refresh_clear is not None and csrf_clear is not None
    # delete_cookie expires the value immediately.
    assert "Max-Age=0" in refresh_clear or "01 Jan 1970" in refresh_clear


@pytest.mark.anyio
async def test_feature_disabled_sets_no_cookies(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_refresh_cookie_enabled", False)
    response = await _login(client, session_factory)

    assert _set_cookie_header(response, settings.auth_refresh_cookie_name) is None
    assert response.json()["refresh_token"]


@pytest.mark.anyio
async def test_body_token_suppressed_when_configured(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The browser app turns the body token off so JavaScript never receives it;
    # the HttpOnly cookie is still delivered.
    monkeypatch.setattr(settings, "auth_refresh_in_response_body", False)
    response = await _login(client, session_factory)

    assert response.json()["refresh_token"] == ""
    assert _set_cookie_header(response, settings.auth_refresh_cookie_name) is not None
