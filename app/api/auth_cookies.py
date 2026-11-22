"""Transport helpers for the optional browser refresh-cookie flow.

The deterministic API authenticates with ``Authorization: Bearer`` headers and is
therefore immune to CSRF: a cross-site page cannot make the browser attach that
header. The only cookie-bearing surface is the refresh endpoint, and only when a
caller presents the refresh token via the HttpOnly cookie instead of the request
body. That path is guarded here by a stateless double-submit CSRF check.

Nothing in this module persists state or touches the database. Cookies are pure
transport: the refresh token's hash is still the only server-side record, exactly
as in the header-bearer flow.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, Response, status

from app.core.config import settings

# The HttpOnly refresh cookie is scoped to the auth router prefix, so the secret
# token is only ever sent to the three endpoints that read it. The readable CSRF
# cookie must be scoped to the whole site: a single-page app served at "/" has to
# read it (document.cookie honours path) to echo it in the X-CSRF-Token header on
# refresh. It carries no secret — only the double-submit value — so a site-wide
# path is safe.
AUTH_COOKIE_PATH = "/api/v1/auth"
CSRF_COOKIE_PATH = "/"

CSRF_HEADER_NAME = "X-CSRF-Token"

# Generic, non-enumerating message. A failed double-submit check never reveals
# whether the cookie, the header, or neither was the problem.
CSRF_FAILED_DETAIL = "Request could not be validated."


def generate_csrf_token() -> str:
    """Return a fresh, unguessable CSRF value for the double-submit cookie."""
    return secrets.token_urlsafe(32)


def set_auth_cookies(
    response: Response,
    *,
    refresh_token: str,
    max_age_seconds: int,
    csrf_token: str,
) -> None:
    """Attach the HttpOnly refresh cookie and the readable CSRF cookie.

    The refresh cookie is HttpOnly so JavaScript can never read it; the CSRF
    cookie is deliberately readable so the single-page app can echo it in the
    ``X-CSRF-Token`` header. Both carry the configured Secure/SameSite/Domain
    attributes and the same lifetime as the refresh token.
    """
    response.set_cookie(
        key=settings.auth_refresh_cookie_name,
        value=refresh_token,
        max_age=max_age_seconds,
        path=AUTH_COOKIE_PATH,
        domain=settings.auth_cookie_domain,
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite=settings.auth_cookie_samesite,
    )
    response.set_cookie(
        key=settings.auth_csrf_cookie_name,
        value=csrf_token,
        max_age=max_age_seconds,
        path=CSRF_COOKIE_PATH,
        domain=settings.auth_cookie_domain,
        secure=settings.auth_cookie_secure,
        httponly=False,
        samesite=settings.auth_cookie_samesite,
    )


def clear_auth_cookies(response: Response) -> None:
    """Expire both auth cookies on logout.

    The delete must echo the Path and Domain the cookies were set with, otherwise
    the browser keeps the original cookie.
    """
    response.delete_cookie(
        key=settings.auth_refresh_cookie_name,
        path=AUTH_COOKIE_PATH,
        domain=settings.auth_cookie_domain,
    )
    response.delete_cookie(
        key=settings.auth_csrf_cookie_name,
        path=CSRF_COOKIE_PATH,
        domain=settings.auth_cookie_domain,
    )


def read_refresh_cookie(request: Request) -> str | None:
    """Return the refresh token carried in the HttpOnly cookie, if present."""
    if not settings.auth_refresh_cookie_enabled:
        return None
    return request.cookies.get(settings.auth_refresh_cookie_name)


def require_csrf(request: Request) -> None:
    """Enforce the double-submit CSRF check for a cookie-sourced request.

    The readable CSRF cookie and the ``X-CSRF-Token`` header must both be present
    and equal. A cross-site attacker can neither read the cookie (it is on the
    target's origin) nor set the custom header (no CORS permits it), so a forged
    refresh cannot satisfy both. Comparison is constant-time.
    """
    cookie_value = request.cookies.get(settings.auth_csrf_cookie_name)
    header_value = request.headers.get(CSRF_HEADER_NAME)
    if (
        not cookie_value
        or not header_value
        or not secrets.compare_digest(cookie_value, header_value)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=CSRF_FAILED_DETAIL,
        )
