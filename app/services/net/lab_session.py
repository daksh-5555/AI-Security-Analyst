"""Establish an authenticated session against an authorized local web lab (M15, ADR-0018).

Scope and safety:

- This performs a single scripted login with operator-supplied *known* lab
  credentials against an already-authorized LOCAL web target (for example DVWA
  on loopback). It is **not** credential discovery: exactly one login is
  attempted, and there is no retry, guessing, or enumeration of any kind.
- The feature is off by default (``WEB_AUTH_LAB_ENABLED``) and forbidden in
  staging/production. The target host must be a literal address inside the
  configured local test networks.
- All requests go through :class:`GuardedHttpClient` built by
  ``build_target_client`` (host-bound, SSRF-safe). Nothing here constructs its
  own client or reaches any other host.
- The password is used once to log in and is never stored, logged, or returned.
  Only the resulting session cookie is kept, to replay against the lab.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.assessment_target import AssessmentTarget
from app.services.net.guarded_client import EgressError, GuardedResponse
from app.services.target_authorization import (
    TargetNotAuthorizedError,
    build_target_client,
    canonicalize_web_target,
    local_test_networks,
    require_authorized_web_target,
)

_MAX_HTML = 1_000_000
# Hidden CSRF token field: name="user_token" value="...". Attribute order varies.
_TOKEN_TEMPLATE = (
    r"""<input[^>]*\bname=['"]{field}['"][^>]*\bvalue=['"]([^'"]*)['"]"""
    r"""|<input[^>]*\bvalue=['"]([^'"]*)['"][^>]*\bname=['"]{field}['"]"""
)


class LabAuthError(RuntimeError):
    """Lab authentication could not be completed. Carries a stable, sanitized code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LabAuthDisabledError(LabAuthError):
    def __init__(self) -> None:
        super().__init__("lab_auth_disabled")


@dataclass(frozen=True)
class LabSession:
    username: str
    login_path: str
    cookie_header: str


def _require_local_target(target: AssessmentTarget) -> None:
    """The lab-auth feature is restricted to literal local addresses."""
    canonical = canonicalize_web_target(target.canonical_target)
    try:
        address = ipaddress.ip_address(canonical.host)
    except ValueError as exc:
        # A hostname cannot be proven local without trusting DNS; refuse.
        raise LabAuthError("target_not_local") from exc
    networks = local_test_networks()
    if not (address.is_loopback or any(address in network for network in networks)):
        raise LabAuthError("target_not_local")


def _merge_cookies(existing: str, response: GuardedResponse) -> str:
    """Fold any ``Set-Cookie`` from ``response`` into a ``name=value; ...`` header."""
    jar: SimpleCookie = SimpleCookie()
    if existing:
        try:
            jar.load(existing)
        except CookieError:
            jar = SimpleCookie()
    raw = response.headers.get("set-cookie")
    if raw:
        incoming: SimpleCookie = SimpleCookie()
        try:
            incoming.load(raw)
        except CookieError:
            incoming = SimpleCookie()
        for key, morsel in incoming.items():
            jar[key] = morsel.value
    return "; ".join(f"{key}={morsel.value}" for key, morsel in jar.items())


def _extract_token(html: str, field: str) -> str | None:
    if not field:
        return None
    pattern = re.compile(_TOKEN_TEMPLATE.format(field=re.escape(field)), re.IGNORECASE)
    match = pattern.search(html[:_MAX_HTML])
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _is_login_page(html: str) -> bool:
    lowered = html[:_MAX_HTML].lower()
    password_field = settings.web_auth_lab_password_field.lower()
    return f'name="{password_field}"' in lowered or f"name='{password_field}'" in lowered


def _form_body(username: str, password: str, token: str | None) -> bytes:
    from urllib.parse import urlencode

    fields = {
        settings.web_auth_lab_username_field: username,
        settings.web_auth_lab_password_field: password,
        **dict(settings.web_auth_lab_extra_fields),
    }
    if token is not None and settings.web_auth_lab_csrf_field:
        fields[settings.web_auth_lab_csrf_field] = token
    return urlencode(fields).encode("utf-8")


def establish_lab_session(
    db: Session,
    target: AssessmentTarget,
    *,
    username: str,
    password: str,
) -> LabSession:
    """Perform one login and return the resulting session (no password retained).

    Raises :class:`LabAuthError` (sanitized code) on any failure. The deployment
    must have the feature enabled and the target must be an authorized local lab.
    """
    if not settings.web_auth_lab_enabled:
        raise LabAuthDisabledError()
    # Fail closed if the target is not an authorized web target.
    require_authorized_web_target(db, target.assessment_id)
    _require_local_target(target)

    login_path = settings.web_auth_lab_login_path
    canonical = canonicalize_web_target(target.canonical_target)
    login_url = f"{canonical.origin}{login_path}"
    client = build_target_client(db, target)

    try:
        page = client.request("GET", login_url)
        cookie = _merge_cookies("", page)
        token = _extract_token(
            page.body.decode("utf-8", "replace"), settings.web_auth_lab_csrf_field
        )

        authed = build_target_client(
            db, target, default_headers={"Cookie": cookie} if cookie else {}
        )
        result = authed.request(
            "POST",
            login_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=_form_body(username, password, token),
        )
    except EgressError as exc:
        raise LabAuthError(f"egress_{exc.code.value}") from exc
    except TargetNotAuthorizedError as exc:
        raise LabAuthError("target_not_authorized") from exc

    cookie = _merge_cookies(cookie, result)
    if not cookie:
        raise LabAuthError("no_session_cookie")

    # Verify the session actually authenticated: fetch the base page and confirm
    # it is no longer the login form. One request, read-only.
    verify = build_target_client(db, target, default_headers={"Cookie": cookie})
    try:
        landing = verify.request("GET", canonical.url)
    except EgressError as exc:
        raise LabAuthError(f"egress_{exc.code.value}") from exc
    cookie = _merge_cookies(cookie, landing)
    if _is_login_page(landing.body.decode("utf-8", "replace")):
        raise LabAuthError("authentication_failed")

    return LabSession(username=username, login_path=login_path, cookie_header=cookie)


__all__ = ["LabAuthDisabledError", "LabAuthError", "LabSession", "establish_lab_session"]
