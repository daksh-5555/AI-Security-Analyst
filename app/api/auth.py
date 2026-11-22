"""Identity lifecycle routes: registration, verification, login, and refresh.

Responses are deliberately generic so callers cannot enumerate accounts. Raw
email action tokens only ever travel in the outbound email body; refresh tokens
are returned once in a token response and never written to logs. Only refresh
token hashes are persisted.

Every route handler is a plain ``def``. Password hashing (Argon2id) and the
synchronous SQLAlchemy session are blocking, so FastAPI must run these handlers
in its worker threadpool instead of on the event loop; an ``async def`` handler
would stall every other request on the worker while Argon2 or a SQLite lock wait
is in progress.
"""

from __future__ import annotations

import hashlib
import logging
import unicodedata
from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy.orm import Session

from app.api.auth_cookies import (
    clear_auth_cookies,
    generate_csrf_token,
    read_refresh_cookie,
    require_csrf,
    set_auth_cookies,
)
from app.api.constants import (
    AUTH_INTERNAL_ERROR_DETAIL,
    AUTH_INVALID_CREDENTIALS_DETAIL,
    AUTH_INVALID_EMAIL_DETAIL,
    AUTH_INVALID_PASSWORD_DETAIL,
    AUTH_INVALID_REFRESH_TOKEN_DETAIL,
    AUTH_INVALID_TOKEN_DETAIL,
    AUTH_PASSWORD_RESET_MESSAGE,
    AUTH_RATE_LIMITED_DETAIL,
    AUTH_REGISTRATION_MESSAGE,
    AUTH_ROLE_CONFIGURATION_DETAIL,
    AUTH_VERIFICATION_RESEND_MESSAGE,
)
from app.api.dependencies import CurrentPrincipal, client_address
from app.core.config import settings
from app.core.mailer import EmailDeliveryError, Mailer, get_mailer
from app.core.rate_limit import auth_rate_limiter, login_failure_limiter
from app.db.session import get_db
from app.schemas.auth import (
    AuthMessageResponse,
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequestPayload,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from app.services import authentication, identity, refresh_tokens, sessions
from app.services.authentication import InvalidCredentialsError, LoginPersistenceError
from app.services.identity import (
    InvalidEmailError,
    InvalidIdentityTokenError,
    InvalidPasswordError,
    PasswordResetPersistenceError,
)
from app.services.refresh_tokens import (
    InvalidRefreshTokenError,
    RefreshPersistenceError,
)
from app.services.roles import RoleConfigurationError
from app.services.sessions import SessionPersistenceError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

DbSession = Annotated[Session, Depends(get_db)]
MailerDep = Annotated[Mailer, Depends(get_mailer)]


LOGIN_FAILURE_PAIR_SCOPE = "auth.login.failure.account_client"
LOGIN_FAILURE_ACCOUNT_SCOPE = "auth.login.failure.account"


def _client_identity(request: Request) -> str:
    """Return the direct peer address; forwarded headers are never trusted here."""
    return client_address(request)


def _login_account_key(email: str) -> str:
    """Return a stable, non-reversible throttling key for a submitted email.

    The key is derived the same way for existing and unknown accounts, so the
    throttle cannot be used to enumerate accounts, and raw addresses are never
    held in limiter memory.
    """
    candidate = unicodedata.normalize("NFC", email).strip().lower()
    return hashlib.sha256(candidate.encode("utf-8", "surrogatepass")).hexdigest()


def _enforce_login_failure_throttle(account_key: str, client: str) -> None:
    """Reject a login when this account/client pair has too many recent failures.

    The pair scope is deliberate: an attacker on another address cannot exhaust
    the allowance of a legitimate user's address, so this cannot be used to lock
    an account out. Distributed guessing across many addresses is detected by
    ``_record_login_failure`` but not blocked; see the README limitations.
    """
    decision = login_failure_limiter.is_limited(
        LOGIN_FAILURE_PAIR_SCOPE,
        f"{account_key}|{client}",
        max_requests=settings.auth_login_failure_max_attempts,
        window_seconds=settings.auth_login_failure_window_seconds,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=AUTH_RATE_LIMITED_DETAIL,
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


def _record_login_failure(account_key: str, client: str) -> None:
    window = settings.auth_login_failure_window_seconds
    login_failure_limiter.record(
        LOGIN_FAILURE_PAIR_SCOPE,
        f"{account_key}|{client}",
        window_seconds=window,
    )
    account_failures = login_failure_limiter.record(
        LOGIN_FAILURE_ACCOUNT_SCOPE,
        account_key,
        window_seconds=window,
    )
    if account_failures == settings.auth_login_account_alert_threshold:
        # Alert once per crossing. Only a truncated, non-reversible key is logged.
        logger.warning(
            "Failed-login threshold reached for one account.",
            extra={
                "security_event": "login_failure_threshold",
                "account_key_prefix": account_key[:16],
                "failures_in_window": account_failures,
            },
        )


def enforce_auth_rate_limit(request: Request) -> None:
    """Apply the process-local per-client limit before any account lookup.

    The limiter keeps counters in this worker process only. Multi-worker or
    multi-instance deployments require a shared limiter or gateway protection;
    see ``app.core.rate_limit``.
    """
    decision = auth_rate_limiter.check(request.url.path, _client_identity(request))
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=AUTH_RATE_LIMITED_DETAIL,
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


RateLimited = Annotated[None, Depends(enforce_auth_rate_limit)]


def _describe_ttl(seconds: int) -> str:
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    minutes = max(1, seconds // 60)
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def _verification_body(raw_token: str) -> str:
    return (
        "Verify your email address\n"
        "\n"
        "Use the following token to verify your email address:\n"
        "\n"
        f"{raw_token}\n"
        "\n"
        "This token expires in "
        f"{_describe_ttl(settings.email_verification_token_ttl_seconds)}.\n"
        "If you did not create this account, you can ignore this message.\n"
    )


def _password_reset_body(raw_token: str) -> str:
    return (
        "Reset your password\n"
        "\n"
        "Use the following token to choose a new password:\n"
        "\n"
        f"{raw_token}\n"
        "\n"
        "This token expires in "
        f"{_describe_ttl(settings.password_reset_token_ttl_seconds)}.\n"
        "If you did not request a password reset, you can ignore this message.\n"
    )


def _send_email_safely(mailer: Mailer, *, to: str, subject: str, body: str) -> None:
    """Deliver a message after the response without leaking failure details."""
    try:
        mailer.send(to=to, subject=subject, body=body)
    except EmailDeliveryError:
        logger.warning("Outbound identity email delivery failed.")


def _schedule_email(
    background_tasks: BackgroundTasks,
    mailer: Mailer,
    *,
    to: str,
    subject: str,
    body: str,
) -> None:
    background_tasks.add_task(
        _send_email_safely,
        mailer,
        to=to,
        subject=subject,
        body=body,
    )


@router.post(
    "/register",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def register(
    _rate_limit: RateLimited,
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: DbSession,
    mailer: MailerDep,
) -> AuthMessageResponse:
    """Create an unverified account without any role assignment."""
    try:
        issued = identity.register_user(
            db,
            email=payload.email,
            password=payload.password,
        )
    except InvalidEmailError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=AUTH_INVALID_EMAIL_DETAIL,
        ) from None
    except InvalidPasswordError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=AUTH_INVALID_PASSWORD_DETAIL,
        ) from None

    if issued is not None:
        raw_token, user = issued
        _schedule_email(
            background_tasks,
            mailer,
            to=user.email,
            subject="Verify your email address",
            body=_verification_body(raw_token),
        )

    return AuthMessageResponse(message=AUTH_REGISTRATION_MESSAGE)


@router.post(
    "/resend-verification",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def resend_verification(
    _rate_limit: RateLimited,
    payload: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    db: DbSession,
    mailer: MailerDep,
) -> AuthMessageResponse:
    """Re-issue a verification token when the account is eligible."""
    issued = identity.resend_verification_email(db, email=payload.email)
    if issued is not None:
        raw_token, user = issued
        _schedule_email(
            background_tasks,
            mailer,
            to=user.email,
            subject="Verify your email address",
            body=_verification_body(raw_token),
        )

    return AuthMessageResponse(message=AUTH_VERIFICATION_RESEND_MESSAGE)


@router.post(
    "/verify-email",
    status_code=status.HTTP_204_NO_CONTENT,
)
def verify_email(
    _rate_limit: RateLimited,
    payload: VerifyEmailRequest,
    db: DbSession,
) -> Response:
    """Consume a verification token and grant the default role if unassigned."""
    try:
        identity.verify_email(db, token=payload.token)
    except InvalidIdentityTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=AUTH_INVALID_TOKEN_DETAIL,
        ) from None
    except RoleConfigurationError:
        logger.error("Default role configuration is invalid; verification rolled back.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=AUTH_ROLE_CONFIGURATION_DETAIL,
        ) from None

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/password-reset/request",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_password_reset(
    _rate_limit: RateLimited,
    payload: PasswordResetRequestPayload,
    background_tasks: BackgroundTasks,
    db: DbSession,
    mailer: MailerDep,
) -> AuthMessageResponse:
    """Send a reset token only when an eligible account exists."""
    issued = identity.request_password_reset(db, email=payload.email)
    if issued is not None:
        raw_token, user = issued
        _schedule_email(
            background_tasks,
            mailer,
            to=user.email,
            subject="Reset your password",
            body=_password_reset_body(raw_token),
        )

    return AuthMessageResponse(message=AUTH_PASSWORD_RESET_MESSAGE)


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
)
def confirm_password_reset(
    _rate_limit: RateLimited,
    payload: PasswordResetConfirmRequest,
    db: DbSession,
) -> Response:
    """Replace the password using a single-use reset token."""
    try:
        identity.confirm_password_reset(
            db,
            token=payload.token,
            new_password=payload.new_password,
        )
    except InvalidIdentityTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=AUTH_INVALID_TOKEN_DETAIL,
        ) from None
    except InvalidPasswordError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=AUTH_INVALID_PASSWORD_DETAIL,
        ) from None
    except PasswordResetPersistenceError:
        logger.error("Password reset persistence failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=AUTH_INTERNAL_ERROR_DETAIL,
        ) from None

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    _rate_limit: RateLimited,
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: DbSession,
) -> LoginResponse:
    """Verify credentials and create a persisted session.

    All unusable identities receive the same generic 401. A successful login
    returns one short-lived access token and one opaque refresh token; only the
    refresh token's hash is stored. Repeated failures for one account from one
    client address are throttled with ``429`` before any password work runs.
    """
    client = _client_identity(request)
    account_key = _login_account_key(payload.email)
    _enforce_login_failure_throttle(account_key, client)
    try:
        result = authentication.login(
            db,
            email=payload.email,
            password=payload.password,
        )
    except InvalidCredentialsError:
        _record_login_failure(account_key, client)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTH_INVALID_CREDENTIALS_DETAIL,
        ) from None
    except LoginPersistenceError:
        logger.error("Login persistence failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=AUTH_INTERNAL_ERROR_DETAIL,
        ) from None

    login_failure_limiter.clear(LOGIN_FAILURE_PAIR_SCOPE, f"{account_key}|{client}")
    if settings.auth_refresh_cookie_enabled:
        set_auth_cookies(
            response,
            refresh_token=result.refresh_token,
            max_age_seconds=result.refresh_expires_in,
            csrf_token=generate_csrf_token(),
        )
    return LoginResponse(
        access_token=result.access_token,
        token_type="bearer",
        expires_in=result.expires_in,
        refresh_token=(
            result.refresh_token if settings.auth_refresh_in_response_body else ""
        ),
        refresh_expires_in=result.refresh_expires_in,
        session_id=result.session_id,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    status_code=status.HTTP_200_OK,
)
def refresh(
    _rate_limit: RateLimited,
    request: Request,
    response: Response,
    db: DbSession,
    payload: Annotated[RefreshRequest | None, Body()] = None,
) -> RefreshResponse:
    """Rotate a refresh token and return a replacement token pair.

    The token may arrive in the request body (the existing API contract) or, for a
    browser client, in the HttpOnly refresh cookie. An explicit body token always
    wins. A cookie-sourced request additionally requires a valid double-submit CSRF
    token; a body-sourced request does not, because an attacker who cannot read the
    token cannot place it in the body, so that path is not a CSRF vector.

    Unknown, malformed, expired, revoked, and replayed tokens all return the same
    generic ``401`` so callers cannot distinguish their state. Replaying a consumed
    token also revokes the entire session family. The session identifier stays
    stable across rotations.
    """
    body_token = payload.refresh_token if payload is not None else None
    if body_token:
        presented_token = body_token
    else:
        presented_token = read_refresh_cookie(request)
        if presented_token is not None:
            # Only the cookie path is a CSRF vector; enforce the check before any
            # rotation work runs.
            require_csrf(request)
    if not presented_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTH_INVALID_REFRESH_TOKEN_DETAIL,
        )

    try:
        result = refresh_tokens.rotate(
            db,
            presented_token=presented_token,
        )
    except InvalidRefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTH_INVALID_REFRESH_TOKEN_DETAIL,
        ) from None
    except RefreshPersistenceError:
        logger.error("Refresh persistence failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=AUTH_INTERNAL_ERROR_DETAIL,
        ) from None

    if settings.auth_refresh_cookie_enabled:
        set_auth_cookies(
            response,
            refresh_token=result.refresh_token,
            max_age_seconds=result.refresh_expires_in,
            csrf_token=generate_csrf_token(),
        )
    return RefreshResponse(
        access_token=result.access_token,
        token_type="bearer",
        expires_in=result.expires_in,
        refresh_token=(
            result.refresh_token if settings.auth_refresh_in_response_body else ""
        ),
        refresh_expires_in=result.refresh_expires_in,
        session_id=result.session_id,
    )


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    status_code=status.HTTP_200_OK,
)
def read_current_user(principal: CurrentPrincipal) -> CurrentUserResponse:
    """Return the authenticated caller's safe identity fields.

    Roles are re-read from the database for every request and are never taken
    from JWT claims or a stale ORM relationship.
    """
    return CurrentUserResponse(
        id=principal.user_id,
        email=principal.email,
        is_active=principal.is_active,
        is_email_verified=principal.is_email_verified,
        roles=list(principal.roles),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(principal: CurrentPrincipal, db: DbSession) -> Response:
    """Revoke the authenticated session and its refresh-token family.

    The session comes only from verified access-token claims bound to a live
    database session; no request field selects it. Other sessions belonging to the
    same user are untouched. A repeated logout cannot authenticate with the revoked
    access token and therefore receives the same generic ``401`` as any other
    unusable token.
    """
    try:
        sessions.revoke_session(db, session_id=principal.session_id)
    except SessionPersistenceError:
        logger.error("Logout persistence failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=AUTH_INTERNAL_ERROR_DETAIL,
        ) from None

    # Logout already requires the Bearer access token, so it is inherently
    # CSRF-safe; only the stale refresh cookie needs clearing here.
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    if settings.auth_refresh_cookie_enabled:
        clear_auth_cookies(result)
    return result
