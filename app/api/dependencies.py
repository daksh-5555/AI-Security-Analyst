"""Database-backed authentication dependencies for protected routes.

Every client-authentication failure returns the same generic 401 with a Bearer
challenge. JWT validation is delegated to ``app.core.security``; this module
only binds the validated claims to a live, non-revoked database session and
freshly resolved roles.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.constants import (
    ADMIN_FORBIDDEN_DETAIL,
    ASSESSMENT_FORBIDDEN_DETAIL,
    ASSESSMENT_NOT_FOUND_DETAIL,
    AUTH_INVALID_ACCESS_TOKEN_DETAIL,
)
from app.core.config import settings
from app.core.rate_limit import unauthenticated_audit_limiter
from app.core.security import AccessTokenClaims, InvalidAccessTokenError, decode_access_token
from app.db.session import get_db
from app.models.assessment import AssessmentJob
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.enums import AuditAction, AuditOutcome, AuditResourceType
from app.services import authorization
from app.services.audit import record_audit_event_safely
from app.services.roles import list_role_names_for_user

logger = logging.getLogger(__name__)

_ASSESSMENT_PATH_PREFIX = "/api/v1/assessments"
_UNAUTHENTICATED_AUDIT_CLIENT_SCOPE = "audit.unauthenticated_denial.client"
_UNAUTHENTICATED_AUDIT_GLOBAL_SCOPE = "audit.unauthenticated_denial.global"
_UNAUTHENTICATED_AUDIT_GLOBAL_IDENTITY = "all-clients"


def client_address(request: Request) -> str:
    """Return the direct peer address without trusting proxy headers.

    ``X-Forwarded-For`` and ``Forwarded`` are never read by the application.
    Behind a reverse proxy, configure Uvicorn's ``--forwarded-allow-ips`` with the
    proxy's address so only that trusted proxy can set the client address;
    Uvicorn then rewrites ``request.client`` before this function runs.
    """
    client = request.client
    return client.host if client is not None else "unknown"


@dataclass(frozen=True, slots=True)
class Principal:
    """Immutable identity and session context for one authenticated request."""

    user_id: uuid.UUID
    email: str
    session_id: uuid.UUID
    is_active: bool
    is_email_verified: bool
    roles: tuple[str, ...]
    claims: AccessTokenClaims


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=AUTH_INVALID_ACCESS_TOKEN_DETAIL,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _single_bearer_token(request: Request) -> str:
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise _unauthorized()

    parts = values[0].split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise _unauthorized()
    return parts[1]


def _is_assessment_path(path: str) -> bool:
    return path == _ASSESSMENT_PATH_PREFIX or path.startswith(f"{_ASSESSMENT_PATH_PREFIX}/")


def _requested_assessment_id(request: Request) -> uuid.UUID | None:
    raw = request.path_params.get("assessment_id")
    if not isinstance(raw, str):
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


def _unauthenticated_denial_recording_allowed(request: Request) -> bool:
    """Bound audit-table writes caused by unauthenticated requests.

    Unauthenticated callers can otherwise force one committed audit row per
    request. Each client address may record a limited number of denials per
    window, and a global budget bounds distributed floods. Requests beyond the
    budget still receive the same 401; only the audit write is skipped. The
    counters are process-local, like the other rate limits.
    """
    window = settings.audit_unauthenticated_denial_window_seconds
    per_client = unauthenticated_audit_limiter.check(
        _UNAUTHENTICATED_AUDIT_CLIENT_SCOPE,
        client_address(request),
        max_requests=settings.audit_unauthenticated_denials_per_client,
        window_seconds=window,
    )
    if not per_client.allowed:
        return False
    overall = unauthenticated_audit_limiter.check(
        _UNAUTHENTICATED_AUDIT_GLOBAL_SCOPE,
        _UNAUTHENTICATED_AUDIT_GLOBAL_IDENTITY,
        max_requests=settings.audit_unauthenticated_denials_global,
        window_seconds=window,
    )
    return overall.allowed


def _record_unauthenticated_denial(request: Request, db: Session) -> None:
    """Persist a 401 for an assessment route without inventing an actor."""
    if not _is_assessment_path(request.url.path):
        return
    if not _unauthenticated_denial_recording_allowed(request):
        return
    record_audit_event_safely(
        db,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        resource_type=AuditResourceType.ASSESSMENT,
        resource_id=_requested_assessment_id(request),
        # The assessment may not exist, so no foreign-key link is created.
        assessment_id=None,
        actor_user_id=None,
        context={"reason": "unauthenticated"},
    )


def _resolve_principal(request: Request, db: Session) -> Principal:
    token = _single_bearer_token(request)

    try:
        claims = decode_access_token(token)
    except InvalidAccessTokenError:
        raise _unauthorized() from None

    user_session = db.get(UserSession, claims.sid)
    if user_session is None or user_session.user_id != claims.sub:
        raise _unauthorized()
    if user_session.revoked_at is not None:
        raise _unauthorized()

    now = datetime.now(UTC)
    if user_session.idle_expires_at <= now or user_session.absolute_expires_at <= now:
        raise _unauthorized()

    user = db.get(User, user_session.user_id)
    if user is None or not user.is_active or not user.is_email_verified:
        raise _unauthorized()

    roles = list_role_names_for_user(db, user_id=user.id)
    return Principal(
        user_id=user.id,
        email=user.email,
        session_id=user_session.id,
        is_active=user.is_active,
        is_email_verified=user.is_email_verified,
        roles=roles,
        claims=claims,
    )


def get_current_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> Principal:
    """Resolve and validate the caller's database-backed access session.

    A failed authentication on an assessment route is recorded with a null
    actor. The original 401 is always preserved, even if the audit write fails.
    """
    try:
        return _resolve_principal(request, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _record_unauthenticated_denial(request, db)
        raise


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def _assessment_forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=ASSESSMENT_FORBIDDEN_DETAIL,
    )


def _assessment_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=ASSESSMENT_NOT_FOUND_DETAIL,
    )


def _record_role_denial(
    db: Session | None,
    principal: Principal,
    *,
    required: str,
) -> None:
    """Record a 403 without exposing any assessment existence information."""
    if db is None:
        # Direct service/test callers do not provide a request session.
        return
    record_audit_event_safely(
        db,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        resource_type=AuditResourceType.ASSESSMENT,
        resource_id=None,
        assessment_id=None,
        actor_user_id=principal.user_id,
        context={"reason": "insufficient_role", "required": required},
    )


def _record_not_visible_denial(
    db: Session,
    principal: Principal,
    assessment_id: uuid.UUID,
    *,
    operation: str,
) -> None:
    """Record a 404 for a resource the principal cannot see.

    The requested identifier is stored only in ``resource_id``; no foreign-key
    link is created, so a nonexistent identifier and another owner's identifier
    remain indistinguishable.
    """
    record_audit_event_safely(
        db,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        resource_type=AuditResourceType.ASSESSMENT,
        resource_id=assessment_id,
        assessment_id=None,
        actor_user_id=principal.user_id,
        context={"reason": "not_visible", "operation": operation},
    )


def require_assessment_reader(
    principal: CurrentPrincipal,
    db: Annotated[Session | None, Depends(get_db)] = None,
) -> Principal:
    """Require a role that may read assessments at all."""
    if not authorization.can_read_assessments(principal):
        _record_role_denial(db, principal, required="read")
        raise _assessment_forbidden()
    return principal


def require_assessment_manager(
    principal: CurrentPrincipal,
    db: Annotated[Session | None, Depends(get_db)] = None,
) -> Principal:
    """Require a role that may create, mutate, or execute assessments."""
    if not authorization.can_manage_assessments(principal):
        _record_role_denial(db, principal, required="manage")
        raise _assessment_forbidden()
    return principal


AssessmentReader = Annotated[Principal, Depends(require_assessment_reader)]
AssessmentManager = Annotated[Principal, Depends(require_assessment_manager)]


def require_admin(principal: CurrentPrincipal) -> Principal:
    """Require the platform Admin role.

    This uses the same database-backed principal and role resolution as the
    assessment dependencies, so revoked sessions and role changes take effect
    immediately. Denials are not recorded as assessment access events because
    the administrative audit surface is not assessment-scoped.
    """
    if not authorization.is_admin(principal):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ADMIN_FORBIDDEN_DETAIL,
        )
    return principal


AdminPrincipal = Annotated[Principal, Depends(require_admin)]


def get_readable_assessment(
    assessment_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: AssessmentReader,
) -> AssessmentJob:
    """Resolve an assessment through the caller's ownership-filtered query."""
    assessment = authorization.get_visible_assessment(db, assessment_id, principal)
    if assessment is None:
        _record_not_visible_denial(db, principal, assessment_id, operation="read")
        raise _assessment_not_found()
    return assessment


def get_manageable_assessment(
    assessment_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    principal: AssessmentManager,
) -> AssessmentJob:
    """Resolve an assessment the caller may mutate or execute."""
    assessment = authorization.get_visible_assessment(db, assessment_id, principal)
    if assessment is None:
        _record_not_visible_denial(db, principal, assessment_id, operation="manage")
        raise _assessment_not_found()
    return assessment


ReadableAssessment = Annotated[AssessmentJob, Depends(get_readable_assessment)]
ManageableAssessment = Annotated[AssessmentJob, Depends(get_manageable_assessment)]


__all__ = [
    "AdminPrincipal",
    "AssessmentManager",
    "AssessmentReader",
    "CurrentPrincipal",
    "ManageableAssessment",
    "Principal",
    "ReadableAssessment",
    "client_address",
    "get_current_principal",
    "get_manageable_assessment",
    "get_readable_assessment",
    "require_admin",
    "require_assessment_manager",
    "require_assessment_reader",
]
