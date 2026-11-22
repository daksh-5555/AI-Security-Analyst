"""Assessment target ownership and authorization (M4, ADR-0004).

Every target that analysis may read or contact has an ``AssessmentTarget`` row.
Analysis refuses to run unless that row is ``authorized``.

- Repository targets are authorized by their owner's registration
  (``owner_registration``) because the path is already confined to the configured
  allowed roots and, with ``REPOSITORY_ISOLATION=per_user``, to the owner's own
  sub-root.
- Web targets require the host to be on ``WEB_TARGET_ALLOWED_HOSTS`` *and* an
  explicit confirmation with a written authorization statement
  (``explicit_confirmation``). Both are audited.
- Authorization can be revoked and re-confirmed. Revocation takes effect for the
  next run.

``DatabaseTargetAuthorizationPolicy`` implements the ``TargetAuthorizationPolicy``
protocol, and ``build_target_client`` is the only way to obtain a network client
for a web target: it is limited to that target's host.
"""

from __future__ import annotations

import ipaddress
import posixpath
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import quote, unquote, urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.assessment import AssessmentJob
from app.models.assessment_target import AssessmentTarget
from app.models.repository_target import RepositoryTarget
from app.schemas.enums import (
    AssessmentStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    AuthorizationBasis,
    TargetStatus,
    TargetType,
)
from app.services.audit import record_audit_event
from app.services.net import GuardedHttpClient
from app.services.tooling.target_policy import (
    NetworkSafetyPolicy,
    TargetDecision,
    TargetDecisionReason,
    TargetKind,
    TargetRequest,
)

POLICY_VERSION: Final[str] = "target-policy-1"
_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}
MAX_TARGET_URL_LENGTH: Final[int] = 2048


class TargetAuthorizationError(ValueError):
    """Base error; ``code`` is safe to expose."""

    code = "target_error"

    def __init__(self, code: str | None = None) -> None:
        super().__init__(code or self.code)
        if code:
            self.code = code


class InvalidTargetError(TargetAuthorizationError):
    code = "invalid_target"


class TargetNotAllowlistedError(TargetAuthorizationError):
    code = "target_not_allowlisted"


class TargetAlreadyRegisteredError(TargetAuthorizationError):
    code = "target_already_registered"


class AssessmentNotWebError(TargetAuthorizationError):
    code = "assessment_not_web_security"


class AssessmentNotQueuedForTargetError(TargetAuthorizationError):
    code = "assessment_not_queued"


class TargetNotFoundError(TargetAuthorizationError):
    code = "target_not_found"


class TargetNotAuthorizedError(TargetAuthorizationError):
    code = "target_not_authorized"


class WebTargetNotFoundError(TargetAuthorizationError):
    code = "web_target_not_found"


class InvalidTargetTransitionError(TargetAuthorizationError):
    code = "invalid_target_transition"


@dataclass(frozen=True, slots=True)
class CanonicalWebTarget:
    scheme: str
    host: str
    port: int
    base_path: str

    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = _DEFAULT_PORTS[self.scheme] == self.port
        return f"{self.scheme}://{host}" if default else f"{self.scheme}://{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.origin}{self.base_path}"


def canonicalize_web_target(raw: str) -> CanonicalWebTarget:
    """Canonical base URL: http(s), no credentials, query, or fragment; normalized path."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > MAX_TARGET_URL_LENGTH:
        raise InvalidTargetError()
    value = raw.strip()
    if any(ord(char) < 33 for char in value):
        raise InvalidTargetError()
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetError() from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise InvalidTargetError("scheme_not_allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise InvalidTargetError("credentials_in_target")
    if parts.query or parts.fragment:
        raise InvalidTargetError("query_or_fragment_not_allowed")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidTargetError()
    try:
        literal = ipaddress.ip_address(host)
        host = str(literal)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise InvalidTargetError() from exc
    path = unquote(parts.path or "/")
    normalized = posixpath.normpath("/" + path.lstrip("/"))
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return CanonicalWebTarget(
        scheme=scheme,
        host=host,
        port=port if port is not None else _DEFAULT_PORTS[scheme],
        base_path=quote(normalized, safe="/-._~!$&'()*+,;=:@%"),
    )


def local_test_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(
        ipaddress.ip_network(network) for network in settings.web_target_allowed_local_networks
    )


def web_network_policy() -> NetworkSafetyPolicy:
    """Network policy for runtime tools contacting authorized web targets."""
    return NetworkSafetyPolicy(
        allowed_local_networks=local_test_networks(),
        max_requests_per_second=settings.web_target_max_requests_per_second,
        user_agent=f"AI-Security-Analyst/{settings.app_version} (authorized security assessment)",
    )


def policy_snapshot(target_type: TargetType) -> dict[str, Any]:
    """Non-sensitive record of the policy in force when a target was authorized."""
    snapshot: dict[str, Any] = {"policy_version": POLICY_VERSION, "target_type": target_type.value}
    if target_type is TargetType.REPOSITORY:
        snapshot["repository_isolation"] = settings.repository_isolation
        return snapshot
    policy = web_network_policy()
    snapshot.update(
        {
            "allowed_schemes": sorted(policy.allowed_schemes),
            "max_redirects": policy.max_redirects,
            "total_timeout_seconds": policy.total_timeout_seconds,
            "max_response_bytes": policy.max_response_bytes,
            "max_requests_per_second": policy.max_requests_per_second,
            "max_concurrency_per_target": policy.max_concurrency_per_target,
            "allowed_local_networks": [str(network) for network in policy.allowed_local_networks],
        }
    )
    return snapshot


def display_target(target: AssessmentTarget, repository_target: RepositoryTarget | None) -> str:
    """Safe display form: repository paths relative to their root, URLs as canonical."""
    if target.target_type is TargetType.WEB_APPLICATION:
        return target.canonical_target
    from app.services.repository_targets import repository_target_display_location

    location = repository_target.location if repository_target else target.canonical_target
    return repository_target_display_location(location)


# -- creation ---------------------------------------------------------------------


def add_repository_authorization(
    db: Session,
    assessment: AssessmentJob,
    repository_target: RepositoryTarget,
    *,
    actor_user_id: uuid.UUID | None,
    now: datetime,
) -> AssessmentTarget:
    """Stage the authorization row for a newly registered repository (caller commits)."""
    target = AssessmentTarget(
        assessment_id=assessment.id,
        target_type=TargetType.REPOSITORY,
        repository_target_id=repository_target.id,
        canonical_target=repository_target.location,
        status=TargetStatus.AUTHORIZED,
        authorization_basis=AuthorizationBasis.OWNER_REGISTRATION,
        authorization_statement=(
            "Repository registered by a user who may manage this assessment, inside the "
            "configured allowed roots."
        ),
        created_by_user_id=actor_user_id,
        authorized_by_user_id=actor_user_id,
        authorized_at=now,
        policy_snapshot=policy_snapshot(TargetType.REPOSITORY),
        created_at=now,
        updated_at=now,
    )
    db.add(target)
    return target


def _audit(
    db: Session,
    target: AssessmentTarget,
    action: AuditAction,
    actor_user_id: uuid.UUID | None,
    now: datetime,
    context: dict[str, Any],
) -> None:
    record_audit_event(
        db,
        action=action,
        outcome=AuditOutcome.SUCCESS,
        resource_type=AuditResourceType.ASSESSMENT_TARGET,
        resource_id=target.id,
        assessment_id=target.assessment_id,
        actor_user_id=actor_user_id,
        occurred_at=now,
        context={"target_type": target.target_type.value, **context},
    )


def _require_allowlisted(canonical: CanonicalWebTarget) -> None:
    if canonical.host not in set(settings.web_target_allowed_hosts):
        raise TargetNotAllowlistedError()


def register_web_target(
    db: Session,
    assessment: AssessmentJob,
    *,
    base_url: str,
    authorization_statement: str,
    actor_user_id: uuid.UUID,
) -> AssessmentTarget:
    """Register and explicitly authorize a web target for a queued web assessment."""
    if assessment.assessment_type is not AssessmentType.WEB_SECURITY:
        raise AssessmentNotWebError()
    if assessment.status is not AssessmentStatus.QUEUED:
        raise AssessmentNotQueuedForTargetError()
    canonical = canonicalize_web_target(base_url)
    _require_allowlisted(canonical)
    existing = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.assessment_id == assessment.id,
            AssessmentTarget.target_type == TargetType.WEB_APPLICATION,
        )
    )
    if existing is not None:
        raise TargetAlreadyRegisteredError()

    now = datetime.now(UTC)
    target = AssessmentTarget(
        assessment_id=assessment.id,
        target_type=TargetType.WEB_APPLICATION,
        canonical_target=canonical.url,
        status=TargetStatus.AUTHORIZED,
        authorization_basis=AuthorizationBasis.EXPLICIT_CONFIRMATION,
        authorization_statement=authorization_statement.strip(),
        created_by_user_id=actor_user_id,
        authorized_by_user_id=actor_user_id,
        authorized_at=now,
        policy_snapshot=policy_snapshot(TargetType.WEB_APPLICATION),
        created_at=now,
        updated_at=now,
    )
    db.add(target)
    try:
        db.flush()
        _audit(
            db,
            target,
            AuditAction.ASSESSMENT_TARGET_AUTHORIZED,
            actor_user_id,
            now,
            {"basis": AuthorizationBasis.EXPLICIT_CONFIRMATION.value, "host": canonical.host},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise TargetAlreadyRegisteredError() from exc
    except Exception:
        db.rollback()
        raise
    return target


# -- lifecycle --------------------------------------------------------------------


def list_targets(db: Session, assessment_id: uuid.UUID) -> list[AssessmentTarget]:
    return list(
        db.scalars(
            select(AssessmentTarget)
            .where(AssessmentTarget.assessment_id == assessment_id)
            .order_by(AssessmentTarget.created_at, AssessmentTarget.id)
        ).all()
    )


def get_target(db: Session, assessment_id: uuid.UUID, target_id: uuid.UUID) -> AssessmentTarget:
    target = db.get(AssessmentTarget, target_id)
    if target is None or target.assessment_id != assessment_id:
        raise TargetNotFoundError()
    return target


def authorize_target(
    db: Session,
    assessment: AssessmentJob,
    target_id: uuid.UUID,
    *,
    authorization_statement: str,
    actor_user_id: uuid.UUID,
) -> AssessmentTarget:
    """Explicitly (re-)authorize a pending or revoked target."""
    target = get_target(db, assessment.id, target_id)
    if target.status is TargetStatus.AUTHORIZED:
        raise InvalidTargetTransitionError()
    if target.target_type is TargetType.WEB_APPLICATION:
        _require_allowlisted(canonicalize_web_target(target.canonical_target))
    now = datetime.now(UTC)
    target.status = TargetStatus.AUTHORIZED
    target.authorization_basis = AuthorizationBasis.EXPLICIT_CONFIRMATION
    target.authorization_statement = authorization_statement.strip()
    target.authorized_by_user_id = actor_user_id
    target.authorized_at = now
    target.revoked_at = None
    target.revoked_by_user_id = None
    target.policy_snapshot = policy_snapshot(target.target_type)
    target.updated_at = now
    try:
        _audit(
            db,
            target,
            AuditAction.ASSESSMENT_TARGET_AUTHORIZED,
            actor_user_id,
            now,
            {"basis": AuthorizationBasis.EXPLICIT_CONFIRMATION.value},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return target


def revoke_target(
    db: Session,
    assessment: AssessmentJob,
    target_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID,
) -> AssessmentTarget:
    """Revoke authorization; new runs are refused until re-authorized."""
    target = get_target(db, assessment.id, target_id)
    if target.status is TargetStatus.REVOKED:
        raise InvalidTargetTransitionError()
    now = datetime.now(UTC)
    previous = target.status.value
    target.status = TargetStatus.REVOKED
    target.revoked_at = now
    target.revoked_by_user_id = actor_user_id
    target.updated_at = now
    try:
        _audit(
            db,
            target,
            AuditAction.ASSESSMENT_TARGET_REVOKED,
            actor_user_id,
            now,
            {"previous_status": previous},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return target


def require_authorized_repository_target(
    db: Session,
    assessment_id: uuid.UUID,
    repository_target: RepositoryTarget,
) -> AssessmentTarget:
    """Fail closed unless the repository target has an authorized record."""
    target = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.assessment_id == assessment_id,
            AssessmentTarget.repository_target_id == repository_target.id,
        )
    )
    if target is None or target.status is not TargetStatus.AUTHORIZED:
        raise TargetNotAuthorizedError()
    return target


def require_authorized_web_target(db: Session, assessment_id: uuid.UUID) -> AssessmentTarget:
    """Return the assessment's authorized web target or fail closed."""
    target = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.assessment_id == assessment_id,
            AssessmentTarget.target_type == TargetType.WEB_APPLICATION,
        )
    )
    if target is None:
        raise WebTargetNotFoundError()
    if target.status is not TargetStatus.AUTHORIZED:
        raise TargetNotAuthorizedError()
    # The deployment allowlist can shrink after authorization; re-check it before
    # any run record or network client is created.
    try:
        _require_allowlisted(canonicalize_web_target(target.canonical_target))
    except (InvalidTargetError, TargetNotAllowlistedError) as exc:
        raise TargetNotAuthorizedError("not_allowlisted") from exc
    return target


# -- policy and client ------------------------------------------------------------


def _within_base_path(path: str, base: str) -> bool:
    """Segment-aware containment: ``/app`` covers ``/app/x`` but not ``/application``."""
    if base == "/" or path == base:
        return True
    prefix = base if base.endswith("/") else base + "/"
    return path.startswith(prefix)


within_base_path = _within_base_path


class DatabaseTargetAuthorizationPolicy:
    """``TargetAuthorizationPolicy`` backed by ``assessment_targets``."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def evaluate(self, request: TargetRequest) -> TargetDecision:
        target_type = (
            TargetType.WEB_APPLICATION
            if request.kind is TargetKind.WEB_APPLICATION
            else TargetType.REPOSITORY
        )
        target = self._db.scalar(
            select(AssessmentTarget).where(
                AssessmentTarget.assessment_id == request.assessment_id,
                AssessmentTarget.target_type == target_type,
            )
        )
        assessment = self._db.get(AssessmentJob, request.assessment_id)
        if target is None or assessment is None:
            return TargetDecision.deny(TargetDecisionReason.NOT_AUTHORIZED)
        if target.status is not TargetStatus.AUTHORIZED:
            return TargetDecision.deny(TargetDecisionReason.NOT_AUTHORIZED)
        if target_type is TargetType.WEB_APPLICATION:
            try:
                requested = canonicalize_web_target(request.canonical_target)
                registered = canonicalize_web_target(target.canonical_target)
            except InvalidTargetError:
                return TargetDecision.deny(TargetDecisionReason.INVALID_TARGET)
            if requested.origin != registered.origin or not _within_base_path(
                requested.base_path, registered.base_path
            ):
                return TargetDecision.deny(TargetDecisionReason.NOT_AUTHORIZED)
            if registered.host not in set(settings.web_target_allowed_hosts):
                return TargetDecision.deny(TargetDecisionReason.NOT_ALLOWLISTED)
        elif request.canonical_target != target.canonical_target:
            return TargetDecision.deny(TargetDecisionReason.NOT_AUTHORIZED)
        return TargetDecision.allow()


def build_target_client(
    db: Session,
    target: AssessmentTarget,
    *,
    default_headers: dict[str, str] | None = None,
) -> GuardedHttpClient:
    """The only way to obtain a network client for a web target.

    The client may contact only the authorized target's host, under the web
    network policy. Revoked, pending, or non-allowlisted targets are refused.
    ``default_headers`` (an authorized local-lab session cookie) are bound to the
    client and travel only to that single host.
    """
    if target.target_type is not TargetType.WEB_APPLICATION:
        raise TargetNotAuthorizedError()
    decision = DatabaseTargetAuthorizationPolicy(db).evaluate(
        TargetRequest(
            kind=TargetKind.WEB_APPLICATION,
            canonical_target=target.canonical_target,
            assessment_id=target.assessment_id,
            requested_by=target.created_by_user_id or uuid.UUID(int=0),
        )
    )
    if not decision.allowed:
        raise TargetNotAuthorizedError(decision.reason.value)
    canonical = canonicalize_web_target(target.canonical_target)
    return GuardedHttpClient(
        web_network_policy(),
        allowed_hosts=frozenset({canonical.host}),
        default_headers=default_headers,
    )


__all__ = [
    "CanonicalWebTarget",
    "DatabaseTargetAuthorizationPolicy",
    "InvalidTargetError",
    "TargetAlreadyRegisteredError",
    "TargetAuthorizationError",
    "TargetNotAllowlistedError",
    "TargetNotAuthorizedError",
    "TargetNotFoundError",
    "WebTargetNotFoundError",
    "require_authorized_web_target",
    "add_repository_authorization",
    "authorize_target",
    "build_target_client",
    "canonicalize_web_target",
    "list_targets",
    "policy_snapshot",
    "register_web_target",
    "require_authorized_repository_target",
    "revoke_target",
    "within_base_path",
]
