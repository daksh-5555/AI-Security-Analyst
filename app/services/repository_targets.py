import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.assessment import AssessmentJob
from app.models.repository_target import RepositoryTarget
from app.schemas.enums import (
    AssessmentStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
)
from app.schemas.repository import RepositorySourceCreate
from app.services.audit import record_audit_event
from app.services.target_authorization import add_repository_authorization


class RepositoryTargetError(ValueError):
    """Base error for repository target operations."""


class AssessmentNotFoundError(RepositoryTargetError):
    """Raised when the assessment does not exist."""

    def __init__(self) -> None:
        super().__init__("Assessment not found")


class AssessmentNotRepositoryError(RepositoryTargetError):
    """Raised when the assessment is not a repository assessment."""

    def __init__(self) -> None:
        super().__init__("Assessment is not a repository assessment")


class AssessmentNotQueuedError(RepositoryTargetError):
    """Raised when the assessment is not queued."""

    def __init__(self) -> None:
        super().__init__("Assessment must be queued to register a repository target")


class DuplicateRepositoryTargetError(RepositoryTargetError):
    """Raised when the assessment already has a repository target."""

    def __init__(self) -> None:
        super().__init__("Repository target is already registered")


class InvalidRepositoryLocationError(RepositoryTargetError):
    """Raised when a repository location is not a safe, usable directory."""


def _resolved_allowed_roots() -> list[Path]:
    roots: list[Path] = []
    for root in settings.repository_allowed_roots:
        try:
            roots.append(root.expanduser().resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            continue
    return roots


def _resolve_root(root: Path) -> Path | None:
    try:
        return root.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def _is_windows_unc_or_device_path(path: Path) -> bool:
    """Return True for Windows UNC, device, and extended-length paths."""
    if os.name != "nt":
        return False
    return path.drive.startswith("\\\\")


def _is_within_root(candidate: Path, root: Path) -> bool:
    """Return True when a canonical path is contained by a canonical root.

    ``Path.is_relative_to`` compares path components rather than string
    prefixes, so a sibling such as ``C:\\projects-evil`` is not treated as
    inside ``C:\\projects``. On Windows, ``WindowsPath`` comparisons are
    case-insensitive.
    """
    try:
        return candidate.is_relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False


def repository_roots_for_owner(owner_id: uuid.UUID | None) -> list[Path] | None:
    """Allowed roots for an assessment owner, or None for the shared layout.

    With ``REPOSITORY_ISOLATION=per_user`` each owner may use only
    ``<allowed root>/<owner id>/`` (the directory must exist). Ownerless legacy
    assessments get no roots at all, so they cannot register or analyse anything.
    """
    if settings.repository_isolation != "per_user":
        return None
    if owner_id is None:
        return []
    return [root / str(owner_id) for root in _resolved_allowed_roots()]


def validate_repository_location(
    location: str,
    *,
    allowed_roots: list[Path] | None = None,
) -> Path:
    """Resolve and validate a repository directory against configured roots.

    The candidate is resolved first, which canonicalizes ``..`` segments and
    follows symbolic links, junctions, and other reparse points before the
    containment check runs. Containment is component-based and platform-aware,
    so Windows comparisons are case-insensitive and sibling-prefix paths are not
    accepted. Windows UNC and device paths are rejected before resolution unless
    an allowed root is itself a UNC or device path.
    """
    if allowed_roots is None:
        allowed_roots = _resolved_allowed_roots()
    else:
        allowed_roots = [_resolve_root(root) for root in allowed_roots]
        allowed_roots = [root for root in allowed_roots if root is not None]
    if not allowed_roots:
        raise InvalidRepositoryLocationError("No repository allowed roots are configured")

    try:
        candidate_input = Path(location).expanduser()
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidRepositoryLocationError(
            "Repository location must be an existing directory"
        ) from exc

    if _is_windows_unc_or_device_path(candidate_input) and not any(
        _is_windows_unc_or_device_path(root) for root in allowed_roots
    ):
        raise InvalidRepositoryLocationError("Repository location must be an existing directory")

    try:
        candidate = candidate_input.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidRepositoryLocationError(
            "Repository location must be an existing directory"
        ) from exc

    if not candidate.is_dir():
        raise InvalidRepositoryLocationError("Repository location must be a directory")

    if not any(_is_within_root(candidate, root) for root in allowed_roots):
        raise InvalidRepositoryLocationError("Repository location is outside the allowed roots")

    return candidate


def repository_target_display_location(location: str | Path) -> str:
    """Return a non-sensitive repository path for API responses.

    The value is relative to the configured allowed root that contains the
    stored location. If the location is no longer under a configured root, a
    generic identifier is returned instead of exposing an absolute host path.
    """
    try:
        candidate = Path(location).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return "repository"

    for root in _resolved_allowed_roots():
        try:
            if candidate.is_relative_to(root):
                relative = candidate.relative_to(root)
                return relative.as_posix() if relative.parts else "."
        except (OSError, RuntimeError, ValueError):
            continue
    return "repository"


def _get_assessment_or_raise(
    db: Session,
    assessment_id: uuid.UUID,
) -> AssessmentJob:
    assessment = db.get(AssessmentJob, assessment_id)
    if assessment is None:
        raise AssessmentNotFoundError
    return assessment


def create_repository_target(
    db: Session,
    assessment: AssessmentJob,
    source: RepositorySourceCreate,
    *,
    actor_user_id: uuid.UUID | None = None,
) -> RepositoryTarget:
    """Register a validated local repository target for a queued assessment.

    The caller must pass an already-authorized assessment object so this mutation
    cannot be reached by supplying an arbitrary assessment identifier. The audit
    event is committed with the target and contains no filesystem path.
    """
    assessment_id = assessment.id

    if assessment.assessment_type is not AssessmentType.REPOSITORY:
        raise AssessmentNotRepositoryError
    if assessment.status is not AssessmentStatus.QUEUED:
        raise AssessmentNotQueuedError

    existing = db.scalar(
        select(RepositoryTarget).where(RepositoryTarget.assessment_id == assessment.id)
    )
    if existing is not None:
        raise DuplicateRepositoryTargetError

    resolved_location = validate_repository_location(
        source.location,
        allowed_roots=repository_roots_for_owner(assessment.owner_id),
    )

    now = datetime.now(UTC)
    target = RepositoryTarget(
        assessment_id=assessment.id,
        source_kind=source.source_kind,
        location=str(resolved_location),
        created_at=now,
        updated_at=now,
    )
    db.add(target)
    try:
        db.flush()
        add_repository_authorization(db, assessment, target, actor_user_id=actor_user_id, now=now)
        record_audit_event(
            db,
            action=AuditAction.REPOSITORY_TARGET_CREATED,
            outcome=AuditOutcome.SUCCESS,
            resource_type=AuditResourceType.REPOSITORY_TARGET,
            resource_id=target.id,
            assessment_id=assessment_id,
            actor_user_id=actor_user_id,
            occurred_at=now,
            context={"source_kind": source.source_kind.value},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        duplicate = db.scalar(
            select(RepositoryTarget).where(RepositoryTarget.assessment_id == assessment_id)
        )
        if duplicate is not None:
            raise DuplicateRepositoryTargetError from exc
        if db.get(AssessmentJob, assessment_id) is None:
            raise AssessmentNotFoundError from exc
        raise
    except Exception:
        db.rollback()
        raise
    return target


def get_repository_target(
    db: Session,
    assessment_id: uuid.UUID,
) -> RepositoryTarget | None:
    """Return the registered repository target, or None when none exists."""
    _get_assessment_or_raise(db, assessment_id)
    return db.scalar(
        select(RepositoryTarget).where(RepositoryTarget.assessment_id == assessment_id)
    )
