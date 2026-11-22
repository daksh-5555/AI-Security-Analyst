"""Role lookup and default-role assignment.

Role decisions use deterministic seeded identifiers from ``app.core.roles``
rather than mutable display names. ``User.roles`` is not consulted because
``SessionLocal`` uses ``expire_on_commit=False`` and that collection can be
stale; assignments are queried directly from ``user_roles``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.roles import DEFAULT_ROLE_ID, DEFAULT_ROLE_NAME
from app.db.integrity import USER_ROLE_ASSIGNMENT, log_unexpected_integrity_error, violates
from app.models.role import Role
from app.models.user_role import UserRole

logger = logging.getLogger(__name__)


class RoleConfigurationError(RuntimeError):
    """Raised when a required canonical role is missing or inconsistent."""


def user_has_any_role(db: Session, *, user_id: uuid.UUID) -> bool:
    """Report whether the user has any role assignment."""
    return (
        db.execute(
            select(UserRole.user_id).where(UserRole.user_id == user_id).limit(1)
        ).scalar_one_or_none()
        is not None
    )


def list_role_names_for_user(db: Session, *, user_id: uuid.UUID) -> tuple[str, ...]:
    """Return the user's role names from a fresh assignment query.

    ``User.roles`` is intentionally not consulted because it may be stale under
    ``expire_on_commit=False``. Unknown names are returned verbatim so callers
    do not silently drop data the database actually contains.
    """
    rows = db.execute(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.name)
    ).scalars()
    return tuple(rows.all())


def _load_default_role(db: Session) -> Role:
    role = db.get(Role, DEFAULT_ROLE_ID)
    if role is None:
        raise RoleConfigurationError(
            "The default Security Analyst role is missing from the roles table."
        )
    if role.name != DEFAULT_ROLE_NAME.value:
        raise RoleConfigurationError(
            "The default role identifier does not match the canonical role name."
        )
    return role


def assign_default_role_if_unassigned(db: Session, *, user_id: uuid.UUID) -> bool:
    """Grant the default role only when the user currently has no assignment.

    Returns ``True`` when a row was added. A concurrent verification that wins
    the composite primary-key race is treated as success for this caller.
    """
    if user_has_any_role(db, user_id=user_id):
        return False

    _load_default_role(db)
    assignment = UserRole(
        user_id=user_id,
        role_id=DEFAULT_ROLE_ID,
        created_at=datetime.now(UTC),
    )
    try:
        with db.begin_nested():
            db.add(assignment)
            db.flush()
    except IntegrityError as exc:
        if violates(exc, USER_ROLE_ASSIGNMENT):
            # Another concurrent request created the same assignment first.
            return False
        # A foreign-key or other violation (for example, the user row was
        # deleted concurrently) is not the expected race and must not be
        # reported as a successful assignment.
        log_unexpected_integrity_error(logger, "default role assignment", exc)
        raise
    return True
