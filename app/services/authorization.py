"""Assessment visibility and management policy.

This module is intentionally independent of FastAPI so route dependencies and
service code can share one policy without importing the API layer. Authorization
is enforced by scoped database queries, never by client-supplied ownership or
identifier secrecy.
"""

from __future__ import annotations

import uuid
from typing import Final, Protocol

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models.assessment import AssessmentJob
from app.schemas.enums import RoleName

READ_ROLE_NAMES: Final[frozenset[str]] = frozenset(
    {
        RoleName.ADMIN.value,
        RoleName.SECURITY_ANALYST.value,
        RoleName.VIEWER.value,
    }
)
MANAGE_ROLE_NAMES: Final[frozenset[str]] = frozenset(
    {
        RoleName.ADMIN.value,
        RoleName.SECURITY_ANALYST.value,
    }
)


class PrincipalLike(Protocol):
    """Minimal authenticated identity consumed by the authorization policy."""

    user_id: uuid.UUID
    roles: tuple[str, ...]


def is_admin(principal: PrincipalLike) -> bool:
    return RoleName.ADMIN.value in principal.roles


def can_read_assessments(principal: PrincipalLike) -> bool:
    return is_admin(principal) or any(role in READ_ROLE_NAMES for role in principal.roles)


def can_manage_assessments(principal: PrincipalLike) -> bool:
    return is_admin(principal) or any(role in MANAGE_ROLE_NAMES for role in principal.roles)


def visible_assessments_statement(principal: PrincipalLike) -> Select[tuple[AssessmentJob]]:
    """Build a query containing only assessments the principal may read.

    Admins deliberately receive no owner predicate so legacy records with a
    null owner remain reachable. Every other caller is constrained to rows they
    own; null-owner rows therefore never match.
    """

    statement = select(AssessmentJob)
    if is_admin(principal):
        return statement
    return statement.where(AssessmentJob.owner_id == principal.user_id)


def get_visible_assessment(
    db: Session,
    assessment_id: uuid.UUID,
    principal: PrincipalLike,
) -> AssessmentJob | None:
    statement = visible_assessments_statement(principal).where(AssessmentJob.id == assessment_id)
    return db.scalar(statement)


def list_visible_assessments(
    db: Session,
    principal: PrincipalLike,
    *,
    limit: int,
    offset: int,
) -> list[AssessmentJob]:
    statement = (
        visible_assessments_statement(principal)
        .order_by(AssessmentJob.created_at.desc(), AssessmentJob.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(db.scalars(statement).all())


__all__ = [
    "MANAGE_ROLE_NAMES",
    "READ_ROLE_NAMES",
    "PrincipalLike",
    "can_manage_assessments",
    "can_read_assessments",
    "get_visible_assessment",
    "is_admin",
    "list_visible_assessments",
    "visible_assessments_statement",
]
