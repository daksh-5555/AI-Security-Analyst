"""Configure and use authenticated local-lab sessions for web targets (M15, ADR-0018).

Stores only the established session cookie, never the password. The cookie is
never returned by the API, logged, or placed in evidence. The feature is
off by default and forbidden in staging/production.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.web_target_lab_session import WebTargetLabSession
from app.schemas.enums import AuditAction, AuditOutcome, AuditResourceType
from app.services.audit import record_audit_event
from app.services.net.lab_session import LabAuthDisabledError, establish_lab_session
from app.services.target_authorization import require_authorized_web_target


def configure_lab_session(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    username: str,
    password: str,
    actor_user_id: uuid.UUID | None,
) -> WebTargetLabSession:
    """Log in once with the supplied lab credentials and persist the session cookie."""
    if not settings.web_auth_lab_enabled:
        raise LabAuthDisabledError()
    target = require_authorized_web_target(db, assessment_id)
    db.rollback()  # release the read transaction before network work
    session = establish_lab_session(db, target, username=username, password=password)

    now = datetime.now(UTC)
    db.execute(
        delete(WebTargetLabSession).where(WebTargetLabSession.assessment_id == assessment_id)
    )
    row = WebTargetLabSession(
        assessment_id=assessment_id,
        username=session.username,
        login_path=session.login_path,
        cookie_header=session.cookie_header,
        established_by_user_id=actor_user_id,
        established_at=now,
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        action=AuditAction.WEB_TARGET_LAB_SESSION_ESTABLISHED,
        outcome=AuditOutcome.SUCCESS,
        resource_type=AuditResourceType.ASSESSMENT_TARGET,
        resource_id=target.id,
        assessment_id=assessment_id,
        actor_user_id=actor_user_id,
        occurred_at=now,
        context={"username": session.username, "login_path": session.login_path},
    )
    db.commit()
    db.refresh(row)
    return row


def get_lab_session(db: Session, assessment_id: uuid.UUID) -> WebTargetLabSession | None:
    return db.scalar(
        select(WebTargetLabSession).where(WebTargetLabSession.assessment_id == assessment_id)
    )


def clear_lab_session(
    db: Session, assessment_id: uuid.UUID, *, actor_user_id: uuid.UUID | None
) -> bool:
    row = get_lab_session(db, assessment_id)
    if row is None:
        return False
    db.delete(row)
    record_audit_event(
        db,
        action=AuditAction.WEB_TARGET_LAB_SESSION_CLEARED,
        outcome=AuditOutcome.SUCCESS,
        resource_type=AuditResourceType.ASSESSMENT_TARGET,
        resource_id=assessment_id,
        assessment_id=assessment_id,
        actor_user_id=actor_user_id,
        occurred_at=datetime.now(UTC),
    )
    db.commit()
    return True


def lab_cookie_header(db: Session, assessment_id: uuid.UUID) -> str | None:
    """The stored lab session cookie for web runs, or None when unavailable.

    Returns None unless the feature is enabled, so a disabled deployment never
    sends a stale cookie.
    """
    if not settings.web_auth_lab_enabled:
        return None
    row = get_lab_session(db, assessment_id)
    return row.cookie_header if row is not None else None


__all__ = [
    "clear_lab_session",
    "configure_lab_session",
    "get_lab_session",
    "lab_cookie_header",
]
