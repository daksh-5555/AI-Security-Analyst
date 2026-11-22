"""Durable audit-event persistence for sensitive assessment operations.

Audit events are written inside the caller's transaction so a successful
mutation and its audit record cannot silently diverge. Denial events, by
contrast, are committed independently because the request is being rejected and
the business mutation (if any) has already been rolled back.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.schemas.enums import AuditAction, AuditOutcome, AuditResourceType

logger = logging.getLogger(__name__)


def record_audit_event(
    db: Session,
    *,
    action: AuditAction,
    outcome: AuditOutcome,
    resource_type: AuditResourceType,
    resource_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    context: Mapping[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> AuditEvent:
    """Stage an audit event in the caller's current transaction."""
    event = AuditEvent(
        occurred_at=occurred_at or datetime.now(UTC),
        actor_user_id=actor_user_id,
        assessment_id=assessment_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        outcome=outcome,
        context=dict(context) if context is not None else None,
    )
    db.add(event)
    return event


def record_audit_event_safely(
    db: Session,
    *,
    action: AuditAction,
    outcome: AuditOutcome,
    resource_type: AuditResourceType,
    resource_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    context: Mapping[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> None:
    """Commit one audit event without changing the caller's rejection outcome.

    Precondition: invoke only when the request is already being rejected and no
    pending business mutation needs to survive. This helper unconditionally
    rolls back the session before writing, so staged business changes are
    discarded by design. Never call it after a mutation that must be committed.

    Any pending transaction state is discarded first so this write cannot commit
    a partial business mutation. A persistence failure is logged generically and
    never surfaces to the client.
    """
    try:
        # Precondition guard: discard all pending business state. Callers must
        # only use this helper on rejection paths with nothing to preserve.
        db.rollback()
        record_audit_event(
            db,
            action=action,
            outcome=outcome,
            resource_type=resource_type,
            resource_id=resource_id,
            assessment_id=assessment_id,
            actor_user_id=actor_user_id,
            context=context,
            occurred_at=occurred_at,
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            logger.error("Rollback failed after an audit persistence error.")
        logger.exception("Audit event persistence failed for action %s", action.value)
