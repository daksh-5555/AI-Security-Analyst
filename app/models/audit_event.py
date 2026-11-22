import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Uuid
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import AuditAction, AuditOutcome, AuditResourceType


class AuditEvent(Base):
    """A durable, queryable record of one sensitive security operation.

    Audit rows are append-only from the application's perspective: no service
    mutates or deletes them and no API endpoint exposes them. ``assessment_id``
    uses ``ON DELETE SET NULL`` so deleting an assessment never removes its audit
    history; the immutable ``resource_id`` still records which assessment the
    event concerned.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index(
            "ix_audit_events_assessment_id_occurred_at",
            "assessment_id",
            "occurred_at",
        ),
        Index(
            "ix_audit_events_actor_user_id_occurred_at",
            "actor_user_id",
            "occurred_at",
        ),
        Index(
            "ix_audit_events_action_occurred_at",
            "action",
            "occurred_at",
        ),
        Index("ix_audit_events_occurred_at", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_audit_events_actor_user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_jobs.id",
            name="fk_audit_events_assessment_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    resource_type: Mapped[AuditResourceType] = mapped_column(
        SAEnum(
            AuditResourceType,
            name="audit_resource_type",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=32,
        ),
        nullable=False,
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    action: Mapped[AuditAction] = mapped_column(
        SAEnum(
            AuditAction,
            name="audit_action",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=64,
        ),
        nullable=False,
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        SAEnum(
            AuditOutcome,
            name="audit_outcome",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=16,
        ),
        nullable=False,
    )
    context: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
