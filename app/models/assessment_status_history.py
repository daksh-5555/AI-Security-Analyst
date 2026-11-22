import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Uuid
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import AssessmentStatus

if TYPE_CHECKING:
    from app.models.assessment import AssessmentJob


class AssessmentStatusHistory(Base):
    """An immutable audit record for one assessment status transition."""

    __tablename__ = "assessment_status_history"
    __table_args__ = (
        CheckConstraint(
            "previous_status <> new_status",
            name="ck_assessment_status_history_status_change",
        ),
        Index(
            "ix_assessment_status_history_assessment_id_changed_at",
            "assessment_id",
            "changed_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assessment_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_status: Mapped[AssessmentStatus] = mapped_column(
        SAEnum(
            AssessmentStatus,
            name="assessment_previous_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    new_status: Mapped[AssessmentStatus] = mapped_column(
        SAEnum(
            AssessmentStatus,
            name="assessment_new_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    changed_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    assessment: Mapped["AssessmentJob"] = relationship(back_populates="status_history")
