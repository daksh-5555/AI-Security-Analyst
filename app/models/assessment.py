import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import AssessmentStatus, AssessmentType

if TYPE_CHECKING:
    from app.models.analysis_run import AnalysisRun
    from app.models.assessment_finding import AssessmentFinding
    from app.models.assessment_status_history import AssessmentStatusHistory
    from app.models.repository_target import RepositoryTarget


class AssessmentJob(Base):
    """A persisted request to run an assessment."""

    __tablename__ = "assessment_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_assessment_jobs_owner_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
        index=True,
    )
    assessment_type: Mapped[AssessmentType] = mapped_column(
        SAEnum(
            AssessmentType,
            name="assessment_type",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    status: Mapped[AssessmentStatus] = mapped_column(
        SAEnum(
            AssessmentStatus,
            name="assessment_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
        default=AssessmentStatus.QUEUED,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    status_history: Mapped[list["AssessmentStatusHistory"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="AssessmentStatusHistory.changed_at",
    )
    repository_target: Mapped["RepositoryTarget | None"] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        uselist=False,
    )
    findings: Mapped[list["AssessmentFinding"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="AssessmentFinding.position",
    )
    analysis_runs: Mapped[list["AnalysisRun"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="AnalysisRun.created_at",
    )
