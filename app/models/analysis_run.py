import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text, Uuid, text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import AnalysisRunStatus

if TYPE_CHECKING:
    from app.models.assessment import AssessmentJob
    from app.models.assessment_finding import AssessmentFinding


class AnalysisRun(Base):
    """A persisted execution of an assessment analysis."""

    __tablename__ = "analysis_runs"
    __table_args__ = (
        Index(
            "ix_analysis_runs_assessment_id_created_at",
            "assessment_id",
            "created_at",
        ),
        Index(
            "uq_analysis_runs_active_assessment",
            "assessment_id",
            unique=True,
            sqlite_where=text("status IN ('queued', 'running')"),
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index("ix_analysis_runs_status_created_at", "status", "created_at"),
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
    status: Mapped[AnalysisRunStatus] = mapped_column(
        SAEnum(
            AnalysisRunStatus,
            name="analysis_run_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
        default=AnalysisRunStatus.RUNNING,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    started_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    cancel_requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_analysis_runs_cancel_requested_by_user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    analysis_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    # Durable background execution (M8, ADR-0011).
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_analysis_runs_requested_by_user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    lease_owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    assessment: Mapped["AssessmentJob"] = relationship(back_populates="analysis_runs")
    findings: Mapped[list["AssessmentFinding"]] = relationship(
        back_populates="analysis_run",
        cascade="all, delete-orphan",
        order_by="AssessmentFinding.position",
    )
