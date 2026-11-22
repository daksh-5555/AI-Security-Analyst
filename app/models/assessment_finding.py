import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import FindingSeverity, FindingStatus

if TYPE_CHECKING:
    from app.models.analysis_run import AnalysisRun
    from app.models.assessment import AssessmentJob
    from app.models.evidence_item import FindingEvidenceLink
    from app.models.finding_evidence import FindingEvidence


class AssessmentFinding(Base):
    """A persisted security finding for an assessment."""

    __tablename__ = "assessment_findings"
    __table_args__ = (
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_assessment_findings_confidence_range",
        ),
        CheckConstraint(
            "position >= 0",
            name="ck_assessment_findings_position_non_negative",
        ),
        UniqueConstraint(
            "assessment_id",
            "position",
            name="uq_assessment_findings_assessment_id_position",
        ),
        Index(
            "ix_assessment_findings_analysis_run_id",
            "analysis_run_id",
        ),
        Index(
            "ix_assessment_findings_assessment_id_identity_key",
            "assessment_id",
            "identity_key",
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
    analysis_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=True,
    )
    position: Mapped[int] = mapped_column(nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        SAEnum(
            FindingSeverity,
            name="finding_severity",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(
            FindingStatus,
            name="finding_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    affected_component: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # M7 normalized-finding fields. All nullable: findings persisted before
    # migration 0017 keep their legacy shape.
    rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    source_stage: Mapped[str | None] = mapped_column(String(100), nullable=True)
    identity_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_ids: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)
    cve_ids: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    previous_status: Mapped[FindingStatus | None] = mapped_column(
        SAEnum(
            FindingStatus,
            name="finding_previous_status",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=True,
    )
    previous_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_findings.id",
            ondelete="SET NULL",
            name="fk_assessment_findings_previous_finding_id",
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    assessment: Mapped["AssessmentJob"] = relationship(back_populates="findings")
    analysis_run: Mapped["AnalysisRun | None"] = relationship(back_populates="findings")
    evidence: Mapped[list["FindingEvidence"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        order_by="FindingEvidence.position",
    )
    evidence_links: Mapped[list["FindingEvidenceLink"]] = relationship(
        cascade="all, delete-orphan",
        order_by="FindingEvidenceLink.position",
    )

    @property
    def evidence_ids(self) -> list[uuid.UUID]:
        """Normalized evidence items referenced by this finding, in order."""
        return [link.evidence_item_id for link in self.evidence_links]
