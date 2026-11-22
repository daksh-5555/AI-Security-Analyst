"""Normalized, redacted evidence and its links to findings (M7, ADR-0010).

``EvidenceItem`` stores one ``EvidenceRecord`` produced by a tool in an analysis
run. It never holds raw secrets, cookies, headers, or response bodies; tools redact
before constructing records (ADR-0002). A finding references one or more evidence
items through ``FindingEvidenceLink``; an item may support several findings, and
a later run's ``not_reproduced`` finding may reference an earlier run's items.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    __table_args__ = (
        UniqueConstraint(
            "analysis_run_id",
            "evidence_key",
            name="uq_evidence_items_analysis_run_id_evidence_key",
        ),
        Index("ix_evidence_items_assessment_id", "assessment_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_jobs.id", ondelete="CASCADE", name="fk_evidence_items_assessment_id"
        ),
        nullable=False,
    )
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "analysis_runs.id", ondelete="CASCADE", name="fk_evidence_items_analysis_run_id"
        ),
        nullable=False,
    )
    evidence_key: Mapped[str] = mapped_column(String(300), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_set_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    method: Mapped[str] = mapped_column(Text, nullable=False)
    location_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    location_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(200), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    redacted_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    response_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    limitations: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=lambda: datetime.now(UTC)
    )


class FindingEvidenceLink(Base):
    __tablename__ = "finding_evidence_links"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_findings.id",
            ondelete="CASCADE",
            name="fk_finding_evidence_links_finding_id",
        ),
        primary_key=True,
    )
    evidence_item_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "evidence_items.id",
            ondelete="CASCADE",
            name="fk_finding_evidence_links_evidence_item_id",
        ),
        primary_key=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
