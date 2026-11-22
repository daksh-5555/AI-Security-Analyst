"""Advisory LLM explanation of one finding (M9, ADR-0012).

An explanation never changes the finding it describes. It records exactly what
produced it (provider, model, prompt template version, the evidence IDs that
were supplied, token usage) so it can be reproduced and audited.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import ExplanationStatus


class FindingExplanation(Base):
    __tablename__ = "finding_explanations"
    __table_args__ = (
        Index("ix_finding_explanations_finding_id_created_at", "finding_id", "created_at"),
        Index("ix_finding_explanations_assessment_id", "assessment_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_jobs.id", name="fk_finding_explanations_assessment_id", ondelete="CASCADE"
        ),
        nullable=False,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_findings.id", name="fk_finding_explanations_finding_id", ondelete="CASCADE"
        ),
        nullable=False,
    )
    status: Mapped[ExplanationStatus] = mapped_column(
        SAEnum(
            ExplanationStatus,
            name="finding_explanation_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=20,
        ),
        nullable=False,
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_template_version: Mapped[str] = mapped_column(String(50), nullable=False)
    output: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    supplied_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    # M11: what retrieval supplied (status, backend, knowledge-base version, source IDs).
    retrieval: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    input_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    output_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id", name="fk_finding_explanations_requested_by_user_id", ondelete="SET NULL"
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=lambda: datetime.now(UTC)
    )
