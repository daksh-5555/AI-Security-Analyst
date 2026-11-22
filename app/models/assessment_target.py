"""Explicit ownership and authorization record for an assessment target (ADR-0004).

Every repository or web target that analysis may touch has one row here. Analysis
refuses to run unless the row is ``authorized``. The row records who created it,
on what basis it is authorized, who authorized or revoked it and when, and the
network/filesystem policy in force at authorization time.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Text, UniqueConstraint, Uuid
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import AuthorizationBasis, TargetStatus, TargetType


def _enum(enum_class: type, name: str, length: int) -> SAEnum:
    return SAEnum(
        enum_class,
        name=name,
        native_enum=False,
        create_constraint=True,
        values_callable=lambda members: [member.value for member in members],
        length=length,
    )


class AssessmentTarget(Base):
    __tablename__ = "assessment_targets"
    __table_args__ = (
        UniqueConstraint(
            "assessment_id",
            "target_type",
            name="uq_assessment_targets_assessment_id_target_type",
        ),
        UniqueConstraint(
            "repository_target_id",
            name="uq_assessment_targets_repository_target_id",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_jobs.id",
            ondelete="CASCADE",
            name="fk_assessment_targets_assessment_id",
        ),
        nullable=False,
    )
    target_type: Mapped[TargetType] = mapped_column(
        _enum(TargetType, "assessment_target_type", 32), nullable=False
    )
    repository_target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "repository_targets.id",
            ondelete="CASCADE",
            name="fk_assessment_targets_repository_target_id",
        ),
        nullable=True,
    )
    canonical_target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[TargetStatus] = mapped_column(
        _enum(TargetStatus, "assessment_target_status", 32), nullable=False
    )
    authorization_basis: Mapped[AuthorizationBasis | None] = mapped_column(
        _enum(AuthorizationBasis, "assessment_target_authorization_basis", 32),
        nullable=True,
    )
    authorization_statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_assessment_targets_created_by"),
        nullable=True,
    )
    authorized_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_assessment_targets_authorized_by"),
        nullable=True,
    )
    authorized_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL", name="fk_assessment_targets_revoked_by"),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    policy_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
