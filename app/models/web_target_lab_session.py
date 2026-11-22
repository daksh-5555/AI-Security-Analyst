"""Authenticated local-lab session for a web target (M15, ADR-0018).

Stores only the established lab session cookie, never the password. The feature
is development/lab-only, off by default, and forbidden in staging/production.
The cookie is never returned by the API, logged, or placed in evidence.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime


class WebTargetLabSession(Base):
    __tablename__ = "web_target_lab_sessions"
    __table_args__ = (
        UniqueConstraint("assessment_id", name="uq_web_target_lab_sessions_assessment_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "assessment_jobs.id",
            name="fk_web_target_lab_sessions_assessment_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    username: Mapped[str] = mapped_column(String(200), nullable=False)
    login_path: Mapped[str] = mapped_column(String(300), nullable=False)
    cookie_header: Mapped[str] = mapped_column(Text, nullable=False)
    established_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_web_target_lab_sessions_established_by_user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    established_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=lambda: datetime.now(UTC)
    )
