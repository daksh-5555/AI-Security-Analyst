import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, Index, String, UniqueConstraint, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime
from app.schemas.enums import UserActionTokenPurpose

if TYPE_CHECKING:
    from app.models.user import User


class UserActionToken(Base):
    """A single-use, hashed token for an identity lifecycle action."""

    __tablename__ = "user_action_tokens"
    __table_args__ = (
        UniqueConstraint(
            "token_hash",
            name="uq_user_action_tokens_token_hash",
        ),
        Index(
            "ix_user_action_tokens_user_id_purpose",
            "user_id",
            "purpose",
        ),
        Index(
            "ix_user_action_tokens_expires_at",
            "expires_at",
        ),
        Index(
            "uq_user_action_tokens_active_user_purpose",
            "user_id",
            "purpose",
            unique=True,
            sqlite_where=text("consumed_at IS NULL"),
            postgresql_where=text("consumed_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    purpose: Mapped[UserActionTokenPurpose] = mapped_column(
        SAEnum(
            UserActionTokenPurpose,
            name="user_action_token_purpose",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [member.value for member in enum_class],
            length=32,
        ),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )

    user: Mapped["User"] = relationship(back_populates="action_tokens")
