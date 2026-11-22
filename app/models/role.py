import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.user_role import UserRole


class Role(Base):
    """A canonical platform role."""

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint(
            "name",
            name="uq_roles_name",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    role_links: Mapped[list["UserRole"]] = relationship(
        back_populates="role",
        passive_deletes=True,
    )
    users: Mapped[list["User"]] = relationship(
        secondary="user_roles",
        viewonly=True,
    )
