"""Deterministic identifiers for canonical platform roles."""

from typing import Final
from uuid import UUID

from app.schemas.enums import RoleName

ROLE_IDS: Final[dict[RoleName, UUID]] = {
    RoleName.ADMIN: UUID("d4cb62aa-d7fe-5173-b863-db5f6f51332c"),
    RoleName.SECURITY_ANALYST: UUID("e6fbed1f-2a57-5880-ab46-48a50e432747"),
    RoleName.VIEWER: UUID("1ccf37b3-3921-5a91-ab87-3192b3a4bba1"),
}

DEFAULT_ROLE_NAME: Final[RoleName] = RoleName.SECURITY_ANALYST
DEFAULT_ROLE_ID: Final[UUID] = ROLE_IDS[DEFAULT_ROLE_NAME]
