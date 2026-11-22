"""Classify database integrity errors by the constraint that was violated.

Services expect specific uniqueness races (for example two concurrent
registrations of one address). Any *other* integrity failure, such as a foreign
key violation or an unexpected constraint, indicates a bug or data problem and
must not be silently treated as the expected race.

PostgreSQL drivers expose the violated constraint name. SQLite only reports the
table and columns (``UNIQUE constraint failed: users.email_normalized``), so both
forms are matched. Log helpers record only the operation, the exception type, and
the constraint name; driver messages are never logged because PostgreSQL detail
text can contain the conflicting values.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError


@dataclass(frozen=True, slots=True)
class UniqueConstraint:
    """A unique constraint or unique index identified by name and columns."""

    name: str
    table: str
    columns: tuple[str, ...]

    @property
    def sqlite_message(self) -> str:
        qualified = ", ".join(f"{self.table}.{column}" for column in self.columns)
        return f"UNIQUE constraint failed: {qualified}"


USERS_EMAIL_NORMALIZED = UniqueConstraint(
    name="uq_users_email_normalized",
    table="users",
    columns=("email_normalized",),
)
ACTIVE_ACTION_TOKEN = UniqueConstraint(
    name="uq_user_action_tokens_active_user_purpose",
    table="user_action_tokens",
    columns=("user_id", "purpose"),
)
USER_ROLE_ASSIGNMENT = UniqueConstraint(
    name="pk_user_roles",
    table="user_roles",
    columns=("user_id", "role_id"),
)


def _constraint_name(exc: IntegrityError) -> str | None:
    original = exc.orig
    diag = getattr(original, "diag", None)
    name = getattr(diag, "constraint_name", None) or getattr(original, "constraint_name", None)
    return name if isinstance(name, str) and name else None


def violates(exc: IntegrityError, constraint: UniqueConstraint) -> bool:
    """Return True only when ``exc`` was raised by ``constraint``."""
    name = _constraint_name(exc)
    if name is not None:
        return name == constraint.name
    return str(exc.orig).strip() == constraint.sqlite_message


def log_unexpected_integrity_error(
    logger: logging.Logger,
    operation: str,
    exc: IntegrityError,
) -> None:
    """Log an unexpected integrity failure without driver detail or values."""
    logger.error(
        "Unexpected database integrity failure during %s.",
        operation,
        extra={
            "security_event": "unexpected_integrity_error",
            "operation": operation,
            "error_type": type(exc.orig).__name__ if exc.orig is not None else "unknown",
            "constraint": _constraint_name(exc),
        },
    )


__all__ = [
    "ACTIVE_ACTION_TOKEN",
    "USERS_EMAIL_NORMALIZED",
    "USER_ROLE_ASSIGNMENT",
    "UniqueConstraint",
    "log_unexpected_integrity_error",
    "violates",
]
