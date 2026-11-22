"""Email normalization and lightweight format validation.

This module contains only pure helpers with no database or HTTP dependencies.
``normalize_email`` produces the uniqueness key stored in
``users.email_normalized``; ``normalize_and_validate_email`` adds a conservative
mailbox-shape check for the identity write boundary.
"""

import re
import unicodedata

MAX_EMAIL_LENGTH = 320
_EMAIL_FORMAT_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    """Return the canonical value used for email uniqueness checks.

    The value is Unicode NFC-normalized, trimmed, and lowercased. The unique
    constraint on ``users.email_normalized`` is the authoritative duplicate
    check; this helper ensures that equivalent inputs produce the same key.
    """
    if not isinstance(value, str):
        raise TypeError("email must be a string")

    candidate = unicodedata.normalize("NFC", value).strip().lower()
    candidate = unicodedata.normalize("NFC", candidate)
    if not candidate:
        raise ValueError("email must not be blank")
    if len(candidate) > MAX_EMAIL_LENGTH:
        raise ValueError(f"email must not exceed {MAX_EMAIL_LENGTH} characters")
    return candidate


def normalize_and_validate_email(value: str) -> str:
    """Normalize an address and require a conservative mailbox format.

    Full RFC 5322 parsing is intentionally out of scope. The check rejects
    whitespace, missing local/domain parts, and domains without a dot. The
    result is the value used for ``users.email_normalized``.
    """
    normalized = normalize_email(value)
    if not _EMAIL_FORMAT_PATTERN.fullmatch(normalized):
        raise ValueError("email must be a valid address")
    return normalized
