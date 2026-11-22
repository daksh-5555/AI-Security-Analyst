"""Redaction, hashing, and evidence identity helpers (ADR-0002).

Every function here is pure: no I/O, no logging, no network. Redaction runs
*before* an ``EvidenceRecord`` is constructed, before persistence, and before any
future LLM call, so sensitive values never enter those layers.

Masks have a fixed width so they do not reveal the length of the hidden value.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.schemas.tooling import MAX_EXCERPT_LENGTH, EvidenceLocation

REDACTED: Final[str] = "[REDACTED]"
MASK: Final[str] = "********"
MIN_FINGERPRINT_KEY_BYTES: Final[int] = 32

SENSITIVE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amz-security-token",
    }
)
_SENSITIVE_NAME: Final[re.Pattern[str]] = re.compile(
    r"(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth|session|"
    r"sig(nature)?|credential|private[_-]?key|jwt|bearer|otp|code)",
    re.IGNORECASE,
)
_CONTROL_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def mask_value(value: str, *, visible_prefix: int = 0) -> str:
    """Replace a sensitive value with a fixed-width mask.

    At most ``visible_prefix`` leading characters are kept, and only when the
    value is long enough that they reveal at most a quarter of it. This allows a
    non-secret type marker such as ``AKIA`` or ``ghp_`` to remain visible.
    """
    if visible_prefix < 0:
        raise ValueError("visible_prefix must not be negative")
    keep = visible_prefix if visible_prefix and len(value) >= 4 * visible_prefix else 0
    return f"{value[:keep]}{MASK}"


def redact_excerpt(
    text: str,
    spans: Sequence[tuple[int, int]],
    *,
    visible_prefix: int = 0,
    max_length: int = MAX_EXCERPT_LENGTH,
) -> str:
    """Mask every ``(start, end)`` span in ``text`` and bound the result.

    Spans may overlap and arrive in any order. Control characters are removed.
    Truncation happens after masking, so a cut can never expose part of a span.
    """
    if max_length < len(MASK) + 1:
        raise ValueError("max_length is too small to hold a mask")
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if not 0 <= start <= end <= len(text):
            raise ValueError("span is outside the text")
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append(mask_value(text[start:end], visible_prefix=visible_prefix))
        cursor = end
    pieces.append(text[cursor:])
    redacted = _CONTROL_CHARACTERS.sub("", "".join(pieces)).strip()
    if len(redacted) > max_length:
        redacted = redacted[: max_length - 1] + "…"
    return redacted


def is_sensitive_name(name: str) -> bool:
    """Return True for header, parameter, or field names that carry secrets."""
    lowered = name.strip().lower()
    return lowered in SENSITIVE_HEADERS or bool(_SENSITIVE_NAME.search(lowered))


def redact_headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    """Return headers with lower-cased names and sensitive values replaced."""
    items = headers.items() if isinstance(headers, Mapping) else headers
    redacted: dict[str, str] = {}
    for name, value in items:
        key = name.strip().lower()
        redacted[key] = REDACTED if is_sensitive_name(key) else value
    return dict(sorted(redacted.items()))


def redact_url(url: str) -> str:
    """Remove credentials and fragments, and mask sensitive query values."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = f"{host}:{parts.port}" if parts.port is not None else host
    query = urlencode(
        [
            (name, REDACTED if is_sensitive_name(name) else value)
            for name, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def _normalize(content: str | bytes) -> bytes:
    if isinstance(content, bytes):
        return content.replace(b"\r\n", b"\n")
    normalized = unicodedata.normalize("NFC", content).replace("\r\n", "\n")
    return normalized.encode("utf-8", "surrogatepass")


def content_hash(content: str | bytes) -> str:
    """SHA-256 hex digest of content with normalized line endings."""
    return hashlib.sha256(_normalize(content)).hexdigest()


def keyed_fingerprint(value: str | bytes, key: bytes) -> str:
    """HMAC-SHA-256 fingerprint for deduplicating sensitive values.

    A plain hash of a low-entropy secret can be confirmed offline by guessing;
    a keyed fingerprint cannot be checked without the deployment key.
    """
    if len(key) < MIN_FINGERPRINT_KEY_BYTES:
        raise ValueError(f"fingerprint key must be at least {MIN_FINGERPRINT_KEY_BYTES} bytes")
    return hmac.new(key, _normalize(value), hashlib.sha256).hexdigest()


def evidence_key(
    tool_name: str,
    rule_id: str,
    location: EvidenceLocation,
    discriminator: str = "",
) -> str:
    """Deterministic evidence identity: the same observation gets the same key.

    ``discriminator`` should be a content hash or fingerprint, never raw content.
    """
    payload = json.dumps(
        {
            "tool": tool_name,
            "rule": rule_id,
            "location": location.model_dump(mode="json"),
            "discriminator": discriminator,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{tool_name}:{rule_id}:{digest}"


__all__ = [
    "MASK",
    "REDACTED",
    "SENSITIVE_HEADERS",
    "content_hash",
    "evidence_key",
    "is_sensitive_name",
    "keyed_fingerprint",
    "mask_value",
    "redact_excerpt",
    "redact_headers",
    "redact_url",
]
