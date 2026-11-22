"""Redaction applied to every string before it reaches an LLM provider (M9).

Evidence is already redacted when it is stored. This is a second, independent
pass over everything sent (and everything received), so a gap in one producer
cannot leak a secret to a third party. It masks:

- every built-in secret-scanner rule match (cloud keys, tokens, private keys);
- ``name = value`` pairs whose name looks sensitive, and URL credentials;
- bearer tokens, JWTs, and cookie headers;
- e-mail addresses (personal data that explanations never need).
"""

from __future__ import annotations

import re
from typing import Final

from app.services.secret_scanning.rules import BUILTIN_RULES, EXCERPT_MASK_PATTERNS
from app.services.tooling.redaction import MASK

_EXTRA_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
        r"(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"
    ),
    re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"(?i)\b(?:set-)?cookie\s*[:=]\s*([^\r\n]+)"),
    re.compile(r"(?i)\bauthorization\s*[:=]\s*([^\r\n]+)"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
)
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for rule in BUILTIN_RULES:
        for match in rule.pattern.finditer(text):
            spans.append(rule.secret_span(match))
    for pattern in (*EXCERPT_MASK_PATTERNS, *_EXTRA_PATTERNS):
        for match in pattern.finditer(text):
            spans.append(match.span(1) if pattern.groups else match.span(0))
    return [(start, end) for start, end in spans if end > start]


def scrub_text(text: str, *, max_length: int | None = None) -> str:
    """Mask secret-like and personal values, drop control characters, and bound length."""
    merged: list[list[int]] = []
    for start, end in sorted(_spans(text)):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append(MASK)
        cursor = end
    pieces.append(text[cursor:])
    cleaned = _CONTROL.sub("", "".join(pieces))
    if max_length is not None and len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1] + "…"
    return cleaned


def contains_sensitive(text: str) -> bool:
    return bool(_spans(text))


__all__ = ["contains_sensitive", "scrub_text"]
