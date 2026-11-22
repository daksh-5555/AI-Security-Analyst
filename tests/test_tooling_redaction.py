"""Redaction helpers must never let synthetic secrets through (M1, ADR-0002)."""

from __future__ import annotations

import pytest

from app.schemas.tooling import MAX_EXCERPT_LENGTH, EvidenceLocation
from app.services.tooling.redaction import (
    MASK,
    REDACTED,
    content_hash,
    evidence_key,
    is_sensitive_name,
    keyed_fingerprint,
    mask_value,
    redact_excerpt,
    redact_headers,
    redact_url,
)

# Synthetic values only. None of these are real credentials.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PASSWORD = "hunter2-correct-horse"
KEY = b"k" * 32


def test_mask_has_fixed_width_and_limited_prefix() -> None:
    assert mask_value("short") == MASK
    assert mask_value(AWS_KEY, visible_prefix=4) == "AKIA" + MASK
    # A prefix is withheld when it would reveal more than a quarter of the value.
    assert mask_value("abcdefgh", visible_prefix=4) == MASK
    assert len(mask_value("x" * 10)) == len(mask_value("x" * 500))
    with pytest.raises(ValueError):
        mask_value("abc", visible_prefix=-1)


def test_redact_excerpt_hides_every_span_and_bounds_length() -> None:
    line = f'aws_key = "{AWS_KEY}"; token = "{GITHUB_TOKEN}"\x07'
    spans = [
        (line.index(AWS_KEY), line.index(AWS_KEY) + len(AWS_KEY)),
        (line.index(GITHUB_TOKEN), line.index(GITHUB_TOKEN) + len(GITHUB_TOKEN)),
    ]
    redacted = redact_excerpt(line, spans, visible_prefix=4)

    assert AWS_KEY not in redacted
    assert GITHUB_TOKEN not in redacted
    assert AWS_KEY[4:] not in redacted
    assert "\x07" not in redacted
    assert redacted.startswith('aws_key = "AKIA' + MASK)


def test_redact_excerpt_merges_overlaps_and_truncates_after_masking() -> None:
    secret = "S" * 400
    text = "prefix " + secret
    start = text.index(secret)
    redacted = redact_excerpt(text, [(start, start + 200), (start + 100, start + 400)])
    assert "S" not in redacted
    long_text = "a" * 1000
    assert len(redact_excerpt(long_text, [])) <= MAX_EXCERPT_LENGTH
    with pytest.raises(ValueError):
        redact_excerpt("abc", [(2, 10)])


def test_truncation_never_exposes_part_of_a_secret() -> None:
    text = "x" * (MAX_EXCERPT_LENGTH - 3) + PASSWORD
    start = text.index(PASSWORD)
    redacted = redact_excerpt(text, [(start, start + len(PASSWORD))])
    assert PASSWORD[:3] not in redacted[-10:]


@pytest.mark.parametrize(
    "name",
    ["Authorization", "Cookie", "Set-Cookie", "X-API-Key", "api_key", "session_id", "password"],
)
def test_sensitive_names(name: str) -> None:
    assert is_sensitive_name(name)


@pytest.mark.parametrize("name", ["Content-Type", "Accept", "page", "q", "Content-Encoding"])
def test_ordinary_names_are_not_sensitive(name: str) -> None:
    assert not is_sensitive_name(name)


def test_redact_headers() -> None:
    redacted = redact_headers(
        {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Cookie": "session=abc123",
            "Content-Type": "text/html",
        }
    )
    assert redacted == {
        "authorization": REDACTED,
        "content-type": "text/html",
        "cookie": REDACTED,
    }
    assert GITHUB_TOKEN not in str(redact_headers([("X-Api-Key", GITHUB_TOKEN)]))


def test_redact_url_removes_credentials_fragment_and_secret_query_values() -> None:
    url = f"https://admin:{PASSWORD}@example.test:8443/a/b?q=shoes&api_key={AWS_KEY}#frag"
    redacted = redact_url(url)

    assert PASSWORD not in redacted
    assert AWS_KEY not in redacted
    assert "admin" not in redacted
    assert "#frag" not in redacted
    assert redacted.startswith("https://example.test:8443/a/b?q=shoes&api_key=")
    assert redact_url("http://[::1]:8080/x?token=1") == "http://[::1]:8080/x?token=%5BREDACTED%5D"


def test_content_hash_normalizes_line_endings() -> None:
    assert content_hash("a\r\nb") == content_hash("a\nb") == content_hash(b"a\nb")
    assert len(content_hash("x")) == 64


def test_fingerprint_is_keyed_and_requires_a_strong_key() -> None:
    first = keyed_fingerprint(PASSWORD, KEY)
    assert first == keyed_fingerprint(PASSWORD, KEY)
    assert first != keyed_fingerprint(PASSWORD, b"j" * 32)
    assert first != content_hash(PASSWORD)
    assert PASSWORD not in first
    with pytest.raises(ValueError):
        keyed_fingerprint(PASSWORD, b"short")


def test_evidence_key_is_deterministic_and_location_sensitive() -> None:
    location = EvidenceLocation(path="src/app.py", line=4)
    key = evidence_key("secret_scanner", "secret.aws", location, "a" * 64)
    assert key == evidence_key("secret_scanner", "secret.aws", location, "a" * 64)
    assert key != evidence_key(
        "secret_scanner", "secret.aws", EvidenceLocation(path="src/app.py", line=5), "a" * 64
    )
    assert key.startswith("secret_scanner:secret.aws:")
