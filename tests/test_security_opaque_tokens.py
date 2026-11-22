import re

import pytest
from auth_helpers import extract_action_token

from app.core.security import (
    generate_opaque_token,
    hash_opaque_token,
    verify_opaque_token,
)

TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]{0,15}_[A-Za-z0-9_-]+$")


def test_generated_tokens_have_prefix_and_sufficient_entropy() -> None:
    token = generate_opaque_token("rt")

    assert token.startswith("rt_")
    assert TOKEN_PATTERN.fullmatch(token)
    assert len(token.split("_", 1)[1]) >= 43


def test_generated_tokens_are_unique() -> None:
    tokens = {generate_opaque_token("rt") for _ in range(100)}

    assert len(tokens) == 100


@pytest.mark.parametrize("suffix", ["-", "_", "A"])
def test_extract_action_token_preserves_base64url_suffixes(suffix: str) -> None:
    raw_token = "reset_" + "A" * 63 + suffix

    assert extract_action_token(f"Use t={raw_token}\n") == raw_token


def test_explicit_byte_count_is_respected() -> None:
    token = generate_opaque_token("ev", nbytes=32)

    assert token.startswith("ev_")
    assert TOKEN_PATTERN.fullmatch(token)


@pytest.mark.parametrize(
    "prefix",
    ["", "RT", "1rt", "a_b", "a-b", "a" * 17, "prefix with space"],
)
def test_invalid_prefixes_are_rejected(prefix: str) -> None:
    with pytest.raises(ValueError):
        generate_opaque_token(prefix)


@pytest.mark.parametrize("nbytes", [31, 65])
def test_out_of_range_byte_counts_are_rejected(nbytes: int) -> None:
    with pytest.raises(ValueError):
        generate_opaque_token("rt", nbytes=nbytes)


def test_boolean_byte_count_is_rejected() -> None:
    with pytest.raises(TypeError):
        generate_opaque_token("rt", nbytes=True)  # type: ignore[arg-type]


def test_hash_is_deterministic_sha256() -> None:
    token = generate_opaque_token("rt")

    first = hash_opaque_token(token)
    second = hash_opaque_token(token)

    assert first == second
    assert len(first) == 64
    assert all(character in "0123456789abcdef" for character in first)


def test_correct_token_verifies() -> None:
    token = generate_opaque_token("rt")
    token_hash = hash_opaque_token(token)

    assert verify_opaque_token(token, token_hash) is True


def test_wrong_token_fails() -> None:
    token = generate_opaque_token("rt")
    other_token = generate_opaque_token("rt")

    assert verify_opaque_token(other_token, hash_opaque_token(token)) is False


def test_modified_token_fails() -> None:
    token = generate_opaque_token("rt")
    token_hash = hash_opaque_token(token)
    replacement = "A" if token[-1] != "A" else "B"
    modified = token[:-1] + replacement

    assert verify_opaque_token(modified, token_hash) is False


def test_uppercase_stored_hash_is_accepted() -> None:
    token = generate_opaque_token("rt")
    token_hash = hash_opaque_token(token)

    assert verify_opaque_token(token, token_hash.upper()) is True


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-token",
        "rt_",
        "RT_" + "a" * 64,
        "rt_" + "a" * 1000,
        "rt_" + "é" * 40,
        "rt_token with spaces",
    ],
)
def test_malformed_tokens_are_rejected_safely(token: str) -> None:
    with pytest.raises(ValueError):
        hash_opaque_token(token)

    assert verify_opaque_token(token, "0" * 64) is False


def test_non_string_inputs_are_handled_safely() -> None:
    with pytest.raises(TypeError):
        hash_opaque_token(b"rt_token")  # type: ignore[arg-type]

    assert verify_opaque_token(b"rt_token", "0" * 64) is False  # type: ignore[arg-type]
    assert verify_opaque_token("rt_token", b"0" * 64) is False  # type: ignore[arg-type]


def test_malformed_expected_hash_is_rejected() -> None:
    token = generate_opaque_token("rt")

    assert verify_opaque_token(token, "") is False
    assert verify_opaque_token(token, "0" * 63) is False
    assert verify_opaque_token(token, "not-a-hash") is False
