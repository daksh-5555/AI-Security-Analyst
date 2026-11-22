from collections.abc import Iterator

import pytest

from app.core import security as security_module
from app.core.config import settings
from app.core.security import (
    DUMMY_HASH_CACHE_MAX_ENTRIES,
    MAX_PASSWORD_BYTES,
    clear_dummy_password_hash_cache,
    dummy_password_hash,
    hash_password,
    password_needs_rehash,
    verify_password,
)


@pytest.fixture(autouse=True)
def low_cost_argon2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argon2_time_cost", 1)
    monkeypatch.setattr(settings, "argon2_memory_cost_kib", 8192)
    monkeypatch.setattr(settings, "argon2_parallelism", 1)
    monkeypatch.setattr(settings, "argon2_hash_len", 32)
    monkeypatch.setattr(settings, "argon2_salt_len", 16)


def test_hashes_use_argon2id_format() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert password_hash.startswith("$argon2id$")
    assert "m=8192,t=1,p=1" in password_hash


def test_correct_password_verifies() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", password_hash) is True


def test_wrong_password_fails() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert verify_password("wrong password", password_hash) is False


def test_each_hash_uses_a_fresh_salt() -> None:
    first = hash_password("same password")
    second = hash_password("same password")

    assert first != second
    assert first.split("$")[4] != second.split("$")[4]


def test_rehash_detection_tracks_configured_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    password_hash = hash_password("password")

    assert password_needs_rehash(password_hash) is False

    monkeypatch.setattr(settings, "argon2_time_cost", 2)

    assert password_needs_rehash(password_hash) is True


def test_verification_uses_embedded_hash_parameters() -> None:
    password_hash = hash_password("password")

    assert verify_password("password", password_hash) is True
    assert password_needs_rehash(password_hash) is False


@pytest.mark.parametrize(
    "password_hash",
    [
        "",
        "not-a-hash",
        "$2b$12$abcdefghijklmnopqrstuv",
        "$argon2id$broken",
        "$argon2i$v=19$m=8192,t=1,p=1$c2FsdA$ZGlnZXN0",
    ],
)
def test_malformed_or_unsupported_hashes_fail_safely(password_hash: str) -> None:
    assert verify_password("password", password_hash) is False
    assert password_needs_rehash(password_hash) is True


def test_unicode_password_round_trip() -> None:
    password = "pässwörd-🔐-日本語"

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True
    assert verify_password("pässwörd-🔐-日本", password_hash) is False


def test_excessively_long_password_is_rejected() -> None:
    too_long = "a" * (MAX_PASSWORD_BYTES + 1)

    with pytest.raises(ValueError):
        hash_password(too_long)

    password_hash = hash_password("password")
    assert verify_password(too_long, password_hash) is False


def test_password_limit_is_measured_in_utf8_bytes() -> None:
    exactly_at_limit = "é" * (MAX_PASSWORD_BYTES // 2)
    over_limit = "é" * (MAX_PASSWORD_BYTES // 2 + 1)

    password_hash = hash_password(exactly_at_limit)
    assert verify_password(exactly_at_limit, password_hash) is True

    with pytest.raises(ValueError):
        hash_password(over_limit)


def test_non_string_password_inputs_are_handled_safely() -> None:
    with pytest.raises(TypeError):
        hash_password(b"password")  # type: ignore[arg-type]

    assert verify_password(b"password", "$argon2id$") is False  # type: ignore[arg-type]
    assert verify_password("password", b"$argon2id$") is False  # type: ignore[arg-type]


def test_dummy_hash_is_stable_for_identical_parameters() -> None:
    clear_dummy_password_hash_cache()

    first = dummy_password_hash()
    second = dummy_password_hash()

    assert first == second
    assert first.startswith("$argon2id$")


def test_dummy_hash_is_not_a_valid_user_password() -> None:
    dummy_hash = dummy_password_hash()

    assert dummy_hash.startswith("$argon2id$")
    assert verify_password("a different password", dummy_hash) is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("argon2_time_cost", 2),
        ("argon2_memory_cost_kib", 16_384),
        ("argon2_parallelism", 2),
        ("argon2_hash_len", 16),
        ("argon2_salt_len", 8),
    ],
)
def test_dummy_hash_changes_when_argon2_parameters_change(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    clear_dummy_password_hash_cache()
    original = dummy_password_hash()

    monkeypatch.setattr(settings, field, value)

    assert dummy_password_hash() != original


def test_dummy_hash_cache_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    clear_dummy_password_hash_cache()

    for time_cost in range(1, 11):
        monkeypatch.setattr(settings, "argon2_time_cost", time_cost)
        dummy_password_hash()

    assert len(security_module._dummy_hash_cache) <= DUMMY_HASH_CACHE_MAX_ENTRIES


@pytest.fixture(autouse=True)
def reset_dummy_hash_cache() -> Iterator[None]:
    clear_dummy_password_hash_cache()
    yield
    clear_dummy_password_hash_cache()
