"""Version ordering and OSV affected-range evaluation (M3, ADR-0007)."""

from __future__ import annotations

import pytest

from app.services.dependencies.versions import (
    Ecosystem,
    RangeCheck,
    SemVer,
    evaluate_affected,
    normalize_name,
    parse_version,
)


def ranges(*events: dict[str, str], kind: str = "ECOSYSTEM") -> list[dict]:
    return [{"ranges": [{"type": kind, "events": list(events)}], "versions": []}]


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("1.0.0-alpha.beta", "1.0.0-beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-rc.1", "1.0.0"),
        ("1.9.9", "1.10.0"),
        ("v1.2.3", "1.2.4"),
    ],
)
def test_semver_precedence(lower: str, higher: str) -> None:
    low, high = SemVer.parse(lower), SemVer.parse(higher)
    assert low is not None and high is not None
    assert low < high


def test_semver_ignores_build_metadata_and_rejects_garbage() -> None:
    assert SemVer.parse("1.2.3+build.5") == SemVer.parse("1.2.3")
    assert SemVer.parse("1.2") is None
    assert SemVer.parse("latest") is None


def test_pep440_ordering_and_names() -> None:
    assert parse_version(Ecosystem.PYPI, "2.0.0rc1") < parse_version(Ecosystem.PYPI, "2.0.0")
    assert parse_version(Ecosystem.PYPI, "1.0.post1") > parse_version(Ecosystem.PYPI, "1.0")
    assert parse_version(Ecosystem.PYPI, "not a version") is None
    assert normalize_name(Ecosystem.PYPI, "Django_REST.framework") == "django-rest-framework"
    assert normalize_name(Ecosystem.NPM, "@scope/Pkg") == "@scope/Pkg"


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("0.9", RangeCheck.AFFECTED),
        ("1.4.9", RangeCheck.AFFECTED),
        ("1.5.0", RangeCheck.NOT_AFFECTED),  # fixed bound is exclusive
        ("2.0.0", RangeCheck.NOT_AFFECTED),
    ],
)
def test_introduced_zero_fixed_range(version: str, expected: RangeCheck) -> None:
    match = evaluate_affected(
        Ecosystem.PYPI, version, ranges({"introduced": "0"}, {"fixed": "1.5.0"})
    )
    assert match.result is expected
    assert match.fixed_versions == ("1.5.0",)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("1.2.0", RangeCheck.AFFECTED),  # introduced bound is inclusive
        ("1.3.5", RangeCheck.AFFECTED),
        ("1.3.6", RangeCheck.NOT_AFFECTED),  # after last_affected
        ("1.1.9", RangeCheck.NOT_AFFECTED),
    ],
)
def test_last_affected_bound(version: str, expected: RangeCheck) -> None:
    match = evaluate_affected(
        Ecosystem.NPM,
        version,
        ranges({"introduced": "1.2.0"}, {"last_affected": "1.3.5"}, kind="SEMVER"),
    )
    assert match.result is expected


def test_multiple_disjoint_ranges_and_prereleases() -> None:
    affected = ranges(
        {"introduced": "1.0.0"},
        {"fixed": "1.5.0"},
        {"introduced": "2.0.0-beta.1"},
        {"fixed": "2.0.3"},
        kind="SEMVER",
    )
    assert evaluate_affected(Ecosystem.NPM, "1.7.0", affected).result is RangeCheck.NOT_AFFECTED
    assert evaluate_affected(Ecosystem.NPM, "2.0.0-beta.2", affected).result is RangeCheck.AFFECTED
    assert evaluate_affected(Ecosystem.NPM, "2.0.0", affected).result is RangeCheck.AFFECTED
    match = evaluate_affected(Ecosystem.NPM, "2.0.3", affected)
    assert match.result is RangeCheck.NOT_AFFECTED
    assert match.fixed_versions == ("1.5.0", "2.0.3")


def test_limit_events_and_explicit_versions() -> None:
    limited = ranges({"introduced": "0"}, {"limit": "3.0"})
    assert evaluate_affected(Ecosystem.PYPI, "2.9", limited).result is RangeCheck.AFFECTED
    assert evaluate_affected(Ecosystem.PYPI, "3.0", limited).result is RangeCheck.NOT_AFFECTED
    explicit = [{"ranges": [], "versions": ["1.0.1", "1.0.2"]}]
    match = evaluate_affected(Ecosystem.PYPI, "1.0.2", explicit)
    assert match.result is RangeCheck.AFFECTED
    assert "listed explicitly" in match.explanation


def test_explanation_is_reproducible() -> None:
    match = evaluate_affected(
        Ecosystem.PYPI, "2.0.1", ranges({"introduced": "0"}, {"fixed": "2.0.3"})
    )
    assert match.explanation == (
        "version 2.0.1 is within the affected range (introduced 0, fixed 2.0.3)"
    )


def test_unparseable_versions_and_git_ranges_are_unsupported() -> None:
    assert (
        evaluate_affected(
            Ecosystem.PYPI, "nightly", ranges({"introduced": "0"}, {"fixed": "1"})
        ).result
        is RangeCheck.UNSUPPORTED
    )
    assert (
        evaluate_affected(
            Ecosystem.NPM, "1.0.0", ranges({"introduced": "0"}, {"fixed": "x.y"})
        ).result
        is RangeCheck.UNSUPPORTED
    )
    git_only = ranges({"introduced": "abc123"}, {"fixed": "def456"}, kind="GIT")
    assert evaluate_affected(Ecosystem.PYPI, "1.0", git_only).result is RangeCheck.NOT_AFFECTED
