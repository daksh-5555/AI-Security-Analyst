"""Package names, version ordering, and OSV affected-range evaluation (ADR-0007).

Matching is evaluated locally so every advisory match has a reproducible
explanation ("version 2.0.1 is within introduced 0, fixed 2.0.3"):

- PyPI versions follow PEP 440 (``packaging.version``);
- npm versions follow SemVer 2.0 precedence (implemented here, prerelease aware);
- ranges follow the OSV schema: events ``introduced``/``fixed``/``last_affected``/
  ``limit`` evaluated in version order, plus explicit ``versions`` lists.

A version that cannot be parsed is reported as ``unsupported`` rather than guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import total_ordering
from typing import Any, Final

from packaging.version import InvalidVersion, Version


class Ecosystem(StrEnum):
    PYPI = "PyPI"
    NPM = "npm"


class RangeCheck(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNSUPPORTED = "unsupported"


_PEP503: Final[re.Pattern[str]] = re.compile(r"[-_.]+")
_SEMVER: Final[re.Pattern[str]] = re.compile(
    r"^v?=?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?(?:\+[0-9A-Za-z\-.]+)?$"
)


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """Canonical package name used for matching advisories."""
    stripped = name.strip()
    if ecosystem is Ecosystem.PYPI:
        return _PEP503.sub("-", stripped).lower()
    return stripped


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> SemVer | None:
        match = _SEMVER.match(text.strip())
        if match is None:
            return None
        pre = tuple(match.group(4).split(".")) if match.group(4) else ()
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)), pre)

    def _key(self) -> tuple[Any, ...]:
        # A release sorts after any of its prereleases; numeric identifiers sort
        # before alphanumeric ones and compare numerically.
        if not self.prerelease:
            return (self.major, self.minor, self.patch, 1, ())
        identifiers = tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part) for part in self.prerelease
        )
        return (self.major, self.minor, self.patch, 0, identifiers)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._key() < other._key()


Comparable = Version | SemVer


def parse_version(ecosystem: Ecosystem, text: str) -> Comparable | None:
    """Parse a version for ordering, or return None when it is not understood."""
    if ecosystem is Ecosystem.PYPI:
        try:
            return Version(text.strip())
        except InvalidVersion:
            return None
    return SemVer.parse(text)


@dataclass(frozen=True, slots=True)
class RangeMatch:
    """The outcome of checking one version against an advisory's affected data."""

    result: RangeCheck
    explanation: str
    fixed_versions: tuple[str, ...]


def _range_description(events: list[dict[str, str]]) -> str:
    parts = []
    for event in events:
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in event:
                parts.append(f"{kind} {event[kind]}")
    return ", ".join(parts) or "no events"


def evaluate_affected(
    ecosystem: Ecosystem,
    version_text: str,
    affected: list[dict[str, Any]],
) -> RangeMatch:
    """Evaluate a version against the ``affected`` entries for one package."""
    version = parse_version(ecosystem, version_text)
    fixed: list[str] = []
    unsupported = False

    for entry in affected:
        explicit = entry.get("versions")
        if isinstance(explicit, list) and version_text in {str(item) for item in explicit}:
            return RangeMatch(
                RangeCheck.AFFECTED,
                f"version {version_text} is listed explicitly as affected",
                tuple(fixed),
            )
        for affected_range in entry.get("ranges") or []:
            if not isinstance(affected_range, dict):
                continue
            if affected_range.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            events = [
                event for event in affected_range.get("events") or [] if isinstance(event, dict)
            ]
            fixed.extend(str(event["fixed"]) for event in events if "fixed" in event)
            if version is None:
                unsupported = True
                continue
            outcome = _evaluate_events(ecosystem, version, events)
            if outcome is None:
                unsupported = True
            elif outcome:
                return RangeMatch(
                    RangeCheck.AFFECTED,
                    f"version {version_text} is within the affected range "
                    f"({_range_description(events)})",
                    tuple(dict.fromkeys(fixed)),
                )

    unique_fixed = tuple(dict.fromkeys(fixed))
    if unsupported:
        return RangeMatch(
            RangeCheck.UNSUPPORTED,
            f"version {version_text} or an advisory range bound could not be parsed",
            unique_fixed,
        )
    return RangeMatch(
        RangeCheck.NOT_AFFECTED,
        f"version {version_text} is outside every affected range",
        unique_fixed,
    )


def _evaluate_events(
    ecosystem: Ecosystem,
    version: Comparable,
    events: list[dict[str, Any]],
) -> bool | None:
    """OSV event evaluation. Returns None when a bound cannot be parsed."""
    parsed: list[tuple[Comparable | None, str, bool]] = []
    for event in events:
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind not in event:
                continue
            raw = str(event[kind])
            if kind == "introduced" and raw == "0":
                parsed.append((None, kind, True))
                continue
            bound = parse_version(ecosystem, raw)
            if bound is None:
                return None
            parsed.append((bound, kind, False))

    def order(item: tuple[Comparable | None, str, bool]) -> tuple[int, Any]:
        bound, _kind, is_zero = item
        return (0, 0) if is_zero else (1, bound)

    try:
        parsed.sort(key=order)
    except TypeError:
        return None

    affected = False
    for bound, kind, is_zero in parsed:
        if kind == "introduced" and (is_zero or version >= bound):
            affected = True
        elif kind == "fixed" and bound is not None and version >= bound:
            affected = False
        elif kind == "last_affected" and bound is not None and version > bound:
            affected = False
        elif kind == "limit" and bound is not None and version >= bound:
            affected = False
    return affected


__all__ = [
    "Ecosystem",
    "RangeCheck",
    "RangeMatch",
    "SemVer",
    "evaluate_affected",
    "normalize_name",
    "parse_version",
]
