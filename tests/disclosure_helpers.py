"""Platform-independent assertions that API responses do not disclose host paths.

A raw ``str(path) in response.text`` check is unreliable on Windows: JSON escapes
each backslash, so ``C:\\repo`` appears as ``C:\\\\repo`` in the body and never
matches. These helpers decode the JSON body and inspect every key and string
value, comparing native and POSIX spellings of each forbidden path.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path, PurePath
from typing import Any


def _strings(value: Any) -> Iterator[tuple[str, str]]:
    stack: list[tuple[str, Any]] = [("$", value)]
    while stack:
        location, current = stack.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                yield f"{location} (key)", str(key)
                stack.append((f"{location}.{key}", item))
        elif isinstance(current, list):
            for index, item in enumerate(current):
                stack.append((f"{location}[{index}]", item))
        elif isinstance(current, str):
            yield location, current


def _spellings(path: Path | str) -> set[str]:
    candidates = {str(path)}
    if isinstance(path, Path):
        candidates.add(str(path.resolve()))
        candidates.add(path.resolve().as_posix())
        candidates.add(PurePath(path).as_posix())
    return {candidate for candidate in candidates if candidate}


def assert_no_path_disclosure(payload: Any, *paths: Path | str) -> None:
    """Fail if any decoded string in ``payload`` contains a forbidden path."""
    forbidden = set().union(*(_spellings(path) for path in paths))
    for location, text in _strings(payload):
        for candidate in forbidden:
            assert candidate not in text, f"host path disclosed at {location}"
