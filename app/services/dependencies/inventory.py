"""Dependency inventory from manifests and lock files (ADR-0007).

Files are parsed as data only (``tomllib``, ``json``, PEP 508 parsing via
``packaging``); no package manager, build script, or repository code is run.

Supported inputs and what they contribute:

| File | Ecosystem | Versions | Direct vs transitive |
| --- | --- | --- | --- |
| ``requirements*.txt`` | PyPI | exact ``==`` pins only | direct |
| ``pyproject.toml`` (PEP 621, Poetry) | PyPI | exact pins only | direct |
| ``poetry.lock`` | PyPI | resolved | direct if declared in the sibling ``pyproject.toml`` |
| ``Pipfile.lock`` | PyPI | resolved | unknown |
| ``package.json`` | npm | exact versions only | direct |
| ``package-lock.json`` (v1–v3) | npm | resolved | direct if declared by the root package |

When a directory has a lock file for an ecosystem, its resolved versions replace
that directory's manifest ranges. Unpinned manifest entries without a lock file
are reported as *unresolved* and are never matched against advisories by guessing
a version. ``pnpm-lock.yaml`` and ``yarn.lock`` are recognised and reported as
unsupported.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Final

from packaging.requirements import InvalidRequirement, Requirement

from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.services.dependencies.versions import Ecosystem, normalize_name
from app.services.tooling.files import read_bounded

PYTHON_MANIFESTS: Final[frozenset[str]] = frozenset({"pyproject.toml"})
LOCK_FILES: Final[dict[str, Ecosystem]] = {
    "poetry.lock": Ecosystem.PYPI,
    "pipfile.lock": Ecosystem.PYPI,
    "package-lock.json": Ecosystem.NPM,
    "npm-shrinkwrap.json": Ecosystem.NPM,
}
UNSUPPORTED_LOCK_FILES: Final[frozenset[str]] = frozenset({"pnpm-lock.yaml", "yarn.lock"})
_EXACT_NPM: Final[re.Pattern[str]] = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$")


class Relationship(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Dependency:
    """One declared or resolved dependency at a specific manifest location."""

    ecosystem: Ecosystem
    name: str
    version: str | None
    manifest: str
    source: str  # "lockfile" or "manifest"
    relationship: Relationship
    specifier: str | None = None
    dev: bool | None = None

    @property
    def key(self) -> tuple[Ecosystem, str]:
        return (self.ecosystem, normalize_name(self.ecosystem, self.name))


@dataclass
class DependencyInventory:
    dependencies: list[Dependency] = field(default_factory=list)
    files_parsed: list[str] = field(default_factory=list)
    issues: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)

    @property
    def resolved(self) -> list[Dependency]:
        return [item for item in self.dependencies if item.version is not None]

    @property
    def unresolved(self) -> list[Dependency]:
        return [item for item in self.dependencies if item.version is None]


def is_dependency_file(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return (
        _is_requirements(name)
        or name in PYTHON_MANIFESTS
        or name in LOCK_FILES
        or name == "package.json"
        or name in UNSUPPORTED_LOCK_FILES
    )


def _is_requirements(name: str) -> bool:
    return name.endswith(".txt") and name.startswith("requirements")


def _directory(relative_path: str) -> str:
    return str(PurePosixPath(relative_path).parent)


def _skip_vendored(relative_path: str) -> bool:
    parts = {part.lower() for part in PurePosixPath(relative_path).parts[:-1]}
    return bool(parts & {"node_modules", "vendor", "site-packages", ".venv", "venv"})


def _exact_pin(requirement: Requirement) -> str | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) == 1 and specifiers[0].operator in {"==", "==="}:
        version = specifiers[0].version
        if "*" not in version:
            return version
    return None


def _parse_requirement_line(raw: str) -> Requirement | None:
    line = raw.split(" #", 1)[0].strip()
    if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:")):
        return None
    try:
        return Requirement(line)
    except InvalidRequirement:
        return None


def _parse_requirements(text: str, path: str) -> list[Dependency]:
    dependencies = []
    joined = text.replace("\\\n", " ")
    for raw in joined.splitlines():
        requirement = _parse_requirement_line(raw.split(" --hash", 1)[0])
        if requirement is None or requirement.url:
            continue
        dependencies.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=requirement.name,
                version=_exact_pin(requirement),
                manifest=path,
                source="manifest",
                relationship=Relationship.DIRECT,
                specifier=str(requirement.specifier) or None,
            )
        )
    return dependencies


def _pep621_requirements(data: dict[str, Any]) -> list[str]:
    project = data.get("project") or {}
    entries = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        entries.extend(group or [])
    for group in (data.get("dependency-groups") or {}).values():
        entries.extend(item for item in group or [] if isinstance(item, str))
    return [entry for entry in entries if isinstance(entry, str)]


def _poetry_declared(data: dict[str, Any]) -> dict[str, str | None]:
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    for group in (poetry.get("group") or {}).values():
        tables.append((group or {}).get("dependencies") or {})
    declared: dict[str, str | None] = {}
    for table in tables:
        for name, spec in table.items():
            if name.lower() == "python":
                continue
            version = spec.get("version") if isinstance(spec, dict) else spec
            declared[name] = version if isinstance(version, str) else None
    return declared


def _parse_pyproject(text: str, path: str) -> tuple[list[Dependency], set[str]]:
    data = tomllib.loads(text)
    dependencies: list[Dependency] = []
    declared_names: set[str] = set()
    for entry in _pep621_requirements(data):
        requirement = _parse_requirement_line(entry)
        if requirement is None:
            continue
        declared_names.add(normalize_name(Ecosystem.PYPI, requirement.name))
        dependencies.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=requirement.name,
                version=_exact_pin(requirement),
                manifest=path,
                source="manifest",
                relationship=Relationship.DIRECT,
                specifier=str(requirement.specifier) or None,
            )
        )
    for name, spec in _poetry_declared(data).items():
        declared_names.add(normalize_name(Ecosystem.PYPI, name))
        exact = spec if spec and spec[0].isdigit() and not set(spec) & set("<>=^~*, |") else None
        dependencies.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=name,
                version=exact,
                manifest=path,
                source="manifest",
                relationship=Relationship.DIRECT,
                specifier=spec,
            )
        )
    return dependencies, declared_names


def _parse_poetry_lock(text: str, path: str, declared: set[str]) -> list[Dependency]:
    data = tomllib.loads(text)
    dependencies = []
    for package in data.get("package") or []:
        if not isinstance(package, dict) or "name" not in package or "version" not in package:
            continue
        name = str(package["name"])
        relationship = (
            Relationship.DIRECT
            if normalize_name(Ecosystem.PYPI, name) in declared
            else (Relationship.TRANSITIVE if declared else Relationship.UNKNOWN)
        )
        category = package.get("category")
        dependencies.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=name,
                version=str(package["version"]),
                manifest=path,
                source="lockfile",
                relationship=relationship,
                dev=None if category is None else category == "dev",
            )
        )
    return dependencies


def _parse_pipfile_lock(text: str, path: str) -> list[Dependency]:
    data = json.loads(text)
    dependencies = []
    for section, dev in (("default", False), ("develop", True)):
        for name, spec in (data.get(section) or {}).items():
            version = spec.get("version") if isinstance(spec, dict) else None
            if not isinstance(version, str) or not version.startswith("=="):
                continue
            dependencies.append(
                Dependency(
                    ecosystem=Ecosystem.PYPI,
                    name=name,
                    version=version[2:],
                    manifest=path,
                    source="lockfile",
                    relationship=Relationship.UNKNOWN,
                    dev=dev,
                )
            )
    return dependencies


def _npm_declared(package_json: dict[str, Any]) -> dict[str, str]:
    declared: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (package_json.get(section) or {}).items():
            if isinstance(spec, str):
                declared[name] = spec
    return declared


def _parse_package_json(text: str, path: str) -> tuple[list[Dependency], set[str]]:
    data = json.loads(text)
    declared = _npm_declared(data if isinstance(data, dict) else {})
    dependencies = [
        Dependency(
            ecosystem=Ecosystem.NPM,
            name=name,
            version=spec if _EXACT_NPM.match(spec) else None,
            manifest=path,
            source="manifest",
            relationship=Relationship.DIRECT,
            specifier=spec,
        )
        for name, spec in sorted(declared.items())
    ]
    return dependencies, set(declared)


def _parse_package_lock(text: str, path: str, declared: set[str]) -> list[Dependency]:
    data = json.loads(text)
    dependencies: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        root = packages.get("") or {}
        root_declared = set(_npm_declared(root)) or declared
        for location, package in packages.items():
            if not location or not isinstance(package, dict) or "version" not in package:
                continue
            if package.get("link"):
                continue
            name = package.get("name") or location.rsplit("node_modules/", 1)[-1]
            top_level = location.count("node_modules/") == 1
            relationship = (
                Relationship.DIRECT
                if top_level and name in root_declared
                else Relationship.TRANSITIVE
            )
            dependencies.append(
                Dependency(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=str(package["version"]),
                    manifest=path,
                    source="lockfile",
                    relationship=relationship,
                    dev=bool(package.get("dev", False)),
                )
            )
        return dependencies

    def walk(tree: dict[str, Any], depth: int) -> None:  # lockfileVersion 1
        for name, package in tree.items():
            if not isinstance(package, dict) or "version" not in package:
                continue
            relationship = (
                Relationship.DIRECT
                if depth == 0 and name in declared
                else (Relationship.TRANSITIVE if declared else Relationship.UNKNOWN)
            )
            dependencies.append(
                Dependency(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=str(package["version"]),
                    manifest=path,
                    source="lockfile",
                    relationship=relationship,
                    dev=bool(package.get("dev", False)),
                )
            )
            walk(package.get("dependencies") or {}, depth + 1)

    walk(data.get("dependencies") or {}, 0)
    return dependencies


def build_inventory(
    root: Path,
    discovery: RepositoryDiscoveryResult,
    *,
    max_bytes: int,
) -> DependencyInventory:
    """Parse every supported dependency file in the inventory (no execution)."""
    inventory = DependencyInventory()
    texts: dict[str, str] = {}
    for entry in sorted(discovery.files, key=lambda item: item.relative_path):
        if not is_dependency_file(entry.relative_path) or _skip_vendored(entry.relative_path):
            continue
        name = PurePosixPath(entry.relative_path).name.lower()
        if name in UNSUPPORTED_LOCK_FILES:
            inventory.issues.append((entry.relative_path, "unsupported_lock_format"))
            continue
        data, outcome = read_bounded(root, entry.relative_path, max_bytes)
        if data is None:
            inventory.issues.append((entry.relative_path, outcome))
            continue
        texts[entry.relative_path] = data.decode("utf-8", errors="replace")

    by_directory: dict[str, dict[str, str]] = defaultdict(dict)
    for path in texts:
        by_directory[_directory(path)][PurePosixPath(path).name.lower()] = path

    for directory in sorted(by_directory):
        files = by_directory[directory]
        manifest_deps: list[Dependency] = []
        python_declared: set[str] = set()
        npm_declared: set[str] = set()

        def parse(path: str, parser: Any, *args: Any) -> Any:
            try:
                result = parser(texts[path], path, *args)
            except (ValueError, TypeError, KeyError, AttributeError, tomllib.TOMLDecodeError):
                inventory.issues.append((path, "malformed"))
                return None
            inventory.files_parsed.append(path)
            return result

        for name, path in sorted(files.items()):
            if _is_requirements(name):
                parsed = parse(path, _parse_requirements)
                manifest_deps.extend(parsed or [])
            elif name == "pyproject.toml":
                parsed = parse(path, _parse_pyproject)
                if parsed:
                    manifest_deps.extend(parsed[0])
                    python_declared |= parsed[1]
            elif name == "package.json":
                parsed = parse(path, _parse_package_json)
                if parsed:
                    manifest_deps.extend(parsed[0])
                    npm_declared |= parsed[1]

        locked: set[Ecosystem] = set()
        for name, path in sorted(files.items()):
            ecosystem = LOCK_FILES.get(name)
            if ecosystem is None:
                continue
            if name == "poetry.lock":
                parsed = parse(path, _parse_poetry_lock, python_declared)
            elif name == "pipfile.lock":
                parsed = parse(path, _parse_pipfile_lock)
            else:
                parsed = parse(path, _parse_package_lock, npm_declared)
            if parsed is not None:
                locked.add(ecosystem)
                inventory.dependencies.extend(parsed)

        # Lock-file versions win; manifest ranges in a locked directory are dropped.
        inventory.dependencies.extend(
            dependency for dependency in manifest_deps if dependency.ecosystem not in locked
        )

    unique: dict[tuple[Any, ...], Dependency] = {}
    for dependency in inventory.dependencies:
        key = (*dependency.key, dependency.version, dependency.manifest)
        unique.setdefault(key, dependency)
    inventory.dependencies = sorted(
        unique.values(),
        key=lambda item: (item.manifest, item.ecosystem, item.key[1], item.version or ""),
    )
    return inventory


__all__ = [
    "Dependency",
    "DependencyInventory",
    "Relationship",
    "build_inventory",
    "is_dependency_file",
]
