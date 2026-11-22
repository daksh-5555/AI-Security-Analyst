"""Dependency inventory parsing without executing anything (M3)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.core.config import settings
from app.services.dependencies.inventory import Relationship, build_inventory
from app.services.dependencies.versions import Ecosystem
from app.services.repository_discovery import discover_repository


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    allowed = tmp_path / "repositories"
    allowed.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])
    return allowed


def inventory(repo: Path, max_bytes: int = 1_000_000):
    return build_inventory(repo.resolve(), discover_repository(repo), max_bytes=max_bytes)


def write(repo: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return repo


def by_name(result) -> dict[str, object]:
    return {dep.name.lower(): dep for dep in result.dependencies}


def test_requirements_pins_ranges_and_noise(root: Path) -> None:
    repo = write(
        root / "repo",
        {
            "requirements.txt": (
                "# comment\n"
                "Django==4.2.1  # pinned\n"
                "requests>=2.0\n"
                "flask[async]==2.3.2 ; python_version >= '3.8'\n"
                "urllib3==2.0.4 \\\n    --hash=sha256:abc\n"
                "-r other.txt\n"
                "-e git+https://example.invalid/repo.git#egg=x\n"
                "https://example.invalid/pkg.tar.gz\n"
                "not a valid line !!\n"
            ),
            "requirements-dev.txt": "pytest==8.2.0\n",
        },
    )
    deps = by_name(inventory(repo))
    assert deps["django"].version == "4.2.1"
    assert deps["flask"].version == "2.3.2"
    assert deps["urllib3"].version == "2.0.4"
    assert deps["pytest"].manifest == "requirements-dev.txt"
    assert deps["requests"].version is None and deps["requests"].specifier == ">=2.0"
    assert all(dep.relationship is Relationship.DIRECT for dep in deps.values())
    assert set(deps) == {"django", "requests", "flask", "urllib3", "pytest"}


def test_pyproject_pep621_and_poetry(root: Path) -> None:
    repo = write(
        root / "repo",
        {
            "pyproject.toml": (
                "[project]\n"
                'dependencies = ["fastapi==0.110.0", "pydantic>=2"]\n'
                "[project.optional-dependencies]\n"
                'dev = ["ruff==0.6.0"]\n'
                "[tool.poetry.dependencies]\n"
                'python = "^3.11"\n'
                'jinja2 = "3.1.2"\n'
                'httpx = {version = "^0.27"}\n'
            )
        },
    )
    deps = by_name(inventory(repo))
    assert deps["fastapi"].version == "0.110.0"
    assert deps["ruff"].version == "0.6.0"
    assert deps["jinja2"].version == "3.1.2"
    assert deps["pydantic"].version is None
    assert deps["httpx"].version is None
    assert "python" not in deps


def test_poetry_lock_wins_and_marks_direct_dependencies(root: Path) -> None:
    repo = write(
        root / "repo",
        {
            "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31"\n',
            "poetry.lock": (
                '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
                '[[package]]\nname = "idna"\nversion = "3.6"\n'
            ),
        },
    )
    result = inventory(repo)
    deps = by_name(result)
    assert deps["requests"].version == "2.31.0" and deps["requests"].source == "lockfile"
    assert deps["requests"].relationship is Relationship.DIRECT
    assert deps["idna"].relationship is Relationship.TRANSITIVE
    assert result.unresolved == []  # the manifest range was replaced by the lock


def test_pipfile_lock(root: Path) -> None:
    lock = {
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {"pytest": {"version": "==8.0.0"}},
    }
    deps = by_name(inventory(write(root / "repo", {"Pipfile.lock": json.dumps(lock)})))
    assert deps["requests"].version == "2.31.0" and deps["requests"].dev is False
    assert deps["pytest"].dev is True
    assert deps["requests"].relationship is Relationship.UNKNOWN


def test_package_json_and_lock_v3(root: Path) -> None:
    package = {"dependencies": {"express": "^4.18.0", "lodash": "4.17.20"}}
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.18.0", "lodash": "4.17.20"}},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express/node_modules/qs": {"version": "6.11.0"},
            "node_modules/linked": {"link": True},
        },
    }
    result = inventory(
        write(
            root / "repo",
            {"package.json": json.dumps(package), "package-lock.json": json.dumps(lock)},
        )
    )
    deps = {(dep.name, dep.version): dep for dep in result.dependencies}
    assert deps[("express", "4.18.2")].relationship is Relationship.DIRECT
    assert deps[("qs", "6.11.0")].relationship is Relationship.TRANSITIVE
    assert all(dep.ecosystem is Ecosystem.NPM and dep.source == "lockfile" for dep in deps.values())
    assert result.unresolved == []


def test_package_lock_v1_nested(root: Path) -> None:
    package = {"dependencies": {"a": "1.0.0"}}
    lock = {
        "lockfileVersion": 1,
        "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}},
    }
    result = inventory(
        write(
            root / "repo",
            {"package.json": json.dumps(package), "package-lock.json": json.dumps(lock)},
        )
    )
    deps = {dep.name: dep for dep in result.dependencies}
    assert deps["a"].relationship is Relationship.DIRECT
    assert deps["b"].relationship is Relationship.TRANSITIVE


def test_package_json_without_lock_keeps_only_exact_versions(root: Path) -> None:
    package = {"dependencies": {"exact": "1.2.3", "caret": "^1.2.3"}}
    deps = by_name(inventory(write(root / "repo", {"package.json": json.dumps(package)})))
    assert deps["exact"].version == "1.2.3"
    assert deps["caret"].version is None


def test_malformed_unsupported_and_oversized_files_are_reported(root: Path) -> None:
    repo = write(
        root / "repo",
        {
            "package-lock.json": "{not json",
            "pyproject.toml": "[project\n",
            "yarn.lock": "lodash@^4:\n  version 4.17.21\n",
            "sub/requirements.txt": "flask==2.0.0\n" + "#" * 2000,
        },
    )
    result = inventory(repo, max_bytes=1000)
    issues = dict(result.issues)
    assert issues["package-lock.json"] == "malformed"
    assert issues["pyproject.toml"] == "malformed"
    assert issues["yarn.lock"] == "unsupported_lock_format"
    assert issues["sub/requirements.txt"] == "oversize"
    assert result.dependencies == []


def test_symlinked_manifests_are_not_followed(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-requirements.txt"
    outside.write_text("leaked==1.0\n", encoding="utf-8")
    repo = write(root / "repo", {"app.py": "x = 1\n"})
    try:
        os.symlink(outside, repo / "requirements.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert inventory(repo).dependencies == []


def test_results_are_deterministic(root: Path) -> None:
    repo = write(
        root / "repo", {"requirements.txt": "b==1.0\na==2.0\n", "x/requirements.txt": "c==3.0\n"}
    )
    assert inventory(repo).dependencies == inventory(repo).dependencies
    assert [dep.name for dep in inventory(repo).dependencies] == ["a", "b", "c"]
