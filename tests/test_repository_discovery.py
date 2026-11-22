import uuid
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.schemas.enums import (
    AssessmentType,
    DiscoveryItemKind,
    DiscoverySkipReason,
    DiscoveryTruncationReason,
    RepositorySourceKind,
)
from app.schemas.repository import RepositorySourceCreate
from app.schemas.repository_discovery import DiscoveryLimits, SkippedItem
from app.services import assessments as assessment_service
from app.services import repository_discovery
from app.services import repository_targets as repository_target_service
from app.services.repository_discovery import (
    InvalidRepositoryRootError,
    discover_registered_repository,
    discover_repository,
)

EXCLUDED_DIRECTORY_NAMES = (
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    "dist",
    "build",
)


@pytest.fixture
def discovery_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


@pytest.fixture
def repository(discovery_root: Path) -> Path:
    repository = discovery_root / "project"
    repository.mkdir()
    return repository


def write_file(path: Path, content: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_basic_nested_traversal_and_relative_paths(repository: Path) -> None:
    write_file(repository / "README.md", b"readme")
    write_file(repository / "src" / "main.py", b"print('hi')\n")
    write_file(repository / "src" / "utils" / "helpers.py", b"pass\n")

    result = discover_repository(repository)

    expected_sizes = {
        "README.md": len(b"readme"),
        "src/main.py": len(b"print('hi')\n"),
        "src/utils/helpers.py": len(b"pass\n"),
    }

    assert result.root == str(repository.resolve())
    assert [entry.relative_path for entry in result.files] == [
        "README.md",
        "src/main.py",
        "src/utils/helpers.py",
    ]
    assert [entry.extension for entry in result.files] == ["md", "py", "py"]
    assert {entry.relative_path: entry.size_bytes for entry in result.files} == expected_sizes
    assert result.summary.directory_count == 2
    assert result.summary.file_count == 3
    assert result.summary.total_size_bytes == sum(expected_sizes.values())
    assert result.summary.skipped_count == 0
    assert result.summary.is_complete is True
    assert result.summary.truncation_reasons == []
    assert result.summary.limits == DiscoveryLimits(
        max_file_count=settings.repository_max_file_count,
        max_depth=settings.repository_max_depth,
        max_total_size_bytes=settings.repository_max_total_size_bytes,
    )
    assert result.skipped == []


def test_extension_extraction_and_hidden_configuration_files(repository: Path) -> None:
    for relative_path in (
        "main.py",
        "ARCHIVE.TAR.GZ",
        "Makefile",
        ".env",
        ".env.example",
        ".gitignore",
        "Dockerfile",
        "pyproject.toml",
        "package.json",
        "requirements.txt",
    ):
        write_file(repository / relative_path)

    result = discover_repository(repository)

    assert {entry.relative_path: entry.extension for entry in result.files} == {
        ".env": None,
        ".env.example": "example",
        ".gitignore": None,
        "ARCHIVE.TAR.GZ": "gz",
        "Dockerfile": None,
        "Makefile": None,
        "main.py": "py",
        "package.json": "json",
        "pyproject.toml": "toml",
        "requirements.txt": "txt",
    }


def test_deterministic_ordering(repository: Path) -> None:
    write_file(repository / "z.txt")
    write_file(repository / "a" / "b.txt")
    write_file(repository / "a" / "a.txt")
    write_file(repository / "m.txt")

    first = discover_repository(repository)
    second = discover_repository(repository)

    assert first == second
    paths = [entry.relative_path for entry in first.files]
    assert paths == sorted(paths)
    assert [item.relative_path for item in first.skipped] == sorted(
        item.relative_path for item in first.skipped
    )


def test_excluded_directories_are_skipped(repository: Path) -> None:
    for directory_name in EXCLUDED_DIRECTORY_NAMES:
        write_file(repository / directory_name / "ignored.py")
    write_file(repository / "src" / "app.py")
    for file_name in (
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Dockerfile",
        ".env.example",
    ):
        write_file(repository / file_name)

    result = discover_repository(repository)

    assert [entry.relative_path for entry in result.files] == [
        ".env.example",
        "Dockerfile",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "src/app.py",
    ]
    assert result.summary.directory_count == 1
    assert result.summary.is_complete is True
    assert result.summary.truncation_reasons == []

    skipped = {(item.relative_path, item.reason, item.kind) for item in result.skipped}
    for directory_name in EXCLUDED_DIRECTORY_NAMES:
        assert (
            directory_name,
            DiscoverySkipReason.EXCLUDED_DIRECTORY,
            DiscoveryItemKind.DIRECTORY,
        ) in skipped


def test_env_files_are_inventoried_without_reading_contents(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_path = write_file(repository / ".env", b"SECRET=super-secret\n")
    write_file(repository / ".env.example", b"SECRET=changeme\n")

    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("Discovery must not open file contents")

    monkeypatch.setattr("builtins.open", fail_open)
    monkeypatch.setattr(Path, "open", fail_open)

    result = discover_repository(repository)

    assert {entry.relative_path for entry in result.files} == {".env", ".env.example"}
    env_entry = next(entry for entry in result.files if entry.relative_path == ".env")
    assert env_entry.size_bytes == env_path.stat().st_size
    assert env_entry.extension is None


def test_symlink_file_and_directory_are_skipped(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = write_file(outside / "secret.txt", b"secret")

    link_directory = repository / "link_directory"
    link_file = repository / "link_file.txt"
    try:
        link_directory.symlink_to(outside, target_is_directory=True)
        link_file.symlink_to(outside_file, target_is_directory=False)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    result = discover_repository(repository)

    assert result.files == []
    assert result.summary.directory_count == 0
    assert result.summary.is_complete is True

    skipped = {(item.relative_path, item.reason, item.kind) for item in result.skipped}
    assert (
        "link_directory",
        DiscoverySkipReason.SYMLINK,
        DiscoveryItemKind.SYMLINK,
    ) in skipped
    assert (
        "link_file.txt",
        DiscoverySkipReason.SYMLINK,
        DiscoveryItemKind.SYMLINK,
    ) in skipped


def test_root_outside_allowed_roots_is_rejected(
    discovery_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(InvalidRepositoryRootError, match="outside the allowed roots"):
        discover_repository(outside)


def test_root_path_traversal_is_rejected(
    discovery_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(InvalidRepositoryRootError, match="outside the allowed roots"):
        discover_repository(discovery_root / ".." / "outside")


def test_nonexistent_root_is_rejected(discovery_root: Path) -> None:
    with pytest.raises(InvalidRepositoryRootError, match="existing directory"):
        discover_repository(discovery_root / "missing")


def test_file_root_is_rejected(discovery_root: Path) -> None:
    file_path = write_file(discovery_root / "file.txt")

    with pytest.raises(InvalidRepositoryRootError, match="must be a directory"):
        discover_repository(file_path)


def test_symlink_root_is_rejected(
    discovery_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = discovery_root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    with pytest.raises(InvalidRepositoryRootError, match="symbolic link"):
        discover_repository(link)


def test_max_file_count_truncates(repository: Path) -> None:
    write_file(repository / "a.txt", b"a")
    write_file(repository / "b.txt", b"b")
    write_file(repository / "c.txt", b"c")

    result = discover_repository(repository, max_file_count=2)

    assert [entry.relative_path for entry in result.files] == ["a.txt", "b.txt"]
    assert result.summary.file_count == 2
    assert result.summary.total_size_bytes == 2
    assert result.summary.is_complete is False
    assert result.summary.truncation_reasons == [DiscoveryTruncationReason.MAX_FILE_COUNT]
    assert result.skipped == [
        SkippedItem(
            relative_path="c.txt",
            kind=DiscoveryItemKind.FILE,
            reason=DiscoverySkipReason.MAX_FILE_COUNT,
            detail="Maximum file count reached",
        )
    ]


def test_max_depth_truncates(repository: Path) -> None:
    write_file(repository / "root.txt", b"r")
    write_file(repository / "a" / "one.txt", b"1")
    write_file(repository / "a" / "b" / "two.txt", b"2")

    result = discover_repository(repository, max_depth=1)

    assert [entry.relative_path for entry in result.files] == ["a/one.txt", "root.txt"]
    assert result.summary.directory_count == 1
    assert result.summary.is_complete is False
    assert result.summary.truncation_reasons == [DiscoveryTruncationReason.MAX_DEPTH]
    assert result.skipped == [
        SkippedItem(
            relative_path="a/b",
            kind=DiscoveryItemKind.DIRECTORY,
            reason=DiscoverySkipReason.MAX_DEPTH,
            detail="Maximum traversal depth reached",
        )
    ]

    zero_depth = discover_repository(repository, max_depth=0)

    assert [entry.relative_path for entry in zero_depth.files] == ["root.txt"]
    assert zero_depth.summary.directory_count == 0
    assert zero_depth.summary.is_complete is False
    assert [item.relative_path for item in zero_depth.skipped] == ["a"]


def test_max_total_size_truncates(repository: Path) -> None:
    write_file(repository / "a.bin", b"aaaa")
    write_file(repository / "b.bin", b"bbbb")
    write_file(repository / "c.bin", b"cccc")

    result = discover_repository(repository, max_total_size_bytes=8)

    assert [entry.relative_path for entry in result.files] == ["a.bin", "b.bin"]
    assert result.summary.total_size_bytes == 8
    assert result.summary.is_complete is False
    assert result.summary.truncation_reasons == [DiscoveryTruncationReason.MAX_TOTAL_SIZE]
    assert result.skipped == [
        SkippedItem(
            relative_path="c.bin",
            kind=DiscoveryItemKind.FILE,
            reason=DiscoverySkipReason.MAX_TOTAL_SIZE,
            detail="Maximum total file size reached",
        )
    ]


def test_single_file_larger_than_total_size_limit_is_skipped(repository: Path) -> None:
    write_file(repository / "large.bin", b"12345")

    result = discover_repository(repository, max_total_size_bytes=4)

    assert result.files == []
    assert result.summary.total_size_bytes == 0
    assert result.summary.is_complete is False
    assert result.summary.truncation_reasons == [DiscoveryTruncationReason.MAX_TOTAL_SIZE]
    assert result.skipped[0].relative_path == "large.bin"
    assert result.skipped[0].reason is DiscoverySkipReason.MAX_TOTAL_SIZE


def test_permission_errors_are_recorded(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_file(repository / "blocked" / "secret.txt")
    write_file(repository / "visible.txt")

    real_scan_directory = repository_discovery._scan_directory

    def scan_directory(path: Path) -> list[object]:
        if path.name == "blocked":
            raise PermissionError("permission denied")
        return real_scan_directory(path)

    monkeypatch.setattr(repository_discovery, "_scan_directory", scan_directory)

    result = discover_repository(repository)

    assert [entry.relative_path for entry in result.files] == ["visible.txt"]
    assert result.summary.directory_count == 1
    assert result.summary.is_complete is False
    assert result.summary.truncation_reasons == []
    assert any(
        item.relative_path == "blocked"
        and item.kind is DiscoveryItemKind.DIRECTORY
        and item.reason is DiscoverySkipReason.PERMISSION_DENIED
        for item in result.skipped
    )


def test_disappearing_file_is_recorded(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_file(repository / "stable.txt", b"stable")
    vanishing = write_file(repository / "vanishing.txt", b"gone")

    real_entry_size = repository_discovery._entry_size

    def entry_size(entry: object) -> int:
        if getattr(entry, "name", None) == "vanishing.txt":
            vanishing.unlink(missing_ok=True)
            raise FileNotFoundError("file disappeared")
        return real_entry_size(entry)

    monkeypatch.setattr(repository_discovery, "_entry_size", entry_size)

    result = discover_repository(repository)

    assert [entry.relative_path for entry in result.files] == ["stable.txt"]
    assert result.summary.is_complete is False
    assert any(
        item.relative_path == "vanishing.txt" and item.reason is DiscoverySkipReason.DISAPPEARED
        for item in result.skipped
    )


def test_empty_repository(repository: Path) -> None:
    result = discover_repository(repository)

    assert result.files == []
    assert result.skipped == []
    assert result.summary.directory_count == 0
    assert result.summary.file_count == 0
    assert result.summary.total_size_bytes == 0
    assert result.summary.skipped_count == 0
    assert result.summary.is_complete is True
    assert result.summary.truncation_reasons == []


def test_discover_registered_repository_uses_stored_location(
    session_factory: sessionmaker[Session],
    repository: Path,
) -> None:
    write_file(repository / "app.py", b"print('hi')\n")

    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        repository_target_service.create_repository_target(
            session,
            assessment,
            RepositorySourceCreate(
                source_kind=RepositorySourceKind.LOCAL_PATH,
                location=str(repository),
            ),
        )

        result = discover_registered_repository(session, assessment.id)

    assert result is not None
    assert result.root == str(repository.resolve())
    assert [entry.relative_path for entry in result.files] == ["app.py"]


def test_discover_registered_repository_revalidates_allowed_roots(
    session_factory: sessionmaker[Session],
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        repository_target_service.create_repository_target(
            session,
            assessment,
            RepositorySourceCreate(
                source_kind=RepositorySourceKind.LOCAL_PATH,
                location=str(repository),
            ),
        )

        other_root = tmp_path / "other"
        other_root.mkdir()
        monkeypatch.setattr(settings, "repository_allowed_roots", [other_root])

        with pytest.raises(InvalidRepositoryRootError, match="outside the allowed roots"):
            discover_registered_repository(session, assessment.id)


def test_discover_registered_repository_returns_none_without_target(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )

        assert discover_registered_repository(session, assessment.id) is None


def test_discover_registered_repository_rejects_unknown_assessment(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        with pytest.raises(repository_target_service.AssessmentNotFoundError):
            discover_registered_repository(session, uuid.uuid4())
