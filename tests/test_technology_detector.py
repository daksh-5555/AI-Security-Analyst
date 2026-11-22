import json
import os
import stat
from pathlib import Path

import pytest

from app.core.config import settings
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.repository_discovery import (
    DiscoveryLimits,
    DiscoverySummary,
    FileInventoryEntry,
    RepositoryDiscoveryResult,
)
from app.schemas.technology import (
    TechnologyCategory,
    TechnologyDetection,
    TechnologyDetectionMethod,
    TechnologyDetectionResult,
    TechnologyIssueReason,
)
from app.services.repository_discovery import discover_repository
from app.services.technology_detector import (
    InvalidTechnologyDetectionRootError,
    detect_technologies,
)


@pytest.fixture
def detection_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


@pytest.fixture
def repository(detection_root: Path) -> Path:
    repository = detection_root / "project"
    repository.mkdir()
    return repository


def write_file(path: Path, content: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def write_text(path: Path, text: str) -> Path:
    return write_file(path, text.encode("utf-8"))


def write_json(path: Path, data: object) -> Path:
    return write_text(path, json.dumps(data))


def detect(repository: Path) -> TechnologyDetectionResult:
    inventory = discover_repository(repository)
    return detect_technologies(repository, inventory)


def manual_inventory(
    root: Path,
    relative_paths: list[str],
    *,
    is_complete: bool = True,
    truncation_reasons: list[DiscoveryTruncationReason] | None = None,
) -> RepositoryDiscoveryResult:
    files: list[FileInventoryEntry] = []
    total_size_bytes = 0
    for relative_path in relative_paths:
        path = root / relative_path
        try:
            size_bytes = path.lstat().st_size
        except OSError:
            size_bytes = 0
        extension = path.suffix[1:].lower() if path.suffix else None
        files.append(
            FileInventoryEntry(
                relative_path=relative_path,
                extension=extension,
                size_bytes=size_bytes,
            )
        )
        total_size_bytes += size_bytes

    return RepositoryDiscoveryResult(
        root=str(root.resolve()),
        files=sorted(files, key=lambda entry: entry.relative_path),
        skipped=[],
        summary=DiscoverySummary(
            directory_count=0,
            file_count=len(files),
            total_size_bytes=total_size_bytes,
            skipped_count=0,
            is_complete=is_complete,
            truncation_reasons=list(truncation_reasons or []),
            limits=DiscoveryLimits(
                max_file_count=settings.repository_max_file_count,
                max_depth=settings.repository_max_depth,
                max_total_size_bytes=settings.repository_max_total_size_bytes,
            ),
        ),
    )


def find(
    result: TechnologyDetectionResult,
    name: str,
    category: TechnologyCategory | None = None,
) -> TechnologyDetection | None:
    for detection in result.detections:
        if detection.name == name and (category is None or detection.category is category):
            return detection
    return None


def detection_names(result: TechnologyDetectionResult) -> set[str]:
    return {detection.name for detection in result.detections}


@pytest.mark.parametrize(
    ("extension", "language"),
    [
        ("py", "Python"),
        ("js", "JavaScript"),
        ("ts", "TypeScript"),
        ("java", "Java"),
        ("c", "C"),
        ("cpp", "C++"),
        ("cs", "C#"),
        ("go", "Go"),
        ("rs", "Rust"),
        ("php", "PHP"),
        ("rb", "Ruby"),
        ("kt", "Kotlin"),
        ("swift", "Swift"),
        ("html", "HTML"),
        ("css", "CSS"),
        ("sql", "SQL"),
    ],
)
def test_individual_language_detection(
    repository: Path,
    extension: str,
    language: str,
) -> None:
    write_file(repository / f"main.{extension}")

    result = detect(repository)

    detection = find(result, language, TechnologyCategory.LANGUAGE)
    assert detection is not None
    assert detection.method is TechnologyDetectionMethod.FILE_EXTENSION
    assert detection.confidence == 0.95
    assert detection.file_count == 1
    assert [evidence.path for evidence in detection.evidence] == [f"main.{extension}"]
    assert result.summary.language_count == 1


def test_multiple_languages_and_extension_counting(repository: Path) -> None:
    for relative_path in (
        "src/a.py",
        "src/b.py",
        "web/app.js",
        "web/app.ts",
        "README.md",
    ):
        write_file(repository / relative_path)

    result = detect(repository)

    python = find(result, "Python", TechnologyCategory.LANGUAGE)
    javascript = find(result, "JavaScript", TechnologyCategory.LANGUAGE)
    typescript = find(result, "TypeScript", TechnologyCategory.LANGUAGE)
    assert python is not None
    assert javascript is not None
    assert typescript is not None
    assert python.file_count == 2
    assert [evidence.path for evidence in python.evidence] == ["src/a.py", "src/b.py"]
    assert javascript.file_count == 1
    assert typescript.file_count == 1
    assert result.summary.language_count == 3
    assert "Markdown" not in detection_names(result)


def test_react_detection(repository: Path) -> None:
    write_json(
        repository / "package.json",
        {
            "dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"},
        },
    )

    result = detect(repository)

    react = find(result, "React", TechnologyCategory.FRAMEWORK)
    assert react is not None
    assert react.method is TechnologyDetectionMethod.MANIFEST_DEPENDENCY
    assert react.confidence == 0.95
    assert react.file_count == 1
    assert {evidence.path for evidence in react.evidence} == {"package.json"}
    assert result.summary.framework_count == 1


def test_next_js_detection(repository: Path) -> None:
    write_json(
        repository / "package.json",
        {"dependencies": {"next": "14.2.0"}},
    )

    result = detect(repository)

    next_js = find(result, "Next.js", TechnologyCategory.FRAMEWORK)
    assert next_js is not None
    assert next_js.method is TechnologyDetectionMethod.MANIFEST_DEPENDENCY
    assert next_js.confidence == 0.95


def test_express_detection_from_dev_dependencies(repository: Path) -> None:
    write_json(
        repository / "package.json",
        {"devDependencies": {"express": "^4.19.0"}},
    )

    result = detect(repository)

    express = find(result, "Express", TechnologyCategory.FRAMEWORK)
    assert express is not None
    assert express.evidence[0].detail == "Declared in devDependencies as 'express'."


def test_nestjs_vue_angular_and_fastify_detection(repository: Path) -> None:
    write_json(
        repository / "package.json",
        {
            "dependencies": {
                "@nestjs/core": "^10.0.0",
                "@nestjs/common": "^10.0.0",
                "vue": "^3.4.0",
                "@angular/core": "^18.0.0",
                "fastify": "^4.28.0",
            }
        },
    )

    result = detect(repository)

    assert {
        "NestJS",
        "Vue",
        "Angular",
        "Fastify",
    }.issubset(detection_names(result))
    nestjs = find(result, "NestJS", TechnologyCategory.FRAMEWORK)
    assert nestjs is not None
    assert nestjs.file_count == 1
    assert len(nestjs.evidence) == 2


def test_fastapi_and_sqlalchemy_detection_from_pyproject(repository: Path) -> None:
    write_text(
        repository / "pyproject.toml",
        """
[project]
name = "example"
version = "0.1.0"
dependencies = [
    "fastapi>=0.115",
    "SQLAlchemy>=2.0",
]
""".lstrip(),
    )

    result = detect(repository)

    fastapi = find(result, "FastAPI", TechnologyCategory.FRAMEWORK)
    sqlalchemy = find(result, "SQLAlchemy", TechnologyCategory.LIBRARY)
    assert fastapi is not None
    assert fastapi.confidence == 0.95
    assert sqlalchemy is not None
    assert sqlalchemy.category is TechnologyCategory.LIBRARY


def test_django_and_flask_detection_from_requirements(repository: Path) -> None:
    write_text(
        repository / "requirements.txt",
        """
# Web frameworks
Django==5.0.6
Flask>=3.0
""".lstrip(),
    )

    result = detect(repository)

    django = find(result, "Django", TechnologyCategory.FRAMEWORK)
    flask = find(result, "Flask", TechnologyCategory.FRAMEWORK)
    assert django is not None
    assert flask is not None
    assert django.evidence[0].path == "requirements.txt"
    assert flask.evidence[0].path == "requirements.txt"


def test_langchain_and_pytest_detection_from_poetry(repository: Path) -> None:
    write_text(
        repository / "pyproject.toml",
        """
[tool.poetry]
name = "example"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.115"
langchain = "^0.2"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
""".lstrip(),
    )

    result = detect(repository)

    assert find(result, "FastAPI", TechnologyCategory.FRAMEWORK) is not None
    assert find(result, "LangChain", TechnologyCategory.LIBRARY) is not None
    assert find(result, "pytest", TechnologyCategory.LIBRARY) is not None


def test_docker_detection(repository: Path) -> None:
    write_text(repository / "Dockerfile", "FROM python:3.11-slim\n")

    result = detect(repository)

    docker = find(result, "Docker", TechnologyCategory.INFRASTRUCTURE)
    assert docker is not None
    assert docker.method is TechnologyDetectionMethod.FILENAME_MARKER
    assert docker.confidence == 0.6
    assert docker.evidence[0].path == "Dockerfile"
    assert result.summary.infrastructure_count == 1


def test_multiple_ecosystems_in_one_repository(repository: Path) -> None:
    for relative_path in ("app.py", "web/app.js", "cmd/main.go", "src/lib.rs", "Main.java"):
        write_file(repository / relative_path)
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )
    write_text(
        repository / "pyproject.toml",
        '[project]\nname = "example"\nversion = "0.1.0"\ndependencies = ["fastapi"]\n',
    )
    write_text(
        repository / "go.mod",
        """
module example.com/app

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.9.0
)
""".lstrip(),
    )
    write_text(
        repository / "Cargo.toml",
        """
[package]
name = "example"
version = "0.1.0"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
""".lstrip(),
    )
    write_text(
        repository / "pom.xml",
        """
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>
""".lstrip(),
    )
    write_text(repository / "Dockerfile", "FROM eclipse-temurin:21\n")

    result = detect(repository)

    expected = {
        "Python",
        "JavaScript",
        "Go",
        "Rust",
        "Java",
        "React",
        "FastAPI",
        "Go Modules",
        "Gin",
        "testify",
        "Cargo",
        "Axum",
        "Tokio",
        "Maven",
        "Spring Boot",
        "Docker",
    }
    assert expected.issubset(detection_names(result))
    assert find(result, "Go Modules", TechnologyCategory.BUILD_TOOL) is not None
    assert find(result, "Cargo", TechnologyCategory.BUILD_TOOL) is not None
    assert find(result, "Maven", TechnologyCategory.BUILD_TOOL) is not None
    assert result.summary.build_tool_count == 3
    assert result.summary.infrastructure_count == 1
    assert result.summary.issue_count == 0


def test_duplicate_dependency_declarations_are_aggregated(repository: Path) -> None:
    write_json(
        repository / "package.json",
        {
            "dependencies": {"react": "^18.0.0"},
            "devDependencies": {"react": "^18.0.0"},
        },
    )
    write_text(
        repository / "requirements.txt",
        "fastapi>=0.115\nfastapi[all]==0.115.0\n",
    )

    result = detect(repository)

    react_detections = [detection for detection in result.detections if detection.name == "React"]
    fastapi_detections = [
        detection for detection in result.detections if detection.name == "FastAPI"
    ]
    assert len(react_detections) == 1
    assert len(fastapi_detections) == 1
    assert react_detections[0].file_count == 1
    assert len(react_detections[0].evidence) == 2
    assert fastapi_detections[0].file_count == 1
    assert len(fastapi_detections[0].evidence) == 1


def test_missing_manifests_only_detects_language(repository: Path) -> None:
    write_file(repository / "app.py")

    result = detect(repository)

    assert detection_names(result) == {"Python"}
    assert result.issues == []
    assert result.summary.manifest_files_read == 0
    assert result.summary.issue_count == 0


def test_malformed_json_is_recorded_without_crashing(repository: Path) -> None:
    write_text(repository / "package.json", "{not valid json")
    write_file(repository / "app.py")

    result = detect(repository)

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.INVALID_JSON
        for issue in result.issues
    )
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is None
    assert find(result, "Python", TechnologyCategory.LANGUAGE) is not None
    assert result.summary.manifest_files_read == 1
    assert result.summary.issue_count == 1


def test_malformed_manifest_structure_is_recorded(repository: Path) -> None:
    write_json(repository / "package.json", [])

    result = detect(repository)

    assert result.issues[0].reason is TechnologyIssueReason.MALFORMED_MANIFEST
    assert result.issues[0].path == "package.json"


def test_invalid_toml_is_recorded_without_crashing(repository: Path) -> None:
    write_text(repository / "pyproject.toml", "[project\nname = 'broken'\n")

    result = detect(repository)

    assert any(
        issue.path == "pyproject.toml" and issue.reason is TechnologyIssueReason.INVALID_TOML
        for issue in result.issues
    )
    assert result.summary.manifest_files_read == 1


def test_invalid_xml_is_recorded_without_crashing(repository: Path) -> None:
    write_text(repository / "pom.xml", "<project><dependencies></project>")

    result = detect(repository)

    assert any(
        issue.path == "pom.xml" and issue.reason is TechnologyIssueReason.INVALID_XML
        for issue in result.issues
    )
    assert result.summary.manifest_files_read == 1


def test_invalid_encoding_is_recorded_without_crashing(repository: Path) -> None:
    write_file(repository / "package.json", b"\xff\xfe\x00\x00")

    result = detect(repository)

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.INVALID_ENCODING
        for issue in result.issues
    )
    assert result.summary.manifest_files_read == 0


def test_manifest_exceeding_maximum_size_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "technology_manifest_max_size_bytes", 16)
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    result = detect(repository)

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.TOO_LARGE
        for issue in result.issues
    )
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is None
    assert result.summary.manifest_files_read == 0


def test_maximum_manifest_files_is_enforced(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "technology_max_manifest_files", 1)
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )
    write_text(repository / "requirements.txt", "fastapi>=0.115\n")

    result = detect(repository)

    assert find(result, "React", TechnologyCategory.FRAMEWORK) is not None
    assert find(result, "FastAPI", TechnologyCategory.FRAMEWORK) is None
    assert any(
        issue.path == "requirements.txt"
        and issue.reason is TechnologyIssueReason.MAX_MANIFEST_FILES
        for issue in result.issues
    )
    assert result.summary.manifest_files_read == 1


def test_symlink_manifest_is_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_manifest = write_json(
        outside / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )
    link = repository / "package.json"
    try:
        link.symlink_to(outside_manifest)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    result = detect_technologies(
        repository,
        manual_inventory(repository, ["package.json"]),
    )

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.SYMLINK
        for issue in result.issues
    )
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is None


def test_symlink_manifest_metadata_is_rejected(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path.name == "package.json":
            return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    result = detect_technologies(
        repository,
        manual_inventory(repository, ["package.json"]),
    )

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.SYMLINK
        for issue in result.issues
    )
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is None


def test_outside_root_manifest_path_is_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    write_json(
        outside / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    result = detect_technologies(
        repository,
        manual_inventory(repository, ["../outside/package.json"]),
    )

    assert any(
        issue.path == "../outside/package.json"
        and issue.reason is TechnologyIssueReason.OUTSIDE_ROOT
        for issue in result.issues
    )
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is None


def test_absolute_manifest_path_is_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    outside_manifest = write_json(
        tmp_path / "outside" / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    result = detect_technologies(
        repository,
        manual_inventory(repository, [str(outside_manifest)]),
    )

    assert any(issue.reason is TechnologyIssueReason.INVALID_PATH for issue in result.issues)
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is None


def test_env_file_is_never_read(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / ".env", "SECRET=super-secret\n")
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == ".env":
            raise AssertionError("Technology detection must not read .env")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = detect(repository)

    assert find(result, "React", TechnologyCategory.FRAMEWORK) is not None
    assert all(
        evidence.path != ".env"
        for detection in result.detections
        for evidence in detection.evidence
    )
    assert result.issues == []


def test_source_code_content_is_never_read(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_text(repository / "app.py", "SECRET = 'super-secret'\n")
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    real_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.suffix == ".py":
            raise AssertionError("Technology detection must not read source code")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    result = detect(repository)

    assert find(result, "Python", TechnologyCategory.LANGUAGE) is not None
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is not None


def test_permission_error_is_recorded(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    def denied_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "package.json":
            raise PermissionError("permission denied")
        return Path.open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied_open)

    result = detect(repository)

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.PERMISSION_DENIED
        for issue in result.issues
    )
    assert result.summary.manifest_files_read == 0


def test_disappearing_manifest_is_recorded(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )

    def disappearing_open(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "package.json":
            raise FileNotFoundError("manifest disappeared")
        return Path.open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", disappearing_open)

    result = detect(repository)

    assert any(
        issue.path == "package.json" and issue.reason is TechnologyIssueReason.DISAPPEARED
        for issue in result.issues
    )


def test_incomplete_discovery_is_propagated(repository: Path) -> None:
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0"}},
    )
    write_json(
        repository / "src" / "package.json",
        {"dependencies": {"next": "14.2.0"}},
    )

    inventory = discover_repository(repository, max_depth=0)
    result = detect_technologies(repository, inventory)

    assert inventory.summary.is_complete is False
    assert result.summary.discovery_is_complete is False
    assert result.summary.discovery_truncation_reasons == [DiscoveryTruncationReason.MAX_DEPTH]
    assert find(result, "React", TechnologyCategory.FRAMEWORK) is not None
    assert find(result, "Next.js", TechnologyCategory.FRAMEWORK) is None


def test_detection_is_deterministic(repository: Path) -> None:
    write_file(repository / "app.py")
    write_file(repository / "web" / "app.js")
    write_json(
        repository / "package.json",
        {"dependencies": {"react": "^18.0.0", "express": "^4.19.0"}},
    )
    write_text(repository / "requirements.txt", "fastapi>=0.115\nDjango==5.0\n")
    write_text(repository / "Dockerfile", "FROM python:3.11\n")

    first = detect(repository)
    second = detect(repository)

    assert first == second
    assert [detection.name for detection in first.detections] == [
        "JavaScript",
        "Python",
        "Django",
        "Express",
        "FastAPI",
        "React",
        "Docker",
    ]
    assert [issue.path for issue in first.issues] == sorted(issue.path for issue in first.issues)


def test_invalid_root_is_rejected(
    detection_root: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    inventory = manual_inventory(outside, [])

    with pytest.raises(InvalidTechnologyDetectionRootError, match="outside the allowed roots"):
        detect_technologies(outside, inventory)


def test_nonexistent_root_is_rejected(detection_root: Path) -> None:
    missing = detection_root / "missing"

    with pytest.raises(InvalidTechnologyDetectionRootError, match="existing directory"):
        detect_technologies(missing, manual_inventory(missing, []))


def test_inventory_root_mismatch_is_rejected(repository: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    inventory = manual_inventory(other, [])

    with pytest.raises(InvalidTechnologyDetectionRootError, match="does not match"):
        detect_technologies(repository, inventory)
