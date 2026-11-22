"""Deterministic, read-only technology stack detection.

The detector consumes a :class:`RepositoryDiscoveryResult` and never traverses
the filesystem or reads source-code files. Languages are inferred from the
inventory's extensions, and frameworks, libraries, databases, infrastructure,
and build tools are inferred only from an explicit allowlist of manifests.

Confidence rules
----------------
- ``0.95`` for an exact language extension mapping.
- ``0.95`` for an exact recognized dependency in a manifest.
- ``0.85`` for a manifest content marker such as a module declaration.
- ``0.60`` for an infrastructure filename marker such as ``Dockerfile``.

TOCTOU limitations
------------------
Manifest paths are validated as relative, contained, and non-symlink
immediately before they are opened, but the filesystem can change between
validation and the read. A manifest could be replaced by a symlink or moved
outside the root after validation. Reads are size-capped and failures are
recorded as structured issues; fully race-free operation would require
platform-specific directory handles.
"""

import json
import os
import re
import stat
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

from app.core.config import settings
from app.schemas.enums import DiscoverySkipReason
from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.technology import (
    TechnologyCategory,
    TechnologyDetection,
    TechnologyDetectionIssue,
    TechnologyDetectionMethod,
    TechnologyDetectionResult,
    TechnologyDetectionSummary,
    TechnologyEvidence,
    TechnologyIssueReason,
)
from app.services.repository_targets import (
    InvalidRepositoryLocationError,
    validate_repository_location,
)

MANIFEST_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "Dockerfile",
    }
)

_EXTENSION_CONFIDENCE: Final[float] = 0.95
_DEPENDENCY_CONFIDENCE: Final[float] = 0.95
_MANIFEST_MARKER_CONFIDENCE: Final[float] = 0.85
_INFRASTRUCTURE_FILENAME_CONFIDENCE: Final[float] = 0.60

_WINDOWS_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")
_REQUIREMENT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_PYTHON_NAME_SEPARATORS_RE: Final[re.Pattern[str]] = re.compile(r"[-_.]+")
_GO_VERSION_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"/v[0-9]+$")

_CATEGORY_ORDER: Final[dict[TechnologyCategory, int]] = {
    TechnologyCategory.LANGUAGE: 0,
    TechnologyCategory.FRAMEWORK: 1,
    TechnologyCategory.LIBRARY: 2,
    TechnologyCategory.DATABASE: 3,
    TechnologyCategory.INFRASTRUCTURE: 4,
    TechnologyCategory.BUILD_TOOL: 5,
}

_METHOD_PRIORITY: Final[dict[TechnologyDetectionMethod, int]] = {
    TechnologyDetectionMethod.MANIFEST_DEPENDENCY: 3,
    TechnologyDetectionMethod.FILE_EXTENSION: 2,
    TechnologyDetectionMethod.MANIFEST_MARKER: 1,
    TechnologyDetectionMethod.FILENAME_MARKER: 0,
}

_DISCOVERY_ISSUE_REASONS: Final[dict[DiscoverySkipReason, TechnologyIssueReason]] = {
    DiscoverySkipReason.SYMLINK: TechnologyIssueReason.SYMLINK,
    DiscoverySkipReason.NOT_REGULAR_FILE: TechnologyIssueReason.NOT_REGULAR_FILE,
    DiscoverySkipReason.PERMISSION_DENIED: TechnologyIssueReason.PERMISSION_DENIED,
    DiscoverySkipReason.DISAPPEARED: TechnologyIssueReason.DISAPPEARED,
    DiscoverySkipReason.INACCESSIBLE: TechnologyIssueReason.INACCESSIBLE,
    DiscoverySkipReason.OUTSIDE_ROOT: TechnologyIssueReason.OUTSIDE_ROOT,
}


class TechnologyDetectionError(ValueError):
    """Base error for technology detection operations."""


class InvalidTechnologyDetectionRootError(TechnologyDetectionError):
    """Raised when a detection root is not a safe, existing directory."""


# Alias matching the discovery service's exception name for callers that
# treat both phases uniformly.
InvalidRepositoryRootError = InvalidTechnologyDetectionRootError


class _ManifestParseError(Exception):
    """A manifest was read but could not be parsed safely."""

    def __init__(self, reason: TechnologyIssueReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class _Technology:
    name: str
    category: TechnologyCategory


@dataclass
class _Detection:
    technology: _Technology
    method: TechnologyDetectionMethod
    confidence: float
    evidence: dict[tuple[str, str], TechnologyEvidence] = field(default_factory=dict)

    def add_evidence(self, path: str, detail: str) -> None:
        self.evidence.setdefault((path, detail), TechnologyEvidence(path=path, detail=detail))


_DetectionRegistry = dict[tuple[TechnologyCategory, str], _Detection]


def _technology(name: str, category: TechnologyCategory) -> _Technology:
    return _Technology(name=name, category=category)


_LANGUAGE_EXTENSIONS: Final[dict[str, _Technology]] = {
    "py": _technology("Python", TechnologyCategory.LANGUAGE),
    "pyi": _technology("Python", TechnologyCategory.LANGUAGE),
    "js": _technology("JavaScript", TechnologyCategory.LANGUAGE),
    "mjs": _technology("JavaScript", TechnologyCategory.LANGUAGE),
    "cjs": _technology("JavaScript", TechnologyCategory.LANGUAGE),
    "jsx": _technology("JavaScript", TechnologyCategory.LANGUAGE),
    "ts": _technology("TypeScript", TechnologyCategory.LANGUAGE),
    "mts": _technology("TypeScript", TechnologyCategory.LANGUAGE),
    "cts": _technology("TypeScript", TechnologyCategory.LANGUAGE),
    "tsx": _technology("TypeScript", TechnologyCategory.LANGUAGE),
    "java": _technology("Java", TechnologyCategory.LANGUAGE),
    "c": _technology("C", TechnologyCategory.LANGUAGE),
    "h": _technology("C", TechnologyCategory.LANGUAGE),
    "cpp": _technology("C++", TechnologyCategory.LANGUAGE),
    "cc": _technology("C++", TechnologyCategory.LANGUAGE),
    "cxx": _technology("C++", TechnologyCategory.LANGUAGE),
    "hpp": _technology("C++", TechnologyCategory.LANGUAGE),
    "hh": _technology("C++", TechnologyCategory.LANGUAGE),
    "hxx": _technology("C++", TechnologyCategory.LANGUAGE),
    "cs": _technology("C#", TechnologyCategory.LANGUAGE),
    "go": _technology("Go", TechnologyCategory.LANGUAGE),
    "rs": _technology("Rust", TechnologyCategory.LANGUAGE),
    "php": _technology("PHP", TechnologyCategory.LANGUAGE),
    "rb": _technology("Ruby", TechnologyCategory.LANGUAGE),
    "kt": _technology("Kotlin", TechnologyCategory.LANGUAGE),
    "kts": _technology("Kotlin", TechnologyCategory.LANGUAGE),
    "swift": _technology("Swift", TechnologyCategory.LANGUAGE),
    "html": _technology("HTML", TechnologyCategory.LANGUAGE),
    "htm": _technology("HTML", TechnologyCategory.LANGUAGE),
    "css": _technology("CSS", TechnologyCategory.LANGUAGE),
    "scss": _technology("CSS", TechnologyCategory.LANGUAGE),
    "sass": _technology("CSS", TechnologyCategory.LANGUAGE),
    "sql": _technology("SQL", TechnologyCategory.LANGUAGE),
}

_DOCKER = _technology("Docker", TechnologyCategory.INFRASTRUCTURE)
_GO_MODULES = _technology("Go Modules", TechnologyCategory.BUILD_TOOL)
_CARGO = _technology("Cargo", TechnologyCategory.BUILD_TOOL)
_MAVEN = _technology("Maven", TechnologyCategory.BUILD_TOOL)

_JS_DEPENDENCIES: Final[dict[str, _Technology]] = {
    "react": _technology("React", TechnologyCategory.FRAMEWORK),
    "react-dom": _technology("React", TechnologyCategory.FRAMEWORK),
    "next": _technology("Next.js", TechnologyCategory.FRAMEWORK),
    "express": _technology("Express", TechnologyCategory.FRAMEWORK),
    "@nestjs/core": _technology("NestJS", TechnologyCategory.FRAMEWORK),
    "@nestjs/common": _technology("NestJS", TechnologyCategory.FRAMEWORK),
    "@nestjs/platform-express": _technology("NestJS", TechnologyCategory.FRAMEWORK),
    "vue": _technology("Vue", TechnologyCategory.FRAMEWORK),
    "@angular/core": _technology("Angular", TechnologyCategory.FRAMEWORK),
    "fastify": _technology("Fastify", TechnologyCategory.FRAMEWORK),
    "pg": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "postgres": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "mysql": _technology("MySQL", TechnologyCategory.DATABASE),
    "mysql2": _technology("MySQL", TechnologyCategory.DATABASE),
    "mongodb": _technology("MongoDB", TechnologyCategory.DATABASE),
    "mongoose": _technology("Mongoose", TechnologyCategory.LIBRARY),
    "redis": _technology("Redis", TechnologyCategory.DATABASE),
    "ioredis": _technology("Redis", TechnologyCategory.DATABASE),
    "sqlite3": _technology("SQLite", TechnologyCategory.DATABASE),
    "better-sqlite3": _technology("SQLite", TechnologyCategory.DATABASE),
    "sequelize": _technology("Sequelize", TechnologyCategory.LIBRARY),
    "prisma": _technology("Prisma", TechnologyCategory.LIBRARY),
    "@prisma/client": _technology("Prisma", TechnologyCategory.LIBRARY),
    "typeorm": _technology("TypeORM", TechnologyCategory.LIBRARY),
    "knex": _technology("Knex", TechnologyCategory.LIBRARY),
    "drizzle-orm": _technology("Drizzle ORM", TechnologyCategory.LIBRARY),
}

_PYTHON_DEPENDENCIES: Final[dict[str, _Technology]] = {
    "fastapi": _technology("FastAPI", TechnologyCategory.FRAMEWORK),
    "django": _technology("Django", TechnologyCategory.FRAMEWORK),
    "flask": _technology("Flask", TechnologyCategory.FRAMEWORK),
    "sqlalchemy": _technology("SQLAlchemy", TechnologyCategory.LIBRARY),
    "flask-sqlalchemy": _technology("SQLAlchemy", TechnologyCategory.LIBRARY),
    "langchain": _technology("LangChain", TechnologyCategory.LIBRARY),
    "langchain-core": _technology("LangChain", TechnologyCategory.LIBRARY),
    "langchain-community": _technology("LangChain", TechnologyCategory.LIBRARY),
    "pytest": _technology("pytest", TechnologyCategory.LIBRARY),
    "psycopg2": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "psycopg2-binary": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "psycopg": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "asyncpg": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "pymysql": _technology("MySQL", TechnologyCategory.DATABASE),
    "mysqlclient": _technology("MySQL", TechnologyCategory.DATABASE),
    "mysql-connector-python": _technology("MySQL", TechnologyCategory.DATABASE),
    "pymongo": _technology("MongoDB", TechnologyCategory.DATABASE),
    "motor": _technology("MongoDB", TechnologyCategory.DATABASE),
    "redis": _technology("Redis", TechnologyCategory.DATABASE),
    "aioredis": _technology("Redis", TechnologyCategory.DATABASE),
}

_GO_DEPENDENCIES: Final[dict[str, _Technology]] = {
    "github.com/gin-gonic/gin": _technology("Gin", TechnologyCategory.FRAMEWORK),
    "github.com/labstack/echo": _technology("Echo", TechnologyCategory.FRAMEWORK),
    "github.com/labstack/echo/v4": _technology("Echo", TechnologyCategory.FRAMEWORK),
    "github.com/gofiber/fiber": _technology("Fiber", TechnologyCategory.FRAMEWORK),
    "github.com/gofiber/fiber/v2": _technology("Fiber", TechnologyCategory.FRAMEWORK),
    "github.com/go-chi/chi": _technology("Chi", TechnologyCategory.FRAMEWORK),
    "github.com/go-chi/chi/v5": _technology("Chi", TechnologyCategory.FRAMEWORK),
    "github.com/gorilla/mux": _technology("Gorilla Mux", TechnologyCategory.FRAMEWORK),
    "google.golang.org/grpc": _technology("gRPC", TechnologyCategory.FRAMEWORK),
    "gorm.io/gorm": _technology("GORM", TechnologyCategory.LIBRARY),
    "github.com/stretchr/testify": _technology("testify", TechnologyCategory.LIBRARY),
    "github.com/spf13/cobra": _technology("Cobra", TechnologyCategory.LIBRARY),
    "github.com/spf13/viper": _technology("Viper", TechnologyCategory.LIBRARY),
    "github.com/golang-jwt/jwt": _technology("JWT", TechnologyCategory.LIBRARY),
    "github.com/golang-jwt/jwt/v5": _technology("JWT", TechnologyCategory.LIBRARY),
    "github.com/sirupsen/logrus": _technology("Logrus", TechnologyCategory.LIBRARY),
    "go.uber.org/zap": _technology("Zap", TechnologyCategory.LIBRARY),
    "github.com/rs/zerolog": _technology("Zerolog", TechnologyCategory.LIBRARY),
    "github.com/joho/godotenv": _technology("godotenv", TechnologyCategory.LIBRARY),
    "github.com/lib/pq": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "github.com/jackc/pgx": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "github.com/jackc/pgx/v5": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "github.com/go-sql-driver/mysql": _technology("MySQL", TechnologyCategory.DATABASE),
    "github.com/mattn/go-sqlite3": _technology("SQLite", TechnologyCategory.DATABASE),
    "go.mongodb.org/mongo-driver": _technology("MongoDB", TechnologyCategory.DATABASE),
    "github.com/redis/go-redis": _technology("Redis", TechnologyCategory.DATABASE),
    "github.com/redis/go-redis/v9": _technology("Redis", TechnologyCategory.DATABASE),
}

_CARGO_DEPENDENCIES: Final[dict[str, _Technology]] = {
    "actix-web": _technology("Actix Web", TechnologyCategory.FRAMEWORK),
    "axum": _technology("Axum", TechnologyCategory.FRAMEWORK),
    "rocket": _technology("Rocket", TechnologyCategory.FRAMEWORK),
    "warp": _technology("Warp", TechnologyCategory.FRAMEWORK),
    "tauri": _technology("Tauri", TechnologyCategory.FRAMEWORK),
    "leptos": _technology("Leptos", TechnologyCategory.FRAMEWORK),
    "yew": _technology("Yew", TechnologyCategory.FRAMEWORK),
    "tokio": _technology("Tokio", TechnologyCategory.LIBRARY),
    "serde": _technology("Serde", TechnologyCategory.LIBRARY),
    "serde-json": _technology("serde_json", TechnologyCategory.LIBRARY),
    "diesel": _technology("Diesel", TechnologyCategory.LIBRARY),
    "sqlx": _technology("SQLx", TechnologyCategory.LIBRARY),
    "sea-orm": _technology("SeaORM", TechnologyCategory.LIBRARY),
    "reqwest": _technology("reqwest", TechnologyCategory.LIBRARY),
    "clap": _technology("Clap", TechnologyCategory.LIBRARY),
    "tracing": _technology("tracing", TechnologyCategory.LIBRARY),
    "thiserror": _technology("thiserror", TechnologyCategory.LIBRARY),
    "anyhow": _technology("anyhow", TechnologyCategory.LIBRARY),
    "chrono": _technology("Chrono", TechnologyCategory.LIBRARY),
    "uuid": _technology("uuid", TechnologyCategory.LIBRARY),
    "log": _technology("log", TechnologyCategory.LIBRARY),
    "env-logger": _technology("env_logger", TechnologyCategory.LIBRARY),
    "rusqlite": _technology("SQLite", TechnologyCategory.DATABASE),
    "postgres": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "tokio-postgres": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "mongodb": _technology("MongoDB", TechnologyCategory.DATABASE),
    "redis": _technology("Redis", TechnologyCategory.DATABASE),
}

_MAVEN_DEPENDENCIES: Final[dict[str, _Technology]] = {
    "spring-boot-starter-web": _technology("Spring Boot", TechnologyCategory.FRAMEWORK),
    "spring-boot-starter": _technology("Spring Boot", TechnologyCategory.FRAMEWORK),
    "spring-boot-starter-data-jpa": _technology("Spring Boot", TechnologyCategory.FRAMEWORK),
    "spring-boot-starter-test": _technology("Spring Boot", TechnologyCategory.FRAMEWORK),
    "spring-webmvc": _technology("Spring Framework", TechnologyCategory.FRAMEWORK),
    "spring-context": _technology("Spring Framework", TechnologyCategory.FRAMEWORK),
    "spring-core": _technology("Spring Framework", TechnologyCategory.FRAMEWORK),
    "hibernate-core": _technology("Hibernate", TechnologyCategory.LIBRARY),
    "spring-data-jpa": _technology("Spring Data JPA", TechnologyCategory.LIBRARY),
    "junit": _technology("JUnit", TechnologyCategory.LIBRARY),
    "junit-jupiter": _technology("JUnit", TechnologyCategory.LIBRARY),
    "junit-jupiter-api": _technology("JUnit", TechnologyCategory.LIBRARY),
    "junit-jupiter-engine": _technology("JUnit", TechnologyCategory.LIBRARY),
    "junit-platform-launcher": _technology("JUnit", TechnologyCategory.LIBRARY),
    "mockito-core": _technology("Mockito", TechnologyCategory.LIBRARY),
    "lombok": _technology("Lombok", TechnologyCategory.LIBRARY),
    "slf4j-api": _technology("SLF4J", TechnologyCategory.LIBRARY),
    "logback-classic": _technology("Logback", TechnologyCategory.LIBRARY),
    "jackson-databind": _technology("Jackson", TechnologyCategory.LIBRARY),
    "jakarta.servlet-api": _technology("Jakarta Servlet", TechnologyCategory.LIBRARY),
    "javax.servlet-api": _technology("Jakarta Servlet", TechnologyCategory.LIBRARY),
    "kafka-clients": _technology("Apache Kafka", TechnologyCategory.INFRASTRUCTURE),
    "postgresql": _technology("PostgreSQL", TechnologyCategory.DATABASE),
    "mysql-connector-java": _technology("MySQL", TechnologyCategory.DATABASE),
    "mysql-connector-j": _technology("MySQL", TechnologyCategory.DATABASE),
    "h2": _technology("H2 Database", TechnologyCategory.DATABASE),
    "mongodb-driver-sync": _technology("MongoDB", TechnologyCategory.DATABASE),
}


def _issue(
    path: str,
    reason: TechnologyIssueReason,
    detail: str | None = None,
) -> TechnologyDetectionIssue:
    return TechnologyDetectionIssue(path=path, reason=reason, detail=detail)


def _normalize_python_name(name: str) -> str:
    return _PYTHON_NAME_SEPARATORS_RE.sub("-", name.strip().lower())


def _normalize_js_name(name: str) -> str:
    return name.strip().lower()


def _normalize_crate_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _normalize_maven_artifact(name: str) -> str:
    return name.strip().lower()


def _extract_requirement_name(requirement: str) -> str | None:
    match = _REQUIREMENT_NAME_RE.match(requirement.strip())
    return match.group(1) if match else None


def _add_detection(
    registry: _DetectionRegistry,
    technology: _Technology,
    *,
    method: TechnologyDetectionMethod,
    confidence: float,
    path: str,
    detail: str,
) -> None:
    key = (technology.category, technology.name)
    detection = registry.get(key)
    if detection is None:
        detection = _Detection(
            technology=technology,
            method=method,
            confidence=confidence,
        )
        registry[key] = detection
    elif confidence > detection.confidence or (
        confidence == detection.confidence
        and _METHOD_PRIORITY[method] > _METHOD_PRIORITY[detection.method]
    ):
        detection.method = method
        detection.confidence = confidence

    detection.add_evidence(path, detail)


def _finalize_detections(registry: _DetectionRegistry) -> list[TechnologyDetection]:
    detections: list[TechnologyDetection] = []
    for detection in registry.values():
        evidence = sorted(
            detection.evidence.values(),
            key=lambda item: (item.path, item.detail),
        )
        detections.append(
            TechnologyDetection(
                name=detection.technology.name,
                category=detection.technology.category,
                confidence=detection.confidence,
                evidence=evidence,
                method=detection.method,
                file_count=len({item.path for item in evidence}),
            )
        )
    return sorted(
        detections,
        key=lambda item: (
            _CATEGORY_ORDER[item.category],
            item.name.casefold(),
            item.name,
        ),
    )


def _detect_languages(
    inventory: RepositoryDiscoveryResult,
    registry: _DetectionRegistry,
) -> None:
    for entry in inventory.files:
        extension = entry.extension.lower() if entry.extension else None
        if extension is None:
            continue
        technology = _LANGUAGE_EXTENSIONS.get(extension)
        if technology is None:
            continue
        _add_detection(
            registry,
            technology,
            method=TechnologyDetectionMethod.FILE_EXTENSION,
            confidence=_EXTENSION_CONFIDENCE,
            path=entry.relative_path,
            detail=f"File extension '.{extension}' maps to {technology.name}.",
        )


def _manifest_candidates(
    inventory: RepositoryDiscoveryResult,
) -> list[tuple[str, str]]:
    candidates: dict[str, str] = {}
    for entry in inventory.files:
        normalized = entry.relative_path.replace("\\", "/")
        basename = PurePosixPath(normalized).name
        if basename in MANIFEST_FILENAMES:
            candidates.setdefault(entry.relative_path, basename)
    return sorted(candidates.items(), key=lambda item: item[0])


def _discovery_manifest_issues(
    inventory: RepositoryDiscoveryResult,
) -> list[TechnologyDetectionIssue]:
    issues: list[TechnologyDetectionIssue] = []
    for item in inventory.skipped:
        normalized = item.relative_path.replace("\\", "/")
        if PurePosixPath(normalized).name not in MANIFEST_FILENAMES:
            continue
        reason = _DISCOVERY_ISSUE_REASONS.get(item.reason)
        if reason is None:
            continue
        issues.append(_issue(item.relative_path, reason, item.detail))
    return issues


def _is_reparse_point(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_manifest_path(
    root: Path,
    relative_path: str,
    max_size: int,
) -> tuple[Path | None, TechnologyDetectionIssue | None]:
    normalized = relative_path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or _WINDOWS_DRIVE_RE.match(normalized):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INVALID_PATH,
            "Manifest path must be relative to the repository root",
        )
    if not pure.parts or any(part == ".." for part in pure.parts):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.OUTSIDE_ROOT,
            "Manifest path escapes the repository root",
        )

    candidate = root.joinpath(*pure.parts)
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.DISAPPEARED,
            "Manifest disappeared before inspection",
        )
    except PermissionError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.PERMISSION_DENIED,
            "Permission denied while reading manifest metadata",
        )
    except ValueError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INVALID_PATH,
            "Manifest path is not a valid filesystem path",
        )
    except OSError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INACCESSIBLE,
            "Manifest metadata could not be inspected",
        )

    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.SYMLINK,
            "Symbolic links are not followed",
        )
    if not stat.S_ISREG(metadata.st_mode):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.NOT_REGULAR_FILE,
            "Manifest is not a regular file",
        )

    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.DISAPPEARED,
            "Manifest disappeared before inspection",
        )
    except ValueError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INVALID_PATH,
            "Manifest path is not a valid filesystem path",
        )
    except (OSError, RuntimeError):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INACCESSIBLE,
            "Manifest path could not be resolved",
        )

    if not resolved.is_relative_to(root):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.OUTSIDE_ROOT,
            "Manifest resolves outside the repository root",
        )
    if metadata.st_size > max_size:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.TOO_LARGE,
            f"Manifest exceeds the {max_size} byte limit",
        )
    return candidate, None


def _read_manifest_text(
    path: Path,
    relative_path: str,
    max_size: int,
) -> tuple[str | None, TechnologyDetectionIssue | None]:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_size + 1)
    except FileNotFoundError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.DISAPPEARED,
            "Manifest disappeared before it could be read",
        )
    except PermissionError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.PERMISSION_DENIED,
            "Permission denied while reading manifest",
        )
    except ValueError:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INVALID_PATH,
            "Manifest path is not a valid filesystem path",
        )
    except (OSError, RuntimeError):
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INACCESSIBLE,
            "Manifest could not be read",
        )

    if len(data) > max_size:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.TOO_LARGE,
            f"Manifest exceeds the {max_size} byte limit",
        )
    try:
        return data.decode("utf-8-sig"), None
    except UnicodeDecodeError as exc:
        return None, _issue(
            relative_path,
            TechnologyIssueReason.INVALID_ENCODING,
            f"Manifest is not valid UTF-8: {exc}",
        )


def _parse_package_json(text: str, path: str, registry: _DetectionRegistry) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ManifestParseError(
            TechnologyIssueReason.INVALID_JSON,
            f"Invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}",
        ) from exc
    if not isinstance(data, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            "package.json must contain a JSON object",
        )

    for section in ("dependencies", "devDependencies"):
        if section not in data:
            continue
        raw_dependencies = data[section]
        if not isinstance(raw_dependencies, dict):
            raise _ManifestParseError(
                TechnologyIssueReason.MALFORMED_MANIFEST,
                f"'{section}' must be a JSON object",
            )
        for raw_name in sorted(raw_dependencies):
            technology = _JS_DEPENDENCIES.get(_normalize_js_name(raw_name))
            if technology is None:
                continue
            _add_detection(
                registry,
                technology,
                method=TechnologyDetectionMethod.MANIFEST_DEPENDENCY,
                confidence=_DEPENDENCY_CONFIDENCE,
                path=path,
                detail=f"Declared in {section} as '{raw_name}'.",
            )


def _add_python_package(
    registry: _DetectionRegistry,
    package_name: str,
    context: str,
    path: str,
) -> None:
    technology = _PYTHON_DEPENDENCIES.get(_normalize_python_name(package_name))
    if technology is None:
        return
    _add_detection(
        registry,
        technology,
        method=TechnologyDetectionMethod.MANIFEST_DEPENDENCY,
        confidence=_DEPENDENCY_CONFIDENCE,
        path=path,
        detail=f"Declared in {context} as '{package_name}'.",
    )


def _add_requirement_list(
    registry: _DetectionRegistry,
    value: Any,
    context: str,
    path: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            f"'{context}' must be an array",
        )
    for requirement in value:
        if not isinstance(requirement, str):
            continue
        package_name = _extract_requirement_name(requirement)
        if package_name is not None:
            _add_python_package(registry, package_name, context, path)


def _add_python_package_mapping(
    registry: _DetectionRegistry,
    value: Any,
    context: str,
    path: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            f"'{context}' must be a table",
        )
    for package_name in sorted(value):
        if not isinstance(package_name, str):
            continue
        if _normalize_python_name(package_name) == "python":
            continue
        _add_python_package(registry, package_name, context, path)


def _parse_poetry(
    registry: _DetectionRegistry,
    poetry: Any,
    path: str,
) -> None:
    if not isinstance(poetry, dict):
        return
    for section in ("dependencies", "dev-dependencies"):
        _add_python_package_mapping(
            registry,
            poetry.get(section),
            f"tool.poetry.{section}",
            path,
        )
    groups = poetry.get("group")
    if groups is None:
        return
    if not isinstance(groups, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            "'tool.poetry.group' must be a table",
        )
    for group_name in sorted(groups):
        group = groups[group_name]
        if not isinstance(group, dict):
            continue
        _add_python_package_mapping(
            registry,
            group.get("dependencies"),
            f"tool.poetry.group.{group_name}.dependencies",
            path,
        )


def _parse_pdm(registry: _DetectionRegistry, pdm: Any, path: str) -> None:
    if not isinstance(pdm, dict):
        return
    dev_dependencies = pdm.get("dev-dependencies")
    if dev_dependencies is None:
        return
    if not isinstance(dev_dependencies, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            "'tool.pdm.dev-dependencies' must be a table",
        )
    for group_name in sorted(dev_dependencies):
        _add_requirement_list(
            registry,
            dev_dependencies[group_name],
            f"tool.pdm.dev-dependencies.{group_name}",
            path,
        )


def _parse_pyproject(text: str, path: str, registry: _DetectionRegistry) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise _ManifestParseError(
            TechnologyIssueReason.INVALID_TOML,
            f"Invalid TOML: {exc}",
        ) from exc
    if not isinstance(data, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            "pyproject.toml must contain a table",
        )

    project = data.get("project")
    if project is not None:
        if not isinstance(project, dict):
            raise _ManifestParseError(
                TechnologyIssueReason.MALFORMED_MANIFEST,
                "'project' must be a table",
            )
        _add_requirement_list(
            registry,
            project.get("dependencies"),
            "project.dependencies",
            path,
        )
        optional = project.get("optional-dependencies")
        if optional is not None:
            if not isinstance(optional, dict):
                raise _ManifestParseError(
                    TechnologyIssueReason.MALFORMED_MANIFEST,
                    "'project.optional-dependencies' must be a table",
                )
            for group_name in sorted(optional):
                _add_requirement_list(
                    registry,
                    optional[group_name],
                    f"project.optional-dependencies.{group_name}",
                    path,
                )

    dependency_groups = data.get("dependency-groups")
    if dependency_groups is not None:
        if not isinstance(dependency_groups, dict):
            raise _ManifestParseError(
                TechnologyIssueReason.MALFORMED_MANIFEST,
                "'dependency-groups' must be a table",
            )
        for group_name in sorted(dependency_groups):
            _add_requirement_list(
                registry,
                dependency_groups[group_name],
                f"dependency-groups.{group_name}",
                path,
            )

    tool = data.get("tool")
    if isinstance(tool, dict):
        _parse_poetry(registry, tool.get("poetry"), path)
        _parse_pdm(registry, tool.get("pdm"), path)


def _parse_requirements(text: str, path: str, registry: _DetectionRegistry) -> None:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        lowered = line.lower()
        if lowered.startswith(("git+", "http://", "https://", "ftp://", "file:")):
            continue
        if line.startswith(("/", "./", "../", "~")):
            continue
        package_name = _extract_requirement_name(line)
        if package_name is not None:
            _add_python_package(registry, package_name, "requirements.txt", path)


def _match_go_dependency(module: str) -> _Technology | None:
    normalized = module.strip().strip('"').lower().split("+", 1)[0]
    technology = _GO_DEPENDENCIES.get(normalized)
    if technology is not None:
        return technology
    without_version = _GO_VERSION_SUFFIX_RE.sub("", normalized)
    return _GO_DEPENDENCIES.get(without_version)


def _parse_go_mod(text: str, path: str, registry: _DetectionRegistry) -> None:
    module_name: str | None = None
    requirements: set[str] = set()
    in_require_block = False

    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if in_require_block:
            if line == ")":
                in_require_block = False
                continue
            parts = line.split()
            if parts:
                requirements.add(parts[0].strip('"'))
            continue
        if line.startswith("module "):
            module_name = line[len("module ") :].strip().strip('"')
        elif line.startswith("require ("):
            in_require_block = True
        elif line.startswith("require "):
            parts = line[len("require ") :].strip().split()
            if parts:
                requirements.add(parts[0].strip('"'))

    marker_detail = (
        f"go.mod declares module '{module_name}'." if module_name else "go.mod is present."
    )
    _add_detection(
        registry,
        _GO_MODULES,
        method=TechnologyDetectionMethod.MANIFEST_MARKER,
        confidence=_MANIFEST_MARKER_CONFIDENCE,
        path=path,
        detail=marker_detail,
    )
    for module in sorted(requirements):
        technology = _match_go_dependency(module)
        if technology is None:
            continue
        _add_detection(
            registry,
            technology,
            method=TechnologyDetectionMethod.MANIFEST_DEPENDENCY,
            confidence=_DEPENDENCY_CONFIDENCE,
            path=path,
            detail=f"Declared Go module dependency '{module}'.",
        )


def _add_cargo_section(
    registry: _DetectionRegistry,
    value: Any,
    context: str,
    path: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            f"'{context}' must be a table",
        )
    for crate_name in sorted(value):
        if not isinstance(crate_name, str):
            continue
        technology = _CARGO_DEPENDENCIES.get(_normalize_crate_name(crate_name))
        if technology is None:
            continue
        _add_detection(
            registry,
            technology,
            method=TechnologyDetectionMethod.MANIFEST_DEPENDENCY,
            confidence=_DEPENDENCY_CONFIDENCE,
            path=path,
            detail=f"Declared in {context} as '{crate_name}'.",
        )


def _parse_cargo(text: str, path: str, registry: _DetectionRegistry) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise _ManifestParseError(
            TechnologyIssueReason.INVALID_TOML,
            f"Invalid TOML: {exc}",
        ) from exc
    if not isinstance(data, dict):
        raise _ManifestParseError(
            TechnologyIssueReason.MALFORMED_MANIFEST,
            "Cargo.toml must contain a table",
        )

    _add_detection(
        registry,
        _CARGO,
        method=TechnologyDetectionMethod.MANIFEST_MARKER,
        confidence=_MANIFEST_MARKER_CONFIDENCE,
        path=path,
        detail="Cargo.toml is present.",
    )

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        _add_cargo_section(registry, data.get(section), section, path)

    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        _add_cargo_section(
            registry,
            workspace.get("dependencies"),
            "workspace.dependencies",
            path,
        )

    targets = data.get("target")
    if isinstance(targets, dict):
        for target_name in sorted(targets):
            target = targets[target_name]
            if not isinstance(target, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                _add_cargo_section(
                    registry,
                    target.get(section),
                    f"target.{target_name}.{section}",
                    path,
                )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_pom(text: str, path: str, registry: _DetectionRegistry) -> None:
    upper_text = text.upper()
    if "<!DOCTYPE" in upper_text or "<!ENTITY" in upper_text:
        raise _ManifestParseError(
            TechnologyIssueReason.INVALID_XML,
            "DTD and entity declarations are not allowed in pom.xml",
        )
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise _ManifestParseError(
            TechnologyIssueReason.INVALID_XML,
            f"Invalid XML: {exc}",
        ) from exc

    _add_detection(
        registry,
        _MAVEN,
        method=TechnologyDetectionMethod.MANIFEST_MARKER,
        confidence=_MANIFEST_MARKER_CONFIDENCE,
        path=path,
        detail="pom.xml is present.",
    )

    for element in root.iter():
        if _local_name(element.tag) != "dependency":
            continue
        artifact_id: str | None = None
        for child in element:
            if _local_name(child.tag) == "artifactId" and child.text:
                artifact_id = child.text.strip()
                break
        if not artifact_id:
            continue
        technology = _MAVEN_DEPENDENCIES.get(_normalize_maven_artifact(artifact_id))
        if technology is None:
            continue
        _add_detection(
            registry,
            technology,
            method=TechnologyDetectionMethod.MANIFEST_DEPENDENCY,
            confidence=_DEPENDENCY_CONFIDENCE,
            path=path,
            detail=f"Declared Maven dependency '{artifact_id}'.",
        )


def _process_manifest(
    root: Path,
    relative_path: str,
    basename: str,
    max_size: int,
    registry: _DetectionRegistry,
    issues: list[TechnologyDetectionIssue],
) -> int:
    manifest_path, path_issue = _validate_manifest_path(root, relative_path, max_size)
    if path_issue is not None:
        issues.append(path_issue)
        return 0

    if basename == "Dockerfile":
        _add_detection(
            registry,
            _DOCKER,
            method=TechnologyDetectionMethod.FILENAME_MARKER,
            confidence=_INFRASTRUCTURE_FILENAME_CONFIDENCE,
            path=relative_path,
            detail="Dockerfile is present.",
        )
        return 0

    text, read_issue = _read_manifest_text(manifest_path, relative_path, max_size)
    if read_issue is not None:
        issues.append(read_issue)
        return 0

    try:
        if basename == "package.json":
            _parse_package_json(text, relative_path, registry)
        elif basename == "pyproject.toml":
            _parse_pyproject(text, relative_path, registry)
        elif basename == "requirements.txt":
            _parse_requirements(text, relative_path, registry)
        elif basename == "go.mod":
            _parse_go_mod(text, relative_path, registry)
        elif basename == "Cargo.toml":
            _parse_cargo(text, relative_path, registry)
        elif basename == "pom.xml":
            _parse_pom(text, relative_path, registry)
    except _ManifestParseError as exc:
        issues.append(_issue(relative_path, exc.reason, exc.detail))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        issues.append(
            _issue(
                relative_path,
                TechnologyIssueReason.MALFORMED_MANIFEST,
                f"Could not parse manifest: {exc}",
            )
        )
    return 1


def _build_summary(
    detections: list[TechnologyDetection],
    issues: list[TechnologyDetectionIssue],
    manifest_files_read: int,
    inventory: RepositoryDiscoveryResult,
) -> TechnologyDetectionSummary:
    counts = Counter(detection.category for detection in detections)
    return TechnologyDetectionSummary(
        detection_count=len(detections),
        language_count=counts[TechnologyCategory.LANGUAGE],
        framework_count=counts[TechnologyCategory.FRAMEWORK],
        library_count=counts[TechnologyCategory.LIBRARY],
        database_count=counts[TechnologyCategory.DATABASE],
        infrastructure_count=counts[TechnologyCategory.INFRASTRUCTURE],
        build_tool_count=counts[TechnologyCategory.BUILD_TOOL],
        manifest_files_read=manifest_files_read,
        issue_count=len(issues),
        discovery_is_complete=inventory.summary.is_complete,
        discovery_truncation_reasons=list(inventory.summary.truncation_reasons),
    )


def detect_technologies(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    *,
    max_manifest_size_bytes: int | None = None,
    max_manifest_files: int | None = None,
) -> TechnologyDetectionResult:
    """Detect languages and manifest-declared technologies for one repository.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match the root recorded in the discovery inventory. Only files present
    in the inventory and named in :data:`MANIFEST_FILENAMES` are inspected.
    """
    candidate = Path(root).expanduser()
    if candidate.is_symlink():
        raise InvalidTechnologyDetectionRootError("Repository root must not be a symbolic link")

    try:
        resolved_root = validate_repository_location(str(candidate))
    except InvalidRepositoryLocationError as exc:
        raise InvalidTechnologyDetectionRootError(str(exc)) from exc

    try:
        inventory_root = Path(inventory.root).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidTechnologyDetectionRootError(
            "Inventory root is not a valid filesystem path"
        ) from exc
    if inventory_root != resolved_root:
        raise InvalidTechnologyDetectionRootError(
            "Inventory root does not match the repository root"
        )

    max_size = (
        settings.technology_manifest_max_size_bytes
        if max_manifest_size_bytes is None
        else max_manifest_size_bytes
    )
    max_files = (
        settings.technology_max_manifest_files if max_manifest_files is None else max_manifest_files
    )
    if max_size < 0 or max_files < 0:
        raise TechnologyDetectionError("Manifest limits must not be negative")

    registry: _DetectionRegistry = {}
    issues: list[TechnologyDetectionIssue] = _discovery_manifest_issues(inventory)
    manifest_files_read = 0

    for index, (relative_path, basename) in enumerate(_manifest_candidates(inventory)):
        if index >= max_files:
            issues.append(
                _issue(
                    relative_path,
                    TechnologyIssueReason.MAX_MANIFEST_FILES,
                    f"Maximum of {max_files} manifest files reached",
                )
            )
            continue
        manifest_files_read += _process_manifest(
            resolved_root,
            relative_path,
            basename,
            max_size,
            registry,
            issues,
        )

    _detect_languages(inventory, registry)
    detections = _finalize_detections(registry)
    sorted_issues = sorted(
        issues,
        key=lambda item: (item.path, item.reason.value, item.detail or ""),
    )

    return TechnologyDetectionResult(
        root=str(resolved_root),
        detections=detections,
        issues=sorted_issues,
        summary=_build_summary(
            detections,
            sorted_issues,
            manifest_files_read,
            inventory,
        ),
    )
