"""Deterministic, read-only mapping of database and sensitive operations.

The analyzer consumes a :class:`RepositoryDiscoveryResult`, a
:class:`TechnologyDetectionResult`, and an :class:`AttackSurfaceResult`. It
inspects only source files already present in the discovery inventory and never
executes or imports repository code, never runs Git, shell commands, or
subprocesses, and never makes network requests.

The output is evidence of *recognizable code operations*. A candidate does not
prove that an operation is reachable with attacker input, that a sink is unsafe,
or that a vulnerability exists. SQL text, command arguments, file contents,
credentials, tokens, and runtime values are never recorded; only statically
readable operation names, receiver expressions, and model or table identifiers
are retained.

Python files are parsed with :mod:`ast`. JavaScript and TypeScript files reuse
the scoped token scanner from the attack-surface phase. Only explicit library
imports, technology evidence, and recognizable receiver patterns are used to
classify an operation. Dynamic expressions and unsupported syntax become
structured issues rather than guesses.

TOCTOU limitations
------------------
Each source path is checked for relative containment, symlink/reparse-point
status, regular-file status, and size immediately before it is opened. The
filesystem can still change between those checks and the read, so a path could be
replaced by a symlink or moved outside the root after validation. Reads are
size-capped and failures become structured issues, but fully race-free operation
would require platform-specific directory handles.
"""

import ast
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from app.core.config import settings
from app.schemas.attack_surface import (
    AnalysisIssue,
    AnalysisIssueReason,
    RouteCandidate,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.auth_controls import AssociatedRoute
from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
    SensitiveOperationCandidate,
    SensitiveOperationResult,
    SensitiveOperationSummary,
)
from app.schemas.technology import TechnologyDetectionResult
from app.services.attack_surface import (
    _JAVASCRIPT_EXTENSIONS,
    _PYTHON_EXTENSIONS,
    InvalidAttackSurfaceRootError,
    _collect_arguments,
    _collect_module_constants,
    _discovery_source_issues,
    _evaluate_js_string,
    _extension,
    _framework_hints,
    _has_excluded_component,
    _is_punct,
    _is_sensitive_path,
    _JsLexError,
    _JsToken,
    _lex_javascript,
    _python_string,
    _read_source_text,
    _resolve_root,
    _source_candidates,
    _statement_end,
    _validate_source_path,
)
from app.services.input_sources import _django_class_route_paths

_PYTHON_CALL_CONFIDENCE: Final[float] = 0.90
_PYTHON_DIRECT_CONFIDENCE: Final[float] = 0.95
_JS_CALL_CONFIDENCE: Final[float] = 0.85
_JS_MODULE_CONFIDENCE: Final[float] = 0.95

_DATABASE_CATEGORIES: Final[frozenset[OperationCategory]] = frozenset(
    {
        OperationCategory.DATABASE_READ,
        OperationCategory.DATABASE_WRITE,
        OperationCategory.DATABASE_DELETE,
        OperationCategory.DATABASE_EXECUTE,
        OperationCategory.DATABASE_TRANSACTION,
    }
)
_FILESYSTEM_CATEGORIES: Final[frozenset[OperationCategory]] = frozenset(
    {
        OperationCategory.FILE_READ,
        OperationCategory.FILE_WRITE,
        OperationCategory.FILE_DELETE,
        OperationCategory.FILE_METADATA,
        OperationCategory.FILE_UPLOAD,
    }
)
_OTHER_SENSITIVE_CATEGORIES: Final[frozenset[OperationCategory]] = frozenset(
    {
        OperationCategory.DESERIALIZATION,
        OperationCategory.ARCHIVE_EXTRACTION,
        OperationCategory.DYNAMIC_CODE_EXECUTION,
        OperationCategory.REDIRECT,
        OperationCategory.OTHER,
    }
)

_SQLALCHEMY_METHODS: Final[dict[str, OperationCategory]] = {
    "add": OperationCategory.DATABASE_WRITE,
    "add_all": OperationCategory.DATABASE_WRITE,
    "merge": OperationCategory.DATABASE_WRITE,
    "delete": OperationCategory.DATABASE_DELETE,
    "execute": OperationCategory.DATABASE_EXECUTE,
    "exec_driver_sql": OperationCategory.DATABASE_EXECUTE,
    "scalars": OperationCategory.DATABASE_READ,
    "scalar": OperationCategory.DATABASE_READ,
    "query": OperationCategory.DATABASE_READ,
    "get": OperationCategory.DATABASE_READ,
    "commit": OperationCategory.DATABASE_TRANSACTION,
    "flush": OperationCategory.DATABASE_TRANSACTION,
    "rollback": OperationCategory.DATABASE_TRANSACTION,
    "begin": OperationCategory.DATABASE_TRANSACTION,
}

_DJANGO_METHODS: Final[dict[str, OperationCategory]] = {
    "get": OperationCategory.DATABASE_READ,
    "filter": OperationCategory.DATABASE_READ,
    "exclude": OperationCategory.DATABASE_READ,
    "all": OperationCategory.DATABASE_READ,
    "first": OperationCategory.DATABASE_READ,
    "last": OperationCategory.DATABASE_READ,
    "count": OperationCategory.DATABASE_READ,
    "exists": OperationCategory.DATABASE_READ,
    "create": OperationCategory.DATABASE_WRITE,
    "update": OperationCategory.DATABASE_WRITE,
    "bulk_create": OperationCategory.DATABASE_WRITE,
    "bulk_update": OperationCategory.DATABASE_WRITE,
    "delete": OperationCategory.DATABASE_DELETE,
    "raw": OperationCategory.DATABASE_EXECUTE,
}

_DB_EXECUTE_METHODS: Final[dict[str, OperationCategory]] = {
    "execute": OperationCategory.DATABASE_EXECUTE,
    "executemany": OperationCategory.DATABASE_EXECUTE,
    "executescript": OperationCategory.DATABASE_EXECUTE,
    "commit": OperationCategory.DATABASE_TRANSACTION,
    "rollback": OperationCategory.DATABASE_TRANSACTION,
    "begin": OperationCategory.DATABASE_TRANSACTION,
}
_DB_RECEIVER_NAMES: Final[frozenset[str]] = frozenset(
    {
        "cursor",
        "cur",
        "connection",
        "conn",
        "cnx",
        "db",
        "db_conn",
        "database",
    }
)

_PYTHON_FILE_METHODS: Final[dict[str, OperationCategory]] = {
    "open": OperationCategory.FILE_READ,
    "read_text": OperationCategory.FILE_READ,
    "read_bytes": OperationCategory.FILE_READ,
    "write_text": OperationCategory.FILE_WRITE,
    "write_bytes": OperationCategory.FILE_WRITE,
    "touch": OperationCategory.FILE_WRITE,
    "unlink": OperationCategory.FILE_DELETE,
    "rename": OperationCategory.FILE_WRITE,
    "replace": OperationCategory.FILE_WRITE,
    "mkdir": OperationCategory.FILE_WRITE,
    "rmdir": OperationCategory.FILE_DELETE,
    "iterdir": OperationCategory.FILE_READ,
    "glob": OperationCategory.FILE_METADATA,
    "rglob": OperationCategory.FILE_METADATA,
    "stat": OperationCategory.FILE_METADATA,
    "exists": OperationCategory.FILE_METADATA,
    "is_file": OperationCategory.FILE_METADATA,
    "is_dir": OperationCategory.FILE_METADATA,
    "resolve": OperationCategory.FILE_METADATA,
    "absolute": OperationCategory.FILE_METADATA,
}
_PYTHON_PATH_RECEIVER_NAMES: Final[frozenset[str]] = frozenset(
    {"path", "file_path", "target_path", "source_path", "destination", "directory", "base_dir"}
)
_OS_FILE_METHODS: Final[dict[str, OperationCategory]] = {
    "remove": OperationCategory.FILE_DELETE,
    "unlink": OperationCategory.FILE_DELETE,
    "rename": OperationCategory.FILE_WRITE,
    "replace": OperationCategory.FILE_WRITE,
    "mkdir": OperationCategory.FILE_WRITE,
    "makedirs": OperationCategory.FILE_WRITE,
    "rmdir": OperationCategory.FILE_DELETE,
    "listdir": OperationCategory.FILE_READ,
    "scandir": OperationCategory.FILE_READ,
    "walk": OperationCategory.FILE_READ,
    "stat": OperationCategory.FILE_METADATA,
    "lstat": OperationCategory.FILE_METADATA,
    "access": OperationCategory.FILE_METADATA,
}
_OS_PATH_METHODS: Final[frozenset[str]] = frozenset(
    {
        "exists",
        "isfile",
        "isdir",
        "islink",
        "getsize",
        "getmtime",
        "getctime",
        "join",
        "abspath",
        "realpath",
        "dirname",
        "basename",
        "splitext",
        "normpath",
    }
)
_SHUTIL_METHODS: Final[dict[str, OperationCategory]] = {
    "copy": OperationCategory.FILE_WRITE,
    "copy2": OperationCategory.FILE_WRITE,
    "copyfile": OperationCategory.FILE_WRITE,
    "copytree": OperationCategory.FILE_WRITE,
    "move": OperationCategory.FILE_WRITE,
    "rmtree": OperationCategory.FILE_DELETE,
    "make_archive": OperationCategory.FILE_WRITE,
    "unpack_archive": OperationCategory.ARCHIVE_EXTRACTION,
}
_PYTHON_PROCESS_METHODS: Final[frozenset[str]] = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "system",
        "popen",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "execv",
        "execve",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    }
)
_PYTHON_DESERIALIZATION_METHODS: Final[frozenset[str]] = frozenset({"load", "loads"})
_YAML_UNSAFE_METHODS: Final[frozenset[str]] = frozenset(
    {"load", "load_all", "unsafe_load", "unsafe_load_all", "full_load", "full_load_all"}
)
_REDIRECT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "redirect",
        "HttpResponseRedirect",
        "HttpResponsePermanentRedirect",
        "HttpResponseRedirectBase",
        "RedirectResponse",
    }
)
_DB_MODULE_ROOTS: Final[frozenset[str]] = frozenset(
    {"sqlite3", "psycopg2", "psycopg", "pymysql", "mysql", "asyncpg", "aiosqlite"}
)
_PYTHON_LIBRARY_DISPLAY: Final[dict[str, str]] = {
    "sqlalchemy": "SQLAlchemy",
    "django": "Django ORM",
    "sqlite3": "SQLite",
    "psycopg2": "PostgreSQL",
    "psycopg": "PostgreSQL",
    "pymysql": "MySQL",
    "mysql": "MySQL",
    "asyncpg": "PostgreSQL",
    "aiosqlite": "SQLite",
    "subprocess": "subprocess",
    "asyncio": "asyncio",
    "os": "Python os",
    "os.path": "Python os.path",
    "pathlib": "pathlib",
    "shutil": "shutil",
    "pickle": "pickle",
    "yaml": "PyYAML",
    "zipfile": "zipfile",
    "tarfile": "tarfile",
    "flask": "Flask",
    "django.http": "Django",
    "django.shortcuts": "Django",
    "fastapi.responses": "FastAPI",
    "starlette.responses": "Starlette",
}

_PRISMA_METHODS: Final[dict[str, OperationCategory]] = {
    "findUnique": OperationCategory.DATABASE_READ,
    "findFirst": OperationCategory.DATABASE_READ,
    "findMany": OperationCategory.DATABASE_READ,
    "create": OperationCategory.DATABASE_WRITE,
    "createMany": OperationCategory.DATABASE_WRITE,
    "update": OperationCategory.DATABASE_WRITE,
    "updateMany": OperationCategory.DATABASE_WRITE,
    "upsert": OperationCategory.DATABASE_WRITE,
    "delete": OperationCategory.DATABASE_DELETE,
    "deleteMany": OperationCategory.DATABASE_DELETE,
    "$queryRaw": OperationCategory.DATABASE_EXECUTE,
    "$queryRawUnsafe": OperationCategory.DATABASE_EXECUTE,
    "$executeRaw": OperationCategory.DATABASE_EXECUTE,
    "$executeRawUnsafe": OperationCategory.DATABASE_EXECUTE,
    "$transaction": OperationCategory.DATABASE_TRANSACTION,
}
_SEQUELIZE_MODEL_METHODS: Final[dict[str, OperationCategory]] = {
    "findOne": OperationCategory.DATABASE_READ,
    "findAll": OperationCategory.DATABASE_READ,
    "findByPk": OperationCategory.DATABASE_READ,
    "findAndCountAll": OperationCategory.DATABASE_READ,
    "count": OperationCategory.DATABASE_READ,
    "create": OperationCategory.DATABASE_WRITE,
    "update": OperationCategory.DATABASE_WRITE,
    "upsert": OperationCategory.DATABASE_WRITE,
    "destroy": OperationCategory.DATABASE_DELETE,
}
_SEQUELIZE_INSTANCE_METHODS: Final[dict[str, OperationCategory]] = {
    "query": OperationCategory.DATABASE_EXECUTE,
    "transaction": OperationCategory.DATABASE_TRANSACTION,
}
_TYPEORM_REPOSITORY_METHODS: Final[dict[str, OperationCategory]] = {
    "find": OperationCategory.DATABASE_READ,
    "findOne": OperationCategory.DATABASE_READ,
    "findOneBy": OperationCategory.DATABASE_READ,
    "findBy": OperationCategory.DATABASE_READ,
    "save": OperationCategory.DATABASE_WRITE,
    "insert": OperationCategory.DATABASE_WRITE,
    "update": OperationCategory.DATABASE_WRITE,
    "delete": OperationCategory.DATABASE_DELETE,
    "remove": OperationCategory.DATABASE_DELETE,
    "query": OperationCategory.DATABASE_EXECUTE,
}
_TYPEORM_SOURCE_METHODS: Final[dict[str, OperationCategory]] = {
    "query": OperationCategory.DATABASE_EXECUTE,
    "transaction": OperationCategory.DATABASE_TRANSACTION,
}
_KNEX_METHODS: Final[dict[str, OperationCategory]] = {
    "select": OperationCategory.DATABASE_READ,
    "first": OperationCategory.DATABASE_READ,
    "pluck": OperationCategory.DATABASE_READ,
    "insert": OperationCategory.DATABASE_WRITE,
    "update": OperationCategory.DATABASE_WRITE,
    "delete": OperationCategory.DATABASE_DELETE,
    "del": OperationCategory.DATABASE_DELETE,
    "raw": OperationCategory.DATABASE_EXECUTE,
    "transaction": OperationCategory.DATABASE_TRANSACTION,
}
_MONGOOSE_METHODS: Final[dict[str, OperationCategory]] = {
    "find": OperationCategory.DATABASE_READ,
    "findOne": OperationCategory.DATABASE_READ,
    "findById": OperationCategory.DATABASE_READ,
    "create": OperationCategory.DATABASE_WRITE,
    "insertOne": OperationCategory.DATABASE_WRITE,
    "insertMany": OperationCategory.DATABASE_WRITE,
    "updateOne": OperationCategory.DATABASE_WRITE,
    "updateMany": OperationCategory.DATABASE_WRITE,
    "deleteOne": OperationCategory.DATABASE_DELETE,
    "deleteMany": OperationCategory.DATABASE_DELETE,
}
_JS_DB_CLIENT_METHODS: Final[dict[str, OperationCategory]] = {
    "query": OperationCategory.DATABASE_EXECUTE,
    "execute": OperationCategory.DATABASE_EXECUTE,
    "run": OperationCategory.DATABASE_EXECUTE,
    "exec": OperationCategory.DATABASE_EXECUTE,
    "all": OperationCategory.DATABASE_READ,
    "get": OperationCategory.DATABASE_READ,
    "each": OperationCategory.DATABASE_READ,
}

_JS_FS_METHODS: Final[dict[str, OperationCategory]] = {
    "readFile": OperationCategory.FILE_READ,
    "readFileSync": OperationCategory.FILE_READ,
    "createReadStream": OperationCategory.FILE_READ,
    "readdir": OperationCategory.FILE_READ,
    "readdirSync": OperationCategory.FILE_READ,
    "writeFile": OperationCategory.FILE_WRITE,
    "writeFileSync": OperationCategory.FILE_WRITE,
    "appendFile": OperationCategory.FILE_WRITE,
    "appendFileSync": OperationCategory.FILE_WRITE,
    "createWriteStream": OperationCategory.FILE_WRITE,
    "rename": OperationCategory.FILE_WRITE,
    "renameSync": OperationCategory.FILE_WRITE,
    "copyFile": OperationCategory.FILE_WRITE,
    "copyFileSync": OperationCategory.FILE_WRITE,
    "cp": OperationCategory.FILE_WRITE,
    "cpSync": OperationCategory.FILE_WRITE,
    "mkdir": OperationCategory.FILE_WRITE,
    "mkdirSync": OperationCategory.FILE_WRITE,
    "unlink": OperationCategory.FILE_DELETE,
    "unlinkSync": OperationCategory.FILE_DELETE,
    "rm": OperationCategory.FILE_DELETE,
    "rmSync": OperationCategory.FILE_DELETE,
    "rmdir": OperationCategory.FILE_DELETE,
    "rmdirSync": OperationCategory.FILE_DELETE,
    "stat": OperationCategory.FILE_METADATA,
    "statSync": OperationCategory.FILE_METADATA,
    "lstat": OperationCategory.FILE_METADATA,
    "lstatSync": OperationCategory.FILE_METADATA,
    "access": OperationCategory.FILE_METADATA,
    "accessSync": OperationCategory.FILE_METADATA,
    "existsSync": OperationCategory.FILE_METADATA,
}
_JS_PATH_METHODS: Final[frozenset[str]] = frozenset(
    {
        "join",
        "resolve",
        "normalize",
        "dirname",
        "basename",
        "extname",
        "parse",
        "format",
        "relative",
        "isAbsolute",
    }
)
_JS_PROCESS_METHODS: Final[frozenset[str]] = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "fork", "execFile", "execFileSync"}
)
_JS_LIBRARY_DISPLAY: Final[dict[str, str]] = {
    "fs": "Node.js fs",
    "fs/promises": "Node.js fs/promises",
    "path": "Node.js path",
    "child_process": "Node.js child_process",
    "@prisma/client": "Prisma",
    "prisma": "Prisma",
    "sequelize": "Sequelize",
    "typeorm": "TypeORM",
    "knex": "Knex",
    "express": "Express",
    "mongoose": "Mongoose",
    "pg": "PostgreSQL",
    "mysql": "MySQL",
    "mysql2": "MySQL",
    "sqlite3": "SQLite",
    "better-sqlite3": "SQLite",
    "mongodb": "MongoDB",
}


class SensitiveOperationAnalysisError(ValueError):
    """Base error for sensitive operation analysis operations."""


class InvalidSensitiveOperationRootError(SensitiveOperationAnalysisError):
    """Raised when an analysis root is not a safe, existing directory."""


@dataclass
class _OperationDraft:
    """An operation candidate before routes are associated and validated."""

    operation_category: OperationCategory
    framework_or_library: str
    operation_name: str
    source_file: str
    line_number: int
    declaration_or_access: str
    detection_confidence: float
    evidence: str
    classification_rule: str
    enclosing_function: str | None = None
    enclosing_class: str | None = None
    receiver_name: str | None = None
    resource_name: str | None = None
    route_positions: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    django_class_name: str | None = None
    unresolved_syntax: bool = False


def _issue(
    source_file: str,
    reason: AnalysisIssueReason,
    detail: str | None = None,
) -> AnalysisIssue:
    return AnalysisIssue(source_file=source_file, reason=reason, detail=detail)


def _resolve_operation_root(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: object,
) -> Path:
    try:
        resolved_root = _resolve_root(root, inventory)
    except InvalidAttackSurfaceRootError as exc:
        raise InvalidSensitiveOperationRootError(str(exc)) from exc

    for label, value in (
        ("Technology detection", getattr(technologies, "root", None)),
        ("Attack surface", getattr(attack_surface, "root", None)),
    ):
        try:
            other_root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidSensitiveOperationRootError(
                f"{label} root is not a valid filesystem path"
            ) from exc
        if other_root != resolved_root:
            raise InvalidSensitiveOperationRootError(
                f"{label} root does not match the repository root"
            )
    return resolved_root


def _display_library(module_path: str, mapping: dict[str, str], fallback: str) -> str:
    root = module_path.split(".")[0]
    return mapping.get(module_path) or mapping.get(root) or fallback


def _safe_expression_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _safe_expression_text(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        return _safe_expression_text(node.func)
    if isinstance(node, ast.Subscript):
        return _safe_expression_text(node.value)
    return None


def _model_name(node: ast.expr | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id if node.id[:1].isupper() else None
    if isinstance(node, ast.Attribute):
        return node.attr if node.attr[:1].isupper() else None
    if isinstance(node, ast.Call):
        func_name = _safe_expression_text(node.func)
        if func_name and func_name.rsplit(".", 1)[-1] in {
            "select",
            "delete",
            "update",
            "insert",
            "from_",
        }:
            for argument in node.args:
                name = _model_name(argument)
                if name:
                    return name
    return None


def _associated_routes(
    draft: _OperationDraft,
    routes: list[RouteCandidate],
    django_class_paths: dict[str, set[str]],
) -> list[RouteCandidate]:
    matched: list[RouteCandidate] = []
    if draft.route_positions:
        positions = draft.route_positions
        matched = [route for route in routes if (route.source_file, route.line_number) in positions]
    if not matched and draft.django_class_name:
        class_paths = django_class_paths.get(draft.django_class_name)
        if class_paths:
            matched = [
                route
                for route in routes
                if route.framework is RouteFramework.DJANGO and route.path in class_paths
            ]
    if not matched and draft.enclosing_function:
        matched = [
            route
            for route in routes
            if route.handler_name == draft.enclosing_function
            and (route.source_file == draft.source_file or route.framework is RouteFramework.DJANGO)
        ]

    unique: dict[tuple[object, ...], RouteCandidate] = {}
    for route in matched:
        key = (
            route.source_file,
            route.line_number,
            route.path,
            route.http_method,
            route.framework,
            route.handler_name,
        )
        unique[key] = route
    return sorted(
        unique.values(),
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.path,
            item.http_method.value,
            item.framework.value,
            item.handler_name or "",
        ),
    )


def _candidate_from_draft(
    draft: _OperationDraft,
    routes: list[RouteCandidate],
    django_class_paths: dict[str, set[str]],
) -> SensitiveOperationCandidate:
    associated = _associated_routes(draft, routes, django_class_paths)
    unresolved = draft.unresolved_syntax or not associated
    if any(route.resolution_status is RouteResolutionStatus.UNRESOLVED for route in associated):
        unresolved = True

    return SensitiveOperationCandidate(
        operation_category=draft.operation_category,
        framework_or_library=draft.framework_or_library,
        operation_name=draft.operation_name,
        source_file=draft.source_file,
        line_number=draft.line_number,
        enclosing_function=draft.enclosing_function,
        enclosing_class=draft.enclosing_class,
        receiver_name=draft.receiver_name,
        resource_name=draft.resource_name,
        associated_routes=[
            AssociatedRoute(
                path=route.path,
                http_method=route.http_method,
                framework=route.framework,
                resolution_status=route.resolution_status,
            )
            for route in associated
        ],
        declaration_or_access=draft.declaration_or_access,
        resolution_status=(
            OperationResolutionStatus.UNRESOLVED
            if unresolved
            else OperationResolutionStatus.RESOLVED
        ),
        detection_confidence=draft.detection_confidence,
        evidence=draft.evidence,
        classification_rule=draft.classification_rule,
    )


def _operation_sort_key(candidate: SensitiveOperationCandidate) -> tuple[object, ...]:
    return (
        candidate.source_file,
        candidate.line_number,
        candidate.operation_category.value,
        candidate.framework_or_library,
        candidate.operation_name,
        candidate.receiver_name or "",
        candidate.resource_name or "",
        candidate.enclosing_function or "",
        candidate.enclosing_class or "",
    )


def _dedupe_operations(
    operations: list[SensitiveOperationCandidate],
) -> list[SensitiveOperationCandidate]:
    unique: list[SensitiveOperationCandidate] = []
    seen: set[tuple[object, ...]] = set()
    for candidate in sorted(operations, key=_operation_sort_key):
        key = (
            candidate.source_file,
            candidate.line_number,
            candidate.operation_category,
            candidate.framework_or_library,
            candidate.operation_name,
            candidate.receiver_name,
            candidate.resource_name,
            candidate.enclosing_function,
            candidate.enclosing_class,
            tuple(
                (
                    route.path,
                    route.http_method,
                    route.framework,
                    route.resolution_status,
                )
                for route in candidate.associated_routes
            ),
        )
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def _dedupe_issues(issues: list[AnalysisIssue]) -> list[AnalysisIssue]:
    unique: list[AnalysisIssue] = []
    seen: set[tuple[str, AnalysisIssueReason, str | None]] = set()
    for issue in issues:
        key = (issue.source_file, issue.reason, issue.detail)
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique


# === PART 2: PYTHON ANALYSIS ===


@dataclass(frozen=True)
class _PythonImports:
    """Local names bound by Python import statements."""

    modules: dict[str, str]
    names: dict[str, tuple[str, str]]


@dataclass(frozen=True)
class _PythonBinding:
    """Statically inferred kind for a local Python expression."""

    kind: str
    resource: str | None = None
    library: str | None = None


def _collect_python_imports(tree: ast.Module) -> _PythonImports:
    modules: dict[str, str] = {}
    names: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    modules[alias.asname] = alias.name
                else:
                    modules[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                names[alias.asname or alias.name] = (node.module, alias.name)
    return _PythonImports(modules=modules, names=names)


def _expression_chain(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        base = _expression_chain(node.value)
        return [*base, node.attr] if base else [node.attr]
    if isinstance(node, ast.Call):
        return _expression_chain(node.func)
    return []


def _resolve_callable_chain(
    parts: list[str],
    imports: _PythonImports,
) -> tuple[str, str] | None:
    if not parts:
        return None
    base = parts[0]
    if base in imports.modules:
        module = imports.modules[base]
        rest = parts[1:]
        if not rest:
            return module, ""
        if len(rest) == 1:
            return module, rest[0]
        return f"{module}.{'.'.join(rest[:-1])}", rest[-1]
    if base in imports.names:
        module, original = imports.names[base]
        combined = f"{module}.{original}" if original else module
        rest = parts[1:]
        if not rest:
            return module, original
        if len(rest) == 1:
            return combined, rest[0]
        return f"{combined}.{'.'.join(rest[:-1])}", rest[-1]
    return None


def _python_imported_modules(imports: _PythonImports) -> set[str]:
    modules = set(imports.modules.values())
    modules.update(module for module, _ in imports.names.values())
    return modules


def _has_python_module(
    imports: _PythonImports,
    hints: frozenset[str],
    name: str,
) -> bool:
    return name in hints or any(
        module == name or module.startswith(f"{name}.")
        for module in _python_imported_modules(imports)
    )


def _python_db_library(
    imports: _PythonImports,
    hints: frozenset[str],
) -> str | None:
    modules = _python_imported_modules(imports)
    for module in sorted(modules):
        root = module.split(".")[0]
        if root in _DB_MODULE_ROOTS:
            return _display_library(root, _PYTHON_LIBRARY_DISPLAY, root)
    for hint in sorted(hints):
        if hint in {"sqlite", "postgresql", "mysql"}:
            return _display_library(hint, _PYTHON_LIBRARY_DISPLAY, hint)
    if _has_python_module(imports, hints, "sqlalchemy"):
        return "SQLAlchemy"
    return None


def _python_binding_kind(
    node: ast.AST | None,
    imports: _PythonImports,
    hints: frozenset[str],
    lookup: Callable[[str], _PythonBinding | None],
) -> _PythonBinding | None:
    if node is None:
        return None
    if isinstance(node, ast.Await):
        return _python_binding_kind(node.value, imports, hints, lookup)
    if isinstance(node, ast.Name):
        return lookup(node.id)
    if isinstance(node, ast.Subscript):
        chain = _expression_chain(node.value)
        if chain and chain[-1] in {"files", "FILES"}:
            return _PythonBinding(kind="upload", library="Flask/Werkzeug")
        return _python_binding_kind(node.value, imports, hints, lookup)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Div):
            left = _python_binding_kind(node.left, imports, hints, lookup)
            right = _python_binding_kind(node.right, imports, hints, lookup)
            if (left and left.kind == "path") or (right and right.kind == "path"):
                return _PythonBinding(kind="path", library="pathlib")
        return None
    if isinstance(node, ast.Attribute):
        chain = _expression_chain(node)
        if chain:
            if chain[-1] in {"files", "FILES"} and chain[0] == "request":
                return _PythonBinding(kind="files", library="Flask/Werkzeug")
            if chain[-2:] == ["db", "session"] and _has_python_module(imports, hints, "sqlalchemy"):
                return _PythonBinding(kind="session", library="SQLAlchemy")
            base_binding = lookup(chain[0])
            if base_binding and base_binding.kind == "path":
                if chain[-1] in {"parent", "resolve", "absolute"}:
                    return _PythonBinding(kind="path", library="pathlib")
        return None
    if isinstance(node, ast.Call):
        chain = _expression_chain(node.func)
        target = _resolve_callable_chain(chain, imports)
        if target is not None:
            module_path, name = target
            root = module_path.split(".")[0]
            if name in {"Path", "PurePath", "PosixPath", "WindowsPath"} and (
                module_path.startswith("pathlib") or root == "pathlib"
            ):
                return _PythonBinding(kind="path", library="pathlib")
            if name in {"create_engine", "create_async_engine"} and root == "sqlalchemy":
                return _PythonBinding(kind="engine", library="SQLAlchemy")
            if name in {"Session", "AsyncSession", "scoped_session"} and root == "sqlalchemy":
                return _PythonBinding(kind="session", library="SQLAlchemy")
            if name in {"sessionmaker", "async_sessionmaker"} and root == "sqlalchemy":
                return _PythonBinding(kind="sessionmaker", library="SQLAlchemy")
            if name == "connect" and root == "sqlite3":
                return _PythonBinding(kind="connection", library="SQLite")
            if name == "connect" and root in {
                "psycopg2",
                "psycopg",
                "pymysql",
                "asyncpg",
                "aiosqlite",
            }:
                return _PythonBinding(
                    kind="connection",
                    library=_display_library(root, _PYTHON_LIBRARY_DISPLAY, root),
                )
            if name == "connect" and root == "mysql":
                return _PythonBinding(kind="connection", library="MySQL")
            if name == "FileStorage" and root in {"werkzeug", "flask"}:
                return _PythonBinding(kind="upload", library="Flask/Werkzeug")
            if name == "FileSystemStorage" and root == "django":
                return _PythonBinding(kind="storage", library="Django")
            if name in {"ZipFile", "TarFile"} and root in {"zipfile", "tarfile"}:
                return _PythonBinding(kind="archive", library=root)
            if name == "open" and root == "tarfile":
                return _PythonBinding(kind="archive", library="tarfile")
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method == "cursor":
                receiver = _python_binding_kind(node.func.value, imports, hints, lookup)
                if receiver and receiver.kind == "connection":
                    return _PythonBinding(
                        kind="cursor",
                        library=receiver.library,
                    )
            if method in {"get", "getlist", "getall"}:
                chain = _expression_chain(node.func.value)
                if chain and chain[-1] in {"files", "FILES"}:
                    return _PythonBinding(kind="upload", library="Flask/Werkzeug")
        if isinstance(node.func, ast.Name):
            binding = lookup(node.func.id)
            if binding and binding.kind == "sessionmaker":
                return _PythonBinding(
                    kind="session",
                    resource=binding.resource,
                    library=binding.library,
                )
        return None
    return None


class _PythonOperationVisitor(ast.NodeVisitor):
    """Walk a Python AST while tracking imports, bindings, and scopes."""

    def __init__(
        self,
        relative_path: str,
        imports: _PythonImports,
        hints: frozenset[str],
        constants: dict[str, str],
        issues: list[AnalysisIssue],
    ) -> None:
        self.relative_path = relative_path
        self.imports = imports
        self.hints = hints
        self.constants = constants
        self.issues = issues
        self.drafts: list[_OperationDraft] = []
        self.scopes: list[dict[str, _PythonBinding | None]] = [{}]
        self.function_stack: list[str] = []
        self.class_stack: list[str] = []

    def _lookup(self, name: str) -> _PythonBinding | None:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def _current_function(self) -> str | None:
        return self.function_stack[-1] if self.function_stack else None

    def _current_class(self) -> str | None:
        return self.class_stack[-1] if self.class_stack else None

    def _add(
        self,
        *,
        category: OperationCategory,
        library: str,
        operation_name: str,
        node: ast.AST,
        receiver_name: str | None = None,
        resource_name: str | None = None,
        confidence: float = _PYTHON_CALL_CONFIDENCE,
        evidence: str,
        rule: str,
        unresolved_syntax: bool = False,
    ) -> None:
        line = getattr(node, "lineno", 1)
        declaration = operation_name
        if receiver_name:
            declaration = f"{receiver_name}.{operation_name}"
        django_class = self._current_class()
        self.drafts.append(
            _OperationDraft(
                operation_category=category,
                framework_or_library=library,
                operation_name=operation_name,
                source_file=self.relative_path,
                line_number=line,
                declaration_or_access=declaration,
                detection_confidence=confidence,
                evidence=evidence,
                classification_rule=rule,
                enclosing_function=self._current_function(),
                enclosing_class=django_class,
                receiver_name=receiver_name,
                resource_name=resource_name,
                django_class_name=django_class,
                unresolved_syntax=unresolved_syntax,
            )
        )

    def _open_category(self, node: ast.Call) -> OperationCategory:
        category, resolved = _open_category(node, self.constants)
        if not resolved:
            self.issues.append(
                _issue(
                    self.relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    (
                        "Dynamic file mode cannot be resolved statically at "
                        f"line {node.lineno}; the operation is recorded without a "
                        "read/write classification"
                    ),
                )
            )
        return category

    def _bind_parameters(self, arguments: ast.arguments) -> None:
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]:
            self.scopes[-1][argument.arg] = _python_annotation_binding(
                argument.annotation, self.imports
            )
        for argument in (arguments.vararg, arguments.kwarg):
            if argument is not None:
                self.scopes[-1][argument.arg] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.scopes.append({})
        self._bind_parameters(node.args)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.scopes.append({})
        self._bind_parameters(node.args)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.function_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.scopes.append({})
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.class_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        binding = _python_binding_kind(node.value, self.imports, self.hints, self._lookup)
        for target in node.targets:
            self._assign(target, binding)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            binding = _python_binding_kind(node.value, self.imports, self.hints, self._lookup)
            if binding is None:
                binding = _python_annotation_binding(node.annotation, self.imports)
            self._assign(node.target, binding)
            self.visit(node.value)

    def _assign(self, target: ast.AST, binding: _PythonBinding | None) -> None:
        if isinstance(target, ast.Name):
            self.scopes[-1][target.id] = binding
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign(element, None)

    def visit_Call(self, node: ast.Call) -> None:
        self._detect_call(node)
        self.generic_visit(node)

    def _detect_call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "getattr":
            self._handle_getattr(node)
            return
        if isinstance(func, ast.Name):
            self._handle_direct_name(node, func.id)
            return
        if isinstance(func, ast.Attribute):
            chain = _expression_chain(func)
            if not chain:
                return
            base = chain[0]
            if isinstance(func.value, ast.Call) or (
                base not in self.imports.modules
                and not (base in self.imports.names and len(chain) == 1)
            ):
                self._method_operation(func.attr, func.value, node)
                return
            target = _resolve_callable_chain(chain, self.imports)
            if target is not None:
                module_path, name = target
                if name:
                    self._module_operation(module_path, name, node)
            return
        if isinstance(func, ast.Call):
            self.issues.append(
                _issue(
                    self.relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    (
                        "Indirect call target could not be resolved statically at "
                        f"line {node.lineno}"
                    ),
                )
            )

    def _handle_direct_name(self, node: ast.Call, name: str) -> None:
        if name in {"eval", "exec"}:
            self._add(
                category=OperationCategory.DYNAMIC_CODE_EXECUTION,
                library="Python builtins",
                operation_name=name,
                node=node,
                confidence=_PYTHON_DIRECT_CONFIDENCE,
                evidence=f"Direct call to the Python builtin '{name}'.",
                rule="Builtin dynamic code execution call.",
            )
            return
        if name == "open":
            category = self._open_category(node)
            self._add(
                category=category,
                library="Python builtins",
                operation_name=name,
                node=node,
                confidence=_PYTHON_DIRECT_CONFIDENCE,
                evidence="Direct call to the Python builtin 'open'.",
                rule="Builtin file access call.",
            )
            return
        if name in self.imports.names:
            module, original = self.imports.names[name]
            self._module_operation(module, original, node)

    def _handle_getattr(self, node: ast.Call) -> None:
        if len(node.args) < 2:
            return
        target = node.args[0]
        chain = _expression_chain(target)
        resolved = _resolve_callable_chain(chain, self.imports)
        if resolved is None:
            return
        module_path, _ = resolved
        attribute, static = _python_string(node.args[1], self.constants)
        if static and attribute:
            self._module_operation(module_path, attribute, node)
            return
        self.issues.append(
            _issue(
                self.relative_path,
                AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                (
                    "Dynamic getattr on a recognized module cannot be resolved "
                    f"statically at line {node.lineno}"
                ),
            )
        )

    def _module_operation(
        self,
        module_path: str,
        name: str,
        node: ast.AST,
    ) -> None:
        if not name:
            return
        root = module_path.split(".")[0]
        library = _display_library(module_path, _PYTHON_LIBRARY_DISPLAY, "Python standard library")
        category: OperationCategory | None = None
        resource: str | None = None

        if module_path == "os" or root == "os":
            if name in _OS_FILE_METHODS:
                category = _OS_FILE_METHODS[name]
            elif module_path.startswith("os.path") and name in _OS_PATH_METHODS:
                category = OperationCategory.FILE_METADATA
            elif name in _PYTHON_PROCESS_METHODS or name.startswith(("exec", "spawn")):
                category = OperationCategory.PROCESS_EXECUTION
                library = "os"
        elif module_path == "subprocess" or root == "subprocess":
            if name in _PYTHON_PROCESS_METHODS:
                category = OperationCategory.PROCESS_EXECUTION
        elif module_path == "asyncio" or root == "asyncio":
            if name in {"create_subprocess_exec", "create_subprocess_shell"}:
                category = OperationCategory.PROCESS_EXECUTION
        elif module_path == "shutil" or root == "shutil":
            category = _SHUTIL_METHODS.get(name)
        elif module_path == "pickle" or root == "pickle":
            if name in _PYTHON_DESERIALIZATION_METHODS:
                category = OperationCategory.DESERIALIZATION
                library = "pickle"
        elif module_path == "yaml" or root == "yaml":
            if name in _YAML_UNSAFE_METHODS:
                category = OperationCategory.DESERIALIZATION
                library = "PyYAML"
        elif root in {"zipfile", "tarfile"}:
            if name in {"extractall", "extract"}:
                category = OperationCategory.ARCHIVE_EXTRACTION
        elif module_path == "builtins" or root == "builtins":
            if name in {"eval", "exec"}:
                category = OperationCategory.DYNAMIC_CODE_EXECUTION
            elif name == "open":
                category = self._open_category(node)
        elif module_path == "flask" or root == "flask":
            if name == "redirect":
                category = OperationCategory.REDIRECT
        elif module_path.startswith("django.") or root == "django":
            if name in _REDIRECT_NAMES:
                category = OperationCategory.REDIRECT
        elif module_path.startswith(("fastapi.", "starlette.")):
            if name == "RedirectResponse":
                category = OperationCategory.REDIRECT
        elif module_path == "sqlalchemy" or root == "sqlalchemy":
            if name == "execute" and module_path.endswith("engine"):
                category = OperationCategory.DATABASE_EXECUTE

        if category is None:
            return
        self._add(
            category=category,
            library=library,
            operation_name=name,
            node=node,
            resource_name=resource,
            evidence=(
                f"Direct call to recognized {library} API '{name}' with "
                "contextual library evidence."
            ),
            rule="Allowlisted module-level API with import or technology evidence.",
        )

    def _method_operation(
        self,
        method: str,
        receiver: ast.AST,
        node: ast.Call,
    ) -> None:
        binding = _python_binding_kind(receiver, self.imports, self.hints, self._lookup)
        chain = _expression_chain(receiver)
        receiver_name = _safe_expression_text(receiver)
        simple = chain[0] if len(chain) == 1 else None

        if _has_python_module(self.imports, self.hints, "sqlalchemy"):
            category = _SQLALCHEMY_METHODS.get(method)
            if category is not None:
                kind = binding.kind if binding else None
                conventional = simple in {
                    "session",
                    "db_session",
                    "session_",
                    "async_session",
                } or chain[-2:] == ["db", "session"]
                if kind in {"session", "engine", "connection"} or conventional:
                    allowed = True
                    if kind == "engine":
                        allowed = method in {
                            "execute",
                            "exec_driver_sql",
                            "commit",
                            "rollback",
                        }
                    if allowed:
                        resource = None
                        if method in {"query", "execute", "exec_driver_sql"} and node.args:
                            resource = _model_name(node.args[0])
                        self._add(
                            category=category,
                            library="SQLAlchemy",
                            operation_name=method,
                            node=node,
                            receiver_name=receiver_name,
                            resource_name=resource,
                            evidence=(
                                "Recognized SQLAlchemy Session, engine, or connection "
                                f"operation '{method}' with import or technology evidence."
                            ),
                            rule=(
                                "Allowlisted SQLAlchemy method supported by an "
                                "imported library, inferred receiver, or conventional "
                                "session receiver."
                            ),
                        )
                        return

        if _has_python_module(self.imports, self.hints, "django"):
            category = _DJANGO_METHODS.get(method)
            if category is not None and ("objects" in chain or "_default_manager" in chain):
                marker = (
                    chain.index("objects")
                    if "objects" in chain
                    else chain.index("_default_manager")
                )
                resource = chain[marker - 1] if marker > 0 else None
                self._add(
                    category=category,
                    library="Django ORM",
                    operation_name=method,
                    node=node,
                    receiver_name=receiver_name,
                    resource_name=resource,
                    evidence=(
                        "Recognized Django manager or queryset operation "
                        f"'{method}' on a model manager."
                    ),
                    rule=(
                        "Allowlisted Django ORM method on an 'objects' or "
                        "'_default_manager' receiver with Django evidence."
                    ),
                )
                return

        db_library = _python_db_library(self.imports, self.hints)
        if method in _DB_EXECUTE_METHODS and db_library:
            kind = binding.kind if binding else None
            if kind in {"cursor", "connection"} or (simple in _DB_RECEIVER_NAMES):
                library = binding.library if binding and binding.library else db_library
                self._add(
                    category=_DB_EXECUTE_METHODS[method],
                    library=library,
                    operation_name=method,
                    node=node,
                    receiver_name=receiver_name,
                    evidence=(
                        f"Recognized database cursor or connection operation "
                        f"'{method}' with database library evidence."
                    ),
                    rule=(
                        "Allowlisted cursor or connection method supported by an "
                        "inferred receiver and database import or technology evidence."
                    ),
                )
                return

        pathlib_present = _has_python_module(self.imports, self.hints, "pathlib")
        if method in _PYTHON_FILE_METHODS and (
            (binding and binding.kind == "path")
            or (pathlib_present and simple in _PYTHON_PATH_RECEIVER_NAMES)
        ):
            category = _PYTHON_FILE_METHODS[method]
            if method == "open":
                category = self._open_category(node)
            self._add(
                category=category,
                library="pathlib",
                operation_name=method,
                node=node,
                receiver_name=receiver_name,
                evidence=(
                    f"Recognized pathlib path operation '{method}' on an inferred Path receiver."
                ),
                rule=(
                    "Allowlisted pathlib method on a Path binding or conventional "
                    "path receiver with pathlib evidence."
                ),
            )
            return

        if method == "save" and (
            (binding and binding.kind in {"upload", "storage"}) or _is_upload_receiver(chain)
        ):
            library = binding.library if binding and binding.library else "Flask/Werkzeug"
            self._add(
                category=OperationCategory.FILE_UPLOAD,
                library=library,
                operation_name=method,
                node=node,
                receiver_name=receiver_name,
                evidence=(
                    "Recognized upload storage operation 'save' on an uploaded "
                    "file or storage receiver."
                ),
                rule=(
                    "Upload storage method on a file-upload binding, request files "
                    "receiver, or storage binding."
                ),
            )
            return

        if method in {"extractall", "extract"} and (
            (binding and binding.kind == "archive")
            or _is_archive_receiver(chain, self.imports, self.hints)
        ):
            self._add(
                category=OperationCategory.ARCHIVE_EXTRACTION,
                library=binding.library if binding and binding.library else "Python archive",
                operation_name=method,
                node=node,
                receiver_name=receiver_name,
                evidence=(
                    f"Recognized archive extraction operation '{method}' on an archive receiver."
                ),
                rule=(
                    "extract or extractall on a zipfile/tarfile binding or "
                    "recognized archive constructor."
                ),
            )


def _python_annotation_binding(
    annotation: ast.AST | None,
    imports: _PythonImports,
) -> _PythonBinding | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Subscript):
        candidates: list[ast.expr] = []
        if isinstance(annotation.slice, ast.Tuple):
            candidates.extend(annotation.slice.elts)
        else:
            candidates.append(annotation.slice)
        for candidate in candidates:
            binding = _python_annotation_binding(candidate, imports)
            if binding is not None:
                return binding
        return None
    chain = _expression_chain(annotation)
    target = _resolve_callable_chain(chain, imports)
    if target is None:
        return None
    module_path, name = target
    root = module_path.split(".")[0]
    if name in {"Path", "PurePath", "PosixPath", "WindowsPath"} and root == "pathlib":
        return _PythonBinding(kind="path", library="pathlib")
    if name in {"Session", "AsyncSession", "scoped_session"} and root == "sqlalchemy":
        return _PythonBinding(kind="session", library="SQLAlchemy")
    if name in {"UploadFile"} and root in {"fastapi", "starlette"}:
        return _PythonBinding(kind="upload", library="FastAPI")
    return None


def _open_category(node: ast.Call, constants: dict[str, str]) -> tuple[OperationCategory, bool]:
    mode_expression: ast.expr | None = None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_expression = keyword.value
            break
    if mode_expression is None and len(node.args) > 1:
        mode_expression = node.args[1]
    if mode_expression is None:
        return OperationCategory.FILE_READ, True
    mode, resolved = _python_string(mode_expression, constants)
    if not resolved or mode is None:
        return OperationCategory.OTHER, False
    if any(character in mode for character in "wax+"):
        return OperationCategory.FILE_WRITE, True
    return OperationCategory.FILE_READ, True


def _is_upload_receiver(chain: list[str]) -> bool:
    if not chain:
        return False
    if chain[0] in {"request", "req"} and any(part in {"files", "FILES", "file"} for part in chain):
        return True
    return chain[0] in {"upload", "uploaded_file", "file_storage"}


def _is_archive_receiver(
    chain: list[str],
    imports: _PythonImports,
    hints: frozenset[str],
) -> bool:
    if not chain:
        return False
    if any(part in {"ZipFile", "TarFile"} for part in chain):
        return True
    if chain[0] == "open" and _has_python_module(imports, hints, "tarfile"):
        return True
    return False


def _extract_python_operations(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> tuple[list[_OperationDraft], dict[str, set[str]]]:
    try:
        tree = ast.parse(text, filename=relative_path)
    except SyntaxError as exc:
        line = exc.lineno if exc.lineno is not None else 1
        column = exc.offset if exc.offset is not None else 0
        issues.append(
            _issue(
                relative_path,
                AnalysisIssueReason.INVALID_SYNTAX,
                f"Invalid Python syntax at line {line} column {column}: {exc.msg}",
            )
        )
        return [], {}
    except (ValueError, RecursionError, MemoryError) as exc:
        issues.append(
            _issue(
                relative_path,
                AnalysisIssueReason.INVALID_SYNTAX,
                f"Python source could not be parsed: {exc}",
            )
        )
        return [], {}

    imports = _collect_python_imports(tree)
    constants = _collect_module_constants(tree)
    visitor = _PythonOperationVisitor(
        relative_path=relative_path,
        imports=imports,
        hints=hints,
        constants=constants,
        issues=issues,
    )
    for statement in tree.body:
        visitor.visit(statement)

    django_class_paths: dict[str, set[str]] = {}
    if _has_python_module(imports, hints, "django"):
        for class_name, paths in _django_class_route_paths(tree, relative_path, constants).items():
            django_class_paths.setdefault(class_name, set()).update(paths)
    return visitor.drafts, django_class_paths


# === PART 3: JAVASCRIPT ANALYSIS ===


@dataclass(frozen=True)
class _JsImports:
    """Module aliases and imported names collected from JavaScript imports."""

    modules: dict[str, str]
    names: dict[str, tuple[str, str]]
    present: frozenset[str]


@dataclass(frozen=True)
class _JsBinding:
    """Statically inferred kind for a local JavaScript expression."""

    kind: str
    resource: str | None = None
    library: str | None = None
    operation_name: str | None = None


@dataclass(frozen=True)
class _JsReceiver:
    """Statically resolved receiver context for a JavaScript method call."""

    base: str
    module: str | None
    binding: _JsBinding | None
    receiver_name: str | None
    subparts: tuple[str, ...]


def _js_matching_forward(
    tokens: list[_JsToken],
    open_index: int,
    open_value: str,
    close_value: str,
) -> int | None:
    depth = 0
    for index in range(open_index, len(tokens)):
        token = tokens[index]
        if token.kind != "punct":
            continue
        if token.value == open_value:
            depth += 1
        elif token.value == close_value:
            depth -= 1
            if depth == 0:
                return index
    return None


def _js_matching_backward(
    tokens: list[_JsToken],
    close_index: int,
    open_value: str,
    close_value: str,
) -> int | None:
    depth = 0
    for index in range(close_index, -1, -1):
        token = tokens[index]
        if token.kind != "punct":
            continue
        if token.value == close_value:
            depth += 1
        elif token.value == open_value:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_js_items(
    tokens: list[_JsToken],
    open_index: int,
    close_index: int,
) -> list[list[_JsToken]]:
    items: list[list[_JsToken]] = []
    current: list[_JsToken] = []
    depth = 0
    for index in range(open_index + 1, close_index):
        token = tokens[index]
        if token.kind == "punct" and token.value in "([{":
            depth += 1
        elif token.kind == "punct" and token.value in ")]}":
            depth -= 1
        if token.kind == "punct" and token.value == "," and depth == 0:
            if current:
                items.append(current)
            current = []
            continue
        current.append(token)
    if current:
        items.append(current)
    return items


def _parse_import_specifiers(
    tokens: list[_JsToken],
    open_index: int,
    close_index: int,
) -> list[tuple[str, str]]:
    specifiers: list[tuple[str, str]] = []
    for item in _split_js_items(tokens, open_index, close_index):
        identifiers = [token.value for token in item if token.kind == "identifier"]
        if len(identifiers) >= 3 and identifiers[1] == "as":
            specifiers.append((identifiers[2], identifiers[0]))
        elif len(identifiers) == 2 and identifiers[0] != "as":
            specifiers.append((identifiers[1], identifiers[0]))
        elif len(identifiers) == 1:
            specifiers.append((identifiers[0], identifiers[0]))
    return specifiers


def _require_target(
    tokens: list[_JsToken],
    require_index: int,
) -> tuple[str, object] | None:
    if require_index < 2 or not _is_punct(tokens, require_index - 1, "="):
        return None
    target_index = require_index - 2
    if target_index < 0:
        return None
    token = tokens[target_index]
    if token.kind == "identifier":
        if token.value not in {"const", "let", "var"}:
            return "name", token.value
        return None
    if token.kind == "punct" and token.value == "}":
        open_index = _js_matching_backward(tokens, target_index, "{", "}")
        if open_index is None:
            return None
        return "destructure", _parse_import_specifiers(tokens, open_index, target_index)
    return None


def _collect_js_imports(tokens: list[_JsToken]) -> _JsImports:
    modules: dict[str, str] = {}
    names: dict[str, tuple[str, str]] = {}
    present: set[str] = set()

    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue
        if token.value == "require" and _is_punct(tokens, index + 1, "("):
            try:
                arguments, _ = _collect_arguments(tokens, index + 1)
            except _JsLexError:
                continue
            if not arguments:
                continue
            module, resolved = _evaluate_js_string(arguments[0])
            if not resolved or module is None:
                continue
            present.add(module)
            target = _require_target(tokens, index)
            if target is None:
                continue
            kind, value = target
            if kind == "name" and isinstance(value, str):
                modules[value] = module
            elif kind == "destructure" and isinstance(value, list):
                for local, original in value:
                    names[local] = (module, original)
            continue

        if token.value != "import":
            continue
        cursor = index + 1
        if _is_punct(tokens, cursor, "("):
            continue
        if cursor < len(tokens) and tokens[cursor].kind == "string":
            present.add(tokens[cursor].value)
            continue

        default_name: str | None = None
        namespace_name: str | None = None
        specifiers: list[tuple[str, str]] = []
        if _is_punct(tokens, cursor, "*"):
            if (
                cursor + 2 < len(tokens)
                and tokens[cursor + 1].kind == "identifier"
                and tokens[cursor + 1].value == "as"
                and tokens[cursor + 2].kind == "identifier"
            ):
                namespace_name = tokens[cursor + 2].value
                cursor += 3
        else:
            if (
                cursor < len(tokens)
                and tokens[cursor].kind == "identifier"
                and (tokens[cursor].value != "from")
            ):
                default_name = tokens[cursor].value
                cursor += 1
                if _is_punct(tokens, cursor, ","):
                    cursor += 1
            if _is_punct(tokens, cursor, "{"):
                close_index = _js_matching_forward(tokens, cursor, "{", "}")
                if close_index is None:
                    continue
                specifiers = _parse_import_specifiers(tokens, cursor, close_index)
                cursor = close_index + 1

        while cursor < len(tokens) and not (
            tokens[cursor].kind == "identifier" and tokens[cursor].value == "from"
        ):
            cursor += 1
        if cursor + 1 >= len(tokens) or tokens[cursor + 1].kind != "string":
            continue
        module = tokens[cursor + 1].value
        present.add(module)
        if default_name is not None:
            modules[default_name] = module
        if namespace_name is not None:
            modules[namespace_name] = module
        for local, original in specifiers:
            names[local] = (module, original)

    return _JsImports(modules=modules, names=names, present=frozenset(present))


def _js_require_module(tokens: list[_JsToken], start: int) -> tuple[str, int] | None:
    if start >= len(tokens) or tokens[start].kind != "identifier":
        return None
    if tokens[start].value != "require" or not _is_punct(tokens, start + 1, "("):
        return None
    try:
        arguments, close_index = _collect_arguments(tokens, start + 1)
    except _JsLexError:
        return None
    if not arguments:
        return None
    module, resolved = _evaluate_js_string(arguments[0])
    if not resolved or module is None:
        return None
    return module, close_index


def _js_namespace_has(tokens: list[_JsToken], start: int, value: str) -> bool:
    return any(token.kind == "identifier" and token.value == value for token in tokens[start:])


def _js_first_string_argument(tokens: list[_JsToken], start: int) -> str | None:
    for index in range(start, len(tokens)):
        if not _is_punct(tokens, index, "("):
            continue
        try:
            arguments, _ = _collect_arguments(tokens, index)
        except _JsLexError:
            return None
        if not arguments:
            return None
        value, resolved = _evaluate_js_string(arguments[0])
        return value if resolved else None
    return None


def _js_resolve_imported_name(
    name: str,
    imports: _JsImports,
) -> tuple[str, str] | None:
    if name in imports.names:
        return imports.names[name]
    if name in imports.modules:
        return imports.modules[name], ""
    return None


def _infer_js_binding(
    tokens: list[_JsToken],
    imports: _JsImports,
    bindings: dict[str, _JsBinding],
) -> _JsBinding | None:
    if not tokens:
        return None

    if tokens[0].kind == "identifier" and tokens[0].value == "new":
        if len(tokens) < 2 or tokens[1].kind != "identifier":
            return None
        parts = [tokens[1].value]
        cursor = 2
        while (
            _is_punct(tokens, cursor, ".")
            and cursor + 1 < len(tokens)
            and tokens[cursor + 1].kind == "identifier"
        ):
            parts.append(tokens[cursor + 1].value)
            cursor += 2
        class_name = parts[-1]
        if len(parts) > 1:
            module = imports.modules.get(parts[0])
            original = class_name
        else:
            resolved = _js_resolve_imported_name(class_name, imports)
            module = resolved[0] if resolved else None
            original = resolved[1] if resolved else class_name
        if original == "PrismaClient" or class_name == "PrismaClient":
            return _JsBinding(kind="prisma_client", library="Prisma")
        if original == "Sequelize" or class_name == "Sequelize":
            return _JsBinding(kind="sequelize_instance", library="Sequelize")
        if original == "DataSource" or class_name == "DataSource":
            return _JsBinding(kind="typeorm_data_source", library="TypeORM")
        if original in {"Client", "Pool"} and module in {"pg", "mysql", "mysql2"}:
            return _JsBinding(
                kind="db_client",
                library=_display_library(module or "", _JS_LIBRARY_DISPLAY, "database"),
            )
        if original == "Database" and module in {"better-sqlite3", "sqlite3"}:
            return _JsBinding(kind="db_client", library="SQLite")
        if original == "MongoClient" and module == "mongodb":
            return _JsBinding(kind="db_client", library="MongoDB")
        return None

    require = _js_require_module(tokens, 0)
    if require is not None:
        module, close_index = require
        if module == "knex":
            return _JsBinding(kind="knex_instance", library="Knex")
        if module == "fs" and _js_namespace_has(tokens, close_index + 1, "promises"):
            return _JsBinding(kind="fs_promises", library="Node.js fs/promises")
        if module == "mongoose":
            return _JsBinding(kind="mongoose_module", library="Mongoose")
        return None

    first = tokens[0]
    if first.kind != "identifier":
        return None
    name = first.value
    module = imports.modules.get(name)
    if module is not None:
        if module == "knex":
            return _JsBinding(kind="knex_instance", library="Knex")
        if module == "fs" and _js_namespace_has(tokens, 1, "promises"):
            return _JsBinding(kind="fs_promises", library="Node.js fs/promises")
        if module == "mongoose" and _js_namespace_has(tokens, 1, "model"):
            resource = _js_first_string_argument(tokens, 1)
            return _JsBinding(
                kind="mongoose_model",
                resource=resource,
                library="Mongoose",
            )
        if module in {"sqlite3", "better-sqlite3", "pg", "mysql", "mysql2", "mongodb"}:
            if any(
                token.kind == "identifier"
                and token.value
                in {
                    "Database",
                    "Client",
                    "Pool",
                    "MongoClient",
                    "createConnection",
                    "createPool",
                }
                for token in tokens[1:]
            ):
                return _JsBinding(
                    kind="db_client",
                    library=_display_library(module, _JS_LIBRARY_DISPLAY, "database"),
                )
        return None

    binding = bindings.get(name)
    if binding is not None:
        if binding.kind == "sequelize_instance" and _js_namespace_has(tokens, 1, "define"):
            resource = _js_first_string_argument(tokens, 1)
            return _JsBinding(
                kind="sequelize_model",
                resource=resource,
                library="Sequelize",
            )
        if binding.kind == "typeorm_data_source" and _js_namespace_has(tokens, 1, "getRepository"):
            resource = None
            for token in tokens[1:]:
                if token.kind == "identifier" and token.value[:1].isupper():
                    resource = token.value
                    break
            return _JsBinding(
                kind="typeorm_repository",
                resource=resource,
                library="TypeORM",
            )
        if len(tokens) == 1:
            return binding

    if name in {"req", "request"}:
        if _js_namespace_has(tokens, 1, "file"):
            return _JsBinding(kind="upload_file", library="Express")
        if _js_namespace_has(tokens, 1, "files"):
            if _js_namespace_has(tokens, 2, "file"):
                return _JsBinding(kind="upload_file", library="Express")
            return _JsBinding(kind="upload_files", library="Express")

    if name == "promisify":
        for token in tokens[1:]:
            if token.kind != "identifier":
                continue
            resolved = _js_resolve_imported_name(token.value, imports)
            if resolved is None:
                continue
            module, original = resolved
            if module == "child_process" and original in _JS_PROCESS_METHODS:
                return _JsBinding(
                    kind="promisified_process",
                    library="Node.js child_process",
                    operation_name=original,
                )
        return None

    if len(tokens) == 1 and name in bindings:
        return bindings[name]
    return None


def _collect_js_bindings(
    tokens: list[_JsToken],
    imports: _JsImports,
) -> dict[str, _JsBinding]:
    bindings: dict[str, _JsBinding] = {}

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value != "class":
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            continue
        class_name = tokens[index + 1].value
        if _js_namespace_has(tokens, index + 2, "Model") and any(
            module == "sequelize" for module in imports.present
        ):
            bindings[class_name] = _JsBinding(
                kind="sequelize_model",
                resource=class_name,
                library="Sequelize",
            )

    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue
        name: str | None = None
        equals_index: int | None = None
        if token.value in {"const", "let", "var"}:
            if index + 2 < len(tokens) and tokens[index + 1].kind == "identifier":
                if _is_punct(tokens, index + 2, "="):
                    name = tokens[index + 1].value
                    equals_index = index + 2
        elif _is_punct(tokens, index + 1, "="):
            if index > 0 and _is_punct(tokens, index - 1, "."):
                continue
            name = token.value
            equals_index = index + 1
        if name is None or equals_index is None:
            continue
        end = _statement_end(tokens, equals_index + 1)
        rhs = tokens[equals_index + 1 : end]
        binding = _infer_js_binding(rhs, imports, bindings)
        if binding is not None:
            bindings[name] = binding

    return bindings


def _arrow_name(tokens: list[_JsToken], arrow_index: int) -> str | None:
    cursor = arrow_index - 1
    if _is_punct(tokens, cursor, ")"):
        open_index = _js_matching_backward(tokens, cursor, "(", ")")
        if open_index is None:
            return None
        cursor = open_index - 1
    if cursor >= 0 and tokens[cursor].kind == "identifier" and tokens[cursor].value == "async":
        cursor -= 1
    if cursor < 1 or tokens[cursor].kind != "identifier":
        return None
    if _is_punct(tokens, cursor - 1, "=") or _is_punct(tokens, cursor - 1, ":"):
        return tokens[cursor].value
    return None


def _js_function_ranges(
    tokens: list[_JsToken],
) -> list[tuple[int, int, str | None]]:
    ranges: list[tuple[int, int, str | None]] = []
    keywords = {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "with",
        "function",
        "return",
        "typeof",
        "await",
        "new",
        "delete",
        "void",
        "do",
        "else",
        "try",
        "finally",
        "class",
        "constructor",
    }

    for index, token in enumerate(tokens):
        if token.kind == "identifier" and token.value == "function":
            cursor = index + 1
            if _is_punct(tokens, cursor, "*"):
                cursor += 1
            name = None
            if cursor < len(tokens) and tokens[cursor].kind == "identifier":
                name = tokens[cursor].value
                cursor += 1
            if not _is_punct(tokens, cursor, "("):
                continue
            close_paren = _js_matching_forward(tokens, cursor, "(", ")")
            if close_paren is None or not _is_punct(tokens, close_paren + 1, "{"):
                continue
            close_brace = _js_matching_forward(tokens, close_paren + 1, "{", "}")
            if close_brace is not None:
                ranges.append((close_paren + 1, close_brace, name))

    for index, token in enumerate(tokens):
        if not (token.kind == "punct" and token.value == "=>"):
            continue
        name = _arrow_name(tokens, index)
        if _is_punct(tokens, index + 1, "{"):
            close_brace = _js_matching_forward(tokens, index + 1, "{", "}")
            if close_brace is not None:
                ranges.append((index + 1, close_brace, name))
        else:
            end = _statement_end(tokens, index + 1)
            ranges.append((index + 1, end, name))

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value in keywords:
            continue
        if not _is_punct(tokens, index + 1, "("):
            continue
        if index > 0:
            previous = tokens[index - 1]
            if previous.kind == "punct" and previous.value in {".", "@", "new"}:
                continue
        close_paren = _js_matching_forward(tokens, index + 1, "(", ")")
        if close_paren is None or not _is_punct(tokens, close_paren + 1, "{"):
            continue
        close_brace = _js_matching_forward(tokens, close_paren + 1, "{", "}")
        if close_brace is not None:
            ranges.append((close_paren + 1, close_brace, token.value))

    return list(dict.fromkeys(ranges))


def _js_class_ranges(tokens: list[_JsToken]) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value != "class":
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            continue
        name = tokens[index + 1].value
        cursor = index + 2
        while cursor < len(tokens) and not _is_punct(tokens, cursor, "{"):
            cursor += 1
        close_brace = _js_matching_forward(tokens, cursor, "{", "}")
        if close_brace is not None:
            ranges.append((cursor, close_brace, name))
    return ranges


def _js_enclosing_name(
    index: int,
    ranges: list[tuple[int, int, str | None]],
) -> str | None:
    candidates = [
        (close - open_index, name)
        for open_index, close, name in ranges
        if open_index < index < close and name is not None
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def _js_enclosing_class(
    index: int,
    ranges: list[tuple[int, int, str]],
) -> str | None:
    candidates = [
        (close - open_index, name)
        for open_index, close, name in ranges
        if open_index < index < close
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def _js_function_after(
    index: int,
    ranges: list[tuple[int, int, str | None]],
) -> str | None:
    candidates = [
        (open_index, name)
        for open_index, close, name in ranges
        if open_index > index and name is not None
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


# === PART 3B: JAVASCRIPT RECEIVERS AND EXTRACTION ===


def _js_present(
    imports: _JsImports,
    hints: frozenset[str],
    module: str,
) -> bool:
    if module in imports.present:
        return True
    aliases = {
        "@prisma/client": {"prisma"},
        "fs/promises": {"fs"},
        "better-sqlite3": {"sqlite"},
        "mysql2": {"mysql"},
        "pg": {"postgresql", "postgres"},
    }
    return any(name in hints for name in aliases.get(module, {module}))


def _js_expression_start(tokens: list[_JsToken], dot_index: int) -> int:
    depth = 0
    index = dot_index - 1
    while index >= 0:
        token = tokens[index]
        if token.kind == "punct":
            if token.value in ")]}":
                depth += 1
            elif token.value in "([{":
                if depth == 0:
                    return index + 1
                depth -= 1
            elif depth == 0 and token.value in {
                ";",
                ",",
                "=",
                "=>",
                ":",
                "!",
                "?",
                "+",
                "-",
                "*",
                "/",
                "%",
                "&",
                "|",
                "<",
                ">",
            }:
                return index + 1
        elif (
            depth == 0
            and token.kind == "identifier"
            and token.value
            in {
                "return",
                "await",
                "yield",
                "throw",
                "case",
            }
        ):
            return index + 1
        index -= 1
    return 0


def _js_receiver_name(tokens: list[_JsToken], base_index: int) -> str:
    parts = [tokens[base_index].value]
    index = base_index + 1
    while index + 1 < len(tokens):
        if not _is_punct(tokens, index, "."):
            break
        if tokens[index + 1].kind != "identifier":
            break
        parts.append(tokens[index + 1].value)
        index += 2
    return ".".join(parts)


def _js_receiver_context(
    expression: list[_JsToken],
    imports: _JsImports,
    bindings: dict[str, _JsBinding],
    hints: frozenset[str],
) -> _JsReceiver | None:
    if not expression:
        return None

    keywords = {
        "return",
        "await",
        "yield",
        "throw",
        "new",
        "const",
        "let",
        "var",
        "async",
        "function",
    }
    conventional = {
        "req",
        "request",
        "res",
        "response",
        "prisma",
        "knex",
        "fs",
        "fsp",
        "path",
        "cp",
        "child_process",
        "file",
        "files",
        "upload",
    }
    base_index: int | None = None
    for index, token in enumerate(expression):
        if token.kind != "identifier" or token.value in keywords:
            continue
        if (
            token.value in imports.modules
            or token.value in imports.names
            or token.value in bindings
            or token.value == "require"
            or token.value in conventional
        ):
            base_index = index
            break
    if base_index is None:
        return None

    base = expression[base_index].value
    require = _js_require_module(expression, base_index)
    if require is not None:
        module, close_index = require
        receiver_name = module
        if _js_namespace_has(expression, close_index + 1, "promises"):
            receiver_name = f"{module}.promises"
        return _JsReceiver(
            base=base,
            module=module,
            binding=None,
            receiver_name=receiver_name,
            subparts=(),
        )

    receiver_name = _js_receiver_name(expression, base_index)
    subparts = tuple(receiver_name.split(".")[1:])
    inferred = _infer_js_binding(expression[base_index:], imports, bindings)
    module: str | None = None
    binding: _JsBinding | None = inferred
    if base in imports.modules:
        module = imports.modules[base]
    elif base in imports.names:
        module = imports.names[base][0]
    elif base in bindings:
        binding = bindings[base]
    elif base == "prisma" and _js_present(imports, hints, "@prisma/client"):
        binding = _JsBinding(kind="prisma_client", library="Prisma")
    elif base == "knex" and (_js_present(imports, hints, "knex") or module == "knex"):
        binding = _JsBinding(kind="knex_instance", library="Knex")
    elif base in {"res", "response"} and (
        _js_present(imports, hints, "express") or _js_present(imports, hints, "@nestjs/common")
    ):
        binding = _JsBinding(kind="express_response", library="Express")
    elif base in {"req", "request"} and (
        _js_present(imports, hints, "express") or _js_present(imports, hints, "multer")
    ):
        binding = _JsBinding(kind="express_request", library="Express")
    elif base in {"fs", "fsp"} and _js_present(imports, hints, "fs"):
        module = "fs"
    elif base == "path" and _js_present(imports, hints, "path"):
        module = "path"
    elif base in {"cp", "child_process"} and _js_present(imports, hints, "child_process"):
        module = "child_process"

    return _JsReceiver(
        base=base,
        module=module,
        binding=binding,
        receiver_name=receiver_name,
        subparts=subparts,
    )


def _js_route_ranges(
    tokens: list[_JsToken],
    routes: list[RouteCandidate],
    source_file: str,
) -> list[tuple[int, int, tuple[str, int]]]:
    ranges: list[tuple[int, int, tuple[str, int]]] = []
    for route in routes:
        if route.source_file != source_file:
            continue
        route_index = None
        for index, token in enumerate(tokens):
            if token.line >= route.line_number:
                route_index = index
                break
        if route_index is None:
            continue
        open_index = None
        for index in range(route_index, len(tokens)):
            if _is_punct(tokens, index, "("):
                open_index = index
                break
            if _is_punct(tokens, index, ";") or _is_punct(tokens, index, "{"):
                break
        if open_index is None:
            continue
        try:
            _, close_index = _collect_arguments(tokens, open_index)
        except _JsLexError:
            continue
        ranges.append((open_index, close_index, (route.source_file, route.line_number)))
    return ranges


def _scan_js_operations(
    tokens: list[_JsToken],
    relative_path: str,
    imports: _JsImports,
    bindings: dict[str, _JsBinding],
    hints: frozenset[str],
    issues: list[AnalysisIssue],
    routes: list[RouteCandidate],
) -> list[_OperationDraft]:
    drafts: list[_OperationDraft] = []
    function_ranges = _js_function_ranges(tokens)
    class_ranges = _js_class_ranges(tokens)
    route_ranges = _js_route_ranges(tokens, routes, relative_path)

    def add(
        *,
        category: OperationCategory,
        library: str,
        operation_name: str,
        token_index: int,
        confidence: float = _JS_CALL_CONFIDENCE,
        evidence: str,
        rule: str,
        receiver_name: str | None = None,
        resource_name: str | None = None,
        fallback_function: str | None = None,
        unresolved_syntax: bool = False,
    ) -> None:
        function_name = _js_enclosing_name(token_index, function_ranges)
        if function_name is None:
            function_name = fallback_function
        class_name = _js_enclosing_class(token_index, class_ranges)
        route_positions = frozenset(
            position
            for open_index, close_index, position in route_ranges
            if open_index <= token_index <= close_index
        )
        declaration = operation_name
        if receiver_name:
            declaration = f"{receiver_name}.{operation_name}"
        drafts.append(
            _OperationDraft(
                operation_category=category,
                framework_or_library=library,
                operation_name=operation_name,
                source_file=relative_path,
                line_number=tokens[token_index].line,
                declaration_or_access=declaration,
                detection_confidence=confidence,
                evidence=evidence,
                classification_rule=rule,
                enclosing_function=function_name,
                enclosing_class=class_name,
                receiver_name=receiver_name,
                resource_name=resource_name,
                route_positions=route_positions,
                unresolved_syntax=unresolved_syntax,
            )
        )

    def detect_module(
        module: str,
        method: str,
        token_index: int,
        *,
        fallback_function: str | None = None,
    ) -> bool:
        library = _display_library(module, _JS_LIBRARY_DISPLAY, module)
        if module in {"fs", "fs/promises"} and method in _JS_FS_METHODS:
            add(
                category=_JS_FS_METHODS[method],
                library=library,
                operation_name=method,
                token_index=token_index,
                evidence=(
                    f"Direct call to recognized Node.js file-system API "
                    f"'{method}' from module '{module}'."
                ),
                rule="Allowlisted fs or fs/promises method with module evidence.",
                fallback_function=fallback_function,
            )
            return True
        if module == "path" and method in _JS_PATH_METHODS:
            add(
                category=OperationCategory.FILE_METADATA,
                library="Node.js path",
                operation_name=method,
                token_index=token_index,
                evidence=(
                    f"Recognized Node.js path construction or metadata API "
                    f"'{method}'; this is not a file access operation."
                ),
                rule="Allowlisted path method with module evidence.",
                fallback_function=fallback_function,
            )
            return True
        if module == "child_process" and method in _JS_PROCESS_METHODS:
            add(
                category=OperationCategory.PROCESS_EXECUTION,
                library="Node.js child_process",
                operation_name=method,
                token_index=token_index,
                evidence=(f"Direct call to recognized Node.js process API '{method}'."),
                rule="Allowlisted child_process method with module evidence.",
                fallback_function=fallback_function,
            )
            return True
        if module == "@nestjs/common" and method == "Redirect":
            add(
                category=OperationCategory.REDIRECT,
                library="NestJS",
                operation_name=method,
                token_index=token_index,
                confidence=_JS_MODULE_CONFIDENCE,
                evidence="Recognized NestJS @Redirect decorator.",
                rule="NestJS Redirect decorator with framework import evidence.",
                fallback_function=fallback_function,
            )
            return True
        if module in {"tar", "adm-zip", "unzipper"} and method in {
            "extract",
            "x",
            "extractAllTo",
        }:
            add(
                category=OperationCategory.ARCHIVE_EXTRACTION,
                library=library,
                operation_name=method,
                token_index=token_index,
                evidence=(
                    f"Direct call to recognized JavaScript archive API "
                    f"'{method}' from module '{module}'."
                ),
                rule="Allowlisted archive extraction method with module evidence.",
                fallback_function=fallback_function,
            )
            return True
        return False

    def detect_method(method: str, expression: list[_JsToken], token_index: int) -> bool:
        context = _js_receiver_context(expression, imports, bindings, hints)
        if context is None:
            return False

        prisma_present = _js_present(imports, hints, "@prisma/client") or _js_present(
            imports, hints, "prisma"
        )
        is_prisma = (
            (context.binding is not None and context.binding.kind == "prisma_client")
            or (context.base == "prisma" and prisma_present)
            or context.module in {"@prisma/client", "prisma"}
        )
        if is_prisma and method in _PRISMA_METHODS:
            resource = None
            if context.subparts and not context.subparts[0].startswith("$"):
                resource = context.subparts[0]
            add(
                category=_PRISMA_METHODS[method],
                library="Prisma",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                resource_name=resource,
                evidence=(
                    f"Recognized Prisma client operation '{method}' with Prisma "
                    "import, technology, or receiver evidence."
                ),
                rule="Allowlisted Prisma method with client receiver evidence.",
            )
            return True

        binding = context.binding
        if binding is not None and binding.kind == "sequelize_model":
            if method in _SEQUELIZE_MODEL_METHODS:
                resource = binding.resource
                if resource is None and context.receiver_name:
                    first_part = context.receiver_name.split(".")[0]
                    if first_part[:1].isupper():
                        resource = first_part
                add(
                    category=_SEQUELIZE_MODEL_METHODS[method],
                    library="Sequelize",
                    operation_name=method,
                    token_index=token_index,
                    receiver_name=context.receiver_name,
                    resource_name=resource,
                    evidence=(
                        f"Recognized Sequelize model operation '{method}' on a model binding."
                    ),
                    rule="Allowlisted Sequelize model method with model evidence.",
                )
                return True

        if (
            binding is not None
            and binding.kind == "sequelize_instance"
            and method in _SEQUELIZE_INSTANCE_METHODS
        ) or (
            context.base == "sequelize"
            and _js_present(imports, hints, "sequelize")
            and method in _SEQUELIZE_INSTANCE_METHODS
        ):
            add(
                category=_SEQUELIZE_INSTANCE_METHODS[method],
                library="Sequelize",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(
                    f"Recognized Sequelize instance operation '{method}' with "
                    "instance or technology evidence."
                ),
                rule="Allowlisted Sequelize instance method.",
            )
            return True

        if binding is not None and binding.kind == "typeorm_repository":
            if method in _TYPEORM_REPOSITORY_METHODS:
                add(
                    category=_TYPEORM_REPOSITORY_METHODS[method],
                    library="TypeORM",
                    operation_name=method,
                    token_index=token_index,
                    receiver_name=context.receiver_name,
                    resource_name=binding.resource,
                    evidence=(
                        f"Recognized TypeORM repository operation '{method}' on a "
                        "repository binding."
                    ),
                    rule="Allowlisted TypeORM repository method with repository evidence.",
                )
                return True

        if (
            binding is not None
            and binding.kind == "typeorm_data_source"
            and method in _TYPEORM_SOURCE_METHODS
        ) or (
            context.base == "dataSource"
            and _js_present(imports, hints, "typeorm")
            and method in _TYPEORM_SOURCE_METHODS
        ):
            add(
                category=_TYPEORM_SOURCE_METHODS[method],
                library="TypeORM",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(
                    f"Recognized TypeORM data-source operation '{method}' with "
                    "data-source evidence."
                ),
                rule="Allowlisted TypeORM data-source method.",
            )
            return True

        is_knex = (binding is not None and binding.kind == "knex_instance") or (
            context.base == "knex"
            and _js_present(imports, hints, "knex")
            and method in _KNEX_METHODS
        )
        if is_knex and method in _KNEX_METHODS:
            add(
                category=_KNEX_METHODS[method],
                library="Knex",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                resource_name=_js_first_string_argument(expression, 0),
                evidence=(
                    f"Recognized Knex query operation '{method}' on a Knex instance or chain."
                ),
                rule="Allowlisted Knex method with Knex instance or module evidence.",
            )
            return True

        if binding is not None and binding.kind == "mongoose_model":
            if method in _MONGOOSE_METHODS:
                add(
                    category=_MONGOOSE_METHODS[method],
                    library="Mongoose",
                    operation_name=method,
                    token_index=token_index,
                    receiver_name=context.receiver_name,
                    resource_name=binding.resource,
                    evidence=(
                        f"Recognized Mongoose model operation '{method}' on a model binding."
                    ),
                    rule="Allowlisted Mongoose model method.",
                )
                return True

        if binding is not None and binding.kind == "db_client":
            if method in _JS_DB_CLIENT_METHODS:
                add(
                    category=_JS_DB_CLIENT_METHODS[method],
                    library=binding.library or "database client",
                    operation_name=method,
                    token_index=token_index,
                    receiver_name=context.receiver_name,
                    evidence=(
                        f"Recognized direct database client operation '{method}' "
                        "on an inferred client or connection."
                    ),
                    rule="Allowlisted client method with database client evidence.",
                )
                return True

        if (
            (context.module in {"fs", "fs/promises"})
            or (binding is not None and binding.kind == "fs_promises")
        ) and method in _JS_FS_METHODS:
            library = (
                "Node.js fs/promises"
                if context.module == "fs/promises"
                or (binding is not None and binding.kind == "fs_promises")
                else "Node.js fs"
            )
            add(
                category=_JS_FS_METHODS[method],
                library=library,
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(
                    f"Recognized Node.js file-system operation '{method}' with "
                    "module or inferred promises receiver evidence."
                ),
                rule="Allowlisted fs or fs/promises method.",
            )
            return True

        if context.module == "path" and method in _JS_PATH_METHODS:
            add(
                category=OperationCategory.FILE_METADATA,
                library="Node.js path",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(
                    f"Recognized Node.js path construction or metadata operation "
                    f"'{method}'; this is not a file access operation."
                ),
                rule="Allowlisted path method with module evidence.",
            )
            return True

        if context.module == "child_process" and method in _JS_PROCESS_METHODS:
            add(
                category=OperationCategory.PROCESS_EXECUTION,
                library="Node.js child_process",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(
                    f"Recognized Node.js process execution operation '{method}' "
                    "with child_process module evidence."
                ),
                rule="Allowlisted child_process method.",
            )
            return True

        if method == "mv" and (
            (binding is not None and binding.kind in {"upload_file", "upload_files"})
            or (
                context.base in {"req", "request"}
                and any(part in {"file", "files"} for part in context.subparts)
            )
            or (context.receiver_name or "").startswith(("req.file", "request.file"))
        ):
            add(
                category=OperationCategory.FILE_UPLOAD,
                library="Express",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=("Recognized upload storage operation 'mv' on an uploaded-file receiver."),
                rule="Upload storage method on a request file receiver or binding.",
            )
            return True

        if (
            method in {"redirect", "location"}
            and (
                _js_present(imports, hints, "express")
                or _js_present(imports, hints, "@nestjs/common")
            )
            and (
                context.base in {"res", "response"}
                or (binding is not None and binding.kind == "express_response")
            )
        ):
            add(
                category=OperationCategory.REDIRECT,
                library="Express",
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(f"Recognized Express response redirect operation '{method}'."),
                rule="Express response redirect or location method.",
            )
            return True

        if context.module in {"tar", "adm-zip", "unzipper"} and method in {
            "extract",
            "x",
            "extractAllTo",
        }:
            add(
                category=OperationCategory.ARCHIVE_EXTRACTION,
                library=_display_library(context.module, _JS_LIBRARY_DISPLAY, context.module),
                operation_name=method,
                token_index=token_index,
                receiver_name=context.receiver_name,
                evidence=(f"Recognized JavaScript archive extraction operation '{method}'."),
                rule="Allowlisted archive extraction method with module evidence.",
            )
            return True

        return False

    def detect_direct(name: str, token_index: int) -> bool:
        if name in {"eval", "Function"}:
            add(
                category=OperationCategory.DYNAMIC_CODE_EXECUTION,
                library="JavaScript",
                operation_name=name,
                token_index=token_index,
                confidence=_JS_MODULE_CONFIDENCE,
                evidence=(f"Direct call to the JavaScript dynamic code API '{name}'."),
                rule="Direct eval or Function call.",
            )
            return True
        if name in imports.names:
            module, original = imports.names[name]
            fallback = None
            if token_index >= 2 and _is_punct(tokens, token_index - 2, "@"):
                fallback = _js_function_after(token_index, function_ranges)
            return detect_module(module, original, token_index, fallback_function=fallback)
        binding = bindings.get(name)
        if binding is not None and binding.kind == "promisified_process":
            add(
                category=OperationCategory.PROCESS_EXECUTION,
                library="Node.js child_process",
                operation_name=binding.operation_name or name,
                token_index=token_index,
                receiver_name=name,
                evidence=(
                    "Recognized promisified child_process operation "
                    f"'{binding.operation_name or name}'."
                ),
                rule="Promisified child_process method with static binding evidence.",
            )
            return True
        return False

    for index, token in enumerate(tokens):
        if (
            token.kind == "identifier"
            and token.value == "new"
            and index + 2 < len(tokens)
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 1].value == "Function"
            and _is_punct(tokens, index + 2, "(")
        ):
            add(
                category=OperationCategory.DYNAMIC_CODE_EXECUTION,
                library="JavaScript",
                operation_name="Function",
                token_index=index,
                confidence=_JS_MODULE_CONFIDENCE,
                evidence="Recognized JavaScript 'new Function' dynamic code call.",
                rule="new Function constructor call.",
            )

    for index, token in enumerate(tokens):
        if (
            token.kind == "identifier"
            and index > 0
            and _is_punct(tokens, index - 1, ".")
            and index + 1 < len(tokens)
            and tokens[index + 1].kind == "template"
        ):
            start = _js_expression_start(tokens, index - 1)
            expression = tokens[start : index - 1]
            detect_method(token.value, expression, index)

    for index, token in enumerate(tokens):
        if not (token.kind == "punct" and token.value == "("):
            continue
        if index == 0:
            continue
        previous = tokens[index - 1]
        if previous.kind == "identifier":
            if index >= 2 and _is_punct(tokens, index - 2, "."):
                method = previous.value
                start = _js_expression_start(tokens, index - 2)
                expression = tokens[start : index - 2]
                detect_method(method, expression, index)
            else:
                detect_direct(previous.value, index)
        elif previous.kind == "punct" and previous.value == "]":
            open_index = _js_matching_backward(tokens, index - 1, "[", "]")
            if open_index is None:
                continue
            start = _js_expression_start(tokens, open_index)
            expression = tokens[start:open_index]
            context = _js_receiver_context(expression, imports, bindings, hints)
            if context is not None and (context.module is not None or context.binding is not None):
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                        (
                            "Computed operation name on a recognized receiver "
                            f"cannot be resolved statically at line {token.line}"
                        ),
                    )
                )

    return drafts


# === PART 4: ENTRYPOINT ===


def _extract_javascript_operations(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
    routes: list[RouteCandidate],
) -> list[_OperationDraft]:
    try:
        tokens = _lex_javascript(text)
    except _JsLexError as exc:
        issues.append(
            _issue(
                relative_path,
                AnalysisIssueReason.INVALID_SYNTAX,
                f"Invalid JavaScript or TypeScript syntax: {exc}",
            )
        )
        return []
    except (ValueError, RecursionError, MemoryError) as exc:
        issues.append(
            _issue(
                relative_path,
                AnalysisIssueReason.INVALID_SYNTAX,
                f"JavaScript or TypeScript source could not be scanned: {exc}",
            )
        )
        return []

    imports = _collect_js_imports(tokens)
    bindings = _collect_js_bindings(tokens, imports)
    return _scan_js_operations(
        tokens,
        relative_path,
        imports,
        bindings,
        hints,
        issues,
        routes,
    )


def identify_sensitive_operations(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: object,
    *,
    max_source_file_size_bytes: int | None = None,
    max_source_files: int | None = None,
) -> SensitiveOperationResult:
    """Identify statically recognizable database and sensitive operations.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match the discovery inventory, technology detection result, and attack
    surface result. Only Python and JavaScript/TypeScript files already present in
    the inventory are read. Repository code is never executed or imported.
    """
    resolved_root = _resolve_operation_root(root, inventory, technologies, attack_surface)

    max_size = (
        settings.sensitive_operation_source_max_size_bytes
        if max_source_file_size_bytes is None
        else max_source_file_size_bytes
    )
    max_files = (
        settings.sensitive_operation_max_source_files
        if max_source_files is None
        else max_source_files
    )
    if max_size < 0 or max_files < 0:
        raise SensitiveOperationAnalysisError("Source inspection limits must not be negative")

    routes = list(getattr(attack_surface, "routes", []))
    hints = _framework_hints(technologies)
    issues = _discovery_source_issues(inventory)
    drafts: list[_OperationDraft] = []
    django_class_paths: dict[str, set[str]] = {}
    inspected = 0
    max_files_reported = False
    candidates = _source_candidates(inventory)

    for index, entry in enumerate(candidates):
        relative_path = entry.relative_path

        if index >= max_files:
            if not max_files_reported:
                remaining = len(candidates) - index
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.MAX_SOURCE_FILES,
                        (
                            f"Maximum of {max_files} source files reached; "
                            f"{remaining} eligible files were not inspected"
                        ),
                    )
                )
                max_files_reported = True
            continue

        if _has_excluded_component(relative_path):
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.EXCLUDED_PATH,
                    "Path contains an excluded dependency or cache directory",
                )
            )
            continue
        if _is_sensitive_path(relative_path):
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.SENSITIVE_FILE,
                    "Sensitive file is never inspected",
                )
            )
            continue

        source_path, path_issue = _validate_source_path(
            resolved_root,
            relative_path,
            max_size,
        )
        if path_issue is not None:
            issues.append(path_issue)
            continue

        text, read_issue = _read_source_text(source_path, relative_path, max_size)
        if read_issue is not None:
            issues.append(read_issue)
            continue

        inspected += 1
        extension = _extension(relative_path, entry.extension)
        if extension in _PYTHON_EXTENSIONS:
            python_drafts, python_class_paths = _extract_python_operations(
                text,
                relative_path,
                issues,
                hints,
            )
            drafts.extend(python_drafts)
            for class_name, class_paths in python_class_paths.items():
                django_class_paths.setdefault(class_name, set()).update(class_paths)
        elif extension in _JAVASCRIPT_EXTENSIONS:
            drafts.extend(
                _extract_javascript_operations(
                    text,
                    relative_path,
                    issues,
                    hints,
                    routes,
                )
            )

    operations = _dedupe_operations(
        [_candidate_from_draft(draft, routes, django_class_paths) for draft in drafts]
    )
    sorted_issues = sorted(
        _dedupe_issues(issues),
        key=lambda item: (item.source_file, item.reason.value, item.detail or ""),
    )

    database_count = sum(
        operation.operation_category in _DATABASE_CATEGORIES for operation in operations
    )
    filesystem_count = sum(
        operation.operation_category in _FILESYSTEM_CATEGORIES for operation in operations
    )
    process_count = sum(
        operation.operation_category is OperationCategory.PROCESS_EXECUTION
        for operation in operations
    )
    other_count = sum(
        operation.operation_category in _OTHER_SENSITIVE_CATEGORIES for operation in operations
    )
    route_association_count = sum(len(operation.associated_routes) for operation in operations)
    unresolved_association_count = sum(
        operation.resolution_status is OperationResolutionStatus.UNRESOLVED
        for operation in operations
    )

    summary = SensitiveOperationSummary(
        source_files_inspected=inspected,
        operation_count=len(operations),
        database_operation_count=database_count,
        filesystem_operation_count=filesystem_count,
        process_execution_count=process_count,
        other_sensitive_operation_count=other_count,
        route_association_count=route_association_count,
        unresolved_association_count=unresolved_association_count,
        issue_count=len(sorted_issues),
        is_complete=inventory.summary.is_complete and not sorted_issues,
        discovery_is_complete=inventory.summary.is_complete,
        discovery_truncation_reasons=list(inventory.summary.truncation_reasons),
    )

    return SensitiveOperationResult(
        root=str(resolved_root),
        operations=operations,
        issues=sorted_issues,
        summary=summary,
    )
