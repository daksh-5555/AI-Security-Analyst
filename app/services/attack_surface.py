"""Deterministic, read-only API route and endpoint extraction.

The analyzer consumes a :class:`RepositoryDiscoveryResult` and a
:class:`TechnologyDetectionResult`. It inspects only source files already present
in the discovery inventory, never executes or imports repository code, never runs
Git, shell commands, or subprocesses, and never makes network requests.

Python files are parsed with :mod:`ast`. JavaScript and TypeScript files use a
small, deliberately scoped token scanner rather than a full parser. The scanner
understands comments, strings, template literals, simple concatenation, Express
route calls, Express router mounts, and NestJS decorators. It does not implement
JavaScript semantics, regular-expression parsing, JSX, TypeScript types, or
control-flow analysis. Unsupported or dynamic declarations become unresolved
route candidates or structured issues instead of invented concrete paths.

TOCTOU limitations
-----------------
Each source path is checked for relative containment, symlink/reparse-point
status, regular-file status, and size immediately before it is opened. The
filesystem can still change between those checks and the read, so a path could be
replaced by a symlink or moved outside the root after validation. Reads are
size-capped and failures become structured issues, but fully race-free operation
would require platform-specific directory handles.
"""

import ast
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from app.core.config import settings
from app.schemas.attack_surface import (
    AnalysisIssue,
    AnalysisIssueReason,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    HttpMethod,
    RouteCandidate,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.enums import DiscoverySkipReason
from app.schemas.repository_discovery import (
    FileInventoryEntry,
    RepositoryDiscoveryResult,
)
from app.schemas.technology import TechnologyCategory, TechnologyDetectionResult
from app.services.repository_discovery import EXCLUDED_DIRECTORY_NAMES
from app.services.repository_targets import (
    InvalidRepositoryLocationError,
    validate_repository_location,
)

_PYTHON_EXTENSIONS: Final[frozenset[str]] = frozenset({"py", "pyi"})
_JAVASCRIPT_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {"js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"}
)
_SOURCE_EXTENSIONS: Final[frozenset[str]] = _PYTHON_EXTENSIONS | _JAVASCRIPT_EXTENSIONS

_WINDOWS_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")

_PYTHON_LITERAL_CONFIDENCE: Final[float] = 0.95
_PYTHON_UNRESOLVED_CONFIDENCE: Final[float] = 0.50
_JAVASCRIPT_LITERAL_CONFIDENCE: Final[float] = 0.85
_JAVASCRIPT_UNRESOLVED_CONFIDENCE: Final[float] = 0.40

_MAX_PATH_DISPLAY_LENGTH: Final[int] = 200

_FASTAPI_METHODS: Final[dict[str, HttpMethod]] = {
    "get": HttpMethod.GET,
    "post": HttpMethod.POST,
    "put": HttpMethod.PUT,
    "patch": HttpMethod.PATCH,
    "delete": HttpMethod.DELETE,
    "head": HttpMethod.HEAD,
    "options": HttpMethod.OPTIONS,
    "trace": HttpMethod.TRACE,
}
_FLASK_METHODS: Final[dict[str, HttpMethod]] = dict(_FASTAPI_METHODS)
_EXPRESS_METHODS: Final[dict[str, HttpMethod]] = {
    **_FASTAPI_METHODS,
    "all": HttpMethod.ANY,
    "use": HttpMethod.ANY,
}
_NESTJS_METHODS: Final[dict[str, HttpMethod]] = {
    "get": HttpMethod.GET,
    "post": HttpMethod.POST,
    "put": HttpMethod.PUT,
    "patch": HttpMethod.PATCH,
    "delete": HttpMethod.DELETE,
}
_HTTP_METHODS: Final[dict[str, HttpMethod]] = {
    method.value: method for method in HttpMethod if method is not HttpMethod.ANY
}

_SENSITIVE_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
    }
)
_SENSITIVE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".der"}
)
_SENSITIVE_BASENAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:.*[._-])?"
    r"(?:credentials?|secrets?|passwords?|passwd|private[_-]?key|"
    r"id_(?:rsa|dsa|ecdsa|ed25519))"
    r"(?:[._-].*)?$",
    re.IGNORECASE,
)

_DISCOVERY_ISSUE_REASONS: Final[dict[DiscoverySkipReason, AnalysisIssueReason]] = {
    DiscoverySkipReason.SYMLINK: AnalysisIssueReason.SYMLINK,
    DiscoverySkipReason.NOT_REGULAR_FILE: AnalysisIssueReason.NOT_REGULAR_FILE,
    DiscoverySkipReason.PERMISSION_DENIED: AnalysisIssueReason.PERMISSION_DENIED,
    DiscoverySkipReason.DISAPPEARED: AnalysisIssueReason.DISAPPEARED,
    DiscoverySkipReason.INACCESSIBLE: AnalysisIssueReason.INACCESSIBLE,
    DiscoverySkipReason.OUTSIDE_ROOT: AnalysisIssueReason.OUTSIDE_ROOT,
    DiscoverySkipReason.EXCLUDED_DIRECTORY: AnalysisIssueReason.EXCLUDED_PATH,
}


class AttackSurfaceError(ValueError):
    """Base error for attack surface analysis operations."""


class InvalidAttackSurfaceRootError(AttackSurfaceError):
    """Raised when an analysis root is not a safe, existing directory."""


# Alias matching the naming used by the earlier repository services.
InvalidRepositoryRootError = InvalidAttackSurfaceRootError


@dataclass(frozen=True)
class _PythonReceiver:
    """A statically known FastAPI or Flask application/blueprint object."""

    framework: RouteFramework
    prefix: str
    prefix_resolved: bool


@dataclass(frozen=True)
class _JsToken:
    """One token produced by the scoped JavaScript/TypeScript scanner."""

    kind: str
    value: str
    line: int
    dynamic: bool = False


class _JsLexError(ValueError):
    """The scoped scanner found syntax it cannot tokenize safely."""


def _issue(
    source_file: str,
    reason: AnalysisIssueReason,
    detail: str | None = None,
) -> AnalysisIssue:
    return AnalysisIssue(source_file=source_file, reason=reason, detail=detail)


def _extension(relative_path: str, declared: str | None) -> str | None:
    if declared:
        return declared.lower()
    suffix = PurePosixPath(relative_path.replace("\\", "/")).suffix
    return suffix[1:].lower() if suffix else None


def _is_reparse_point(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _is_sensitive_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts:
        return False

    lowered_parts = [part.casefold() for part in parts]
    if any(part == ".env" or part.startswith(".env.") for part in lowered_parts):
        return True

    basename = parts[-1]
    lowered = basename.casefold()
    if lowered in _SENSITIVE_BASENAMES:
        return True
    if PurePosixPath(lowered).suffix in _SENSITIVE_SUFFIXES:
        return True
    return bool(_SENSITIVE_BASENAME_RE.match(basename))


def _has_excluded_component(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    return any(part in EXCLUDED_DIRECTORY_NAMES for part in PurePosixPath(normalized).parts)


def _validate_source_path(
    root: Path,
    relative_path: str,
    max_size: int,
) -> tuple[Path | None, AnalysisIssue | None]:
    normalized = relative_path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or _WINDOWS_DRIVE_RE.match(normalized):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INVALID_PATH,
            "Source path must be relative to the repository root",
        )
    if not pure.parts or any(part == ".." for part in pure.parts):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.OUTSIDE_ROOT,
            "Source path escapes the repository root",
        )

    candidate = root.joinpath(*pure.parts)
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.DISAPPEARED,
            "Source file disappeared before inspection",
        )
    except PermissionError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.PERMISSION_DENIED,
            "Permission denied while reading source file metadata",
        )
    except ValueError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INVALID_PATH,
            "Source path is not a valid filesystem path",
        )
    except OSError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INACCESSIBLE,
            "Source file metadata could not be inspected",
        )

    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.SYMLINK,
            "Symbolic links and reparse points are not followed",
        )
    if not stat.S_ISREG(metadata.st_mode):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.NOT_REGULAR_FILE,
            "Source path is not a regular file",
        )

    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.DISAPPEARED,
            "Source file disappeared before inspection",
        )
    except ValueError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INVALID_PATH,
            "Source path is not a valid filesystem path",
        )
    except (OSError, RuntimeError):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INACCESSIBLE,
            "Source file path could not be resolved",
        )

    if not resolved.is_relative_to(root):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.OUTSIDE_ROOT,
            "Source path resolves outside the repository root",
        )
    if metadata.st_size > max_size:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.TOO_LARGE,
            f"Source file exceeds the {max_size} byte limit",
        )
    return candidate, None


def _read_source_text(
    path: Path,
    relative_path: str,
    max_size: int,
) -> tuple[str | None, AnalysisIssue | None]:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_size + 1)
    except FileNotFoundError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.DISAPPEARED,
            "Source file disappeared before it could be read",
        )
    except PermissionError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.PERMISSION_DENIED,
            "Permission denied while reading source file",
        )
    except ValueError:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INVALID_PATH,
            "Source path is not a valid filesystem path",
        )
    except (OSError, RuntimeError):
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INACCESSIBLE,
            "Source file could not be read",
        )

    if len(data) > max_size:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.TOO_LARGE,
            f"Source file exceeds the {max_size} byte limit",
        )
    try:
        return data.decode("utf-8-sig"), None
    except UnicodeDecodeError as exc:
        return None, _issue(
            relative_path,
            AnalysisIssueReason.INVALID_ENCODING,
            f"Source file is not valid UTF-8: {exc}",
        )


def _resolve_root(root: Path, inventory: RepositoryDiscoveryResult) -> Path:
    candidate = Path(root).expanduser()
    if candidate.is_symlink():
        raise InvalidAttackSurfaceRootError("Repository root must not be a symbolic link")

    try:
        resolved_root = validate_repository_location(str(candidate))
    except InvalidRepositoryLocationError as exc:
        raise InvalidAttackSurfaceRootError(str(exc)) from exc

    try:
        inventory_root = Path(inventory.root).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidAttackSurfaceRootError(
            "Inventory root is not a valid filesystem path"
        ) from exc
    if inventory_root != resolved_root:
        raise InvalidAttackSurfaceRootError("Inventory root does not match the repository root")
    return resolved_root


def _source_candidates(
    inventory: RepositoryDiscoveryResult,
) -> list[FileInventoryEntry]:
    candidates = [
        entry
        for entry in inventory.files
        if _extension(entry.relative_path, entry.extension) in _SOURCE_EXTENSIONS
    ]
    return sorted(candidates, key=lambda entry: entry.relative_path)


def _discovery_source_issues(
    inventory: RepositoryDiscoveryResult,
) -> list[AnalysisIssue]:
    issues: list[AnalysisIssue] = []
    for item in inventory.skipped:
        extension = _extension(item.relative_path, None)
        if extension not in _SOURCE_EXTENSIONS:
            continue
        reason = _DISCOVERY_ISSUE_REASONS.get(item.reason)
        if reason is None:
            continue
        issues.append(_issue(item.relative_path, reason, item.detail))
    return issues


def _framework_hints(technologies: TechnologyDetectionResult) -> frozenset[str]:
    return frozenset(
        detection.name.casefold()
        for detection in technologies.detections
        if detection.category is TechnologyCategory.FRAMEWORK
    )


def _call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _keyword_expression(call: ast.Call, keyword: str) -> ast.expr | None:
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    return None


def _python_string(
    node: ast.expr,
    constants: dict[str, str],
) -> tuple[str | None, bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, True
    if isinstance(node, ast.Name):
        value = constants.get(node.id)
        if value is None:
            return None, False
        return value, True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, left_ok = _python_string(node.left, constants)
        right, right_ok = _python_string(node.right, constants)
        if left_ok and right_ok:
            return f"{left}{right}", True
        return None, False
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None, False
        return "".join(parts), True
    return None, False


def _python_expression_text(node: ast.expr) -> str:
    try:
        text = ast.unparse(node)
    except (AttributeError, RecursionError, ValueError):
        text = type(node).__name__
    text = " ".join(text.split())
    if len(text) > _MAX_PATH_DISPLAY_LENGTH:
        text = text[: _MAX_PATH_DISPLAY_LENGTH - 3] + "..."
    return text or "<dynamic>"


def _collect_module_constants(tree: ast.Module) -> dict[str, str]:
    assignments: dict[str, list[ast.expr]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                assignments.setdefault(node.targets[0].id, []).append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assignments.setdefault(node.target.id, []).append(node.value)

    raw = {name: values[0] for name, values in assignments.items() if len(values) == 1}
    constants: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for name, expression in raw.items():
            if name in constants:
                continue
            value, resolved = _python_string(expression, constants)
            if resolved and value is not None:
                constants[name] = value
                changed = True
    return constants


def _collect_receivers(
    tree: ast.Module,
    constants: dict[str, str],
) -> dict[str, _PythonReceiver]:
    raw: dict[str, list[_PythonReceiver]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue

        name = _call_name(value.func)
        receiver: _PythonReceiver | None = None
        if name == "APIRouter":
            prefix_expr = _keyword_expression(value, "prefix")
            if prefix_expr is None:
                receiver = _PythonReceiver(RouteFramework.FASTAPI, "", True)
            else:
                prefix, resolved = _python_string(prefix_expr, constants)
                receiver = _PythonReceiver(
                    RouteFramework.FASTAPI,
                    prefix
                    if resolved and prefix is not None
                    else _python_expression_text(prefix_expr),
                    resolved,
                )
        elif name == "FastAPI":
            receiver = _PythonReceiver(RouteFramework.FASTAPI, "", True)
        elif name == "Blueprint":
            prefix_expr = _keyword_expression(value, "url_prefix")
            if prefix_expr is None:
                receiver = _PythonReceiver(RouteFramework.FLASK, "", True)
            else:
                prefix, resolved = _python_string(prefix_expr, constants)
                receiver = _PythonReceiver(
                    RouteFramework.FLASK,
                    prefix
                    if resolved and prefix is not None
                    else _python_expression_text(prefix_expr),
                    resolved,
                )
        elif name == "Flask":
            receiver = _PythonReceiver(RouteFramework.FLASK, "", True)

        if receiver is not None:
            raw.setdefault(targets[0].id, []).append(receiver)

    return {name: values[0] for name, values in raw.items() if len(values) == 1}


def _collect_include_edges(
    tree: ast.Module,
    constants: dict[str, str],
) -> dict[str, list[tuple[str, bool]]]:
    edges: dict[str, list[tuple[str, bool]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attribute = node.func.attr
        if attribute not in {"include_router", "register_blueprint"}:
            continue
        if not node.args or not isinstance(node.args[0], ast.Name):
            continue
        keyword = "prefix" if attribute == "include_router" else "url_prefix"
        prefix_expr = _keyword_expression(node, keyword)
        if prefix_expr is None:
            edges.setdefault(node.args[0].id, []).append(("", True))
            continue
        prefix, resolved = _python_string(prefix_expr, constants)
        edges.setdefault(node.args[0].id, []).append(
            (
                prefix if resolved and prefix is not None else _python_expression_text(prefix_expr),
                resolved,
            )
        )
    return edges


def _collect_imported_frameworks(tree: ast.Module) -> frozenset[RouteFramework]:
    frameworks: set[RouteFramework] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            module = node.module.split(".")[0]
            if module == "fastapi":
                frameworks.add(RouteFramework.FASTAPI)
            elif module == "flask":
                frameworks.add(RouteFramework.FLASK)
            elif module == "django":
                frameworks.add(RouteFramework.DJANGO)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]
                if module == "fastapi":
                    frameworks.add(RouteFramework.FASTAPI)
                elif module == "flask":
                    frameworks.add(RouteFramework.FLASK)
                elif module == "django":
                    frameworks.add(RouteFramework.DJANGO)
    return frozenset(frameworks)


def _normalize_route_path(path: str) -> str:
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


def _join_route_path(prefix: str, path: str) -> str:
    prefix = prefix or ""
    path = path or ""
    if not prefix:
        return _normalize_route_path(path)
    if not path or path == "/":
        return _normalize_route_path(prefix)
    return _normalize_route_path(f"{prefix.rstrip('/')}/{path.lstrip('/')}")


def _join_route_display(
    prefix: str,
    prefix_resolved: bool,
    path: str,
    path_resolved: bool,
) -> str:
    prefix_text = _normalize_route_path(prefix) if prefix_resolved and prefix else prefix
    if not prefix_resolved:
        prefix_text = prefix or "<prefix>"
    path_text = _normalize_route_path(path) if path_resolved and path else path
    if not path_resolved:
        path_text = path or "<path>"
    if prefix_text and path_text:
        combined = f"{prefix_text.rstrip('/')}/{path_text.lstrip('/')}"
    else:
        combined = prefix_text or path_text or "<dynamic>"
    if len(combined) > _MAX_PATH_DISPLAY_LENGTH:
        combined = combined[: _MAX_PATH_DISPLAY_LENGTH - 3] + "..."
    return combined or "<dynamic>"


def _http_method_from_text(value: str) -> HttpMethod | None:
    return _HTTP_METHODS.get(value.strip().upper())


def _keyword_methods(
    call: ast.Call,
    constants: dict[str, str],
) -> tuple[list[HttpMethod], bool]:
    expression = _keyword_expression(call, "methods")
    if expression is None:
        return [HttpMethod.GET], True
    if not isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        return [HttpMethod.ANY], False

    methods: list[HttpMethod] = []
    for element in expression.elts:
        value, resolved = _python_string(element, constants)
        if not resolved or value is None:
            return [HttpMethod.ANY], False
        method = _http_method_from_text(value)
        if method is None:
            return [HttpMethod.ANY], False
        if method not in methods:
            methods.append(method)
    return (methods or [HttpMethod.GET]), True


def _django_path_aliases(tree: ast.Module) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "django.urls":
            for alias in node.names:
                if alias.name in {"path", "re_path"}:
                    aliases.add(alias.asname or alias.name)
    return aliases


def _is_django_qualified_call(func: ast.expr) -> bool:
    if not isinstance(func, ast.Attribute):
        return False
    chain: list[str] = []
    current: ast.expr = func
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        chain.append(current.id)
    return "django" in chain or "urls" in chain


def _is_django_url_config(tree: ast.Module, relative_path: str) -> bool:
    if PurePosixPath(relative_path.replace("\\", "/")).name.casefold() == "urls.py":
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "urlpatterns":
                    return True
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "urlpatterns"
        ):
            return True
    return False


def _django_handler_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_django_routes(
    tree: ast.Module,
    relative_path: str,
    constants: dict[str, str],
    issues: list[AnalysisIssue],
) -> list[RouteCandidate]:
    if not _is_django_url_config(tree, relative_path):
        return []

    aliases = _django_path_aliases(tree)
    is_urls_file = PurePosixPath(relative_path.replace("\\", "/")).name.casefold() == "urls.py"
    routes: list[RouteCandidate] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = _call_name(node.func)
        if function_name not in {"path", "re_path"}:
            continue
        if not (function_name in aliases or _is_django_qualified_call(node.func) or is_urls_file):
            continue
        if not node.args:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    "Django route declaration has no path argument",
                )
            )
            continue

        path_expression = node.args[0]
        value, resolved = _python_string(path_expression, constants)
        if resolved and value is not None:
            path = value or "/"
            status = RouteResolutionStatus.RESOLVED
            confidence = _PYTHON_LITERAL_CONFIDENCE
        else:
            path = _python_expression_text(path_expression)
            status = RouteResolutionStatus.UNRESOLVED
            confidence = _PYTHON_UNRESOLVED_CONFIDENCE

        handler = _django_handler_name(node.args[1]) if len(node.args) > 1 else None
        routes.append(
            RouteCandidate(
                path=path,
                http_method=HttpMethod.ANY,
                framework=RouteFramework.DJANGO,
                source_file=relative_path,
                line_number=node.lineno,
                handler_name=handler,
                detection_confidence=confidence,
                resolution_status=status,
            )
        )
    return routes


def _infer_decorator_framework(
    imported: frozenset[RouteFramework],
    hints: frozenset[str],
) -> RouteFramework | None:
    if RouteFramework.FASTAPI in imported and RouteFramework.FLASK not in imported:
        return RouteFramework.FASTAPI
    if RouteFramework.FLASK in imported and RouteFramework.FASTAPI not in imported:
        return RouteFramework.FLASK
    if "fastapi" in hints and "flask" not in hints:
        return RouteFramework.FASTAPI
    if "flask" in hints and "fastapi" not in hints:
        return RouteFramework.FLASK
    return None


def _extract_python_routes(
    tree: ast.Module,
    relative_path: str,
    constants: dict[str, str],
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> list[RouteCandidate]:
    receivers = _collect_receivers(tree, constants)
    include_edges = _collect_include_edges(tree, constants)
    imported = _collect_imported_frameworks(tree)
    routes: list[RouteCandidate] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            receiver = decorator.func.value
            if not isinstance(receiver, ast.Name):
                continue

            method_name = decorator.func.attr.lower()
            receiver_info = receivers.get(receiver.id)
            methods: list[HttpMethod]
            methods_resolved = True

            if method_name == "route":
                if (
                    receiver_info is not None
                    and receiver_info.framework is not RouteFramework.FLASK
                ):
                    continue
                if (
                    receiver_info is None
                    and RouteFramework.FLASK not in imported
                    and "flask" not in hints
                ):
                    continue
                framework = RouteFramework.FLASK
                methods, methods_resolved = _keyword_methods(decorator, constants)
            elif method_name in _FASTAPI_METHODS:
                if receiver_info is not None:
                    framework = receiver_info.framework
                else:
                    inferred = _infer_decorator_framework(imported, hints)
                    if inferred is None:
                        issues.append(
                            _issue(
                                relative_path,
                                AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                                (
                                    f"Could not determine the framework for decorator "
                                    f"'@{receiver.id}.{method_name}'"
                                ),
                            )
                        )
                        continue
                    framework = inferred
                methods = [
                    _FLASK_METHODS[method_name]
                    if framework is RouteFramework.FLASK
                    else _FASTAPI_METHODS[method_name]
                ]
            else:
                continue

            path_expression = (
                decorator.args[0] if decorator.args else _keyword_expression(decorator, "path")
            )
            if path_expression is None:
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                        (f"Route declaration '@{receiver.id}.{method_name}' has no path argument"),
                    )
                )
                continue

            path_value, path_resolved = _python_string(path_expression, constants)
            if path_resolved and path_value is not None:
                path_text = path_value
            else:
                path_text = _python_expression_text(path_expression)
                path_resolved = False

            if not methods_resolved:
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                        (
                            f"Route methods for '@{receiver.id}.{method_name}' "
                            "could not be determined statically"
                        ),
                    )
                )

            base_prefix = receiver_info.prefix if receiver_info is not None else ""
            base_resolved = receiver_info.prefix_resolved if receiver_info is not None else True
            edges = include_edges.get(receiver.id, [])
            prefix_options: list[tuple[str, bool]] = []
            if edges:
                for edge_prefix, edge_resolved in edges:
                    if base_resolved and edge_resolved:
                        prefix_options.append((_join_route_path(base_prefix, edge_prefix), True))
                    else:
                        prefix_options.append(
                            (
                                _join_route_display(
                                    base_prefix,
                                    base_resolved,
                                    edge_prefix,
                                    edge_resolved,
                                ),
                                False,
                            )
                        )
            else:
                prefix_options.append((base_prefix, base_resolved))

            unique_options: list[tuple[str, bool]] = []
            seen_options: set[tuple[str, bool]] = set()
            for option in prefix_options:
                if option not in seen_options:
                    seen_options.add(option)
                    unique_options.append(option)

            for method in methods:
                for prefix, prefix_resolved in unique_options:
                    if path_resolved and prefix_resolved:
                        path = _join_route_path(prefix, path_text)
                        status = RouteResolutionStatus.RESOLVED
                        confidence = _PYTHON_LITERAL_CONFIDENCE
                    else:
                        path = _join_route_display(
                            prefix,
                            prefix_resolved,
                            path_text,
                            path_resolved,
                        )
                        status = RouteResolutionStatus.UNRESOLVED
                        confidence = _PYTHON_UNRESOLVED_CONFIDENCE

                    routes.append(
                        RouteCandidate(
                            path=path,
                            http_method=method,
                            framework=framework,
                            source_file=relative_path,
                            line_number=decorator.lineno,
                            handler_name=node.name,
                            detection_confidence=confidence,
                            resolution_status=status,
                        )
                    )
    return routes


_JS_ESCAPES: Final[dict[str, str]] = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
    "/": "/",
}

_REGEX_PRECEDING_PUNCT: Final[frozenset[str]] = frozenset("=([,{!:;&|?+-*%<>~^")
_REGEX_PRECEDING_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "return",
        "case",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "else",
        "do",
        "yield",
        "await",
    }
)


def _read_js_string(
    text: str,
    index: int,
    quote: str,
    line: int,
) -> tuple[str, int, int]:
    i = index + 1
    parts: list[str] = []
    while i < len(text):
        character = text[i]
        if character == quote:
            return "".join(parts), i + 1, line
        if character == "\\":
            i += 1
            if i >= len(text):
                break
            escape = text[i]
            if escape == "\n":
                line += 1
                i += 1
                continue
            if escape == "u" and i + 4 < len(text):
                try:
                    parts.append(chr(int(text[i + 1 : i + 5], 16)))
                    i += 5
                    continue
                except ValueError:
                    pass
            if escape == "x" and i + 2 < len(text):
                try:
                    parts.append(chr(int(text[i + 1 : i + 3], 16)))
                    i += 3
                    continue
                except ValueError:
                    pass
            parts.append(_JS_ESCAPES.get(escape, escape))
            i += 1
            continue
        if character == "\n":
            raise _JsLexError("Unterminated string literal", line)
        parts.append(character)
        i += 1
    raise _JsLexError("Unterminated string literal", line)


def _skip_js_braced_expression(
    text: str,
    index: int,
    line: int,
) -> tuple[int, int]:
    depth = 1
    i = index + 1
    while i < len(text):
        character = text[i]
        if character in "'\"":
            _, i, line = _read_js_string(text, i, character, line)
            continue
        if character == "`":
            _, i, line, _ = _read_js_template(text, i, line)
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return i + 1, line
        elif character == "\n":
            line += 1
        i += 1
    raise _JsLexError("Unterminated template expression", line)


def _read_js_template(
    text: str,
    index: int,
    line: int,
) -> tuple[str, int, int, bool]:
    i = index + 1
    parts: list[str] = []
    raw_parts: list[str] = []
    dynamic = False
    while i < len(text):
        character = text[i]
        if character == "`":
            if dynamic:
                return "".join(raw_parts), i + 1, line, True
            return "".join(parts), i + 1, line, False
        if character == "\\":
            raw_parts.append(character)
            i += 1
            if i < len(text):
                escape = text[i]
                raw_parts.append(escape)
                if escape == "\n":
                    line += 1
                parts.append(_JS_ESCAPES.get(escape, escape))
                i += 1
            continue
        if character == "$" and i + 1 < len(text) and text[i + 1] == "{":
            dynamic = True
            start = i
            i, line = _skip_js_braced_expression(text, i + 1, line)
            raw_parts.append(text[start:i])
            continue
        if character == "\n":
            line += 1
        raw_parts.append(character)
        parts.append(character)
        i += 1
    raise _JsLexError("Unterminated template literal", line)


def _read_js_regex(text: str, index: int, line: int) -> int | None:
    i = index + 1
    in_class = False
    while i < len(text):
        character = text[i]
        if character == "\\":
            i += 2
            continue
        if character == "[":
            in_class = True
        elif character == "]":
            in_class = False
        elif character == "/" and not in_class:
            i += 1
            while i < len(text) and text[i].isalpha():
                i += 1
            return i
        elif character == "\n":
            return None
        i += 1
    return None


def _can_start_regex(previous: _JsToken | None) -> bool:
    if previous is None:
        return True
    if previous.kind == "punct":
        return previous.value in _REGEX_PRECEDING_PUNCT
    if previous.kind == "identifier":
        return previous.value in _REGEX_PRECEDING_KEYWORDS
    return False


def _lex_javascript(text: str) -> list[_JsToken]:
    tokens: list[_JsToken] = []
    i = 0
    line = 1
    length = len(text)

    while i < length:
        character = text[i]

        if character in " \t\r":
            i += 1
            continue
        if character == "\n":
            line += 1
            i += 1
            continue
        if character == "/" and i + 1 < length and text[i + 1] == "/":
            i += 2
            while i < length and text[i] != "\n":
                i += 1
            continue
        if character == "/" and i + 1 < length and text[i + 1] == "*":
            start_line = line
            i += 2
            while i < length and not (text[i] == "*" and i + 1 < length and text[i + 1] == "/"):
                if text[i] == "\n":
                    line += 1
                i += 1
            if i >= length:
                raise _JsLexError("Unterminated block comment", start_line)
            i += 2
            continue
        if character in "'\"":
            start_line = line
            value, i, line = _read_js_string(text, i, character, line)
            tokens.append(_JsToken("string", value, start_line))
            continue
        if character == "`":
            start_line = line
            value, i, line, dynamic = _read_js_template(text, i, line)
            tokens.append(_JsToken("template", value, start_line, dynamic=dynamic))
            continue
        if character == "/":
            previous = tokens[-1] if tokens else None
            if _can_start_regex(previous):
                next_index = _read_js_regex(text, i, line)
                if next_index is not None:
                    tokens.append(_JsToken("regex", text[i:next_index], line))
                    i = next_index
                    continue
            tokens.append(_JsToken("punct", "/", line))
            i += 1
            continue
        if character == "@":
            tokens.append(_JsToken("punct", "@", line))
            i += 1
            continue
        if character.isalpha() or character in "_$":
            start = i
            start_line = line
            while i < length and (text[i].isalnum() or text[i] in "_$"):
                i += 1
            tokens.append(_JsToken("identifier", text[start:i], start_line))
            continue
        if character.isdigit():
            start = i
            start_line = line
            while i < length and (text[i].isalnum() or text[i] in "._"):
                i += 1
            tokens.append(_JsToken("number", text[start:i], start_line))
            continue

        tokens.append(_JsToken("punct", character, line))
        i += 1

    return tokens


_STATEMENT_STARTERS: Final[frozenset[str]] = frozenset(
    {
        "const",
        "let",
        "var",
        "function",
        "class",
        "export",
        "import",
        "module",
        "app",
        "router",
        "server",
        "api",
        "routes",
        "route",
    }
)


def _punct(token: _JsToken | None, value: str) -> bool:
    return token is not None and token.kind == "punct" and token.value == value


def _is_punct(tokens: list[_JsToken], index: int, value: str) -> bool:
    return 0 <= index < len(tokens) and _punct(tokens[index], value)


def _collect_arguments(
    tokens: list[_JsToken],
    open_index: int,
) -> tuple[list[list[_JsToken]], int]:
    depth = 0
    arguments: list[list[_JsToken]] = []
    current: list[_JsToken] = []
    index = open_index

    while index < len(tokens):
        token = tokens[index]
        if token.kind == "punct":
            if token.value in "([{":
                depth += 1
                if depth > 1:
                    current.append(token)
            elif token.value in ")]}":
                depth -= 1
                if depth == 0:
                    if current or arguments:
                        arguments.append(current)
                    return arguments, index
                current.append(token)
            elif token.value == "," and depth == 1:
                arguments.append(current)
                current = []
            else:
                current.append(token)
        else:
            current.append(token)
        index += 1

    raise _JsLexError("Unbalanced parentheses", tokens[open_index].line)


def _statement_end(tokens: list[_JsToken], start: int) -> int:
    depth = 0
    previous = tokens[start - 1] if start > 0 else None
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.kind == "punct":
            if token.value in "([{":
                depth += 1
            elif token.value in ")]}":
                if depth == 0:
                    return index
                depth -= 1
            elif token.value == ";" and depth == 0:
                return index
        if depth == 0 and previous is not None and token.line > previous.line:
            if token.kind == "identifier" and token.value in _STATEMENT_STARTERS:
                return index
        previous = token
    return len(tokens)


def _tokens_to_text(tokens: list[_JsToken]) -> str:
    pieces: list[str] = []
    for token in tokens:
        if token.kind == "string":
            pieces.append(repr(token.value))
        elif token.kind == "template":
            pieces.append(f"`{token.value}`")
        else:
            pieces.append(token.value)
    text = "".join(pieces)
    text = " ".join(text.split())
    if len(text) > _MAX_PATH_DISPLAY_LENGTH:
        text = text[: _MAX_PATH_DISPLAY_LENGTH - 3] + "..."
    return text or "<dynamic>"


def _evaluate_js_string(tokens: list[_JsToken]) -> tuple[str | None, bool]:
    if not tokens:
        return None, False

    parts: list[str] = []
    expect_value = True
    for token in tokens:
        if expect_value:
            if token.kind == "string":
                parts.append(token.value)
            elif token.kind == "template" and not token.dynamic:
                parts.append(token.value)
            else:
                return _tokens_to_text(tokens), False
            expect_value = False
        else:
            if token.kind == "punct" and token.value == "+":
                expect_value = True
            else:
                return _tokens_to_text(tokens), False

    if expect_value:
        return _tokens_to_text(tokens), False
    return "".join(parts), True


def _contains_identifier(tokens: list[_JsToken], value: str) -> bool:
    return any(token.kind == "identifier" and token.value == value for token in tokens)


def _contains_string(tokens: list[_JsToken], value: str) -> bool:
    return any(token.kind == "string" and token.value == value for token in tokens)


def _rhs_is_router(tokens: list[_JsToken]) -> bool:
    for index, token in enumerate(tokens):
        if token.kind == "identifier" and token.value == "Router":
            if _is_punct(tokens, index + 1, "("):
                return True
    return False


def _rhs_is_app(tokens: list[_JsToken]) -> bool:
    if _rhs_is_router(tokens):
        return False
    for index, token in enumerate(tokens):
        if token.kind == "identifier" and token.value == "express":
            if _is_punct(tokens, index + 1, "("):
                return True
        if token.kind == "identifier" and token.value == "require":
            if _is_punct(tokens, index + 1, "("):
                if _contains_string(tokens[index + 2 : index + 4], "express"):
                    return True
    return False


def _collect_js_bindings(
    tokens: list[_JsToken],
) -> tuple[set[str], set[str], bool]:
    app_vars: set[str] = set()
    router_vars: set[str] = set()
    express_present = _contains_identifier(tokens, "express") or _contains_string(tokens, "express")

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {"const", "let", "var"}:
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            continue
        name = tokens[index + 1].value
        equals = index + 2
        if not _is_punct(tokens, equals, "="):
            continue
        end = _statement_end(tokens, equals + 1)
        rhs = tokens[equals + 1 : end]
        if name == "express":
            continue
        if _rhs_is_router(rhs):
            router_vars.add(name)
        elif _rhs_is_app(rhs):
            app_vars.add(name)

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or not _is_punct(tokens, index + 1, "="):
            continue
        if (
            index > 0
            and tokens[index - 1].kind == "identifier"
            and tokens[index - 1].value in {"const", "let", "var"}
        ):
            continue
        name = token.value
        if name in app_vars or name in router_vars or name == "express":
            continue
        end = _statement_end(tokens, index + 2)
        rhs = tokens[index + 2 : end]
        if _rhs_is_router(rhs):
            router_vars.add(name)
        elif _rhs_is_app(rhs):
            app_vars.add(name)

    return app_vars, router_vars, express_present


def _is_router_reference(
    tokens: list[_JsToken],
    known_routers: set[str],
) -> str | None:
    if len(tokens) != 1 or tokens[0].kind != "identifier":
        return None
    name = tokens[0].value
    lowered = name.casefold()
    if name in known_routers or "router" in lowered or lowered in {"routes", "route"}:
        return name
    return None


def _is_handler_like(tokens: list[_JsToken]) -> bool:
    if not tokens:
        return False
    first = tokens[0]
    if first.kind == "identifier":
        if first.value in {"function", "async"}:
            return True
        if len(tokens) >= 2 and _punct(tokens[1], "=>"):
            return True
        return all(
            token.kind == "identifier" or (token.kind == "punct" and token.value == ".")
            for token in tokens
        )
    if first.kind == "punct" and first.value == "(":
        return any(token.kind == "punct" and token.value == "=>" for token in tokens)
    return False


def _js_handler_name(tokens: list[_JsToken]) -> str | None:
    if not tokens:
        return None

    index = 0
    if tokens[0].kind == "identifier" and tokens[0].value == "async":
        index = 1
    if (
        index < len(tokens)
        and tokens[index].kind == "identifier"
        and tokens[index].value == "function"
    ):
        index += 1
        if index < len(tokens) and tokens[index].kind == "identifier":
            return tokens[index].value
        return None

    if index < len(tokens) and tokens[index].kind == "identifier":
        if len(tokens) == index + 1:
            return tokens[index].value
        if all(
            token.kind == "identifier" or (token.kind == "punct" and token.value == ".")
            for token in tokens[index:]
        ):
            return tokens[-1].value
    return None


def _dedupe_options(options: list[tuple[str, bool]]) -> list[tuple[str, bool]]:
    unique: list[tuple[str, bool]] = []
    seen: set[tuple[str, bool]] = set()
    for option in options:
        if option not in seen:
            seen.add(option)
            unique.append(option)
    return unique


def _collect_express_mounts(
    tokens: list[_JsToken],
    known_apps: set[str],
    known_routers: set[str],
) -> dict[str, list[tuple[str, bool]]]:
    mounts: dict[str, list[tuple[str, bool]]] = {}
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in known_apps:
            continue
        if not _is_punct(tokens, index + 1, "."):
            continue
        if index + 2 >= len(tokens) or tokens[index + 2].kind != "identifier":
            continue
        if tokens[index + 2].value.casefold() != "use":
            continue
        if not _is_punct(tokens, index + 3, "("):
            continue
        arguments, _ = _collect_arguments(tokens, index + 3)
        if not arguments:
            continue
        path_tokens = arguments[0]
        path_value, path_resolved = _evaluate_js_string(path_tokens)
        path_text = (
            path_value if path_resolved and path_value is not None else _tokens_to_text(path_tokens)
        )
        router_references = [
            reference
            for argument in arguments[1:]
            if (reference := _is_router_reference(argument, known_routers)) is not None
        ]
        for reference in router_references:
            known_routers.add(reference)
            mounts.setdefault(reference, []).append((path_text, path_resolved))
    return mounts


def _extract_express_routes(
    tokens: list[_JsToken],
    relative_path: str,
    hints: frozenset[str],
) -> list[RouteCandidate]:
    app_vars, router_vars, express_present = _collect_js_bindings(tokens)
    if not express_present and "express" not in hints:
        return []

    known_apps = set(app_vars) | {"app", "server", "api"}
    known_routers = set(router_vars) | {"router", "routes", "route"}
    mounts = _collect_express_mounts(tokens, known_apps, known_routers)
    routes: list[RouteCandidate] = []

    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue
        receiver = token.value
        if receiver not in known_apps and receiver not in known_routers:
            continue
        if not _is_punct(tokens, index + 1, "."):
            continue
        if index + 2 >= len(tokens) or tokens[index + 2].kind != "identifier":
            continue
        method_name = tokens[index + 2].value.casefold()
        if method_name not in _EXPRESS_METHODS:
            continue
        if not _is_punct(tokens, index + 3, "("):
            continue

        arguments, _ = _collect_arguments(tokens, index + 3)
        if len(arguments) < 2:
            continue
        path_tokens = arguments[0]
        if not path_tokens:
            continue

        if method_name == "use":
            router_references = [
                reference
                for argument in arguments[1:]
                if (reference := _is_router_reference(argument, known_routers)) is not None
            ]
            if router_references:
                continue
            if not _is_handler_like(arguments[1]):
                continue

        path_value, path_resolved = _evaluate_js_string(path_tokens)
        if path_resolved and path_value is not None:
            path_text = path_value
        else:
            path_text = _tokens_to_text(path_tokens)
            path_resolved = False

        handler = _js_handler_name(arguments[-1])
        options = mounts.get(receiver, [("", True)]) if receiver in known_routers else [("", True)]

        for prefix, prefix_resolved in _dedupe_options(options):
            if path_resolved and prefix_resolved:
                path = _join_route_path(prefix, path_text)
                status = RouteResolutionStatus.RESOLVED
                confidence = _JAVASCRIPT_LITERAL_CONFIDENCE
            else:
                path = _join_route_display(
                    prefix,
                    prefix_resolved,
                    path_text,
                    path_resolved,
                )
                status = RouteResolutionStatus.UNRESOLVED
                confidence = _JAVASCRIPT_UNRESOLVED_CONFIDENCE

            routes.append(
                RouteCandidate(
                    path=path,
                    http_method=_EXPRESS_METHODS[method_name],
                    framework=RouteFramework.EXPRESS,
                    source_file=relative_path,
                    line_number=token.line,
                    handler_name=handler,
                    detection_confidence=confidence,
                    resolution_status=status,
                )
            )

    return routes


_JS_NON_METHOD_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "function",
        "constructor",
        "return",
        "new",
        "typeof",
        "await",
        "async",
        "super",
        "this",
    }
)


def _next_js_method_name(tokens: list[_JsToken], start: int) -> str | None:
    index = start
    while index < len(tokens):
        token = tokens[index]
        if _punct(token, "@"):
            index += 1
            if index < len(tokens) and tokens[index].kind == "identifier":
                index += 1
            if _is_punct(tokens, index, "("):
                _, close = _collect_arguments(tokens, index)
                index = close + 1
            continue
        if token.kind == "identifier" and _is_punct(tokens, index + 1, "("):
            if token.value not in _JS_NON_METHOD_KEYWORDS:
                return token.value
        if token.kind == "punct" and token.value in ";}":
            return None
        index += 1
    return None


def _has_nestjs_markers(tokens: list[_JsToken]) -> bool:
    if _contains_string(tokens, "@nestjs/common"):
        return True
    for index in range(len(tokens) - 1):
        if (
            _punct(tokens[index], "@")
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 1].value.casefold() == "controller"
        ):
            return True
    return False


def _extract_nestjs_routes(
    tokens: list[_JsToken],
    relative_path: str,
    issues: list[AnalysisIssue],
) -> list[RouteCandidate]:
    if not _has_nestjs_markers(tokens):
        return []

    routes: list[RouteCandidate] = []
    controller_prefix = ""
    controller_resolved = True
    pending_controller = False
    index = 0

    while index < len(tokens):
        token = tokens[index]

        if token.kind == "identifier" and token.value == "class":
            if pending_controller:
                pending_controller = False
            else:
                controller_prefix = ""
                controller_resolved = True
            index += 1
            continue

        if not _punct(token, "@"):
            index += 1
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            index += 1
            continue

        decorator_name = tokens[index + 1].value
        argument_start = index + 2
        arguments: list[list[_JsToken]] = []
        if _is_punct(tokens, argument_start, "("):
            arguments, close = _collect_arguments(tokens, argument_start)
        else:
            close = index + 1

        if decorator_name.casefold() == "controller":
            if not arguments:
                controller_prefix = ""
                controller_resolved = True
            else:
                first = arguments[0]
                value, resolved = _evaluate_js_string(first)
                if resolved and value is not None:
                    controller_prefix = value
                    controller_resolved = True
                else:
                    controller_prefix = _tokens_to_text(first)
                    controller_resolved = False
                    detail = "NestJS controller prefix is not a statically readable string literal"
                    if first and _punct(first[0], "{"):
                        detail = "NestJS controller object arguments are not supported"
                    issues.append(
                        _issue(
                            relative_path,
                            AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                            detail,
                        )
                    )
            pending_controller = True
            index = close + 1
            continue

        method = _NESTJS_METHODS.get(decorator_name.casefold())
        if method is None:
            index = close + 1
            continue

        if not arguments:
            method_path = ""
            method_resolved = True
        else:
            first = arguments[0]
            value, resolved = _evaluate_js_string(first)
            if resolved and value is not None:
                method_path = value
                method_resolved = True
            else:
                method_path = _tokens_to_text(first)
                method_resolved = False
                if first and _punct(first[0], "{"):
                    issues.append(
                        _issue(
                            relative_path,
                            AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                            "NestJS route object arguments are not supported",
                        )
                    )

        handler = _next_js_method_name(tokens, close + 1)
        if controller_resolved and method_resolved:
            path = _join_route_path(controller_prefix, method_path)
            status = RouteResolutionStatus.RESOLVED
            confidence = _JAVASCRIPT_LITERAL_CONFIDENCE
        else:
            path = _join_route_display(
                controller_prefix,
                controller_resolved,
                method_path,
                method_resolved,
            )
            status = RouteResolutionStatus.UNRESOLVED
            confidence = _JAVASCRIPT_UNRESOLVED_CONFIDENCE

        routes.append(
            RouteCandidate(
                path=path,
                http_method=method,
                framework=RouteFramework.NESTJS,
                source_file=relative_path,
                line_number=token.line,
                handler_name=handler,
                detection_confidence=confidence,
                resolution_status=status,
            )
        )
        index = close + 1

    return routes


def _extract_javascript_routes(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> list[RouteCandidate]:
    try:
        tokens = _lex_javascript(text)
    except _JsLexError as exc:
        issues.append(
            _issue(
                relative_path,
                AnalysisIssueReason.INVALID_SYNTAX,
                str(exc),
            )
        )
        return []

    routes = _extract_express_routes(tokens, relative_path, hints)
    routes.extend(_extract_nestjs_routes(tokens, relative_path, issues))
    return routes


def _extract_python_file_routes(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> list[RouteCandidate]:
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
        return []
    except (ValueError, RecursionError, MemoryError) as exc:
        issues.append(
            _issue(
                relative_path,
                AnalysisIssueReason.INVALID_SYNTAX,
                f"Python source could not be parsed: {exc}",
            )
        )
        return []

    constants = _collect_module_constants(tree)
    routes = _extract_python_routes(tree, relative_path, constants, issues, hints)
    routes.extend(_extract_django_routes(tree, relative_path, constants, issues))
    return routes


def _dedupe_routes(routes: list[RouteCandidate]) -> list[RouteCandidate]:
    unique: list[RouteCandidate] = []
    seen: set[tuple[object, ...]] = set()
    for route in routes:
        key = (
            route.path,
            route.http_method,
            route.framework,
            route.source_file,
            route.line_number,
            route.handler_name,
            route.resolution_status,
        )
        if key not in seen:
            seen.add(key)
            unique.append(route)
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


def identify_attack_surface(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    *,
    max_source_file_size_bytes: int | None = None,
    max_source_files: int | None = None,
) -> AttackSurfaceResult:
    """Extract API route declarations from eligible inventoried source files.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match both the discovery inventory and the technology detection result.
    Only Python and JavaScript/TypeScript files already present in the inventory
    are read. Repository code is never executed or imported.
    """
    resolved_root = _resolve_root(root, inventory)

    try:
        technology_root = Path(technologies.root).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidAttackSurfaceRootError(
            "Technology detection root is not a valid filesystem path"
        ) from exc
    if technology_root != resolved_root:
        raise InvalidAttackSurfaceRootError(
            "Technology detection root does not match the repository root"
        )

    max_size = (
        settings.attack_surface_source_max_size_bytes
        if max_source_file_size_bytes is None
        else max_source_file_size_bytes
    )
    max_files = (
        settings.attack_surface_max_source_files if max_source_files is None else max_source_files
    )
    if max_size < 0 or max_files < 0:
        raise AttackSurfaceError("Source inspection limits must not be negative")

    hints = _framework_hints(technologies)
    issues = _discovery_source_issues(inventory)
    routes: list[RouteCandidate] = []
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
            routes.extend(_extract_python_file_routes(text, relative_path, issues, hints))
        elif extension in _JAVASCRIPT_EXTENSIONS:
            routes.extend(_extract_javascript_routes(text, relative_path, issues, hints))

    deduped_routes = _dedupe_routes(routes)
    sorted_routes = sorted(
        deduped_routes,
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.path,
            item.http_method.value,
            item.framework.value,
            item.handler_name or "",
            item.resolution_status.value,
        ),
    )
    sorted_issues = sorted(
        _dedupe_issues(issues),
        key=lambda item: (item.source_file, item.reason.value, item.detail or ""),
    )

    resolved_count = sum(
        route.resolution_status is RouteResolutionStatus.RESOLVED for route in sorted_routes
    )
    unresolved_count = sum(
        route.resolution_status is RouteResolutionStatus.UNRESOLVED for route in sorted_routes
    )

    summary = AttackSurfaceSummary(
        source_files_inspected=inspected,
        route_count=len(sorted_routes),
        resolved_route_count=resolved_count,
        unresolved_route_count=unresolved_count,
        issue_count=len(sorted_issues),
        is_complete=inventory.summary.is_complete and not sorted_issues,
        discovery_is_complete=inventory.summary.is_complete,
        discovery_truncation_reasons=list(inventory.summary.truncation_reasons),
    )

    return AttackSurfaceResult(
        root=str(resolved_root),
        routes=sorted_routes,
        issues=sorted_issues,
        summary=summary,
    )
