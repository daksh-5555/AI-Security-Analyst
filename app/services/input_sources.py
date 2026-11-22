"""Deterministic, read-only extraction of external input sources and parameters.

The analyzer consumes a :class:`RepositoryDiscoveryResult`, a
:class:`TechnologyDetectionResult`, and an :class:`AttackSurfaceResult`. It
inspects only source files already present in the discovery inventory and never
executes or imports repository code, never runs Git, shell commands, or
subprocesses, and never makes network requests.

The output is evidence of *declared or accessed* inputs. A candidate does not
prove that a value reaches a sink, that validation is absent, or that a
vulnerability exists. Request values, credentials, tokens, cookie values, and
header values are never recorded; only statically readable names and access
expressions are retained.

Python files are parsed with :mod:`ast`. JavaScript and TypeScript files reuse
the scoped token scanner from the attack-surface phase. Only deterministic
framework declarations and statically readable property names are classified.
Dynamic expressions and unsupported syntax become structured issues rather than
guesses.

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
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
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
from app.schemas.input_sources import (
    InputCandidate,
    InputResolutionStatus,
    InputSourceResult,
    InputSourceSummary,
    InputType,
)
from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.technology import TechnologyDetectionResult
from app.services.attack_surface import (
    _FASTAPI_METHODS,
    _JAVASCRIPT_EXTENSIONS,
    _PYTHON_EXTENSIONS,
    InvalidAttackSurfaceRootError,
    _call_name,
    _collect_arguments,
    _collect_imported_frameworks,
    _collect_js_bindings,
    _collect_module_constants,
    _collect_receivers,
    _discovery_source_issues,
    _django_path_aliases,
    _evaluate_js_string,
    _extension,
    _framework_hints,
    _has_excluded_component,
    _has_nestjs_markers,
    _is_django_qualified_call,
    _is_django_url_config,
    _is_punct,
    _is_sensitive_path,
    _js_handler_name,
    _JsLexError,
    _JsToken,
    _lex_javascript,
    _punct,
    _python_expression_text,
    _python_string,
    _read_source_text,
    _resolve_root,
    _source_candidates,
    _statement_end,
    _tokens_to_text,
    _validate_source_path,
)

_PYTHON_LITERAL_CONFIDENCE: Final[float] = 0.90
_PYTHON_DECLARATION_CONFIDENCE: Final[float] = 0.95
_PYTHON_ANNOTATION_CONFIDENCE: Final[float] = 0.85
_JAVASCRIPT_ACCESS_CONFIDENCE: Final[float] = 0.85
_JAVASCRIPT_DECORATOR_CONFIDENCE: Final[float] = 0.95

_FASTAPI_DECLARATIONS: Final[dict[str, InputType]] = {
    "Path": InputType.PATH,
    "Query": InputType.QUERY,
    "Header": InputType.HEADER,
    "Cookie": InputType.COOKIE,
    "Body": InputType.BODY,
    "Form": InputType.FORM,
    "File": InputType.FILE,
}
_FASTAPI_ANNOTATIONS: Final[dict[str, InputType]] = {
    "UploadFile": InputType.FILE,
    "Request": InputType.REQUEST_OBJECT,
}
_FASTAPI_REQUEST_ACCESS: Final[dict[str, InputType]] = {
    "query_params": InputType.QUERY,
    "path_params": InputType.PATH,
    "headers": InputType.HEADER,
    "cookies": InputType.COOKIE,
}
_FASTAPI_REQUEST_CALLS: Final[dict[str, InputType]] = {
    "json": InputType.BODY,
    "form": InputType.FORM,
    "body": InputType.BODY,
    "stream": InputType.BODY,
}

_FLASK_REQUEST_ACCESS: Final[dict[str, InputType]] = {
    "args": InputType.QUERY,
    "form": InputType.FORM,
    "json": InputType.BODY,
    "files": InputType.FILE,
    "values": InputType.OTHER,
    "headers": InputType.HEADER,
    "cookies": InputType.COOKIE,
    "data": InputType.BODY,
}
_FLASK_REQUEST_CALLS: Final[dict[str, InputType]] = {
    "get_json": InputType.BODY,
    "get_data": InputType.BODY,
}

_DJANGO_REQUEST_ACCESS: Final[dict[str, InputType]] = {
    "GET": InputType.QUERY,
    "POST": InputType.FORM,
    "FILES": InputType.FILE,
    "body": InputType.BODY,
    "headers": InputType.HEADER,
    "COOKIES": InputType.COOKIE,
}

_EXPRESS_ACCESS: Final[dict[str, InputType]] = {
    "params": InputType.PATH,
    "query": InputType.QUERY,
    "body": InputType.BODY,
    "headers": InputType.HEADER,
    "cookies": InputType.COOKIE,
    "files": InputType.FILE,
}
_EXPRESS_METHOD_NAMES: Final[frozenset[str]] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "trace", "all"}
)
_EXPRESS_REQUEST_NAMES: Final[frozenset[str]] = frozenset({"req", "request"})

_NESTJS_PARAM_DECORATORS: Final[dict[str, InputType]] = {
    "param": InputType.PATH,
    "query": InputType.QUERY,
    "body": InputType.BODY,
    "headers": InputType.HEADER,
    "req": InputType.REQUEST_OBJECT,
    "uploadedfile": InputType.FILE,
    "uploadedfiles": InputType.FILE,
}
_NESTJS_REQUEST_ACCESS: Final[dict[str, InputType]] = {
    **_EXPRESS_ACCESS,
}

_PYTHON_MAPPING_METHODS: Final[frozenset[str]] = frozenset({"get", "getlist", "getall"})
_JS_PARAMETER_MODIFIERS: Final[frozenset[str]] = frozenset(
    {"public", "private", "protected", "readonly", "override"}
)
_JS_OBJECT_PATTERN_SKIP: Final[frozenset[str]] = frozenset({"..."})


class InputSourceAnalysisError(ValueError):
    """Base error for input source analysis operations."""


class InvalidInputSourceRootError(InputSourceAnalysisError):
    """Raised when an analysis root is not a safe, existing directory."""


@dataclass
class _InputDraft:
    """An input candidate before routes are associated and Pydantic-validated."""

    input_type: InputType
    framework: RouteFramework
    source_file: str
    line_number: int
    declaration_or_access: str
    detection_confidence: float
    evidence: str
    classification_rule: str
    parameter_name: str | None = None
    variable_name: str | None = None
    handler_name: str | None = None
    route_positions: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    django_class_name: str | None = None
    unresolved_syntax: bool = False


def _issue(
    source_file: str,
    reason: AnalysisIssueReason,
    detail: str | None = None,
) -> AnalysisIssue:
    return AnalysisIssue(source_file=source_file, reason=reason, detail=detail)


def _resolve_input_root(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: object,
) -> Path:
    try:
        resolved_root = _resolve_root(root, inventory)
    except InvalidAttackSurfaceRootError as exc:
        raise InvalidInputSourceRootError(str(exc)) from exc

    for label, value in (
        ("Technology detection", getattr(technologies, "root", None)),
        ("Attack surface", getattr(attack_surface, "root", None)),
    ):
        try:
            other_root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidInputSourceRootError(
                f"{label} root is not a valid filesystem path"
            ) from exc
        if other_root != resolved_root:
            raise InvalidInputSourceRootError(f"{label} root does not match the repository root")
    return resolved_root


def _python_key(node: ast.expr | None, constants: dict[str, str]) -> tuple[str | None, bool]:
    if node is None:
        return None, False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, True
    if isinstance(node, ast.Name):
        value = constants.get(node.id)
        if value is not None:
            return value, True
    return None, False


def _source_info(
    node: ast.expr,
    request_names: frozenset[str],
    access_map: dict[str, InputType],
    call_map: dict[str, InputType],
) -> tuple[InputType, str] | None:
    if isinstance(node, ast.Attribute):
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in request_names
            and node.attr in access_map
        ):
            return access_map[node.attr], f"{node.value.id}.{node.attr}"
    elif isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in request_names
            and node.func.attr in call_map
        ):
            return call_map[node.func.attr], f"{node.func.value.id}.{node.func.attr}()"
    return None


def _function_arguments(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.arg, ast.expr | None]]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = node.args.defaults
    offset = len(positional) - len(defaults)
    arguments: list[tuple[ast.arg, ast.expr | None]] = []
    for index, argument in enumerate(positional):
        default = defaults[index - offset] if index >= offset else None
        arguments.append((argument, default))
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=False):
        arguments.append((argument, default))
    return arguments


def _annotation_input_source(annotation: ast.expr | None) -> tuple[InputType, str] | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Name) and annotation.id in _FASTAPI_ANNOTATIONS:
        return _FASTAPI_ANNOTATIONS[annotation.id], annotation.id
    if isinstance(annotation, ast.Attribute) and annotation.attr in _FASTAPI_ANNOTATIONS:
        return _FASTAPI_ANNOTATIONS[annotation.attr], annotation.attr
    if isinstance(annotation, ast.Call):
        name = _call_name(annotation.func)
        if name in _FASTAPI_DECLARATIONS:
            return _FASTAPI_DECLARATIONS[name], f"{name}(...)"
        if name in _FASTAPI_ANNOTATIONS:
            return _FASTAPI_ANNOTATIONS[name], name
    return None


def _annotated_input_source(annotation: ast.expr | None) -> tuple[InputType, str] | None:
    if not isinstance(annotation, ast.Subscript):
        return None
    if not isinstance(annotation.value, ast.Name) or annotation.value.id != "Annotated":
        return None
    elements = (
        annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
    )
    for element in elements:
        source = _annotation_input_source(element)
        if source is not None:
            input_type, mechanism = source
            return input_type, f"Annotated[..., {mechanism}]"
    return None


def _fastapi_parameter_source(
    argument: ast.arg,
    default: ast.expr | None,
) -> tuple[InputType, str, float] | None:
    if isinstance(default, ast.Call):
        name = _call_name(default.func)
        if name in _FASTAPI_DECLARATIONS:
            return (
                _FASTAPI_DECLARATIONS[name],
                f"{name}(...)",
                _PYTHON_DECLARATION_CONFIDENCE,
            )
    annotated = _annotated_input_source(argument.annotation)
    if annotated is not None:
        return annotated[0], annotated[1], _PYTHON_ANNOTATION_CONFIDENCE
    annotation = _annotation_input_source(argument.annotation)
    if annotation is not None:
        return annotation[0], annotation[1], _PYTHON_ANNOTATION_CONFIDENCE
    return None


def _fastapi_route_functions(
    tree: ast.Module,
    constants: dict[str, str],
    imported: frozenset[RouteFramework],
    hints: frozenset[str],
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    receivers = _collect_receivers(tree, constants)
    inferred = (RouteFramework.FASTAPI in imported and RouteFramework.FLASK not in imported) or (
        "fastapi" in hints and "flask" not in hints
    )

    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    seen: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or id(node) in seen:
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            receiver = decorator.func.value
            if not isinstance(receiver, ast.Name):
                continue
            receiver_info = receivers.get(receiver.id)
            if receiver_info is not None:
                if receiver_info.framework is not RouteFramework.FASTAPI:
                    continue
            elif not inferred:
                continue
            if decorator.func.attr.casefold() not in _FASTAPI_METHODS:
                continue
            functions.append(node)
            seen.add(id(node))
            break
    return functions


class _PythonAccessVisitor(ast.NodeVisitor):
    """Collect request-object accesses from one Python function body."""

    def __init__(
        self,
        *,
        source_file: str,
        framework: RouteFramework,
        request_names: frozenset[str],
        access_map: dict[str, InputType],
        call_map: dict[str, InputType],
        constants: dict[str, str],
        handler_name: str | None,
        django_class_name: str | None,
        issues: list[AnalysisIssue],
    ) -> None:
        self.source_file = source_file
        self.framework = framework
        self.request_names = request_names
        self.access_map = access_map
        self.call_map = call_map
        self.constants = constants
        self.handler_name = handler_name
        self.django_class_name = django_class_name
        self.issues = issues
        self.drafts: list[_InputDraft] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def _add(
        self,
        *,
        input_type: InputType,
        node: ast.AST,
        declaration: str,
        parameter_name: str | None,
        variable_name: str | None,
        confidence: float,
        rule: str,
        unresolved_syntax: bool = False,
    ) -> None:
        self.drafts.append(
            _InputDraft(
                input_type=input_type,
                framework=self.framework,
                source_file=self.source_file,
                line_number=getattr(node, "lineno", 1),
                declaration_or_access=declaration,
                detection_confidence=confidence,
                evidence=(
                    f"Access '{declaration}' reads a {input_type.value} input"
                    + (
                        f" in handler '{self.handler_name}'."
                        if self.handler_name is not None
                        else "."
                    )
                ),
                classification_rule=rule,
                parameter_name=parameter_name,
                variable_name=variable_name,
                handler_name=self.handler_name,
                django_class_name=self.django_class_name,
                unresolved_syntax=unresolved_syntax,
            )
        )

    def _dynamic_issue(self, node: ast.AST, expression: ast.expr | None) -> None:
        detail = "Dynamic input key could not be resolved statically"
        if expression is not None:
            detail = (
                f"Dynamic input key '{_python_expression_text(expression)}' could not "
                "be resolved statically"
            )
        self.issues.append(
            _issue(
                self.source_file,
                AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                detail,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.request_names
                and node.func.attr in self.call_map
            ):
                input_type = self.call_map[node.func.attr]
                display = f"{node.func.value.id}.{node.func.attr}()"
                self._add(
                    input_type=input_type,
                    node=node,
                    declaration=display,
                    parameter_name=None,
                    variable_name=None,
                    confidence=_PYTHON_LITERAL_CONFIDENCE,
                    rule=(
                        "Recognized request-object call that returns an external input. "
                        "Only the access is recorded; runtime values are never retained."
                    ),
                )
                return

            if node.func.attr in _PYTHON_MAPPING_METHODS:
                base = _source_info(
                    node.func.value,
                    self.request_names,
                    self.access_map,
                    self.call_map,
                )
                if base is not None:
                    input_type, display = base
                    key, resolved = _python_key(node.args[0] if node.args else None, self.constants)
                    if key is not None and resolved:
                        parameter_name: str | None = key
                        declaration = f"{display}.{node.func.attr}({key!r})"
                    else:
                        parameter_name = None
                        declaration = f"{display}.{node.func.attr}(<dynamic>)"
                        if node.args:
                            self._dynamic_issue(node, node.args[0])
                    self._add(
                        input_type=input_type,
                        node=node,
                        declaration=declaration,
                        parameter_name=parameter_name,
                        variable_name=None,
                        confidence=_PYTHON_LITERAL_CONFIDENCE,
                        rule=(
                            "Recognized request mapping access. The parameter name is "
                            "recorded only when it is a static string or module constant."
                        ),
                        unresolved_syntax=parameter_name is None,
                    )
                    for argument in node.args[1:]:
                        self.visit(argument)
                    for keyword in node.keywords:
                        self.visit(keyword.value)
                    return
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        base = _source_info(node.value, self.request_names, self.access_map, self.call_map)
        if base is not None:
            input_type, display = base
            key, resolved = _python_key(node.slice, self.constants)
            if key is not None and resolved:
                parameter_name: str | None = key
                declaration = f"{display}[{key!r}]"
            else:
                parameter_name = None
                declaration = f"{display}[<dynamic>]"
                self._dynamic_issue(node, node.slice)
            self._add(
                input_type=input_type,
                node=node,
                declaration=declaration,
                parameter_name=parameter_name,
                variable_name=None,
                confidence=_PYTHON_LITERAL_CONFIDENCE,
                rule=(
                    "Recognized indexed request mapping access. The parameter name is "
                    "recorded only when it is a static string or module constant."
                ),
                unresolved_syntax=parameter_name is None,
            )
            self.visit(node.slice)
            return
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        direct = _source_info(node, self.request_names, self.access_map, self.call_map)
        if direct is not None:
            input_type, display = direct
            self._add(
                input_type=input_type,
                node=node,
                declaration=display,
                parameter_name=None,
                variable_name=None,
                confidence=_JAVASCRIPT_ACCESS_CONFIDENCE,
                rule=(
                    "Recognized request-object attribute that exposes an external input "
                    "mapping or raw value."
                ),
            )
            return
        self.generic_visit(node)


def _python_class_names(tree: ast.Module) -> dict[int, str]:
    class_names: dict[int, str] = {}

    def visit(node: ast.AST, current: str | None) -> None:
        if isinstance(node, ast.ClassDef):
            current = node.name
        for child in ast.iter_child_nodes(node):
            if current is not None:
                class_names[id(child)] = current
            visit(child, current)

    visit(tree, None)
    return class_names


def _visit_function_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    visitor: _PythonAccessVisitor,
) -> list[_InputDraft]:
    for statement in node.body:
        visitor.visit(statement)
    return visitor.drafts


def _fastapi_input_drafts(
    tree: ast.Module,
    relative_path: str,
    constants: dict[str, str],
    imported: frozenset[RouteFramework],
    hints: frozenset[str],
    issues: list[AnalysisIssue],
) -> list[_InputDraft]:
    drafts: list[_InputDraft] = []
    for node in _fastapi_route_functions(tree, constants, imported, hints):
        request_names: set[str] = set()
        for argument, default in _function_arguments(node):
            source = _fastapi_parameter_source(argument, default)
            if source is None:
                continue
            input_type, mechanism, confidence = source
            parameter_name = None if input_type is InputType.REQUEST_OBJECT else argument.arg
            if input_type is InputType.REQUEST_OBJECT:
                request_names.add(argument.arg)
            declaration = f"{argument.arg}: {mechanism}"
            drafts.append(
                _InputDraft(
                    input_type=input_type,
                    framework=RouteFramework.FASTAPI,
                    source_file=relative_path,
                    line_number=(
                        default.lineno
                        if default is not None
                        else argument.annotation.lineno
                        if argument.annotation is not None
                        else node.lineno
                    ),
                    declaration_or_access=declaration,
                    detection_confidence=confidence,
                    evidence=(
                        f"FastAPI endpoint '{node.name}' declares parameter "
                        f"'{argument.arg}' as a {input_type.value} input via {mechanism}."
                    ),
                    classification_rule=(
                        "Recognized FastAPI parameter declaration. The declaration is "
                        "evidence of an input source, not proof of vulnerability or "
                        "missing validation."
                    ),
                    parameter_name=parameter_name,
                    variable_name=argument.arg,
                    handler_name=node.name,
                )
            )

        if request_names:
            visitor = _PythonAccessVisitor(
                source_file=relative_path,
                framework=RouteFramework.FASTAPI,
                request_names=frozenset(request_names),
                access_map=_FASTAPI_REQUEST_ACCESS,
                call_map=_FASTAPI_REQUEST_CALLS,
                constants=constants,
                handler_name=node.name,
                django_class_name=None,
                issues=issues,
            )
            drafts.extend(_visit_function_body(node, visitor))
    return drafts


def _request_access_drafts(
    tree: ast.Module,
    relative_path: str,
    framework: RouteFramework,
    access_map: dict[str, InputType],
    call_map: dict[str, InputType],
    constants: dict[str, str],
    class_names: dict[int, str],
    issues: list[AnalysisIssue],
) -> list[_InputDraft]:
    drafts: list[_InputDraft] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        visitor = _PythonAccessVisitor(
            source_file=relative_path,
            framework=framework,
            request_names=frozenset({"request"}),
            access_map=access_map,
            call_map=call_map,
            constants=constants,
            handler_name=node.name,
            django_class_name=(
                class_names.get(id(node)) if framework is RouteFramework.DJANGO else None
            ),
            issues=issues,
        )
        drafts.extend(_visit_function_body(node, visitor))
    return drafts


def _django_handler_class_name(node: ast.expr) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "as_view":
        return None
    value = node.func.value
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        return value.attr
    return None


def _django_class_route_paths(
    tree: ast.Module,
    relative_path: str,
    constants: dict[str, str],
) -> dict[str, set[str]]:
    if not _is_django_url_config(tree, relative_path):
        return {}

    aliases = _django_path_aliases(tree)
    is_urls_file = PurePosixPath(relative_path.replace("\\", "/")).name.casefold() == "urls.py"
    paths: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = _call_name(node.func)
        if function_name not in {"path", "re_path"}:
            continue
        if not (function_name in aliases or _is_django_qualified_call(node.func) or is_urls_file):
            continue
        if len(node.args) < 2:
            continue
        path_value, resolved = _python_string(node.args[0], constants)
        if not resolved or path_value is None:
            continue
        class_name = _django_handler_class_name(node.args[1])
        if class_name is None:
            continue
        paths.setdefault(class_name, set()).add(path_value or "/")
    return paths


def _extract_python_inputs(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> tuple[list[_InputDraft], dict[str, set[str]]]:
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

    constants = _collect_module_constants(tree)
    imported = _collect_imported_frameworks(tree)
    class_names = _python_class_names(tree)
    drafts: list[_InputDraft] = []
    django_class_paths: dict[str, set[str]] = {}

    if RouteFramework.FASTAPI in imported or "fastapi" in hints:
        drafts.extend(
            _fastapi_input_drafts(tree, relative_path, constants, imported, hints, issues)
        )
    if RouteFramework.FLASK in imported or "flask" in hints:
        drafts.extend(
            _request_access_drafts(
                tree,
                relative_path,
                RouteFramework.FLASK,
                _FLASK_REQUEST_ACCESS,
                _FLASK_REQUEST_CALLS,
                constants,
                class_names,
                issues,
            )
        )
    if RouteFramework.DJANGO in imported or "django" in hints:
        drafts.extend(
            _request_access_drafts(
                tree,
                relative_path,
                RouteFramework.DJANGO,
                _DJANGO_REQUEST_ACCESS,
                {},
                constants,
                class_names,
                issues,
            )
        )
        django_class_paths = _django_class_route_paths(tree, relative_path, constants)

    return drafts, django_class_paths


def _matching_delimiter(
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


def _split_object_items(
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


def _js_source_info(
    tokens: list[_JsToken],
    start: int,
    request_names: frozenset[str],
) -> tuple[InputType, str, int] | None:
    if start >= len(tokens):
        return None
    token = tokens[start]
    if token.kind != "identifier" or token.value not in request_names:
        return None
    if not _is_punct(tokens, start + 1, "."):
        return None
    if start + 2 >= len(tokens) or tokens[start + 2].kind != "identifier":
        return None
    member = tokens[start + 2].value
    input_type = _EXPRESS_ACCESS.get(member)
    if input_type is None:
        return None
    return input_type, f"{token.value}.{member}", start + 3


def _js_assignment_variable(tokens: list[_JsToken], index: int) -> str | None:
    if index < 3:
        return None
    if not _is_punct(tokens, index - 1, "=") or tokens[index - 2].kind != "identifier":
        return None
    declaration = tokens[index - 3]
    if declaration.kind == "identifier" and declaration.value in {"const", "let", "var"}:
        return tokens[index - 2].value
    return None


def _js_dynamic_issue(
    source_file: str,
    issues: list[AnalysisIssue],
    framework: RouteFramework,
    expression: str,
) -> None:
    issues.append(
        _issue(
            source_file,
            AnalysisIssueReason.UNSUPPORTED_SYNTAX,
            f"Dynamic {framework.value} input key '{expression}' could not be resolved statically",
        )
    )


def _destructured_drafts(
    tokens: list[_JsToken],
    start: int,
    *,
    source_file: str,
    framework: RouteFramework,
    handler_name: str | None,
    route_positions: frozenset[tuple[str, int]],
    issues: list[AnalysisIssue],
    request_names: frozenset[str],
) -> tuple[list[_InputDraft], int] | None:
    if start + 1 >= len(tokens) or not _punct(tokens[start + 1], "{"):
        return None
    close = _matching_delimiter(tokens, start + 1, "{", "}")
    if close is None or not _is_punct(tokens, close + 1, "="):
        return None
    source = _js_source_info(tokens, close + 2, request_names)
    if source is None:
        return None
    input_type, source_display, end = source
    drafts: list[_InputDraft] = []
    for item in _split_object_items(tokens, start + 1, close):
        if not item or item[0].kind not in {"identifier", "string"}:
            continue
        if item[0].kind == "identifier" and item[0].value in _JS_OBJECT_PATTERN_SKIP:
            continue
        key = item[0].value
        variable = key if item[0].kind == "identifier" else None
        if len(item) >= 3 and _punct(item[1], ":") and item[2].kind in {"identifier", "string"}:
            variable = item[2].value
        elif len(item) >= 2 and _punct(item[1], "="):
            variable = key if item[0].kind == "identifier" else None
        elif len(item) >= 2 and _punct(item[1], ":"):
            continue
        drafts.append(
            _InputDraft(
                input_type=input_type,
                framework=framework,
                source_file=source_file,
                line_number=tokens[start].line,
                declaration_or_access=f"const {{{key}}} = {source_display}",
                detection_confidence=_JAVASCRIPT_ACCESS_CONFIDENCE,
                evidence=(
                    f"Destructuring from '{source_display}' reads a {input_type.value} "
                    "input" + (f" in handler '{handler_name}'." if handler_name else ".")
                ),
                classification_rule=(
                    "Recognized JavaScript or TypeScript request destructuring. Only the "
                    "static property name and local variable are recorded."
                ),
                parameter_name=key,
                variable_name=variable,
                handler_name=handler_name,
                route_positions=route_positions,
            )
        )
    return drafts, end


def _scan_js_request_accesses(
    tokens: list[_JsToken],
    *,
    source_file: str,
    framework: RouteFramework,
    access_map: dict[str, InputType],
    handler_name: str | None,
    route_positions: frozenset[tuple[str, int]],
    issues: list[AnalysisIssue],
    request_names: frozenset[str] = _EXPRESS_REQUEST_NAMES,
) -> list[_InputDraft]:
    drafts: list[_InputDraft] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "identifier" and token.value in {"const", "let", "var"}:
            destructured = _destructured_drafts(
                tokens,
                index,
                source_file=source_file,
                framework=framework,
                handler_name=handler_name,
                route_positions=route_positions,
                issues=issues,
                request_names=request_names,
            )
            if destructured is not None:
                destructured_drafts, end = destructured
                drafts.extend(destructured_drafts)
                index = end
                continue

        if token.kind != "identifier" or token.value not in request_names:
            index += 1
            continue
        if not _is_punct(tokens, index + 1, "."):
            index += 1
            continue
        if index + 2 >= len(tokens) or tokens[index + 2].kind != "identifier":
            index += 1
            continue

        member = tokens[index + 2].value
        if member == "get" and _is_punct(tokens, index + 3, "("):
            try:
                arguments, close = _collect_arguments(tokens, index + 3)
            except _JsLexError:
                index += 1
                continue
            key: str | None = None
            dynamic = False
            if arguments:
                key, resolved = _evaluate_js_string(arguments[0])
                if not resolved or key is None:
                    dynamic = True
                    _js_dynamic_issue(
                        source_file,
                        issues,
                        framework,
                        _tokens_to_text(arguments[0]),
                    )
            declaration = (
                f"{token.value}.get({key!r})"
                if key is not None
                else f"{token.value}.get(<dynamic>)"
            )
            drafts.append(
                _InputDraft(
                    input_type=InputType.HEADER,
                    framework=framework,
                    source_file=source_file,
                    line_number=token.line,
                    declaration_or_access=declaration,
                    detection_confidence=_JAVASCRIPT_ACCESS_CONFIDENCE,
                    evidence=(
                        f"Request header access '{declaration}' reads a header input"
                        + (f" in handler '{handler_name}'." if handler_name else ".")
                    ),
                    classification_rule=(
                        "Recognized Express-style req.get header access. The header name is "
                        "recorded only when it is a static string."
                    ),
                    parameter_name=key,
                    variable_name=_js_assignment_variable(tokens, index),
                    handler_name=handler_name,
                    route_positions=route_positions,
                    unresolved_syntax=dynamic,
                )
            )
            index = close + 1
            continue

        input_type = access_map.get(member)
        if input_type is None:
            index += 1
            continue

        property_name: str | None = None
        property_bracket = False
        dynamic = False
        end = index + 3
        if _is_punct(tokens, index + 3, ".") and index + 4 < len(tokens):
            if tokens[index + 4].kind == "identifier":
                property_name = tokens[index + 4].value
                end = index + 5
                if _is_punct(tokens, end, "("):
                    property_name = None
                    dynamic = False
                    end = index + 3
        elif _is_punct(tokens, index + 3, "["):
            if index + 4 < len(tokens):
                key_token = tokens[index + 4]
                if key_token.kind == "string" and _is_punct(tokens, index + 5, "]"):
                    property_name = key_token.value
                    property_bracket = True
                    end = index + 6
                else:
                    dynamic = True
                    _js_dynamic_issue(
                        source_file,
                        issues,
                        framework,
                        _tokens_to_text(tokens[index + 4 : index + 6]),
                    )
                    end = index + 4
            else:
                end = index + 4

        declaration = f"{token.value}.{member}"
        if property_name is not None:
            declaration += f"[{property_name!r}]" if property_bracket else f".{property_name}"
        elif dynamic:
            declaration += "[<dynamic>]"
        variable_name = _js_assignment_variable(tokens, index)
        drafts.append(
            _InputDraft(
                input_type=input_type,
                framework=framework,
                source_file=source_file,
                line_number=token.line,
                declaration_or_access=declaration,
                detection_confidence=_JAVASCRIPT_ACCESS_CONFIDENCE,
                evidence=(
                    f"Request access '{declaration}' reads a {input_type.value} input"
                    + (f" in handler '{handler_name}'." if handler_name else ".")
                ),
                classification_rule=(
                    "Recognized request property access. Only the statically readable "
                    "property name and local variable are recorded."
                ),
                parameter_name=property_name,
                variable_name=variable_name,
                handler_name=handler_name,
                route_positions=route_positions,
                unresolved_syntax=dynamic,
            )
        )
        index = end
    return drafts


def _js_function_body(
    tokens: list[_JsToken],
    open_paren: int,
) -> tuple[list[_JsToken], int] | None:
    try:
        _, close = _collect_arguments(tokens, open_paren)
    except _JsLexError:
        return None
    cursor = close + 1
    while cursor < len(tokens) and not _punct(tokens[cursor], "{"):
        if _punct(tokens[cursor], ";"):
            return None
        cursor += 1
    if cursor >= len(tokens):
        return None
    body_close = _matching_delimiter(tokens, cursor, "{", "}")
    if body_close is None:
        return None
    return tokens[cursor + 1 : body_close], body_close


def _js_named_function_bodies(tokens: list[_JsToken]) -> list[tuple[str, list[_JsToken]]]:
    bodies: list[tuple[str, list[_JsToken]]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "identifier" and token.value == "function":
            name_index = index + 1
            if (
                name_index + 1 < len(tokens)
                and tokens[name_index].kind == "identifier"
                and _is_punct(tokens, name_index + 1, "(")
            ):
                body = _js_function_body(tokens, name_index + 1)
                if body is not None:
                    bodies.append((tokens[name_index].value, body[0]))
                    index = body[1] + 1
                    continue
        elif (
            token.kind == "identifier"
            and token.value in {"const", "let", "var"}
            and index + 2 < len(tokens)
            and tokens[index + 1].kind == "identifier"
            and _is_punct(tokens, index + 2, "=")
        ):
            name = tokens[index + 1].value
            cursor = index + 3
            if cursor < len(tokens) and tokens[cursor].kind == "identifier":
                if tokens[cursor].value == "function":
                    cursor += 1
                    if cursor < len(tokens) and tokens[cursor].kind == "identifier":
                        cursor += 1
                elif tokens[cursor].value != "async":
                    cursor += 1
            if cursor < len(tokens) and tokens[cursor].kind == "identifier":
                if tokens[cursor].value == "async":
                    cursor += 1
            if _is_punct(tokens, cursor, "("):
                body = _js_function_body(tokens, cursor)
                if body is not None:
                    bodies.append((name, body[0]))
                    index = body[1] + 1
                    continue
                try:
                    _, close = _collect_arguments(tokens, cursor)
                except _JsLexError:
                    index += 1
                    continue
                arrow = close + 1
                if _is_punct(tokens, arrow, "=>"):
                    if _is_punct(tokens, arrow + 1, "{"):
                        body_close = _matching_delimiter(tokens, arrow + 1, "{", "}")
                        if body_close is not None:
                            bodies.append((name, tokens[arrow + 2 : body_close]))
                            index = body_close + 1
                            continue
                    else:
                        end = _statement_end(tokens, arrow + 1)
                        bodies.append((name, tokens[arrow + 1 : end]))
                        index = end + 1
                        continue
        index += 1
    return bodies


def _express_input_drafts(
    tokens: list[_JsToken],
    relative_path: str,
    hints: frozenset[str],
    issues: list[AnalysisIssue],
) -> list[_InputDraft]:
    app_vars, router_vars, express_present = _collect_js_bindings(tokens)
    if not express_present and "express" not in hints:
        return []

    known_receivers = (
        set(app_vars)
        | set(router_vars)
        | {
            "app",
            "server",
            "api",
            "router",
            "routes",
        }
    )
    drafts: list[_InputDraft] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token.kind == "identifier"
            and token.value in known_receivers
            and _is_punct(tokens, index + 1, ".")
            and index + 2 < len(tokens)
            and tokens[index + 2].kind == "identifier"
            and _is_punct(tokens, index + 3, "(")
        ):
            method_name = tokens[index + 2].value.casefold()
            if method_name in _EXPRESS_METHOD_NAMES:
                try:
                    arguments, close = _collect_arguments(tokens, index + 3)
                except _JsLexError:
                    index += 1
                    continue
                if len(arguments) >= 2:
                    handler_name = _js_handler_name(arguments[-1])
                    route_positions = frozenset({(relative_path, token.line)})
                    for argument in arguments[1:]:
                        drafts.extend(
                            _scan_js_request_accesses(
                                argument,
                                source_file=relative_path,
                                framework=RouteFramework.EXPRESS,
                                access_map=_EXPRESS_ACCESS,
                                handler_name=handler_name,
                                route_positions=route_positions,
                                issues=issues,
                            )
                        )
                index = close + 1
                continue
        index += 1

    for name, body in _js_named_function_bodies(tokens):
        drafts.extend(
            _scan_js_request_accesses(
                body,
                source_file=relative_path,
                framework=RouteFramework.EXPRESS,
                access_map=_EXPRESS_ACCESS,
                handler_name=name,
                route_positions=frozenset(),
                issues=issues,
                request_names=_EXPRESS_REQUEST_NAMES,
            )
        )
    return drafts


def _nestjs_method_ranges(
    tokens: list[_JsToken],
) -> list[tuple[str | None, str, int, int, int]]:
    ranges: list[tuple[str | None, str, int, int, int]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind != "identifier" or token.value != "class":
            index += 1
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            index += 1
            continue
        class_name = tokens[index + 1].value
        cursor = index + 2
        while cursor < len(tokens) and not _punct(tokens[cursor], "{"):
            cursor += 1
        if cursor >= len(tokens):
            break
        class_close = _matching_delimiter(tokens, cursor, "{", "}")
        if class_close is None:
            break

        scan = cursor + 1
        while scan < class_close:
            current = tokens[scan]
            if (
                current.kind == "identifier"
                and current.value not in {"constructor", "if", "for", "while", "switch", "catch"}
                and _is_punct(tokens, scan + 1, "(")
                and not (scan > 0 and _punct(tokens[scan - 1], "@"))
            ):
                try:
                    _, parameters_close = _collect_arguments(tokens, scan + 1)
                except _JsLexError:
                    scan += 1
                    continue
                after = parameters_close + 1
                while (
                    after < class_close
                    and not _punct(tokens[after], "{")
                    and not _punct(tokens[after], ";")
                ):
                    after += 1
                if after < class_close and _punct(tokens[after], "{"):
                    body_close = _matching_delimiter(tokens, after, "{", "}")
                    if body_close is not None:
                        ranges.append((class_name, current.value, scan, after, body_close))
                        scan = body_close + 1
                        continue
            scan += 1
        index = class_close + 1
    return ranges


def _nestjs_parameter_variable(tokens: list[_JsToken], start: int) -> str | None:
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "identifier":
            if token.value in _JS_PARAMETER_MODIFIERS:
                index += 1
                continue
            return token.value
        if token.kind == "punct" and token.value in {":", ",", ")", ";"}:
            return None
        index += 1
    return None


def _nestjs_input_drafts(
    tokens: list[_JsToken],
    relative_path: str,
    issues: list[AnalysisIssue],
) -> list[_InputDraft]:
    if not _has_nestjs_markers(tokens):
        return []

    ranges = _nestjs_method_ranges(tokens)
    drafts: list[_InputDraft] = []
    request_variables: dict[int, set[str]] = {}
    index = 0
    while index < len(tokens):
        if not _punct(tokens[index], "@") or index + 1 >= len(tokens):
            index += 1
            continue
        if tokens[index + 1].kind != "identifier":
            index += 1
            continue
        decorator_name = tokens[index + 1].value
        input_type = _NESTJS_PARAM_DECORATORS.get(decorator_name.casefold())
        if input_type is None:
            index += 1
            continue

        argument_start = index + 2
        arguments: list[list[_JsToken]] = []
        if _is_punct(tokens, argument_start, "("):
            try:
                arguments, close = _collect_arguments(tokens, argument_start)
            except _JsLexError as exc:
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.INVALID_SYNTAX,
                        (
                            "Unbalanced NestJS parameter decorator at line "
                            f"{tokens[index].line}: {exc}"
                        ),
                    )
                )
                index += 1
                continue
        else:
            close = index + 1

        containing = next(
            (item for item in ranges if item[2] <= index <= item[4]),
            None,
        )
        method_range = next(
            (offset for offset, item in enumerate(ranges) if item[2] <= index <= item[4]),
            None,
        )
        handler_name = containing[1] if containing is not None else None
        variable_name = _nestjs_parameter_variable(tokens, close + 1)

        parameter_name: str | None = None
        dynamic = False
        if arguments:
            value, resolved = _evaluate_js_string(arguments[0])
            if resolved and value is not None:
                parameter_name = value
            else:
                dynamic = True
                detail = f"NestJS {decorator_name} argument could not be resolved statically"
                if arguments[0] and _punct(arguments[0][0], "{"):
                    detail = f"NestJS {decorator_name} object arguments are not supported"
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                        detail,
                    )
                )

        declaration = f"@{decorator_name}"
        if parameter_name is not None:
            declaration += f"({parameter_name!r})"
        elif arguments:
            declaration += "(<dynamic>)"
        else:
            declaration += "()"
        drafts.append(
            _InputDraft(
                input_type=input_type,
                framework=RouteFramework.NESTJS,
                source_file=relative_path,
                line_number=tokens[index].line,
                declaration_or_access=declaration,
                detection_confidence=(
                    _JAVASCRIPT_DECORATOR_CONFIDENCE
                    if not dynamic
                    else _JAVASCRIPT_ACCESS_CONFIDENCE
                ),
                evidence=(
                    f"@NestJS {decorator_name} declares a {input_type.value} input"
                    + (f" on method '{handler_name}'." if handler_name else ".")
                ),
                classification_rule=(
                    "Recognized NestJS parameter decorator. The decorator is evidence of an "
                    "input declaration, not proof of vulnerability or missing validation."
                ),
                parameter_name=parameter_name,
                variable_name=variable_name,
                handler_name=handler_name,
                unresolved_syntax=dynamic,
            )
        )
        if input_type is InputType.REQUEST_OBJECT and variable_name is not None:
            if method_range is not None:
                request_variables.setdefault(method_range, set()).add(variable_name)
        index = close + 1

    for method_index, variables in request_variables.items():
        _, handler_name, _, body_open, body_close = ranges[method_index]
        drafts.extend(
            _scan_js_request_accesses(
                tokens[body_open + 1 : body_close],
                source_file=relative_path,
                framework=RouteFramework.NESTJS,
                access_map=_NESTJS_REQUEST_ACCESS,
                handler_name=handler_name,
                route_positions=frozenset(),
                issues=issues,
                request_names=frozenset(variables),
            )
        )
    return drafts


def _extract_javascript_inputs(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> list[_InputDraft]:
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

    drafts = _express_input_drafts(tokens, relative_path, hints, issues)
    drafts.extend(_nestjs_input_drafts(tokens, relative_path, issues))
    return drafts


def _associated_routes(
    draft: _InputDraft,
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
    if not matched and draft.handler_name:
        matched = [
            route
            for route in routes
            if route.handler_name == draft.handler_name
            and (route.source_file == draft.source_file or draft.framework is RouteFramework.DJANGO)
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
    draft: _InputDraft,
    routes: list[RouteCandidate],
    django_class_paths: dict[str, set[str]],
) -> InputCandidate:
    associated = _associated_routes(draft, routes, django_class_paths)
    unresolved = draft.unresolved_syntax or not associated
    if any(route.resolution_status is RouteResolutionStatus.UNRESOLVED for route in associated):
        unresolved = True

    return InputCandidate(
        input_type=draft.input_type,
        framework=draft.framework,
        source_file=draft.source_file,
        line_number=draft.line_number,
        parameter_name=draft.parameter_name,
        variable_name=draft.variable_name,
        handler_name=draft.handler_name,
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
            InputResolutionStatus.UNRESOLVED if unresolved else InputResolutionStatus.RESOLVED
        ),
        detection_confidence=draft.detection_confidence,
        evidence=draft.evidence,
        classification_rule=draft.classification_rule,
    )


def _candidate_sort_key(candidate: InputCandidate) -> tuple[object, ...]:
    return (
        candidate.source_file,
        candidate.line_number,
        candidate.input_type.value,
        candidate.framework.value,
        candidate.parameter_name or "",
        candidate.variable_name or "",
        candidate.handler_name or "",
        candidate.declaration_or_access,
    )


def _dedupe_inputs(inputs: list[InputCandidate]) -> list[InputCandidate]:
    unique: list[InputCandidate] = []
    seen: set[tuple[object, ...]] = set()
    for candidate in sorted(inputs, key=_candidate_sort_key):
        key = (
            candidate.source_file,
            candidate.line_number,
            candidate.input_type,
            candidate.framework,
            candidate.parameter_name,
            candidate.variable_name,
            candidate.handler_name,
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


def identify_input_sources(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: object,
    *,
    max_source_file_size_bytes: int | None = None,
    max_source_files: int | None = None,
) -> InputSourceResult:
    """Identify external input declarations and accesses.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match the discovery inventory, technology detection result, and attack
    surface result. Only Python and JavaScript/TypeScript files already present in
    the inventory are read. Repository code is never executed or imported.
    """
    resolved_root = _resolve_input_root(root, inventory, technologies, attack_surface)

    max_size = (
        settings.input_source_max_size_bytes
        if max_source_file_size_bytes is None
        else max_source_file_size_bytes
    )
    max_files = (
        settings.input_source_max_source_files if max_source_files is None else max_source_files
    )
    if max_size < 0 or max_files < 0:
        raise InputSourceAnalysisError("Source inspection limits must not be negative")

    routes = list(getattr(attack_surface, "routes", []))
    hints = _framework_hints(technologies)
    issues = _discovery_source_issues(inventory)
    drafts: list[_InputDraft] = []
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
            python_drafts, python_class_paths = _extract_python_inputs(
                text,
                relative_path,
                issues,
                hints,
            )
            drafts.extend(python_drafts)
            for class_name, class_paths in python_class_paths.items():
                django_class_paths.setdefault(class_name, set()).update(class_paths)
        elif extension in _JAVASCRIPT_EXTENSIONS:
            drafts.extend(_extract_javascript_inputs(text, relative_path, issues, hints))

    inputs = _dedupe_inputs(
        [_candidate_from_draft(draft, routes, django_class_paths) for draft in drafts]
    )
    sorted_issues = sorted(
        _dedupe_issues(issues),
        key=lambda item: (item.source_file, item.reason.value, item.detail or ""),
    )

    named_parameter_count = sum(1 for item in inputs if item.parameter_name is not None)
    route_association_count = sum(len(item.associated_routes) for item in inputs)
    unresolved_association_count = sum(
        item.resolution_status is InputResolutionStatus.UNRESOLVED for item in inputs
    )

    summary = InputSourceSummary(
        source_files_inspected=inspected,
        input_count=len(inputs),
        named_parameter_count=named_parameter_count,
        route_association_count=route_association_count,
        unresolved_association_count=unresolved_association_count,
        issue_count=len(sorted_issues),
        is_complete=inventory.summary.is_complete and not sorted_issues,
        discovery_is_complete=inventory.summary.is_complete,
        discovery_truncation_reasons=list(inventory.summary.truncation_reasons),
    )

    return InputSourceResult(
        root=str(resolved_root),
        inputs=inputs,
        issues=sorted_issues,
        summary=summary,
    )
