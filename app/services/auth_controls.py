"""Deterministic, read-only authentication and authorization declaration mapping.

The analyzer consumes a :class:`RepositoryDiscoveryResult`, a
:class:`TechnologyDetectionResult`, and an :class:`AttackSurfaceResult`. It
inspects only source files already present in the discovery inventory and never
executes or imports repository code, never runs Git, shell commands, or
subprocesses, and never makes network requests.

The output is evidence of *declared* controls. A candidate does not prove that a
control is enforced, that it covers every code path, or that an associated route
is secure. Routes without a detected candidate are deliberately not described as
unprotected.

Python files are parsed with :mod:`ast`. JavaScript and TypeScript files reuse
the scoped token scanner from the attack-surface phase. Only deterministic
framework declarations and recognizable naming conventions are classified.
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
import json
import re
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
from app.schemas.auth_controls import (
    AssociatedRoute,
    AuthControlCandidate,
    AuthControlResult,
    AuthControlSummary,
    ControlResolutionStatus,
    ControlScopeType,
    ControlType,
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
    _is_router_reference,
    _is_sensitive_path,
    _JsLexError,
    _JsToken,
    _keyword_expression,
    _lex_javascript,
    _next_js_method_name,
    _punct,
    _python_expression_text,
    _python_string,
    _read_source_text,
    _resolve_root,
    _source_candidates,
    _tokens_to_text,
    _validate_source_path,
)

_AUTHN_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "apikey",
        "auth",
        "authenticate",
        "authentication",
        "basic",
        "bearer",
        "credential",
        "credentials",
        "current",
        "identity",
        "jwt",
        "login",
        "logged",
        "oauth",
        "oauth2",
        "passport",
        "principal",
        "token",
        "user",
        "whoami",
    }
)
_AUTHZ_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "access",
        "acl",
        "admin",
        "authorization",
        "authorize",
        "authorized",
        "can",
        "forbidden",
        "grant",
        "granted",
        "owner",
        "ownership",
        "permission",
        "permissions",
        "perm",
        "policy",
        "policies",
        "privilege",
        "privileges",
        "role",
        "roles",
        "scope",
        "scopes",
        "staff",
        "superuser",
    }
)

_CAMEL_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|\d+")

_ROUTE_DECORATOR_NAMES: Final[frozenset[str]] = frozenset(
    set(_FASTAPI_METHODS) | {"route", "api_route"}
)

_FLASK_AUTHN_DECORATORS: Final[frozenset[str]] = frozenset(
    {
        "auth_required",
        "fresh_login_required",
        "jwt_required",
        "login_required",
        "requires_auth",
        "token_required",
    }
)
_FLASK_AUTHZ_DECORATORS: Final[frozenset[str]] = frozenset(
    {
        "admin_required",
        "permission_required",
        "permissions_required",
        "requires_permission",
        "requires_roles",
        "roles_accepted",
        "roles_allowed",
        "roles_required",
    }
)

_DJANGO_AUTHN_DECORATORS: Final[frozenset[str]] = frozenset({"login_required"})
_DJANGO_AUTHZ_DECORATORS: Final[frozenset[str]] = frozenset(
    {
        "permission_required",
        "permission_required_or_403",
        "staff_member_required",
        "user_passes_test",
    }
)
_DJANGO_AUTHN_MIXINS: Final[frozenset[str]] = frozenset({"LoginRequiredMixin"})
_DJANGO_AUTHZ_MIXINS: Final[frozenset[str]] = frozenset(
    {
        "PermissionRequiredMixin",
        "StaffMemberRequiredMixin",
        "UserPassesTestMixin",
    }
)
_DJANGO_PUBLIC_PERMISSIONS: Final[frozenset[str]] = frozenset({"AllowAny"})
_DJANGO_AUTHN_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        "IsAuthenticated",
        "IsAuthenticatedOrReadOnly",
    }
)
_DJANGO_AUTHZ_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        "DjangoModelPermissions",
        "DjangoModelPermissionsOrAnonReadOnly",
        "DjangoObjectPermissions",
        "IsAdminOrReadOnly",
        "IsAdminUser",
        "IsOwnerOrReadOnly",
    }
)

_NESTJS_PUBLIC_DECORATORS: Final[frozenset[str]] = frozenset(
    {"allowanonymous", "public", "skipauth"}
)


class AuthControlAnalysisError(ValueError):
    """Base error for authentication control analysis operations."""


class InvalidAuthControlRootError(AuthControlAnalysisError):
    """Raised when an analysis root is not a safe, existing directory."""


@dataclass(frozen=True)
class _JsClassInfo:
    """A class declaration parsed from the scoped JavaScript/TypeScript tokens."""

    name: str
    line: int
    bases: frozenset[str]
    methods: frozenset[str]


@dataclass
class _ControlDraft:
    """A control candidate before routes are associated and Pydantic-validated."""

    control_type: ControlType
    framework: RouteFramework
    mechanism: str
    source_file: str
    line_number: int
    scope_type: ControlScopeType
    detection_confidence: float
    evidence: str
    classification_rule: str
    symbol_name: str | None = None
    declaration: str | None = None
    handler_names: frozenset[str] = field(default_factory=frozenset)
    route_positions: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    associate_all_in_file: bool = False
    global_handlers: bool = False
    require_route_association: bool = False
    django_class_name: str | None = None


def _issue(
    source_file: str,
    reason: AnalysisIssueReason,
    detail: str | None = None,
) -> AnalysisIssue:
    return AnalysisIssue(source_file=source_file, reason=reason, detail=detail)


def _name_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for piece in re.split(r"[^A-Za-z0-9]+", value):
        if not piece:
            continue
        tokens.update(token.casefold() for token in _CAMEL_TOKEN_RE.findall(piece))
    return tokens


def _classify_name(value: str) -> tuple[ControlType, str] | None:
    tokens = _name_tokens(value)
    if not tokens:
        return None
    if tokens & _AUTHZ_TOKENS:
        return (
            ControlType.AUTHORIZATION,
            "Declaration name contains a recognizable authorization marker.",
        )
    if tokens & _AUTHN_TOKENS:
        return (
            ControlType.AUTHENTICATION,
            "Declaration name contains a recognizable authentication marker.",
        )
    return None


def _resolve_control_root(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: object,
) -> Path:
    try:
        resolved_root = _resolve_root(root, inventory)
    except InvalidAttackSurfaceRootError as exc:
        raise InvalidAuthControlRootError(str(exc)) from exc

    for label, value in (
        ("Technology detection", getattr(technologies, "root", None)),
        ("Attack surface", getattr(attack_surface, "root", None)),
    ):
        try:
            other_root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidAuthControlRootError(
                f"{label} root is not a valid filesystem path"
            ) from exc
        if other_root != resolved_root:
            raise InvalidAuthControlRootError(f"{label} root does not match the repository root")
    return resolved_root


def _decorator_base(node: ast.expr) -> ast.expr:
    return node.func if isinstance(node, ast.Call) else node


def _decorator_name(node: ast.expr) -> str | None:
    base = _decorator_base(node)
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return None


def _decorator_receiver_and_method(node: ast.expr) -> tuple[str, str] | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if not isinstance(node.func.value, ast.Name):
        return None
    return node.func.value.id, node.func.attr


def _collect_receiver_handlers(tree: ast.Module) -> dict[str, set[str]]:
    handlers: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            pair = _decorator_receiver_and_method(decorator)
            if pair is None:
                continue
            receiver, method = pair
            if method.casefold() in _ROUTE_DECORATOR_NAMES:
                handlers.setdefault(receiver, set()).add(node.name)
    return handlers


def _python_bindings(tree: ast.Module) -> tuple[set[str], set[str], set[str], set[str]]:
    fastapi_apps: set[str] = set()
    fastapi_routers: set[str] = set()
    flask_apps: set[str] = set()
    flask_blueprints: set[str] = set()

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
        if name == "FastAPI":
            fastapi_apps.add(targets[0].id)
        elif name == "APIRouter":
            fastapi_routers.add(targets[0].id)
        elif name == "Flask":
            flask_apps.add(targets[0].id)
        elif name == "Blueprint":
            flask_blueprints.add(targets[0].id)

    return fastapi_apps, fastapi_routers, flask_apps, flask_blueprints


def _route_functions(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    receivers: dict[str, object],
) -> set[str]:
    names: set[str] = set()
    for decorator in node.decorator_list:
        pair = _decorator_receiver_and_method(decorator)
        if pair is None:
            continue
        receiver, method = pair
        info = receivers.get(receiver)
        if info is None:
            continue
        if method.casefold() in _ROUTE_DECORATOR_NAMES:
            names.add(receiver)
    return names


def _dependency_call(
    node: ast.expr,
) -> tuple[str, ast.expr | None, bool] | None:
    if not isinstance(node, ast.Call):
        return None
    name = _call_name(node.func)
    if name not in {"Depends", "Security"}:
        return None
    target = node.args[0] if node.args else _keyword_expression(node, "dependency")
    scopes = _keyword_expression(node, "scopes") is not None
    return name, target, scopes


def _function_arguments_with_defaults(
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


def _iter_dependency_expressions(
    node: ast.expr,
) -> list[tuple[str, ast.expr | None, bool]]:
    direct = _dependency_call(node)
    if direct is not None:
        return [direct]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        found: list[tuple[str, ast.expr | None, bool]] = []
        for element in node.elts:
            info = _dependency_call(element)
            if info is not None:
                found.append(info)
        return found
    return []


def _annotated_dependencies(
    annotation: ast.expr | None,
) -> list[tuple[str, ast.expr | None, bool]]:
    if not isinstance(annotation, ast.Subscript):
        return []
    if not isinstance(annotation.value, ast.Name) or annotation.value.id != "Annotated":
        return []
    elements = (
        annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
    )
    found: list[tuple[str, ast.expr | None, bool]] = []
    for element in elements:
        info = _dependency_call(element)
        if info is not None:
            found.append(info)
    return found


def _dependency_symbol(target: ast.expr | None) -> tuple[str | None, bool]:
    if target is None:
        return None, False
    if isinstance(target, ast.Name):
        return target.id, False
    if isinstance(target, ast.Attribute):
        return target.attr, False
    if isinstance(target, ast.Call):
        return _call_name(target.func), True
    return _python_expression_text(target), True


def _dependency_drafts(
    *,
    framework: RouteFramework,
    mechanism: str,
    source_file: str,
    line_number: int,
    dependency_kind: str,
    target: ast.expr | None,
    scopes: bool,
    scope_type: ControlScopeType,
    symbol_name: str | None,
    handler_names: frozenset[str] = frozenset(),
    associate_all_in_file: bool = False,
    require_route_association: bool = False,
    issues: list[AnalysisIssue],
) -> list[_ControlDraft]:
    target_name, dynamic = _dependency_symbol(target)
    declaration = _python_expression_text(target) if target is not None else None

    if dynamic:
        issues.append(
            _issue(
                source_file,
                AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                (
                    f"Dynamic {dependency_kind} target '{declaration}' could not be "
                    "classified statically"
                ),
            )
        )
        return []

    if dependency_kind == "Depends":
        classification = _classify_name(target_name or "")
        if classification is None:
            return []
        control_type, rule = classification
        confidence = 0.70
    else:
        name_classification = _classify_name(target_name or "")
        if scopes:
            control_type = ControlType.AUTHORIZATION
            rule = "FastAPI Security dependency declares scopes (authorization)."
        elif (
            name_classification is not None and name_classification[0] is ControlType.AUTHORIZATION
        ):
            control_type = ControlType.AUTHORIZATION
            rule = "FastAPI Security dependency targets a recognizable authorization declaration."
        else:
            control_type = ControlType.AUTHENTICATION
            rule = "FastAPI Security dependency is an explicit security declaration."
        confidence = 0.90

    evidence = (
        f"{mechanism} was declared" + (f" for target '{target_name}'" if target_name else "") + "."
    )
    return [
        _ControlDraft(
            control_type=control_type,
            framework=framework,
            mechanism=mechanism,
            declaration=declaration,
            source_file=source_file,
            line_number=line_number,
            symbol_name=symbol_name or target_name,
            scope_type=scope_type,
            detection_confidence=confidence,
            evidence=evidence,
            classification_rule=rule,
            handler_names=handler_names,
            associate_all_in_file=associate_all_in_file,
            require_route_association=require_route_association,
        )
    ]


def _fastapi_dependency_drafts(
    tree: ast.Module,
    relative_path: str,
    constants: dict[str, str],
    receivers: dict[str, object],
    receiver_handlers: dict[str, set[str]],
    issues: list[AnalysisIssue],
) -> list[_ControlDraft]:
    drafts: list[_ControlDraft] = []
    fastapi_apps, fastapi_routers, _, _ = _python_bindings(tree)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_receivers = _route_functions(node, receivers)
        if not route_receivers:
            continue
        handler_names = frozenset({node.name})

        for argument, default in _function_arguments_with_defaults(node):
            dependencies = _iter_dependency_expressions(default) if default else []
            dependencies.extend(_annotated_dependencies(argument.annotation))
            for kind, target, scopes in dependencies:
                drafts.extend(
                    _dependency_drafts(
                        framework=RouteFramework.FASTAPI,
                        mechanism=kind,
                        source_file=relative_path,
                        line_number=argument.lineno,
                        dependency_kind=kind,
                        target=target,
                        scopes=scopes,
                        scope_type=ControlScopeType.ROUTE,
                        symbol_name=None,
                        handler_names=handler_names,
                        require_route_association=True,
                        issues=issues,
                    )
                )

        for decorator in node.decorator_list:
            pair = _decorator_receiver_and_method(decorator)
            if pair is None:
                continue
            receiver, method = pair
            if receiver not in route_receivers or method.casefold() not in _ROUTE_DECORATOR_NAMES:
                continue
            if not isinstance(decorator, ast.Call):
                continue
            dependency_expression = _keyword_expression(decorator, "dependencies")
            if dependency_expression is None:
                continue
            dependencies = _iter_dependency_expressions(dependency_expression)
            if not dependencies and dependency_expression is not None:
                issues.append(
                    _issue(
                        relative_path,
                        AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                        (
                            f"Route dependencies for '{node.name}' are not a statically "
                            "readable list"
                        ),
                    )
                )
                continue
            for kind, target, scopes in dependencies:
                drafts.extend(
                    _dependency_drafts(
                        framework=RouteFramework.FASTAPI,
                        mechanism=f"@{receiver}.{method}(dependencies=...)",
                        source_file=relative_path,
                        line_number=decorator.lineno,
                        dependency_kind=kind,
                        target=target,
                        scopes=scopes,
                        scope_type=ControlScopeType.ROUTE,
                        symbol_name=node.name,
                        handler_names=handler_names,
                        require_route_association=True,
                        issues=issues,
                    )
                )

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
        call_name = _call_name(value.func)
        if call_name not in {"FastAPI", "APIRouter"}:
            continue
        dependency_expression = _keyword_expression(value, "dependencies")
        if dependency_expression is None:
            continue
        dependencies = _iter_dependency_expressions(dependency_expression)
        if not dependencies:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    (f"Dependencies for '{targets[0].id}' are not a statically readable list"),
                )
            )
            continue
        variable = targets[0].id
        is_application = call_name == "FastAPI" and variable in fastapi_apps
        is_router = call_name == "APIRouter" and variable in fastapi_routers
        for kind, target, scopes in dependencies:
            drafts.extend(
                _dependency_drafts(
                    framework=RouteFramework.FASTAPI,
                    mechanism=f"{call_name}(dependencies=...)",
                    source_file=relative_path,
                    line_number=value.lineno,
                    dependency_kind=kind,
                    target=target,
                    scopes=scopes,
                    scope_type=(
                        ControlScopeType.APPLICATION if is_application else ControlScopeType.ROUTER
                    ),
                    symbol_name=variable,
                    handler_names=frozenset(
                        receiver_handlers.get(variable, set()) if is_router else set()
                    ),
                    associate_all_in_file=is_application,
                    issues=issues,
                )
            )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "include_router":
            continue
        if not node.args or not isinstance(node.args[0], ast.Name):
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    "include_router target is not a statically readable router name",
                )
            )
            continue
        dependency_expression = _keyword_expression(node, "dependencies")
        if dependency_expression is None:
            continue
        dependencies = _iter_dependency_expressions(dependency_expression)
        if not dependencies:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    "include_router dependencies are not a statically readable list",
                )
            )
            continue
        router_name = node.args[0].id
        for kind, target, scopes in dependencies:
            drafts.extend(
                _dependency_drafts(
                    framework=RouteFramework.FASTAPI,
                    mechanism="include_router(dependencies=...)",
                    source_file=relative_path,
                    line_number=node.lineno,
                    dependency_kind=kind,
                    target=target,
                    scopes=scopes,
                    scope_type=ControlScopeType.ROUTER,
                    symbol_name=router_name,
                    handler_names=frozenset(receiver_handlers.get(router_name, set())),
                    issues=issues,
                )
            )

    return drafts


def _flask_decorator_drafts(
    tree: ast.Module,
    relative_path: str,
    receivers: dict[str, object],
    issues: list[AnalysisIssue],
) -> list[_ControlDraft]:
    drafts: list[_ControlDraft] = []
    _, _, _, flask_blueprints = _python_bindings(tree)
    receiver_handlers = _collect_receiver_handlers(tree)
    decorator_ids: set[int] = set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routed = bool(_route_functions(node, receivers))
        for decorator in node.decorator_list:
            decorator_ids.add(id(decorator))
            name = _decorator_name(decorator)
            lowered = name.casefold() if name else ""
            if not lowered:
                continue
            if lowered == "before_request":
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                receiver_name = (
                    target.value.id
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                    else None
                )
                if receiver_name is None:
                    continue
                blueprint = receiver_name in flask_blueprints
                drafts.append(
                    _ControlDraft(
                        control_type=ControlType.AUTHENTICATION,
                        framework=RouteFramework.FLASK,
                        mechanism="@before_request",
                        declaration=_python_expression_text(decorator),
                        source_file=relative_path,
                        line_number=decorator.lineno,
                        symbol_name=node.name,
                        scope_type=(
                            ControlScopeType.ROUTER if blueprint else ControlScopeType.APPLICATION
                        ),
                        detection_confidence=0.45,
                        evidence=(
                            f"Function '{node.name}' is registered as a "
                            f"before_request hook on '{receiver_name}'."
                        ),
                        classification_rule=(
                            "Flask before_request hooks run before requests and may enforce "
                            "authentication; registration is evidence of a declared request-wide "
                            "control, not proof."
                        ),
                        handler_names=frozenset(
                            receiver_handlers.get(receiver_name, set()) if blueprint else set()
                        ),
                        associate_all_in_file=not blueprint,
                    )
                )
                continue
            if lowered in _FLASK_AUTHN_DECORATORS:
                control_type = ControlType.AUTHENTICATION
                rule = "Recognized Flask authentication decorator."
                confidence = 0.95
            elif lowered in _FLASK_AUTHZ_DECORATORS:
                control_type = ControlType.AUTHORIZATION
                rule = "Recognized Flask authorization decorator."
                confidence = 0.95
            else:
                continue
            drafts.append(
                _ControlDraft(
                    control_type=control_type,
                    framework=RouteFramework.FLASK,
                    mechanism=f"@{name}",
                    declaration=_python_expression_text(decorator),
                    source_file=relative_path,
                    line_number=decorator.lineno,
                    symbol_name=node.name,
                    scope_type=(ControlScopeType.ROUTE if routed else ControlScopeType.FUNCTION),
                    detection_confidence=confidence,
                    evidence=f"Decorator '@{name}' is attached to function '{node.name}'.",
                    classification_rule=rule,
                    handler_names=frozenset({node.name}),
                )
            )

    for node in ast.walk(tree):
        if id(node) in decorator_ids:
            continue
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr.casefold() != "before_request":
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        receiver_name = node.func.value.id
        blueprint = receiver_name in flask_blueprints
        symbol_name = node.args[0].id if node.args and isinstance(node.args[0], ast.Name) else None
        if symbol_name is None:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    "before_request registration does not use a statically readable function name",
                )
            )
            continue
        drafts.append(
            _ControlDraft(
                control_type=ControlType.AUTHENTICATION,
                framework=RouteFramework.FLASK,
                mechanism="before_request",
                declaration=_python_expression_text(node),
                source_file=relative_path,
                line_number=node.lineno,
                symbol_name=symbol_name,
                scope_type=(ControlScopeType.ROUTER if blueprint else ControlScopeType.APPLICATION),
                detection_confidence=0.45,
                evidence=(
                    f"Function '{symbol_name}' is registered as a before_request hook "
                    f"on '{receiver_name}'."
                ),
                classification_rule=(
                    "Flask before_request hooks run before requests and may enforce "
                    "authentication; registration is evidence of a declared request-wide "
                    "control, not proof."
                ),
                handler_names=frozenset(
                    receiver_handlers.get(receiver_name, set()) if blueprint else set()
                ),
                associate_all_in_file=not blueprint,
            )
        )

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


def _django_decorator_drafts(
    tree: ast.Module,
    relative_path: str,
    issues: list[AnalysisIssue],
) -> list[_ControlDraft]:
    drafts: list[_ControlDraft] = []

    def classify_decorator(decorator: ast.expr) -> tuple[ControlType, str] | None:
        name = _decorator_name(decorator)
        if name in _DJANGO_AUTHN_DECORATORS:
            return ControlType.AUTHENTICATION, "Recognized Django authentication decorator."
        if name in _DJANGO_AUTHZ_DECORATORS:
            return ControlType.AUTHORIZATION, "Recognized Django authorization decorator."
        if name == "method_decorator" and isinstance(decorator, ast.Call) and decorator.args:
            inner = decorator.args[0]
            inner_name = _decorator_name(inner)
            if inner_name in _DJANGO_AUTHN_DECORATORS:
                return ControlType.AUTHENTICATION, "Recognized Django method_decorator."
            if inner_name in _DJANGO_AUTHZ_DECORATORS:
                return ControlType.AUTHORIZATION, "Recognized Django method_decorator."
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                classification = classify_decorator(decorator)
                if classification is None:
                    continue
                control_type, rule = classification
                name = _decorator_name(decorator) or "decorator"
                drafts.append(
                    _ControlDraft(
                        control_type=control_type,
                        framework=RouteFramework.DJANGO,
                        mechanism=f"@{name}",
                        declaration=_python_expression_text(decorator),
                        source_file=relative_path,
                        line_number=decorator.lineno,
                        symbol_name=node.name,
                        scope_type=ControlScopeType.FUNCTION,
                        detection_confidence=0.95,
                        evidence=(
                            f"Decorator '@{name}' is attached to view function '{node.name}'."
                        ),
                        classification_rule=rule,
                        handler_names=frozenset({node.name}),
                        global_handlers=True,
                    )
                )
        elif isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = (
                    base.id
                    if isinstance(base, ast.Name)
                    else base.attr
                    if isinstance(base, ast.Attribute)
                    else None
                )
                if base_name in _DJANGO_AUTHN_MIXINS:
                    drafts.append(
                        _ControlDraft(
                            control_type=ControlType.AUTHENTICATION,
                            framework=RouteFramework.DJANGO,
                            mechanism=f"class {base_name}",
                            declaration=_python_expression_text(node),
                            source_file=relative_path,
                            line_number=node.lineno,
                            symbol_name=node.name,
                            scope_type=ControlScopeType.CLASS,
                            detection_confidence=0.95,
                            evidence=(f"Class '{node.name}' inherits from '{base_name}'."),
                            classification_rule=(
                                "Recognized Django LoginRequiredMixin authentication declaration."
                            ),
                            handler_names=frozenset({node.name}),
                            global_handlers=True,
                        )
                    )
                elif base_name in _DJANGO_AUTHZ_MIXINS:
                    drafts.append(
                        _ControlDraft(
                            control_type=ControlType.AUTHORIZATION,
                            framework=RouteFramework.DJANGO,
                            mechanism=f"class {base_name}",
                            declaration=_python_expression_text(node),
                            source_file=relative_path,
                            line_number=node.lineno,
                            symbol_name=node.name,
                            scope_type=ControlScopeType.CLASS,
                            detection_confidence=0.95,
                            evidence=(f"Class '{node.name}' inherits from '{base_name}'."),
                            classification_rule=(
                                "Recognized Django permission or user-test mixin."
                            ),
                            handler_names=frozenset({node.name}),
                            global_handlers=True,
                        )
                    )
            for decorator in node.decorator_list:
                classification = classify_decorator(decorator)
                if classification is None:
                    continue
                control_type, rule = classification
                name = _decorator_name(decorator) or "decorator"
                drafts.append(
                    _ControlDraft(
                        control_type=control_type,
                        framework=RouteFramework.DJANGO,
                        mechanism=f"@{name}",
                        declaration=_python_expression_text(decorator),
                        source_file=relative_path,
                        line_number=decorator.lineno,
                        symbol_name=node.name,
                        scope_type=ControlScopeType.CLASS,
                        detection_confidence=0.90,
                        evidence=(f"Decorator '@{name}' is attached to class '{node.name}'."),
                        classification_rule=rule,
                        handler_names=frozenset({node.name}),
                        global_handlers=True,
                    )
                )
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                    value = statement.value
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                    value = statement.value
                else:
                    continue
                if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                    continue
                attribute = targets[0].id
                if attribute == "permission_required":
                    drafts.append(
                        _ControlDraft(
                            control_type=ControlType.AUTHORIZATION,
                            framework=RouteFramework.DJANGO,
                            mechanism="permission_required attribute",
                            declaration=_python_expression_text(statement),
                            source_file=relative_path,
                            line_number=statement.lineno,
                            symbol_name=node.name,
                            scope_type=ControlScopeType.CLASS,
                            detection_confidence=0.85,
                            evidence=(
                                f"Class '{node.name}' declares a permission_required attribute."
                            ),
                            classification_rule=(
                                "Recognized Django permission declaration on a class."
                            ),
                            handler_names=frozenset({node.name}),
                            global_handlers=True,
                        )
                    )
                elif attribute == "permission_classes" and value is not None:
                    elements: list[ast.expr] = (
                        list(value.elts)
                        if isinstance(value, (ast.List, ast.Tuple, ast.Set))
                        else [value]
                    )
                    for element in elements:
                        element_name = (
                            element.id
                            if isinstance(element, ast.Name)
                            else element.attr
                            if isinstance(element, ast.Attribute)
                            else None
                        )
                        if element_name in _DJANGO_PUBLIC_PERMISSIONS:
                            control_type = ControlType.AUTHENTICATION
                            rule = (
                                "Recognized DRF AllowAny declaration; records an intended "
                                "public-access exemption, not proof of exposure."
                            )
                            confidence = 0.45
                        elif element_name in _DJANGO_AUTHN_PERMISSIONS:
                            control_type = ControlType.AUTHENTICATION
                            rule = "Recognized DRF authentication permission class."
                            confidence = 0.90
                        elif element_name in _DJANGO_AUTHZ_PERMISSIONS:
                            control_type = ControlType.AUTHORIZATION
                            rule = "Recognized DRF authorization permission class."
                            confidence = 0.90
                        else:
                            continue
                        drafts.append(
                            _ControlDraft(
                                control_type=control_type,
                                framework=RouteFramework.DJANGO,
                                mechanism=f"permission_classes[{element_name}]",
                                declaration=_python_expression_text(statement),
                                source_file=relative_path,
                                line_number=statement.lineno,
                                symbol_name=node.name,
                                scope_type=ControlScopeType.CLASS,
                                detection_confidence=confidence,
                                evidence=(
                                    f"Class '{node.name}' declares permission class "
                                    f"'{element_name}'."
                                ),
                                classification_rule=rule,
                                handler_names=frozenset({node.name}),
                                global_handlers=True,
                            )
                        )

    for draft in drafts:
        if draft.scope_type is ControlScopeType.CLASS:
            draft.django_class_name = draft.symbol_name
    return drafts


def _extract_python_controls(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> tuple[list[_ControlDraft], dict[str, set[str]]]:
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
    receivers = _collect_receivers(tree, constants)
    receiver_handlers = _collect_receiver_handlers(tree)
    imported = _collect_imported_frameworks(tree)
    drafts: list[_ControlDraft] = []
    django_class_paths: dict[str, set[str]] = {}

    if RouteFramework.FASTAPI in imported or "fastapi" in hints:
        drafts.extend(
            _fastapi_dependency_drafts(
                tree,
                relative_path,
                constants,
                receivers,
                receiver_handlers,
                issues,
            )
        )
    if RouteFramework.FLASK in imported or "flask" in hints:
        drafts.extend(
            _flask_decorator_drafts(
                tree,
                relative_path,
                receivers,
                issues,
            )
        )
    if RouteFramework.DJANGO in imported or "django" in hints:
        drafts.extend(_django_decorator_drafts(tree, relative_path, issues))
        django_class_paths = _django_class_route_paths(tree, relative_path, constants)

    return drafts, django_class_paths


def _js_identifiers(tokens: list[_JsToken]) -> str:
    return " ".join(token.value for token in tokens if token.kind == "identifier")


def _js_reference_name(tokens: list[_JsToken]) -> str | None:
    for index, token in enumerate(tokens):
        if token.kind == "punct" and token.value == "(":
            for previous in range(index - 1, -1, -1):
                if tokens[previous].kind == "identifier":
                    return tokens[previous].value
            return None
    for token in reversed(tokens):
        if token.kind == "identifier":
            return token.value
    return None


def _classify_js_control(
    tokens: list[_JsToken],
) -> tuple[ControlType, str, str | None] | None:
    if not tokens:
        return None
    identifiers = _js_identifiers(tokens)
    classification = _classify_name(identifiers)
    if classification is None:
        return None
    control_type, rule = classification
    return control_type, rule, _js_reference_name(tokens)


def _split_js_array(tokens: list[_JsToken]) -> list[list[_JsToken]]:
    if len(tokens) < 2 or not _punct(tokens[0], "[") or not _punct(tokens[-1], "]"):
        return [tokens]
    parts: list[list[_JsToken]] = []
    current: list[_JsToken] = []
    depth = 0
    for token in tokens[1:-1]:
        if token.kind == "punct" and token.value in "([{":
            depth += 1
        elif token.kind == "punct" and token.value in ")]}":
            depth -= 1
        if token.kind == "punct" and token.value == "," and depth == 0:
            if current:
                parts.append(current)
            current = []
            continue
        current.append(token)
    if current:
        parts.append(current)
    return parts


def _express_route_lines(
    tokens: list[_JsToken],
    known_apps: set[str],
    known_routers: set[str],
) -> tuple[dict[str, set[int]], set[int]]:
    route_lines: dict[str, set[int]] = {}
    all_lines: set[int] = set()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token.kind == "identifier"
            and token.value in known_apps | known_routers
            and _is_punct(tokens, index + 1, ".")
            and index + 2 < len(tokens)
            and tokens[index + 2].kind == "identifier"
        ):
            method_name = tokens[index + 2].value.casefold()
            if method_name in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "trace",
                "all",
                "use",
            } and _is_punct(tokens, index + 3, "("):
                try:
                    arguments, close = _collect_arguments(tokens, index + 3)
                except _JsLexError:
                    index += 1
                    continue
                if method_name != "use" and len(arguments) >= 2 and arguments[0]:
                    route_lines.setdefault(token.value, set()).add(token.line)
                    all_lines.add(token.line)
                elif method_name == "use":
                    route_lines.setdefault(token.value, set()).add(token.line)
                    all_lines.add(token.line)
                index = close + 1
                continue
        index += 1
    return route_lines, all_lines


def _express_control_drafts(
    tokens: list[_JsToken],
    relative_path: str,
    hints: frozenset[str],
    issues: list[AnalysisIssue],
) -> list[_ControlDraft]:
    app_vars, router_vars, express_present = _collect_js_bindings(tokens)
    if not express_present and "express" not in hints:
        return []

    known_apps = set(app_vars) | {"app", "server", "api"}
    known_routers = set(router_vars) | {"router", "routes", "route"}
    route_lines, all_route_lines = _express_route_lines(tokens, known_apps, known_routers)
    drafts: list[_ControlDraft] = []

    def add_middleware_controls(
        middleware_arguments: list[list[_JsToken]],
        *,
        receiver: str,
        route_line: int | None,
        mount_scope: ControlScopeType | None,
        router_reference: str | None,
        mechanism: str,
    ) -> None:
        for argument in middleware_arguments:
            if _is_router_reference(argument, known_routers) is not None:
                continue
            for candidate in _split_js_array(argument):
                if not candidate:
                    continue
                if _is_router_reference(candidate, known_routers) is not None:
                    continue
                classification = _classify_js_control(candidate)
                if classification is None:
                    continue
                control_type, rule, symbol_name = classification
                if mount_scope is not None:
                    scope_type = mount_scope
                    route_positions = (
                        frozenset(
                            (relative_path, line)
                            for line in route_lines.get(router_reference or "", set())
                        )
                        if router_reference is not None
                        else frozenset((relative_path, line) for line in all_route_lines)
                    )
                    associated_all = False
                    require_association = False
                else:
                    scope_type = (
                        ControlScopeType.APPLICATION
                        if receiver in known_apps
                        else ControlScopeType.ROUTER
                    )
                    route_positions = frozenset(
                        (relative_path, line)
                        for line in (
                            all_route_lines
                            if receiver in known_apps
                            else route_lines.get(receiver, set())
                        )
                    )
                    associated_all = False
                    require_association = False
                if route_line is not None:
                    scope_type = ControlScopeType.ROUTE
                    route_positions = frozenset({(relative_path, route_line)})
                    require_association = True
                drafts.append(
                    _ControlDraft(
                        control_type=control_type,
                        framework=RouteFramework.EXPRESS,
                        mechanism=mechanism,
                        declaration=_tokens_to_text(candidate),
                        source_file=relative_path,
                        line_number=candidate[0].line,
                        symbol_name=symbol_name,
                        scope_type=scope_type,
                        detection_confidence=0.75,
                        evidence=(
                            f"Middleware expression '{_tokens_to_text(candidate)}' is "
                            f"passed to '{receiver}.{mechanism.split('(')[0]}'."
                        ),
                        classification_rule=(
                            rule + " Classification uses the middleware declaration and a "
                            "recognizable naming convention; the middleware body is not "
                            "executed or verified."
                        ),
                        route_positions=route_positions,
                        associate_all_in_file=associated_all,
                        require_route_association=require_association,
                    )
                )

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token.kind != "identifier"
            or token.value not in known_apps | known_routers
            or not _is_punct(tokens, index + 1, ".")
            or index + 2 >= len(tokens)
            or tokens[index + 2].kind != "identifier"
            or not _is_punct(tokens, index + 3, "(")
        ):
            index += 1
            continue

        receiver = token.value
        method_name = tokens[index + 2].value.casefold()
        if method_name not in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "trace",
            "all",
            "use",
        }:
            index += 1
            continue

        try:
            arguments, close = _collect_arguments(tokens, index + 3)
        except _JsLexError as exc:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.INVALID_SYNTAX,
                    f"Unbalanced Express declaration at line {token.line}: {exc}",
                )
            )
            return drafts

        if method_name == "use":
            remaining = arguments
            if arguments:
                first = arguments[0]
                _, first_resolved = _evaluate_js_string(first)
                if first_resolved or (len(arguments) >= 2 and _classify_js_control(first) is None):
                    remaining = arguments[1:]
            router_references = [
                reference
                for argument in remaining
                if (reference := _is_router_reference(argument, known_routers)) is not None
            ]
            middleware = [
                argument
                for argument in remaining
                if _is_router_reference(argument, known_routers) is None
            ]
            if middleware:
                add_middleware_controls(
                    middleware,
                    receiver=receiver,
                    route_line=None,
                    mount_scope=(ControlScopeType.ROUTER if router_references else None),
                    router_reference=router_references[-1] if router_references else None,
                    mechanism=f"{receiver}.use",
                )
        elif len(arguments) >= 2:
            add_middleware_controls(
                arguments[1:-1],
                receiver=receiver,
                route_line=token.line,
                mount_scope=None,
                router_reference=None,
                mechanism=f"{receiver}.{method_name}",
            )

        index = close + 1

    return drafts


def _nestjs_classes(tokens: list[_JsToken]) -> list[_JsClassInfo]:
    classes: list[_JsClassInfo] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token.kind == "identifier"
            and token.value == "class"
            and index + 1 < len(tokens)
            and tokens[index + 1].kind == "identifier"
        ):
            name = tokens[index + 1].value
            cursor = index + 2
            bases: set[str] = set()
            while cursor < len(tokens) and not _punct(tokens[cursor], "{"):
                candidate = tokens[cursor]
                if candidate.kind == "identifier" and candidate.value not in {
                    "extends",
                    "implements",
                    "export",
                    "default",
                }:
                    bases.add(candidate.value)
                cursor += 1
            if cursor >= len(tokens):
                break
            depth = 0
            methods: set[str] = set()
            scan = cursor
            while scan < len(tokens):
                current = tokens[scan]
                if _punct(current, "{"):
                    depth += 1
                elif _punct(current, "}"):
                    depth -= 1
                    if depth == 0:
                        break
                elif (
                    depth == 1
                    and current.kind == "identifier"
                    and current.value
                    not in {
                        "constructor",
                        "if",
                        "for",
                        "while",
                        "switch",
                        "catch",
                    }
                    and _is_punct(tokens, scan + 1, "(")
                    and not (scan > 0 and _punct(tokens[scan - 1], "@"))
                ):
                    try:
                        _, method_close = _collect_arguments(tokens, scan + 1)
                    except _JsLexError:
                        scan += 1
                        continue
                    after = method_close + 1
                    if _is_punct(tokens, after, "{") or _is_punct(tokens, after, ":"):
                        methods.add(current.value)
                scan += 1
            classes.append(
                _JsClassInfo(
                    name=name,
                    line=token.line,
                    bases=frozenset(bases),
                    methods=frozenset(methods),
                )
            )
            index = scan + 1
            continue
        index += 1
    return classes


def _next_js_class_name(tokens: list[_JsToken], start: int) -> str | None:
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "identifier":
            if token.value == "class" and index + 1 < len(tokens):
                if tokens[index + 1].kind == "identifier":
                    return tokens[index + 1].value
                return None
            if _is_punct(tokens, index + 1, "("):
                return None
        if token.kind == "punct" and token.value in ";{}=,":
            return None
        index += 1
    return None


def _nestjs_control_drafts(
    tokens: list[_JsToken],
    relative_path: str,
    issues: list[AnalysisIssue],
) -> list[_ControlDraft]:
    if not _has_nestjs_markers(tokens):
        return []

    classes = _nestjs_classes(tokens)
    class_methods = {info.name: info.methods for info in classes}
    drafts: list[_ControlDraft] = []
    index = 0

    while index < len(tokens):
        if not _punct(tokens[index], "@") or index + 1 >= len(tokens):
            index += 1
            continue
        if tokens[index + 1].kind != "identifier":
            index += 1
            continue

        decorator_name = tokens[index + 1].value
        lowered = decorator_name.casefold()
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
                        f"Unbalanced NestJS decorator at line {tokens[index].line}: {exc}",
                    )
                )
                return drafts
        else:
            close = index + 1

        class_name = _next_js_class_name(tokens, close + 1)
        method_name = None if class_name is not None else _next_js_method_name(tokens, close + 1)
        target_name = class_name or method_name
        target_label = f"class {class_name}" if class_name is not None else f"method {method_name}"

        if lowered == "useguards":
            if class_name is not None:
                scope = ControlScopeType.CONTROLLER
                handler_names = frozenset(class_methods.get(class_name, set()))
            elif method_name is not None:
                scope = ControlScopeType.ROUTE
                handler_names = frozenset({method_name})
            else:
                scope = ControlScopeType.UNKNOWN
                handler_names = frozenset()
            for argument in arguments:
                classification = _classify_js_control(argument)
                if classification is None:
                    issues.append(
                        _issue(
                            relative_path,
                            AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                            (
                                "NestJS guard "
                                f"'{_tokens_to_text(argument)}' has no recognizable "
                                "authentication or authorization marker"
                            ),
                        )
                    )
                    continue
                control_type, rule, symbol_name = classification
                drafts.append(
                    _ControlDraft(
                        control_type=control_type,
                        framework=RouteFramework.NESTJS,
                        mechanism="@UseGuards",
                        declaration=_tokens_to_text(argument),
                        source_file=relative_path,
                        line_number=tokens[index].line,
                        symbol_name=symbol_name or target_name,
                        scope_type=scope,
                        detection_confidence=0.80,
                        evidence=(
                            f"@UseGuards declares guard '{_tokens_to_text(argument)}' "
                            f"on {target_label}."
                        ),
                        classification_rule=(
                            rule + " Guard use is a declaration only; the guard body is not "
                            "executed or verified."
                        ),
                        handler_names=handler_names,
                        require_route_association=scope is ControlScopeType.ROUTE,
                    )
                )
        elif lowered == "roles":
            if class_name is not None:
                scope = ControlScopeType.CONTROLLER
                handler_names = frozenset(class_methods.get(class_name, set()))
            elif method_name is not None:
                scope = ControlScopeType.ROUTE
                handler_names = frozenset({method_name})
            else:
                scope = ControlScopeType.UNKNOWN
                handler_names = frozenset()
            drafts.append(
                _ControlDraft(
                    control_type=ControlType.AUTHORIZATION,
                    framework=RouteFramework.NESTJS,
                    mechanism="@Roles",
                    declaration=_tokens_to_text(tokens[index : close + 1]),
                    source_file=relative_path,
                    line_number=tokens[index].line,
                    symbol_name=target_name,
                    scope_type=scope,
                    detection_confidence=0.90,
                    evidence=(f"@Roles declares role requirements on {target_label}."),
                    classification_rule=(
                        "Recognized NestJS authorization decorator. Role values are recorded "
                        "as declared requirements, not verified assignments."
                    ),
                    handler_names=handler_names,
                    require_route_association=scope is ControlScopeType.ROUTE,
                )
            )
        elif lowered in _NESTJS_PUBLIC_DECORATORS:
            if class_name is not None:
                scope = ControlScopeType.CONTROLLER
                handler_names = frozenset(class_methods.get(class_name, set()))
            elif method_name is not None:
                scope = ControlScopeType.ROUTE
                handler_names = frozenset({method_name})
            else:
                scope = ControlScopeType.UNKNOWN
                handler_names = frozenset()
            drafts.append(
                _ControlDraft(
                    control_type=ControlType.AUTHENTICATION,
                    framework=RouteFramework.NESTJS,
                    mechanism=f"@{decorator_name}",
                    declaration=_tokens_to_text(tokens[index : close + 1]),
                    source_file=relative_path,
                    line_number=tokens[index].line,
                    symbol_name=target_name,
                    scope_type=scope,
                    detection_confidence=0.40,
                    evidence=(
                        f"@{decorator_name} marks {target_label} as a public or "
                        "authentication-exempt declaration."
                    ),
                    classification_rule=(
                        "Recognized NestJS public-route marker. This records an intended "
                        "authentication exemption, not proof that a route is exposed."
                    ),
                    handler_names=handler_names,
                    require_route_association=scope is ControlScopeType.ROUTE,
                )
            )

        index = close + 1

    for info in classes:
        classification = _classify_name(info.name)
        if classification is None:
            continue
        if not (
            info.name.casefold().endswith("guard")
            or "CanActivate" in info.bases
            or "canActivate" in info.methods
        ):
            continue
        control_type, rule = classification
        drafts.append(
            _ControlDraft(
                control_type=control_type,
                framework=RouteFramework.NESTJS,
                mechanism="guard class",
                declaration=f"class {info.name}",
                source_file=relative_path,
                line_number=info.line,
                symbol_name=info.name,
                scope_type=ControlScopeType.CLASS,
                detection_confidence=0.70,
                evidence=(
                    f"Class '{info.name}' has a guard marker and a recognizable "
                    "authentication or authorization name."
                ),
                classification_rule=(
                    rule + " The class declaration is evidence of a guard implementation, not "
                    "evidence that it is applied or that it works."
                ),
            )
        )

    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue
        if token.value not in {"useGlobalGuards"}:
            continue
        open_index = index + 1
        if _is_punct(tokens, open_index, "."):
            open_index += 1
            if open_index < len(tokens) and tokens[open_index].kind == "identifier":
                if tokens[open_index].value != "useGlobalGuards":
                    continue
                open_index += 1
        if not _is_punct(tokens, open_index, "("):
            continue
        try:
            arguments, _ = _collect_arguments(tokens, open_index)
        except _JsLexError as exc:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.INVALID_SYNTAX,
                    f"Unbalanced useGlobalGuards declaration at line {token.line}: {exc}",
                )
            )
            continue
        for argument in arguments:
            classification = _classify_js_control(argument)
            if classification is None:
                continue
            control_type, rule, symbol_name = classification
            drafts.append(
                _ControlDraft(
                    control_type=control_type,
                    framework=RouteFramework.NESTJS,
                    mechanism="useGlobalGuards",
                    declaration=_tokens_to_text(argument),
                    source_file=relative_path,
                    line_number=token.line,
                    symbol_name=symbol_name,
                    scope_type=ControlScopeType.APPLICATION,
                    detection_confidence=0.75,
                    evidence=(f"useGlobalGuards registers guard '{_tokens_to_text(argument)}'."),
                    classification_rule=(
                        rule + " Global guard registration is evidence of an application-wide "
                        "declaration, not proof of enforcement."
                    ),
                    associate_all_in_file=True,
                )
            )

    return drafts


def _extract_javascript_controls(
    text: str,
    relative_path: str,
    issues: list[AnalysisIssue],
    hints: frozenset[str],
) -> list[_ControlDraft]:
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

    drafts = _express_control_drafts(tokens, relative_path, hints, issues)
    drafts.extend(_nestjs_control_drafts(tokens, relative_path, issues))
    return drafts


def _associated_routes(
    draft: _ControlDraft,
    routes: list[RouteCandidate],
    django_class_paths: dict[str, set[str]],
) -> list[RouteCandidate]:
    matched: list[RouteCandidate] = []
    if draft.route_positions:
        positions = draft.route_positions
        matched = [route for route in routes if (route.source_file, route.line_number) in positions]
    if not matched and draft.handler_names:
        matched = [
            route
            for route in routes
            if route.handler_name in draft.handler_names
            and (draft.global_handlers or route.source_file == draft.source_file)
        ]
    if not matched and draft.django_class_name:
        class_paths = django_class_paths.get(draft.django_class_name)
        if class_paths:
            matched = [
                route
                for route in routes
                if route.framework is RouteFramework.DJANGO and route.path in class_paths
            ]
    if not matched and draft.associate_all_in_file:
        matched = [route for route in routes if route.source_file == draft.source_file]

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


def _control_from_draft(
    draft: _ControlDraft,
    routes: list[RouteCandidate],
    django_class_paths: dict[str, set[str]],
) -> AuthControlCandidate:
    associated = _associated_routes(draft, routes, django_class_paths)
    unresolved = draft.scope_type is ControlScopeType.UNKNOWN
    if draft.require_route_association and not associated:
        unresolved = True
    if any(route.resolution_status is RouteResolutionStatus.UNRESOLVED for route in associated):
        unresolved = True

    return AuthControlCandidate(
        control_type=draft.control_type,
        framework=draft.framework,
        mechanism=draft.mechanism,
        declaration=draft.declaration,
        source_file=draft.source_file,
        line_number=draft.line_number,
        symbol_name=draft.symbol_name,
        scope_type=draft.scope_type,
        associated_routes=[
            AssociatedRoute(
                path=route.path,
                http_method=route.http_method,
                framework=route.framework,
                resolution_status=route.resolution_status,
            )
            for route in associated
        ],
        resolution_status=(
            ControlResolutionStatus.UNRESOLVED if unresolved else ControlResolutionStatus.RESOLVED
        ),
        detection_confidence=draft.detection_confidence,
        evidence=draft.evidence,
        classification_rule=draft.classification_rule,
    )


def _dedupe_controls(controls: list[AuthControlCandidate]) -> list[AuthControlCandidate]:
    unique: list[AuthControlCandidate] = []
    seen: set[str] = set()
    for control in controls:
        key = json.dumps(control.model_dump(mode="json"), sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(control)
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


def identify_auth_controls(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: object,
    *,
    max_source_file_size_bytes: int | None = None,
    max_source_files: int | None = None,
) -> AuthControlResult:
    """Identify declared authentication and authorization controls.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match the discovery inventory, technology detection result, and attack
    surface result. Only Python and JavaScript/TypeScript files already present in
    the inventory are read. Repository code is never executed or imported.
    """
    resolved_root = _resolve_control_root(root, inventory, technologies, attack_surface)

    max_size = (
        settings.auth_control_source_max_size_bytes
        if max_source_file_size_bytes is None
        else max_source_file_size_bytes
    )
    max_files = (
        settings.auth_control_max_source_files if max_source_files is None else max_source_files
    )
    if max_size < 0 or max_files < 0:
        raise AuthControlAnalysisError("Source inspection limits must not be negative")

    routes = list(getattr(attack_surface, "routes", []))
    hints = _framework_hints(technologies)
    issues = _discovery_source_issues(inventory)
    drafts: list[_ControlDraft] = []
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
            python_drafts, python_class_paths = _extract_python_controls(
                text, relative_path, issues, hints
            )
            drafts.extend(python_drafts)
            for class_name, class_paths in python_class_paths.items():
                django_class_paths.setdefault(class_name, set()).update(class_paths)
        elif extension in _JAVASCRIPT_EXTENSIONS:
            drafts.extend(_extract_javascript_controls(text, relative_path, issues, hints))

    controls = _dedupe_controls(
        [_control_from_draft(draft, routes, django_class_paths) for draft in drafts]
    )
    sorted_controls = sorted(
        controls,
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.mechanism,
            item.control_type.value,
            item.scope_type.value,
            item.symbol_name or "",
            item.detection_confidence,
            item.declaration or "",
        ),
    )
    sorted_issues = sorted(
        _dedupe_issues(issues),
        key=lambda item: (item.source_file, item.reason.value, item.detail or ""),
    )

    authentication_count = sum(
        control.control_type is ControlType.AUTHENTICATION for control in sorted_controls
    )
    authorization_count = sum(
        control.control_type is ControlType.AUTHORIZATION for control in sorted_controls
    )
    route_association_count = sum(len(control.associated_routes) for control in sorted_controls)
    unresolved_scope_count = sum(
        control.scope_type is ControlScopeType.UNKNOWN
        or control.resolution_status is ControlResolutionStatus.UNRESOLVED
        for control in sorted_controls
    )

    summary = AuthControlSummary(
        source_files_inspected=inspected,
        authentication_control_count=authentication_count,
        authorization_control_count=authorization_count,
        route_association_count=route_association_count,
        unresolved_scope_count=unresolved_scope_count,
        issue_count=len(sorted_issues),
        is_complete=inventory.summary.is_complete and not sorted_issues,
        discovery_is_complete=inventory.summary.is_complete,
        discovery_truncation_reasons=list(inventory.summary.truncation_reasons),
    )

    return AuthControlResult(
        root=str(resolved_root),
        controls=sorted_controls,
        issues=sorted_issues,
        summary=summary,
    )
