"""Deterministic, read-only handler and local call-relationship analysis.

The analyzer consumes a repository discovery inventory, a technology detection
result, and an attack-surface result. It reads only source files already present
in the inventory, parses Python files with :mod:`ast`, and never executes or
imports repository code. It does not run Git, shell commands, or subprocesses and
does not make network requests.

The output is evidence of *statically identifiable* definitions and call
expressions. A call site does not prove that the call executes at runtime, and a
resolved relationship does not prove that a value flows between definitions.
Calls to external libraries, dynamically computed callables, and cross-module
targets that cannot be resolved deterministically are preserved as external,
unresolved, or ambiguous evidence rather than guessed.

Resolution policy
-----------------
* A bare name resolves only to module-level functions in the same file (or to
  the caller itself for direct recursion). Imported names and Python builtins are
  classified as external unless a repository module can be mapped to exactly one
  inventoried file and the imported symbol is a unique top-level definition.
* ``self.method()`` and ``cls.method()`` resolve only to methods of the caller's
  enclosing class. ``ClassName.method()`` resolves only when the class is defined
  locally or imported from a deterministically resolved repository module.
* An instance receiver resolves only when a single visible assignment binds it to
  a locally defined class (``service = Service()``). Receivers bound to imported
  or external calls are classified as external, not as local calls.
* Duplicate definitions with the same name, duplicate methods on a class, and
  ambiguous receiver assignments produce ambiguous relationships instead of a
  guessed target.
* Cross-file calls are resolved only through absolute or relative imports whose
  module path maps to exactly one inventoried Python file and whose target is
  unique. Relative imports outside the repository and unresolved package layouts
  remain unresolved.

TOCTOU limitations
------------------
Each source path is checked for relative containment, symlink/reparse-point
status, regular-file status, and size immediately before it is opened. The
filesystem can still change between those checks and the read, so fully race-free
operation would require platform-specific directory handles.
"""

import ast
import builtins
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final

from app.core.config import settings
from app.schemas.attack_surface import (
    AnalysisIssue,
    AnalysisIssueReason,
    AttackSurfaceResult,
    RouteCandidate,
    RouteFramework,
)
from app.schemas.handler_calls import (
    CallRelationship,
    CallRelationshipType,
    CallResolutionStatus,
    CallSite,
    FunctionKind,
    HandlerCallIssue,
    HandlerCallIssueCategory,
    HandlerCallResult,
    HandlerCallSummary,
    HandlerResolutionStatus,
    LocalFunctionDefinition,
    RouteHandler,
)
from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.technology import TechnologyDetectionResult
from app.services.attack_surface import (
    _PYTHON_EXTENSIONS,
    InvalidAttackSurfaceRootError,
    _discovery_source_issues,
    _extension,
    _has_excluded_component,
    _is_sensitive_path,
    _read_source_text,
    _resolve_root,
    _source_candidates,
    _validate_source_path,
)

_BUILTIN_NAMES: Final[frozenset[str]] = frozenset(dir(builtins))

_DEFINITION_CONFIDENCE: Final[float] = 0.95
_HANDLER_DECORATOR_CONFIDENCE: Final[float] = 0.95
_HANDLER_NAME_CONFIDENCE: Final[float] = 0.90
_AMBIGUOUS_CONFIDENCE: Final[float] = 0.50
_UNRESOLVED_CONFIDENCE: Final[float] = 0.30
_UNSUPPORTED_CONFIDENCE: Final[float] = 0.20

_CALL_SAME_FILE_CONFIDENCE: Final[float] = 0.95
_CALL_SELF_CONFIDENCE: Final[float] = 0.90
_CALL_REPOSITORY_CONFIDENCE: Final[float] = 0.85
_EXTERNAL_CONFIDENCE: Final[float] = 0.90
_UNRESOLVED_CALL_CONFIDENCE: Final[float] = 0.30
_AMBIGUOUS_CALL_CONFIDENCE: Final[float] = 0.50

_MAX_EXPRESSION_LENGTH: Final[int] = 200

_PYTHON_FRAMEWORKS: Final[frozenset[RouteFramework]] = frozenset(
    {
        RouteFramework.FASTAPI,
        RouteFramework.FLASK,
        RouteFramework.DJANGO,
    }
)


class HandlerCallAnalysisError(ValueError):
    """Base error for handler and local call-relationship analysis."""


class InvalidHandlerCallRootError(HandlerCallAnalysisError):
    """Raised when an analysis root is not safe or does not match its inputs."""


@dataclass(frozen=True)
class _ImportModuleBinding:
    """An imported module bound to a local name."""

    module: str
    level: int


@dataclass(frozen=True)
class _ImportNameBinding:
    """A symbol imported from a module into a local name."""

    module: str | None
    name: str
    level: int


@dataclass
class _FileImports:
    """Import bindings collected from one Python source file."""

    modules: dict[str, _ImportModuleBinding] = field(default_factory=dict)
    names: dict[str, _ImportNameBinding] = field(default_factory=dict)


@dataclass
class _ClassRecord:
    """A statically identified class definition."""

    source_file: str
    name: str
    qualified_name: str
    line_number: int
    column_number: int
    node: ast.ClassDef


@dataclass
class _Definition:
    """A statically identified function or method definition."""

    definition_id: str
    name: str
    qualified_name: str
    kind: FunctionKind
    source_file: str
    line_number: int
    column_number: int
    end_line_number: int
    class_name: str | None
    class_qualified_name: str | None
    parent_definition_id: str | None
    is_async: bool
    parameter_count: int
    decorator_lines: tuple[int, ...]
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: "_FileContext" = field(repr=False)
    route_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _ReceiverBinding:
    """Statically inferred local receiver binding."""

    kind: str
    class_refs: tuple[tuple[str, str], ...] = ()


@dataclass
class _FileContext:
    """Parsed source state for one Python file."""

    relative_path: str
    module_name: str
    package_parts: tuple[str, ...]
    tree: ast.Module
    imports: _FileImports
    definitions: list[_Definition]
    classes: list[_ClassRecord]
    module_bindings: dict[str, _ReceiverBinding] = field(default_factory=dict)
    definition_bindings: dict[str, dict[str, _ReceiverBinding]] = field(default_factory=dict)
    definition_imports: dict[str, _FileImports] = field(default_factory=dict)


@dataclass(frozen=True)
class _CallResolution:
    """Internal result of resolving one call expression."""

    status: CallResolutionStatus
    target_ids: tuple[str, ...]
    confidence: float
    explanation: str
    is_method_call: bool
    callee_name: str
    receiver_expression: str | None


@dataclass
class _AnalysisIndex:
    """Lookup tables shared by all parsed files."""

    contexts: dict[str, _FileContext]
    module_paths: dict[str, list[str]]
    definitions_by_id: dict[str, _Definition]
    definitions_by_file: dict[str, list[_Definition]]

    def module_top_level_defs(self, module: str, name: str) -> list[_Definition]:
        matches: list[_Definition] = []
        for relative_path in self.module_paths.get(module, []):
            context = self.contexts.get(relative_path)
            if context is None:
                continue
            for definition in context.definitions:
                if definition.name != name:
                    continue
                if definition.kind is not FunctionKind.FUNCTION:
                    continue
                if definition.parent_definition_id is not None:
                    continue
                matches.append(definition)
        return _sort_definitions(matches)

    def module_classes(self, module: str, name: str) -> list[_ClassRecord]:
        matches: list[_ClassRecord] = []
        for relative_path in self.module_paths.get(module, []):
            context = self.contexts.get(relative_path)
            if context is None:
                continue
            for record in context.classes:
                if record.name == name:
                    matches.append(record)
        return sorted(
            matches,
            key=lambda item: (
                item.source_file,
                item.line_number,
                item.column_number,
                item.qualified_name,
            ),
        )

    def class_methods(
        self,
        source_file: str,
        class_qualified_name: str,
        name: str,
    ) -> list[_Definition]:
        context = self.contexts.get(source_file)
        if context is None:
            return []
        matches = [
            definition
            for definition in context.definitions
            if definition.kind is FunctionKind.METHOD
            and definition.class_qualified_name == class_qualified_name
            and definition.name == name
        ]
        return _sort_definitions(matches)


def _issue(
    source_file: str,
    reason: AnalysisIssueReason,
    detail: str | None = None,
) -> AnalysisIssue:
    return AnalysisIssue(source_file=source_file, reason=reason, detail=detail)


def _normalized_path(relative_path: str) -> str:
    return relative_path.replace("\\", "/")


def _module_name(relative_path: str) -> str:
    pure = PurePosixPath(_normalized_path(relative_path))
    parts = list(pure.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _package_parts(relative_path: str) -> tuple[str, ...]:
    module = _module_name(relative_path)
    if not module:
        return ()
    parts = tuple(module.split("."))
    if PurePosixPath(_normalized_path(relative_path)).name == "__init__.py":
        return parts
    return parts[:-1]


def _module_paths_from_inventory(
    inventory: RepositoryDiscoveryResult,
) -> dict[str, list[str]]:
    module_paths: dict[str, list[str]] = {}
    for entry in _source_candidates(inventory):
        if _extension(entry.relative_path, entry.extension) not in _PYTHON_EXTENSIONS:
            continue
        module = _module_name(entry.relative_path)
        if not module:
            continue
        module_paths.setdefault(module, []).append(entry.relative_path)
    for paths in module_paths.values():
        paths.sort()
    return module_paths


def _absolute_module(
    context: _FileContext,
    module: str | None,
    level: int,
) -> str | None:
    if level == 0:
        return module
    package = list(context.package_parts)
    if level - 1 > len(package):
        return None
    base = package[: len(package) - (level - 1)]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _expression_text(node: ast.AST) -> str:
    try:
        text = ast.unparse(node)
    except (AttributeError, RecursionError, ValueError):
        text = type(node).__name__
    text = " ".join(text.split())
    if len(text) > _MAX_EXPRESSION_LENGTH:
        text = text[: _MAX_EXPRESSION_LENGTH - 3] + "..."
    return text or "<dynamic>"


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


def _call_chain(node: ast.expr) -> list[str] | None:
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    parts.reverse()
    return parts


def _callee_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return _expression_text(node)


def _parameter_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    arguments = node.args
    return (
        len(arguments.posonlyargs)
        + len(arguments.args)
        + len(arguments.kwonlyargs)
        + (1 if arguments.vararg is not None else 0)
        + (1 if arguments.kwarg is not None else 0)
    )


def _definition_id(
    relative_path: str,
    kind: FunctionKind,
    qualified_name: str,
    line_number: int,
    column_number: int,
) -> str:
    return f"{relative_path}:{line_number}:{column_number}:{kind.value}:{qualified_name}"


class _ImportCollector(ast.NodeVisitor):
    """Collect imports in one lexical scope without entering nested scopes."""

    def __init__(self) -> None:
        self.imports = _FileImports()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.imports.modules[alias.asname] = _ImportModuleBinding(
                    alias.name,
                    0,
                )
            else:
                root = alias.name.split(".")[0]
                self.imports.modules[root] = _ImportModuleBinding(root, 0)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                continue
            self.imports.names[alias.asname or alias.name] = _ImportNameBinding(
                node.module,
                alias.name,
                node.level or 0,
            )


def _collect_imports(body: list[ast.stmt]) -> _FileImports:
    collector = _ImportCollector()
    for statement in body:
        collector.visit(statement)
    return collector.imports


class _DefinitionCollector(ast.NodeVisitor):
    """Collect function, method, and class definitions with lexical context."""

    def __init__(self, context: _FileContext) -> None:
        self.context = context
        self.name_stack: list[str] = []
        self.scope_stack: list[str] = []
        self.class_stack: list[_ClassRecord] = []
        self.function_stack: list[_Definition] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified_name = ".".join([*self.name_stack, node.name])
        record = _ClassRecord(
            source_file=self.context.relative_path,
            name=node.name,
            qualified_name=qualified_name,
            line_number=node.lineno,
            column_number=node.col_offset + 1,
            node=node,
        )
        self.context.classes.append(record)
        self.name_stack.append(node.name)
        self.scope_stack.append("class")
        self.class_stack.append(record)
        self.generic_visit(node)
        self.class_stack.pop()
        self.scope_stack.pop()
        self.name_stack.pop()

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualified_name = ".".join([*self.name_stack, node.name])
        parent_scope = self.scope_stack[-1] if self.scope_stack else None
        if parent_scope == "class":
            kind = FunctionKind.METHOD
        elif "function" in self.scope_stack:
            kind = FunctionKind.NESTED_FUNCTION
        else:
            kind = FunctionKind.FUNCTION

        enclosing_class = self.class_stack[-1] if self.class_stack else None
        enclosing_function = self.function_stack[-1] if self.function_stack else None
        column_number = node.col_offset + 1
        definition = _Definition(
            definition_id=_definition_id(
                self.context.relative_path,
                kind,
                qualified_name,
                node.lineno,
                column_number,
            ),
            name=node.name,
            qualified_name=qualified_name,
            kind=kind,
            source_file=self.context.relative_path,
            line_number=node.lineno,
            column_number=column_number,
            end_line_number=node.end_lineno or node.lineno,
            class_name=enclosing_class.name if enclosing_class else None,
            class_qualified_name=(enclosing_class.qualified_name if enclosing_class else None),
            parent_definition_id=(enclosing_function.definition_id if enclosing_function else None),
            is_async=isinstance(node, ast.AsyncFunctionDef),
            parameter_count=_parameter_count(node),
            decorator_lines=tuple(decorator.lineno for decorator in node.decorator_list),
            node=node,
            file=self.context,
        )
        self.context.definitions.append(definition)
        self.name_stack.append(node.name)
        self.scope_stack.append("function")
        self.function_stack.append(definition)
        self.generic_visit(node)
        self.function_stack.pop()
        self.scope_stack.pop()
        self.name_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)


def _build_file_context(relative_path: str, tree: ast.Module) -> _FileContext:
    context = _FileContext(
        relative_path=relative_path,
        module_name=_module_name(relative_path),
        package_parts=_package_parts(relative_path),
        tree=tree,
        imports=_collect_imports(tree.body),
        definitions=[],
        classes=[],
    )
    _DefinitionCollector(context).visit(tree)
    context.definitions = _sort_definitions(context.definitions)
    context.classes = sorted(
        context.classes,
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.column_number,
            item.qualified_name,
        ),
    )
    return context


def _sort_definitions(definitions: list[_Definition]) -> list[_Definition]:
    return sorted(
        definitions,
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.column_number,
            item.definition_id,
        ),
    )


class _BindingCollector(ast.NodeVisitor):
    """Collect simple single-name assignments without entering nested scopes."""

    def __init__(self) -> None:
        self.values: dict[str, list[ast.expr]] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self.values.setdefault(node.targets[0].id, []).append(node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.values.setdefault(node.target.id, []).append(node.value)
        self.generic_visit(node)


def _merge_receiver_bindings(
    bindings: list[_ReceiverBinding],
) -> _ReceiverBinding:
    class_refs: set[tuple[str, str]] = set()
    external = False
    unknown = False
    for binding in bindings:
        if binding.kind == "local_class":
            class_refs.update(binding.class_refs)
        elif binding.kind == "external":
            external = True
        else:
            unknown = True

    if class_refs and not external and not unknown:
        ordered = tuple(sorted(class_refs))
        if len(ordered) == 1:
            return _ReceiverBinding("local_class", ordered)
        return _ReceiverBinding("ambiguous", ordered)
    if external and not class_refs and not unknown:
        return _ReceiverBinding("external")
    if class_refs:
        return _ReceiverBinding("ambiguous", tuple(sorted(class_refs)))
    if external:
        return _ReceiverBinding("ambiguous")
    return _ReceiverBinding("unknown")


def _import_module_binding(
    context: _FileContext,
    caller: _Definition | None,
    name: str,
) -> _ImportModuleBinding | None:
    if caller is not None:
        local = context.definition_imports.get(caller.definition_id)
        if local is not None and name in local.modules:
            return local.modules[name]
    return context.imports.modules.get(name)


def _import_name_binding(
    context: _FileContext,
    caller: _Definition | None,
    name: str,
) -> _ImportNameBinding | None:
    if caller is not None:
        local = context.definition_imports.get(caller.definition_id)
        if local is not None and name in local.names:
            return local.names[name]
    return context.imports.names.get(name)


def _classify_receiver_expression(
    node: ast.expr,
    context: _FileContext,
    index: _AnalysisIndex,
    caller: _Definition | None,
) -> _ReceiverBinding:
    if not isinstance(node, ast.Call):
        return _ReceiverBinding("unknown")
    chain = _call_chain(node.func)
    if not chain:
        return _ReceiverBinding("unknown")

    base = chain[0]
    if len(chain) == 1:
        local_classes = [record for record in context.classes if record.name == base]
        if local_classes:
            return _ReceiverBinding(
                "local_class",
                tuple(
                    sorted((record.source_file, record.qualified_name) for record in local_classes)
                ),
            )
        imported = _import_name_binding(context, caller, base)
        if imported is not None:
            module = _absolute_module(context, imported.module, imported.level)
            if module:
                classes = index.module_classes(module, imported.name)
                if classes:
                    return _ReceiverBinding(
                        "local_class",
                        tuple(
                            sorted(
                                (record.source_file, record.qualified_name) for record in classes
                            )
                        ),
                    )
            return _ReceiverBinding("external")
        if _import_module_binding(context, caller, base) is not None:
            return _ReceiverBinding("external")
        if base in _BUILTIN_NAMES:
            return _ReceiverBinding("external")
        return _ReceiverBinding("unknown")

    if _import_module_binding(context, caller, base) is not None:
        return _ReceiverBinding("external")
    if _import_name_binding(context, caller, base) is not None:
        return _ReceiverBinding("external")
    if base in _BUILTIN_NAMES:
        return _ReceiverBinding("external")
    return _ReceiverBinding("unknown")


def _collect_receiver_bindings(
    context: _FileContext,
    body: list[ast.stmt],
    index: _AnalysisIndex,
    caller: _Definition | None,
) -> dict[str, _ReceiverBinding]:
    collector = _BindingCollector()
    for statement in body:
        collector.visit(statement)

    bindings: dict[str, _ReceiverBinding] = {}
    for name, values in collector.values.items():
        bindings[name] = _merge_receiver_bindings(
            [_classify_receiver_expression(value, context, index, caller) for value in values]
        )
    return bindings


def _lookup_receiver_binding(
    caller: _Definition,
    name: str,
    context: _FileContext,
) -> _ReceiverBinding | None:
    local = context.definition_bindings.get(caller.definition_id, {})
    if name in local:
        return local[name]
    return context.module_bindings.get(name)


def _visible_function_candidates(
    name: str,
    caller: _Definition,
    context: _FileContext,
) -> list[_Definition]:
    by_id = {definition.definition_id: definition for definition in context.definitions}
    visible_scope_ids: set[str] = set()
    current: _Definition | None = caller
    while current is not None:
        visible_scope_ids.add(current.definition_id)
        current = (
            by_id.get(current.parent_definition_id)
            if current.parent_definition_id is not None
            else None
        )

    matches: list[_Definition] = []
    for definition in context.definitions:
        if definition.name != name:
            continue
        if definition.kind is FunctionKind.METHOD:
            continue
        if definition.kind is FunctionKind.FUNCTION and definition.parent_definition_id is None:
            matches.append(definition)
        elif definition.definition_id == caller.definition_id:
            matches.append(definition)
        elif (
            definition.kind is FunctionKind.NESTED_FUNCTION
            and definition.parent_definition_id in visible_scope_ids
        ):
            matches.append(definition)
    unique = {definition.definition_id: definition for definition in matches}
    return _sort_definitions(list(unique.values()))


def _resolved(
    targets: list[_Definition],
    *,
    confidence: float,
    explanation: str,
    is_method_call: bool,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    ids = tuple(sorted(definition.definition_id for definition in targets))
    if len(ids) == 1:
        return _CallResolution(
            status=CallResolutionStatus.RESOLVED,
            target_ids=ids,
            confidence=confidence,
            explanation=explanation,
            is_method_call=is_method_call,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )
    return _CallResolution(
        status=CallResolutionStatus.AMBIGUOUS,
        target_ids=ids,
        confidence=_AMBIGUOUS_CALL_CONFIDENCE,
        explanation=(
            f"{len(ids)} local definitions match the call target and cannot be "
            "distinguished statically. " + explanation
        ),
        is_method_call=is_method_call,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _external(
    *,
    confidence: float,
    explanation: str,
    is_method_call: bool,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    return _CallResolution(
        status=CallResolutionStatus.EXTERNAL,
        target_ids=(),
        confidence=confidence,
        explanation=explanation,
        is_method_call=is_method_call,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _unresolved(
    *,
    explanation: str,
    is_method_call: bool,
    callee_name: str,
    receiver_expression: str | None,
    confidence: float = _UNRESOLVED_CALL_CONFIDENCE,
) -> _CallResolution:
    return _CallResolution(
        status=CallResolutionStatus.UNRESOLVED,
        target_ids=(),
        confidence=confidence,
        explanation=explanation,
        is_method_call=is_method_call,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _resolve_imported_name(
    binding: _ImportNameBinding,
    context: _FileContext,
    index: _AnalysisIndex,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    module = _absolute_module(context, binding.module, binding.level)
    if module is None:
        return _unresolved(
            explanation=(
                "The relative import escapes the repository package layout, so "
                "the imported call target cannot be resolved."
            ),
            is_method_call=False,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    submodule = f"{module}.{binding.name}" if module else binding.name
    if index.module_paths.get(submodule):
        return _external(
            confidence=_EXTERNAL_CONFIDENCE,
            explanation=(
                f"The imported name '{binding.name}' resolves to the repository "
                "module "
                f"'{submodule}', which is not a local function or method."
            ),
            is_method_call=False,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    definitions = index.module_top_level_defs(module, binding.name)
    if definitions:
        return _resolved(
            definitions,
            confidence=_CALL_REPOSITORY_CONFIDENCE,
            explanation=(
                f"The import maps '{binding.name}' to a unique top-level "
                f"definition in repository module '{module}'."
            ),
            is_method_call=False,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    classes = index.module_classes(module, binding.name)
    if classes:
        return _external(
            confidence=_EXTERNAL_CONFIDENCE,
            explanation=(
                f"The imported name '{binding.name}' is a locally defined class "
                "in a repository module, so the call is object construction "
                "rather than a local function or method call."
            ),
            is_method_call=False,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    if index.module_paths.get(module):
        return _unresolved(
            explanation=(
                f"Repository module '{module}' was found, but no unique "
                f"top-level function named '{binding.name}' is defined there."
            ),
            is_method_call=False,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
            confidence=0.40,
        )

    return _external(
        confidence=_EXTERNAL_CONFIDENCE,
        explanation=(
            f"The import target module '{module}' is not defined in the "
            "inspected repository, so the call is treated as external."
        ),
        is_method_call=False,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _resolve_methods(
    class_refs: list[tuple[str, str]],
    method_name: str,
    index: _AnalysisIndex,
    *,
    confidence: float,
    context_text: str,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    targets: list[_Definition] = []
    for source_file, class_qualified_name in class_refs:
        targets.extend(index.class_methods(source_file, class_qualified_name, method_name))
    targets = _sort_definitions(targets)
    unique = {definition.definition_id: definition for definition in targets}
    targets = _sort_definitions(list(unique.values()))

    if targets and len(class_refs) > 1:
        return _CallResolution(
            status=CallResolutionStatus.AMBIGUOUS,
            target_ids=tuple(sorted(unique)),
            confidence=_AMBIGUOUS_CALL_CONFIDENCE,
            explanation=(
                f"{context_text}, but the receiver class is ambiguous and "
                f"{len(unique)} candidate methods named '{method_name}' remain. "
                "No receiver class was guessed."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )
    if targets:
        return _resolved(
            targets,
            confidence=confidence,
            explanation=(
                f"{context_text}, and a local method named '{method_name}' matches that class."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    if len(class_refs) > 1:
        return _unresolved(
            explanation=(
                f"{context_text}, but the receiver class is ambiguous and no "
                f"local method named '{method_name}' was found."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
            confidence=0.40,
        )

    return _unresolved(
        explanation=(
            f"{context_text}, but no local method named '{method_name}' is "
            "defined on that class. Inherited and dynamically attached methods "
            "are not resolved."
        ),
        is_method_call=True,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
        confidence=0.40,
    )


def _resolve_module_chain(
    module: str,
    rest: list[str],
    index: _AnalysisIndex,
    *,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    for consumed in range(len(rest), -1, -1):
        candidate_module = ".".join([module, *rest[:consumed]]) if consumed else module
        if not index.module_paths.get(candidate_module):
            continue
        remaining = rest[consumed:]
        if not remaining:
            return _unresolved(
                explanation=(
                    f"The call targets repository module '{candidate_module}' "
                    "rather than a local function or method."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
                confidence=0.50,
            )
        if len(remaining) == 1:
            name = remaining[0]
            definitions = index.module_top_level_defs(candidate_module, name)
            if definitions:
                return _resolved(
                    definitions,
                    confidence=_CALL_REPOSITORY_CONFIDENCE,
                    explanation=(
                        f"The receiver resolves to repository module "
                        f"'{candidate_module}', where '{name}' is a unique "
                        "top-level definition."
                    ),
                    is_method_call=True,
                    callee_name=callee_name,
                    receiver_expression=receiver_expression,
                )
            classes = index.module_classes(candidate_module, name)
            if classes:
                return _external(
                    confidence=_EXTERNAL_CONFIDENCE,
                    explanation=(
                        f"The receiver resolves to repository module "
                        f"'{candidate_module}', where '{name}' is a class, so the "
                        "call is object construction rather than a local function "
                        "or method call."
                    ),
                    is_method_call=True,
                    callee_name=callee_name,
                    receiver_expression=receiver_expression,
                )
            return _unresolved(
                explanation=(
                    f"Repository module '{candidate_module}' was found, but no "
                    f"unique top-level function or class named '{name}' is "
                    "defined there."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
                confidence=0.40,
            )
        if len(remaining) == 2:
            class_name, method_name = remaining
            classes = index.module_classes(candidate_module, class_name)
            if classes:
                return _resolve_methods(
                    [(record.source_file, record.qualified_name) for record in classes],
                    method_name,
                    index,
                    confidence=_CALL_REPOSITORY_CONFIDENCE,
                    context_text=(
                        f"The receiver resolves to class '{class_name}' in "
                        f"repository module '{candidate_module}'"
                    ),
                    callee_name=callee_name,
                    receiver_expression=receiver_expression,
                )
            return _unresolved(
                explanation=(
                    f"Repository module '{candidate_module}' was found, but no "
                    f"local class named '{class_name}' is defined there."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
                confidence=0.40,
            )
        return _unresolved(
            explanation=(
                "The attribute receiver is deeper than the deterministic module, "
                "class, and method resolution rules support."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
            confidence=0.40,
        )

    return _external(
        confidence=_EXTERNAL_CONFIDENCE,
        explanation=(
            f"Module '{module}' is not defined in the inspected repository, so "
            "the call is treated as external."
        ),
        is_method_call=True,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _resolve_imported_attribute(
    binding: _ImportNameBinding,
    context: _FileContext,
    index: _AnalysisIndex,
    rest: list[str],
    *,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    module = _absolute_module(context, binding.module, binding.level)
    if module is None:
        return _unresolved(
            explanation=(
                "The relative import escapes the repository package layout, so "
                "the attribute receiver cannot be resolved."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    submodule = f"{module}.{binding.name}" if module else binding.name
    if index.module_paths.get(submodule):
        return _resolve_module_chain(
            submodule,
            rest,
            index,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    classes = index.module_classes(module, binding.name)
    if classes:
        if len(rest) != 1:
            return _unresolved(
                explanation=(
                    "The imported class is chained through more than one "
                    "attribute, which is not resolved statically."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
                confidence=0.40,
            )
        return _resolve_methods(
            [(record.source_file, record.qualified_name) for record in classes],
            rest[0],
            index,
            confidence=_CALL_REPOSITORY_CONFIDENCE,
            context_text=(
                f"The imported name '{binding.name}' is a class in repository module '{module}'"
            ),
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    if index.module_paths.get(module):
        return _unresolved(
            explanation=(
                f"Repository module '{module}' was found, but the imported name "
                f"'{binding.name}' is not a locally defined class there."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
            confidence=0.40,
        )

    return _external(
        confidence=_EXTERNAL_CONFIDENCE,
        explanation=(
            f"The imported name '{binding.name}' originates in module "
            f"'{module}', which is not defined in the inspected repository."
        ),
        is_method_call=True,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _resolve_name_call(
    name: str,
    caller: _Definition,
    context: _FileContext,
    index: _AnalysisIndex,
    *,
    receiver_expression: str | None,
) -> _CallResolution:
    candidates = _visible_function_candidates(name, caller, context)
    imported = _import_name_binding(context, caller, name)

    if candidates:
        ids = tuple(sorted(definition.definition_id for definition in candidates))
        if imported is not None:
            return _CallResolution(
                status=CallResolutionStatus.AMBIGUOUS,
                target_ids=ids,
                confidence=_AMBIGUOUS_CALL_CONFIDENCE,
                explanation=(
                    f"The name '{name}' has {len(ids)} local definitions and is "
                    "also bound by an import. The call target is retained as "
                    "ambiguous."
                ),
                is_method_call=False,
                callee_name=name,
                receiver_expression=receiver_expression,
            )
        return _resolved(
            candidates,
            confidence=_CALL_SAME_FILE_CONFIDENCE,
            explanation=(
                f"The call name '{name}' matches a local definition in the same source file."
            ),
            is_method_call=False,
            callee_name=name,
            receiver_expression=receiver_expression,
        )

    if imported is not None:
        return _resolve_imported_name(
            imported,
            context,
            index,
            name,
            receiver_expression,
        )

    local_classes = [record for record in context.classes if record.name == name]
    if local_classes:
        return _external(
            confidence=_EXTERNAL_CONFIDENCE,
            explanation=(
                f"The call name '{name}' is a locally defined class, so the call "
                "is object construction rather than a local function or method "
                "call."
            ),
            is_method_call=False,
            callee_name=name,
            receiver_expression=receiver_expression,
        )

    if name in _BUILTIN_NAMES:
        return _external(
            confidence=_EXTERNAL_CONFIDENCE,
            explanation=(
                f"The call name '{name}' is a Python builtin rather than a local definition."
            ),
            is_method_call=False,
            callee_name=name,
            receiver_expression=receiver_expression,
        )

    return _unresolved(
        explanation=(
            f"No local function definition, import binding, builtin, or "
            f"resolvable class named '{name}' was found. The call target is not "
            "guessed from name similarity."
        ),
        is_method_call=False,
        callee_name=name,
        receiver_expression=receiver_expression,
    )


def _resolve_attribute_call(
    chain: list[str],
    caller: _Definition,
    context: _FileContext,
    index: _AnalysisIndex,
    *,
    callee_name: str,
    receiver_expression: str | None,
) -> _CallResolution:
    base = chain[0]
    rest = chain[1:]

    if base in {"self", "cls"}:
        class_qualified_name = caller.class_qualified_name
        if class_qualified_name is None:
            return _unresolved(
                explanation=(
                    f"The receiver '{base}' is used outside a method, so the "
                    "local method target cannot be established."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
            )
        if len(rest) != 1:
            return _unresolved(
                explanation=(
                    f"The receiver '{base}' is chained through more than one "
                    "attribute, which is not resolved statically."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
                confidence=0.40,
            )
        return _resolve_methods(
            [(context.relative_path, class_qualified_name)],
            callee_name,
            index,
            confidence=_CALL_SELF_CONFIDENCE,
            context_text=(f"The receiver '{base}' is the enclosing class instance or class"),
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    module_binding = _import_module_binding(context, caller, base)
    if module_binding is not None:
        module = _absolute_module(
            context,
            module_binding.module,
            module_binding.level,
        )
        if module is None:
            return _unresolved(
                explanation=(
                    "The relative import escapes the repository package layout, "
                    "so the module receiver cannot be resolved."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
            )
        return _resolve_module_chain(
            module,
            rest,
            index,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    name_binding = _import_name_binding(context, caller, base)
    if name_binding is not None:
        return _resolve_imported_attribute(
            name_binding,
            context,
            index,
            rest,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    local_classes = [record for record in context.classes if record.name == base]
    if local_classes:
        if len(rest) != 1:
            return _unresolved(
                explanation=(
                    f"The locally defined class '{base}' is chained through more "
                    "than one attribute, which is not resolved statically."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
                confidence=0.40,
            )
        return _resolve_methods(
            [(record.source_file, record.qualified_name) for record in local_classes],
            callee_name,
            index,
            confidence=_CALL_SELF_CONFIDENCE,
            context_text=(f"The receiver '{base}' is a class defined in the same source file"),
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    binding = _lookup_receiver_binding(caller, base, context)
    if binding is not None:
        if binding.kind in {"local_class", "ambiguous"}:
            if len(rest) != 1:
                return _unresolved(
                    explanation=(
                        f"The receiver variable '{base}' is chained through more "
                        "than one attribute, which is not resolved statically."
                    ),
                    is_method_call=True,
                    callee_name=callee_name,
                    receiver_expression=receiver_expression,
                    confidence=0.40,
                )
            return _resolve_methods(
                list(binding.class_refs),
                callee_name,
                index,
                confidence=_CALL_REPOSITORY_CONFIDENCE,
                context_text=(
                    f"The receiver variable '{base}' is assigned a locally defined class"
                ),
                callee_name=callee_name,
                receiver_expression=receiver_expression,
            )
        if binding.kind == "external":
            return _external(
                confidence=_EXTERNAL_CONFIDENCE,
                explanation=(
                    f"The receiver variable '{base}' is bound to a call to an "
                    "imported or external symbol, so the call is treated as "
                    "external rather than as a local relationship."
                ),
                is_method_call=True,
                callee_name=callee_name,
                receiver_expression=receiver_expression,
            )
        return _unresolved(
            explanation=(
                f"The receiver variable '{base}' is assigned an expression whose "
                "type cannot be established statically."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    if base in _BUILTIN_NAMES:
        return _external(
            confidence=_EXTERNAL_CONFIDENCE,
            explanation=(
                f"The receiver '{base}' is a Python builtin rather than a local definition."
            ),
            is_method_call=True,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )

    return _unresolved(
        explanation=(
            f"No local class, import binding, or resolvable receiver assignment "
            f"named '{base}' was found. The receiver type is not guessed."
        ),
        is_method_call=True,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


def _resolve_call(
    node: ast.Call,
    caller: _Definition,
    context: _FileContext,
    index: _AnalysisIndex,
) -> _CallResolution:
    is_method_call = isinstance(node.func, ast.Attribute)
    receiver_expression = _safe_expression_text(node.func.value) if is_method_call else None
    callee_name = _callee_name(node.func)
    chain = _call_chain(node.func)
    if chain is None:
        return _unresolved(
            explanation=(
                "The callee expression is not a statically readable name or "
                "attribute chain, so no local target is inferred."
            ),
            is_method_call=is_method_call,
            callee_name=callee_name,
            receiver_expression=receiver_expression,
        )
    if len(chain) == 1:
        return _resolve_name_call(
            chain[0],
            caller,
            context,
            index,
            receiver_expression=receiver_expression,
        )
    return _resolve_attribute_call(
        chain,
        caller,
        context,
        index,
        callee_name=callee_name,
        receiver_expression=receiver_expression,
    )


class _CallCollector(ast.NodeVisitor):
    """Collect call expressions in one definition without entering nested scopes."""

    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)


def _definition_calls(definition: _Definition) -> list[ast.Call]:
    collector = _CallCollector()
    for statement in definition.node.body:
        collector.visit(statement)
    return sorted(
        collector.calls,
        key=lambda node: (node.lineno, node.col_offset, node.end_col_offset or 0),
    )


def _call_id(
    relative_path: str,
    node: ast.Call,
    caller: _Definition,
) -> str:
    return f"{relative_path}:{node.lineno}:{node.col_offset + 1}:call:{caller.definition_id}"


def _route_id(route: RouteCandidate) -> str:
    return (
        f"{route.source_file}:{route.line_number}:"
        f"{route.http_method.value}:{route.framework.value}:{route.path}"
    )


def _relationship_type(
    caller: _Definition,
    callee: _Definition,
    handler_definition_ids: frozenset[str],
) -> CallRelationshipType:
    if caller.definition_id in handler_definition_ids:
        return (
            CallRelationshipType.HANDLER_TO_METHOD
            if callee.kind is FunctionKind.METHOD
            else CallRelationshipType.HANDLER_TO_FUNCTION
        )
    if caller.kind is FunctionKind.METHOD:
        return (
            CallRelationshipType.METHOD_TO_METHOD
            if callee.kind is FunctionKind.METHOD
            else CallRelationshipType.METHOD_TO_FUNCTION
        )
    return (
        CallRelationshipType.FUNCTION_TO_METHOD
        if callee.kind is FunctionKind.METHOD
        else CallRelationshipType.FUNCTION_TO_FUNCTION
    )


def _handler_sort_key(handler: RouteHandler) -> tuple[object, ...]:
    return (
        handler.route_source_file,
        handler.route_line_number,
        handler.route_path,
        handler.http_method.value,
        handler.framework.value,
        handler.handler_name or "",
        handler.handler_id,
    )


def _definition_schema_sort_key(
    definition: LocalFunctionDefinition,
) -> tuple[object, ...]:
    return (
        definition.source_file,
        definition.line_number,
        definition.column_number,
        definition.definition_id,
    )


def _call_sort_key(call: CallSite) -> tuple[object, ...]:
    return (
        call.source_file,
        call.line_number,
        call.column_number,
        call.call_id,
    )


def _relationship_sort_key(
    relationship: CallRelationship,
) -> tuple[object, ...]:
    return (
        relationship.source_file,
        relationship.line_number,
        relationship.caller_definition_id,
        relationship.callee_definition_id,
        relationship.relationship_id,
    )


def _issue_sort_key(issue: AnalysisIssue) -> tuple[object, ...]:
    return (issue.source_file, issue.reason.value, issue.detail or "")


def _call_issue_sort_key(issue: HandlerCallIssue) -> tuple[object, ...]:
    return (
        issue.source_file,
        issue.line_number or 0,
        issue.category.value,
        issue.handler_id or "",
        issue.call_id or "",
        issue.definition_id or "",
        issue.explanation,
    )


def _dedupe_issues(issues: list[AnalysisIssue]) -> list[AnalysisIssue]:
    unique: dict[tuple[str, AnalysisIssueReason, str | None], AnalysisIssue] = {}
    for issue in issues:
        key = (issue.source_file, issue.reason, issue.detail)
        unique.setdefault(key, issue)
    return sorted(unique.values(), key=_issue_sort_key)


def _dedupe_call_issues(issues: list[HandlerCallIssue]) -> list[HandlerCallIssue]:
    unique: dict[tuple[object, ...], HandlerCallIssue] = {}
    for issue in issues:
        key = (
            issue.source_file,
            issue.line_number,
            issue.category,
            issue.handler_id,
            issue.call_id,
            issue.definition_id,
            issue.explanation,
        )
        unique.setdefault(key, issue)
    return sorted(unique.values(), key=_call_issue_sort_key)


def _dedupe_routes(routes: list[RouteCandidate]) -> list[RouteCandidate]:
    unique: dict[tuple[object, ...], RouteCandidate] = {}
    for route in routes:
        key = (
            route.path,
            route.http_method,
            route.framework,
            route.source_file,
            route.line_number,
            route.handler_name,
            route.resolution_status,
            route.detection_confidence,
        )
        unique.setdefault(key, route)
    return sorted(
        unique.values(),
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


def _resolve_handler_call_root(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: AttackSurfaceResult,
) -> Path:
    try:
        resolved_root = _resolve_root(root, inventory)
    except InvalidAttackSurfaceRootError as exc:
        raise InvalidHandlerCallRootError(str(exc)) from exc

    for label, value in (
        ("Technology detection", getattr(technologies, "root", None)),
        ("Attack surface", getattr(attack_surface, "root", None)),
    ):
        try:
            other_root = Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidHandlerCallRootError(
                f"{label} root is not a valid filesystem path"
            ) from exc
        if other_root != resolved_root:
            raise InvalidHandlerCallRootError(f"{label} root does not match the repository root")
    return resolved_root


def _build_handlers(
    routes: list[RouteCandidate],
    contexts: dict[str, _FileContext],
    call_issues: list[HandlerCallIssue],
) -> tuple[list[RouteHandler], frozenset[str]]:
    handlers: list[RouteHandler] = []
    handler_definition_ids: set[str] = set()

    for route in routes:
        handler_id = _route_id(route)
        definition_ids: list[str] = []
        resolution_status = HandlerResolutionStatus.UNRESOLVED
        confidence = _UNRESOLVED_CONFIDENCE
        explanation = ""

        if route.handler_name is None:
            confidence = 0.0
            explanation = (
                "Route extraction recorded no handler name, so no local "
                "definition can be linked to this route."
            )
            call_issues.append(
                HandlerCallIssue(
                    source_file=route.source_file,
                    line_number=route.line_number,
                    category=HandlerCallIssueCategory.MISSING_HANDLER_NAME,
                    handler_id=handler_id,
                    explanation=explanation,
                )
            )
        elif route.framework not in _PYTHON_FRAMEWORKS:
            confidence = _UNSUPPORTED_CONFIDENCE
            explanation = (
                f"Local call analysis supports Python source only. The "
                f"'{route.framework.value}' route handler is not parsed by this "
                "phase, so no handler definition is inferred."
            )
            call_issues.append(
                HandlerCallIssue(
                    source_file=route.source_file,
                    line_number=route.line_number,
                    category=HandlerCallIssueCategory.UNSUPPORTED_LANGUAGE,
                    handler_id=handler_id,
                    explanation=explanation,
                )
            )
        else:
            context = contexts.get(route.source_file)
            if context is None:
                confidence = _UNSUPPORTED_CONFIDENCE
                explanation = (
                    "The route source file was not successfully parsed as Python, "
                    "so no handler definition is available."
                )
                call_issues.append(
                    HandlerCallIssue(
                        source_file=route.source_file,
                        line_number=route.line_number,
                        category=HandlerCallIssueCategory.HANDLER_DEFINITION_NOT_FOUND,
                        handler_id=handler_id,
                        explanation=explanation,
                    )
                )
            else:
                candidates = [
                    definition
                    for definition in context.definitions
                    if definition.name == route.handler_name
                ]
                decorated = [
                    definition
                    for definition in candidates
                    if route.line_number in definition.decorator_lines
                ]
                chosen = decorated if decorated else candidates

                if len(chosen) == 1:
                    definition = chosen[0]
                    definition_ids = [definition.definition_id]
                    resolution_status = HandlerResolutionStatus.RESOLVED
                    if decorated:
                        confidence = _HANDLER_DECORATOR_CONFIDENCE
                        explanation = (
                            "Exactly one local definition matches the recorded "
                            "handler name and is decorated at the route declaration "
                            "line."
                        )
                    else:
                        confidence = _HANDLER_NAME_CONFIDENCE
                        explanation = (
                            "Exactly one local definition in the route's source "
                            "file matches the recorded handler name."
                        )
                elif len(chosen) > 1:
                    definition_ids = sorted(definition.definition_id for definition in chosen)
                    resolution_status = HandlerResolutionStatus.AMBIGUOUS
                    confidence = _AMBIGUOUS_CONFIDENCE
                    explanation = (
                        f"{len(chosen)} local definitions match the recorded "
                        "handler name and cannot be distinguished statically; all "
                        "plausible definitions are preserved."
                    )
                    call_issues.append(
                        HandlerCallIssue(
                            source_file=route.source_file,
                            line_number=route.line_number,
                            category=HandlerCallIssueCategory.AMBIGUOUS_HANDLER_DEFINITION,
                            handler_id=handler_id,
                            explanation=(
                                f"{explanation} Candidate definition identifiers: "
                                f"{', '.join(definition_ids)}."
                            ),
                        )
                    )
                else:
                    confidence = _UNRESOLVED_CONFIDENCE
                    explanation = (
                        "No local definition with the recorded handler name was "
                        "found in the route's source file. Cross-file handler "
                        "resolution is not attempted from a name alone."
                    )
                    call_issues.append(
                        HandlerCallIssue(
                            source_file=route.source_file,
                            line_number=route.line_number,
                            category=HandlerCallIssueCategory.HANDLER_DEFINITION_NOT_FOUND,
                            handler_id=handler_id,
                            explanation=explanation,
                        )
                    )

        for definition_id in definition_ids:
            handler_definition_ids.add(definition_id)
            matching = next(
                (
                    definition
                    for context in contexts.values()
                    for definition in context.definitions
                    if definition.definition_id == definition_id
                ),
                None,
            )
            if matching is not None and handler_id not in matching.route_ids:
                matching.route_ids.append(handler_id)

        handlers.append(
            RouteHandler(
                handler_id=handler_id,
                route_id=handler_id,
                route_path=route.path,
                http_method=route.http_method,
                framework=route.framework,
                route_source_file=route.source_file,
                route_line_number=route.line_number,
                route_resolution_status=route.resolution_status,
                handler_name=route.handler_name,
                definition_ids=definition_ids,
                resolution_status=resolution_status,
                detection_confidence=confidence,
                explanation=explanation,
            )
        )

    handlers.sort(key=_handler_sort_key)
    return handlers, frozenset(handler_definition_ids)


def analyze_handler_calls(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    technologies: TechnologyDetectionResult,
    attack_surface: AttackSurfaceResult,
    *,
    max_source_file_size_bytes: int | None = None,
    max_source_files: int | None = None,
) -> HandlerCallResult:
    """Identify route handlers and local call relationships in Python source.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match the discovery inventory, technology detection result, and attack
    surface result. Only source files already present in the inventory are read.
    Repository code is never executed or imported.
    """
    resolved_root = _resolve_handler_call_root(
        root,
        inventory,
        technologies,
        attack_surface,
    )

    max_size = (
        settings.handler_call_source_max_size_bytes
        if max_source_file_size_bytes is None
        else max_source_file_size_bytes
    )
    max_files = (
        settings.handler_call_max_source_files if max_source_files is None else max_source_files
    )
    if max_size < 0 or max_files < 0:
        raise HandlerCallAnalysisError("Source inspection limits must not be negative")

    module_paths = _module_paths_from_inventory(inventory)
    issues = _discovery_source_issues(inventory)
    contexts: dict[str, _FileContext] = {}
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
        if extension not in _PYTHON_EXTENSIONS:
            continue

        try:
            tree = ast.parse(text, filename=relative_path)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.INVALID_SYNTAX,
                    f"Python source could not be parsed: {exc}",
                )
            )
            continue

        try:
            contexts[relative_path] = _build_file_context(relative_path, tree)
        except (RecursionError, ValueError) as exc:
            issues.append(
                _issue(
                    relative_path,
                    AnalysisIssueReason.UNSUPPORTED_SYNTAX,
                    f"Python definitions could not be collected safely: {exc}",
                )
            )
            continue

    definitions_by_file: dict[str, list[_Definition]] = {}
    definitions_by_id: dict[str, _Definition] = {}
    for relative_path, context in contexts.items():
        definitions_by_file[relative_path] = context.definitions
        for definition in context.definitions:
            definitions_by_id[definition.definition_id] = definition

    index_data = _AnalysisIndex(
        contexts=contexts,
        module_paths=module_paths,
        definitions_by_id=definitions_by_id,
        definitions_by_file=definitions_by_file,
    )

    for context in contexts.values():
        context.module_bindings = _collect_receiver_bindings(
            context,
            context.tree.body,
            index_data,
            None,
        )
        for definition in context.definitions:
            context.definition_imports[definition.definition_id] = _collect_imports(
                definition.node.body
            )
            context.definition_bindings[definition.definition_id] = _collect_receiver_bindings(
                context,
                definition.node.body,
                index_data,
                definition,
            )

    routes = _dedupe_routes(list(attack_surface.routes))
    call_issues: list[HandlerCallIssue] = []
    handlers, handler_definition_ids = _build_handlers(
        routes,
        contexts,
        call_issues,
    )

    calls: list[CallSite] = []
    relationships: list[CallRelationship] = []

    for definition in sorted(
        definitions_by_id.values(),
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.column_number,
            item.definition_id,
        ),
    ):
        context = contexts.get(definition.source_file)
        if context is None:
            continue
        for node in _definition_calls(definition):
            call_id = _call_id(definition.source_file, node, definition)
            resolution = _resolve_call(node, definition, context, index_data)
            is_recursive = definition.definition_id in resolution.target_ids
            calls.append(
                CallSite(
                    call_id=call_id,
                    caller_definition_id=definition.definition_id,
                    caller_name=definition.name,
                    caller_kind=definition.kind,
                    source_file=definition.source_file,
                    line_number=node.lineno,
                    column_number=node.col_offset + 1,
                    callee_expression=_expression_text(node.func),
                    callee_name=resolution.callee_name,
                    receiver_expression=resolution.receiver_expression,
                    is_method_call=resolution.is_method_call,
                    resolution_status=resolution.status,
                    target_definition_ids=list(resolution.target_ids),
                    is_recursive=is_recursive,
                    detection_confidence=resolution.confidence,
                    explanation=resolution.explanation,
                )
            )

            if resolution.status in {
                CallResolutionStatus.RESOLVED,
                CallResolutionStatus.AMBIGUOUS,
            }:
                for target_id in resolution.target_ids:
                    callee = index_data.definitions_by_id.get(target_id)
                    if callee is None:
                        continue
                    relationships.append(
                        CallRelationship(
                            relationship_id=f"{call_id}->{target_id}",
                            relationship_type=_relationship_type(
                                definition,
                                callee,
                                handler_definition_ids,
                            ),
                            caller_definition_id=definition.definition_id,
                            callee_definition_id=target_id,
                            call_id=call_id,
                            source_file=definition.source_file,
                            line_number=node.lineno,
                            resolution_status=resolution.status,
                            is_recursive=definition.definition_id == target_id,
                            detection_confidence=resolution.confidence,
                            explanation=resolution.explanation,
                        )
                    )
                if resolution.status is CallResolutionStatus.AMBIGUOUS:
                    call_issues.append(
                        HandlerCallIssue(
                            source_file=definition.source_file,
                            line_number=node.lineno,
                            category=HandlerCallIssueCategory.AMBIGUOUS_CALL,
                            call_id=call_id,
                            definition_id=definition.definition_id,
                            explanation=resolution.explanation,
                        )
                    )
            elif resolution.status is CallResolutionStatus.UNRESOLVED:
                call_issues.append(
                    HandlerCallIssue(
                        source_file=definition.source_file,
                        line_number=node.lineno,
                        category=HandlerCallIssueCategory.UNRESOLVED_CALL,
                        call_id=call_id,
                        definition_id=definition.definition_id,
                        explanation=resolution.explanation,
                    )
                )

    definition_schemas = [
        LocalFunctionDefinition(
            definition_id=definition.definition_id,
            name=definition.name,
            qualified_name=definition.qualified_name,
            kind=definition.kind,
            source_file=definition.source_file,
            line_number=definition.line_number,
            column_number=definition.column_number,
            end_line_number=definition.end_line_number,
            class_name=definition.class_name,
            parent_definition_id=definition.parent_definition_id,
            is_async=definition.is_async,
            parameter_count=definition.parameter_count,
            is_route_handler=bool(definition.route_ids),
            route_ids=sorted(definition.route_ids),
            detection_confidence=_DEFINITION_CONFIDENCE,
        )
        for definition in sorted(
            definitions_by_id.values(),
            key=lambda item: (
                item.source_file,
                item.line_number,
                item.column_number,
                item.definition_id,
            ),
        )
    ]

    calls.sort(key=_call_sort_key)
    relationships.sort(key=_relationship_sort_key)
    sorted_issues = _dedupe_issues(issues)
    sorted_call_issues = _dedupe_call_issues(call_issues)

    resolved_handler_count = sum(
        handler.resolution_status is HandlerResolutionStatus.RESOLVED for handler in handlers
    )
    ambiguous_handler_count = sum(
        handler.resolution_status is HandlerResolutionStatus.AMBIGUOUS for handler in handlers
    )
    unresolved_handler_count = sum(
        handler.resolution_status is HandlerResolutionStatus.UNRESOLVED for handler in handlers
    )

    summary = HandlerCallSummary(
        source_files_inspected=inspected,
        route_handler_count=len(handlers),
        resolved_handler_count=resolved_handler_count,
        ambiguous_handler_count=ambiguous_handler_count,
        unresolved_handler_count=unresolved_handler_count,
        definition_count=len(definition_schemas),
        function_definition_count=sum(
            definition.kind is FunctionKind.FUNCTION for definition in definition_schemas
        ),
        method_definition_count=sum(
            definition.kind is FunctionKind.METHOD for definition in definition_schemas
        ),
        nested_function_definition_count=sum(
            definition.kind is FunctionKind.NESTED_FUNCTION for definition in definition_schemas
        ),
        call_site_count=len(calls),
        resolved_call_count=sum(
            call.resolution_status is CallResolutionStatus.RESOLVED for call in calls
        ),
        ambiguous_call_count=sum(
            call.resolution_status is CallResolutionStatus.AMBIGUOUS for call in calls
        ),
        unresolved_call_count=sum(
            call.resolution_status is CallResolutionStatus.UNRESOLVED for call in calls
        ),
        external_call_count=sum(
            call.resolution_status is CallResolutionStatus.EXTERNAL for call in calls
        ),
        recursive_call_count=sum(call.is_recursive for call in calls),
        relationship_count=len(relationships),
        issue_count=len(sorted_issues),
        call_issue_count=len(sorted_call_issues),
        is_complete=(
            inventory.summary.is_complete
            and attack_surface.summary.is_complete
            and not sorted_issues
        ),
        discovery_is_complete=inventory.summary.is_complete,
        route_analysis_is_complete=attack_surface.summary.is_complete,
        discovery_truncation_reasons=list(inventory.summary.truncation_reasons),
        route_analysis_truncation_reasons=list(attack_surface.summary.discovery_truncation_reasons),
    )

    return HandlerCallResult(
        root=str(resolved_root),
        handlers=handlers,
        definitions=definition_schemas,
        calls=calls,
        relationships=relationships,
        issues=sorted_issues,
        call_issues=sorted_call_issues,
        summary=summary,
    )
