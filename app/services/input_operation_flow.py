"""Deterministic, read-only input-to-sensitive-operation relationship analysis.

The analyzer consumes the completed input-source, sensitive-operation,
handler-call, and attack-surface-correlation results. It reuses the recorded
evidence and the resolved local call graph; it does not rediscover routes, inputs,
operations, or calls.

Additional Python AST parsing is necessary because the existing evidence records
source locations and expressions but not the assignment, argument, parameter, and
return edges needed to connect them. Only inventoried Python files referenced by
that evidence or by the resolved call graph are parsed. Repository code is never
executed or imported, no network, shell, subprocess, Git, or LLM calls are made,
and nothing is persisted.

A relationship means only that a statically supported propagation path was found
between an input evidence candidate and a sensitive-operation evidence candidate.
It does not prove runtime execution, runtime value flow, absent validation, or
exploitability. External-call return values, object fields, dynamic dispatch, and
unsupported syntax stop propagation rather than producing a guessed edge.
"""

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from app.core.config import settings
from app.schemas.attack_surface import AnalysisIssue, AnalysisIssueReason
from app.schemas.attack_surface_correlation import AttackSurfaceCorrelationResult
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.handler_calls import (
    CallResolutionStatus,
    CallSite,
    FunctionKind,
    HandlerCallResult,
    LocalFunctionDefinition,
    RouteHandler,
)
from app.schemas.input_operation_flow import (
    FlowAnalysisSource,
    FlowIssueCategory,
    FlowPropagationKind,
    FlowResolutionStatus,
    FlowSourceStatus,
    HandlerReference,
    InputOperationFlowResult,
    InputOperationFlowSummary,
    InputOperationIssue,
    InputOperationRelationship,
    PropagationStep,
)
from app.schemas.input_sources import (
    InputCandidate,
    InputResolutionStatus,
    InputSourceResult,
    InputType,
)
from app.schemas.repository_discovery import FileInventoryEntry, RepositoryDiscoveryResult
from app.schemas.sensitive_operations import (
    OperationResolutionStatus,
    SensitiveOperationCandidate,
    SensitiveOperationResult,
)
from app.services.attack_surface import (
    _PYTHON_EXTENSIONS,
    InvalidAttackSurfaceRootError,
    _collect_module_constants,
    _discovery_source_issues,
    _extension,
    _has_excluded_component,
    _is_sensitive_path,
    _python_expression_text,
    _read_source_text,
    _resolve_root,
    _validate_source_path,
)

_MAX_EXPRESSION_LENGTH: Final[int] = 200
# Repository-wide issues use this repository-relative label instead of the
# resolved absolute root, which must never leave the service boundary.
_REPOSITORY_ROOT_LABEL: Final[str] = "."
_STATUS_CONFIDENCE_CAP: Final[dict[FlowResolutionStatus, float]] = {
    FlowResolutionStatus.RESOLVED: 1.0,
    FlowResolutionStatus.AMBIGUOUS: 1.0,
    FlowResolutionStatus.UNRESOLVED: 0.5,
    FlowResolutionStatus.UNSUPPORTED: 0.5,
}
_LIMITATIONS: Final[tuple[str, ...]] = (
    "Static analysis only: the path may not execute at runtime.",
    "No full control-flow, value, sanitization, or field-sensitivity analysis.",
    "External call return values, object fields, inherited methods, and dynamic "
    "dispatch are not tracked.",
)
_MAPPING_METHODS: Final[frozenset[str]] = frozenset({"get", "getlist", "getall"})


class InputOperationFlowError(ValueError):
    """Base error for input-to-operation flow analysis."""


class InvalidInputOperationRootError(InputOperationFlowError):
    """Raised when supplied analysis results do not share one safe repository root."""


@dataclass
class _ParsedFile:
    """Parsed Python source state for one inventoried file."""

    relative_path: str
    tree: ast.Module
    constants: dict[str, str]
    function_nodes_by_key: dict[tuple[int, int, str], list[ast.FunctionDef | ast.AsyncFunctionDef]]
    expression_nodes_by_line: dict[int, list[ast.expr]]


@dataclass(frozen=True)
class _FunctionNode:
    """A handler-call definition linked to its parsed AST node."""

    definition: LocalFunctionDefinition
    node: ast.FunctionDef | ast.AsyncFunctionDef
    source_file: str
    positional: tuple[str, ...]
    keyword_only: tuple[str, ...]
    vararg: str | None
    kwarg: str | None
    argument_nodes: dict[str, ast.arg]

    @property
    def all_parameters(self) -> frozenset[str]:
        return frozenset({*self.positional, *self.keyword_only})


@dataclass(frozen=True)
class _InputEvidence:
    """Input evidence and the AST seed(s) used to propagate it."""

    input_id: str
    index: int
    candidate: InputCandidate
    seed_definition_ids: tuple[str, ...]
    parameter_name: str | None
    anchor_node_ids: tuple[int, ...]
    anchor_ambiguous: bool


@dataclass(frozen=True)
class _OperationEvidence:
    """Operation evidence and the AST sink(s) used to detect it."""

    operation_id: str
    index: int
    candidate: SensitiveOperationCandidate
    definition_ids: tuple[str, ...]
    anchor_node_ids: tuple[int, ...]
    anchor_ambiguous: bool


@dataclass(frozen=True)
class _FlowPath:
    """One representative propagation path for one input in one value."""

    steps: tuple[PropagationStep, ...] = ()
    call_ids: tuple[str, ...] = ()
    ambiguous_definition_ids: tuple[str, ...] = ()
    unsupported_reasons: tuple[str, ...] = ()


@dataclass
class _Summary:
    """Result of analyzing one definition under one parameter-taint state."""

    operations: dict[tuple[str, str], _FlowPath] = field(default_factory=dict)
    returns: dict[str, _FlowPath] = field(default_factory=dict)


@dataclass
class _AnalysisContext:
    """Lookup tables shared by all parsed files and definitions."""

    parsed_files: dict[str, _ParsedFile]
    functions: dict[str, _FunctionNode]
    call_index: dict[tuple[str, int, int], CallSite]
    call_sites: dict[str, CallSite]
    input_anchors: dict[int, tuple[str, ...]]
    operation_anchors: dict[int, tuple[str, ...]]
    input_evidence: dict[str, _InputEvidence]
    operation_evidence: dict[str, _OperationEvidence]
    parameter_seeds: dict[str, dict[str, set[str]]]
    functions_with_inputs: frozenset[str]
    functions_with_operations: frozenset[str]


def _issue(
    source_file: str,
    category: FlowIssueCategory,
    explanation: str,
    *,
    line_number: int | None = None,
    input_id: str | None = None,
    operation_id: str | None = None,
    call_id: str | None = None,
    definition_id: str | None = None,
) -> InputOperationIssue:
    return InputOperationIssue(
        source_file=source_file,
        line_number=line_number,
        category=category,
        input_id=input_id,
        operation_id=operation_id,
        call_id=call_id,
        definition_id=definition_id,
        explanation=explanation,
    )


def _normalized_root(value: str | Path) -> str:
    return os.path.normcase(os.path.normpath(str(value)))


def _resolve_flow_root(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    correlation: AttackSurfaceCorrelationResult,
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
    handler_calls: HandlerCallResult,
) -> Path:
    try:
        resolved_root = _resolve_root(root, inventory)
    except InvalidAttackSurfaceRootError as exc:
        raise InvalidInputOperationRootError(str(exc)) from exc

    expected = _normalized_root(resolved_root)
    for label, value in (
        ("Attack surface correlation", correlation.root),
        ("Input sources", input_sources.root),
        ("Sensitive operations", sensitive_operations.root),
        ("Handler calls", handler_calls.root),
    ):
        try:
            normalized = _normalized_root(Path(value).expanduser().resolve(strict=False))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidInputOperationRootError(
                f"{label} root is not a valid filesystem path"
            ) from exc
        if normalized != expected:
            raise InvalidInputOperationRootError(f"{label} root does not match the repository root")
    return resolved_root


def _input_sort_key(candidate: InputCandidate) -> tuple[object, ...]:
    return (
        candidate.source_file,
        candidate.line_number,
        candidate.input_type.value,
        candidate.framework.value,
        candidate.parameter_name or "",
        candidate.variable_name or "",
        candidate.handler_name or "",
        candidate.declaration_or_access,
        candidate.evidence,
        candidate.classification_rule,
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
        candidate.evidence,
        candidate.classification_rule,
    )


def _input_identity(candidate: InputCandidate) -> tuple[object, ...]:
    return (
        candidate.source_file,
        candidate.line_number,
        candidate.input_type.value,
        candidate.framework.value,
        candidate.declaration_or_access,
        candidate.parameter_name or "",
        candidate.variable_name or "",
        candidate.handler_name or "",
    )


def _operation_identity(candidate: SensitiveOperationCandidate) -> tuple[object, ...]:
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


def _safe_chain(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _safe_chain(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _safe_chain(node.func)
    if isinstance(node, ast.Subscript):
        return _safe_chain(node.value)
    return None


def _safe_display(node: ast.AST | None) -> str:
    text = _safe_chain(node)
    if text is None:
        text = "<expression>"
    if len(text) > _MAX_EXPRESSION_LENGTH:
        text = text[: _MAX_EXPRESSION_LENGTH - 3] + "..."
    return text


def _constant_string(node: ast.expr | None, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _input_node_display(node: ast.expr, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            base = _safe_chain(node.func.value)
            if not base:
                return None
            if node.func.attr in _MAPPING_METHODS:
                key = _constant_string(node.args[0] if node.args else None, constants)
                if key is None:
                    return f"{base}.{node.func.attr}(<dynamic>)"
                return f"{base}.{node.func.attr}({key!r})"
            return f"{base}.{node.func.attr}()"
        if isinstance(node.func, ast.Name):
            return f"{node.func.id}()"
        return None
    if isinstance(node, ast.Subscript):
        base = _safe_chain(node.value)
        if not base:
            return None
        key = _constant_string(node.slice, constants)
        if key is None:
            return f"{base}[<dynamic>]"
        return f"{base}[{key!r}]"
    if isinstance(node, ast.Attribute):
        return _safe_chain(node)
    return None


def _callee_display(node: ast.Call) -> str | None:
    return _safe_chain(node.func)


def _parameter_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[tuple[str, ...], tuple[str, ...], str | None, str | None, dict[str, ast.arg]]:
    positional = tuple(argument.arg for argument in [*node.args.posonlyargs, *node.args.args])
    keyword_only = tuple(argument.arg for argument in node.args.kwonlyargs)
    vararg = node.args.vararg.arg if node.args.vararg is not None else None
    kwarg = node.args.kwarg.arg if node.args.kwarg is not None else None
    nodes: dict[str, ast.arg] = {}
    for argument in [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]:
        nodes.setdefault(argument.arg, argument)
    if node.args.vararg is not None:
        nodes.setdefault(node.args.vararg.arg, node.args.vararg)
    if node.args.kwarg is not None:
        nodes.setdefault(node.args.kwarg.arg, node.args.kwarg)
    return positional, keyword_only, vararg, kwarg, nodes


def _parse_file(relative_path: str, text: str) -> _ParsedFile:
    tree = ast.parse(text, filename=relative_path)
    function_nodes_by_key: dict[
        tuple[int, int, str], list[ast.FunctionDef | ast.AsyncFunctionDef]
    ] = {}
    expression_nodes_by_line: dict[int, list[ast.expr]] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_nodes_by_key.setdefault(
                (node.lineno, node.col_offset + 1, node.name),
                [],
            ).append(node)
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)):
            expression_nodes_by_line.setdefault(node.lineno, []).append(node)

    return _ParsedFile(
        relative_path=relative_path,
        tree=tree,
        constants=_collect_module_constants(tree),
        function_nodes_by_key=function_nodes_by_key,
        expression_nodes_by_line=expression_nodes_by_line,
    )


def _load_parsed_files(
    resolved_root: Path,
    inventory: RepositoryDiscoveryResult,
    relevant_files: set[str],
    *,
    max_size: int,
    max_files: int,
) -> tuple[dict[str, _ParsedFile], list[AnalysisIssue], int, bool]:
    issues = _discovery_source_issues(inventory)
    inventory_by_path = {entry.relative_path: entry for entry in inventory.files}
    sorted_files = sorted(relevant_files)
    limit_hit = False
    if len(sorted_files) > max_files:
        remaining = len(sorted_files) - max_files
        issues.append(
            AnalysisIssue(
                source_file=sorted_files[max_files],
                reason=AnalysisIssueReason.MAX_SOURCE_FILES,
                detail=(
                    f"Maximum of {max_files} relevant source files reached; "
                    f"{remaining} eligible files were not inspected"
                ),
            )
        )
        sorted_files = sorted_files[:max_files]
        limit_hit = True

    parsed: dict[str, _ParsedFile] = {}
    inspected = 0
    for relative_path in sorted_files:
        entry: FileInventoryEntry | None = inventory_by_path.get(relative_path)
        if entry is None:
            issues.append(
                AnalysisIssue(
                    source_file=relative_path,
                    reason=AnalysisIssueReason.DISAPPEARED,
                    detail="Evidence references a source file absent from the inventory",
                )
            )
            continue
        if _extension(relative_path, entry.extension) not in _PYTHON_EXTENSIONS:
            continue
        if _has_excluded_component(relative_path):
            issues.append(
                AnalysisIssue(
                    source_file=relative_path,
                    reason=AnalysisIssueReason.EXCLUDED_PATH,
                    detail="Path contains an excluded dependency or cache directory",
                )
            )
            continue
        if _is_sensitive_path(relative_path):
            issues.append(
                AnalysisIssue(
                    source_file=relative_path,
                    reason=AnalysisIssueReason.SENSITIVE_FILE,
                    detail="Sensitive file is never inspected",
                )
            )
            continue

        source_path, path_issue = _validate_source_path(resolved_root, relative_path, max_size)
        if path_issue is not None:
            issues.append(path_issue)
            continue
        text, read_issue = _read_source_text(source_path, relative_path, max_size)
        if read_issue is not None:
            issues.append(read_issue)
            continue

        inspected += 1
        try:
            parsed[relative_path] = _parse_file(relative_path, text)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            issues.append(
                AnalysisIssue(
                    source_file=relative_path,
                    reason=AnalysisIssueReason.INVALID_SYNTAX,
                    detail=f"Python source could not be parsed: {exc}",
                )
            )
    return parsed, issues, inspected, limit_hit


def _build_functions(
    parsed_files: dict[str, _ParsedFile],
    handler_calls: HandlerCallResult,
    issues: list[InputOperationIssue],
) -> dict[str, _FunctionNode]:
    functions: dict[str, _FunctionNode] = {}
    for definition in sorted(handler_calls.definitions, key=lambda item: item.definition_id):
        parsed = parsed_files.get(definition.source_file)
        if parsed is None:
            issues.append(
                _issue(
                    definition.source_file,
                    FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                    (
                        "The source file for a resolved local function definition was "
                        "not inspected, so interprocedural propagation through it is "
                        "not attempted."
                    ),
                    line_number=definition.line_number,
                    definition_id=definition.definition_id,
                )
            )
            continue
        key = (definition.line_number, definition.column_number, definition.name)
        matches = parsed.function_nodes_by_key.get(key, [])
        if len(matches) != 1:
            issues.append(
                _issue(
                    definition.source_file,
                    FlowIssueCategory.AMBIGUOUS_EVIDENCE_LOCATION
                    if matches
                    else FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                    (
                        "The resolved function definition could not be matched to "
                        "exactly one parsed AST function node."
                    ),
                    line_number=definition.line_number,
                    definition_id=definition.definition_id,
                )
            )
            continue
        node = matches[0]
        positional, keyword_only, vararg, kwarg, argument_nodes = _parameter_names(node)
        functions[definition.definition_id] = _FunctionNode(
            definition=definition,
            node=node,
            source_file=definition.source_file,
            positional=positional,
            keyword_only=keyword_only,
            vararg=vararg,
            kwarg=kwarg,
            argument_nodes=argument_nodes,
        )
    return functions


def _innermost_function(
    functions_by_file: dict[str, list[_FunctionNode]],
    source_file: str,
    line_number: int,
) -> _FunctionNode | None:
    matches = [
        function
        for function in functions_by_file.get(source_file, [])
        if function.definition.line_number <= line_number <= function.definition.end_line_number
    ]
    if not matches:
        return None
    return max(
        matches,
        key=lambda item: (
            item.definition.line_number,
            item.definition.column_number,
            item.definition.definition_id,
        ),
    )


def _match_input_anchor(
    parsed: _ParsedFile,
    candidate: InputCandidate,
) -> tuple[list[ast.expr], bool]:
    nodes = [
        node
        for node in parsed.expression_nodes_by_line.get(candidate.line_number, [])
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript))
    ]
    exact: list[ast.expr] = []
    for node in nodes:
        display = _input_node_display(node, parsed.constants)
        if display == candidate.declaration_or_access:
            exact.append(node)
        elif _python_expression_text(node) == candidate.declaration_or_access:
            exact.append(node)
    if exact:
        unique: dict[int, ast.expr] = {id(node): node for node in exact}
        return list(unique.values()), len(unique) > 1

    structural: list[ast.expr] = []
    for node in nodes:
        display = _input_node_display(node, parsed.constants) or ""
        if display and candidate.declaration_or_access.startswith(display.split("(")[0]):
            structural.append(node)
    unique = {id(node): node for node in structural}
    if len(unique) == 1:
        return list(unique.values()), False
    return [], bool(unique)


def _match_operation_anchor(
    parsed: _ParsedFile,
    candidate: SensitiveOperationCandidate,
) -> tuple[list[ast.Call], bool]:
    nodes = [
        node
        for node in parsed.expression_nodes_by_line.get(candidate.line_number, [])
        if isinstance(node, ast.Call)
    ]
    exact = [node for node in nodes if _callee_display(node) == candidate.declaration_or_access]
    if exact:
        unique = {id(node): node for node in exact}
        return list(unique.values()), len(unique) > 1

    by_name = [
        node
        for node in nodes
        if (_safe_chain(node.func) or "").rsplit(".", 1)[-1] == candidate.operation_name
    ]
    unique = {id(node): node for node in by_name}
    if len(unique) == 1:
        return list(unique.values()), False
    return [], bool(unique)


def _build_evidence(
    parsed_files: dict[str, _ParsedFile],
    functions: dict[str, _FunctionNode],
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
    issues: list[InputOperationIssue],
) -> tuple[
    dict[str, _InputEvidence],
    dict[str, _OperationEvidence],
    dict[int, tuple[str, ...]],
    dict[int, tuple[str, ...]],
    dict[str, dict[str, set[str]]],
    frozenset[str],
    frozenset[str],
]:
    functions_by_file: dict[str, list[_FunctionNode]] = {}
    for function in functions.values():
        functions_by_file.setdefault(function.source_file, []).append(function)
    for entries in functions_by_file.values():
        entries.sort(key=lambda item: (item.definition.line_number, item.definition.column_number))

    input_evidence: dict[str, _InputEvidence] = {}
    operation_evidence: dict[str, _OperationEvidence] = {}
    input_anchors: dict[int, list[str]] = {}
    operation_anchors: dict[int, list[str]] = {}
    parameter_seeds: dict[str, dict[str, set[str]]] = {}
    functions_with_inputs: set[str] = set()
    functions_with_operations: set[str] = set()

    input_entries = list(enumerate(input_sources.inputs))
    input_entries.sort(key=lambda item: (_input_sort_key(item[1]), item[0]))
    for index, candidate in input_entries:
        input_id = f"inputs[{index}]"
        extension = _extension(candidate.source_file, None)
        if extension not in _PYTHON_EXTENSIONS:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.UNSUPPORTED_LANGUAGE,
                    (
                        "Input-to-operation propagation currently supports Python "
                        "source only; this evidence is preserved without a flow edge."
                    ),
                    line_number=candidate.line_number,
                    input_id=input_id,
                )
            )
            input_evidence[input_id] = _InputEvidence(
                input_id=input_id,
                index=index,
                candidate=candidate,
                seed_definition_ids=(),
                parameter_name=None,
                anchor_node_ids=(),
                anchor_ambiguous=False,
            )
            continue

        parsed = parsed_files.get(candidate.source_file)
        if parsed is None:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                    "The input evidence source file was not parsed.",
                    line_number=candidate.line_number,
                    input_id=input_id,
                )
            )
            input_evidence[input_id] = _InputEvidence(
                input_id=input_id,
                index=index,
                candidate=candidate,
                seed_definition_ids=(),
                parameter_name=None,
                anchor_node_ids=(),
                anchor_ambiguous=False,
            )
            continue

        if candidate.resolution_status is InputResolutionStatus.UNRESOLVED:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.UNRESOLVED_INPUT_EVIDENCE,
                    (
                        "The input evidence is unresolved in its source analysis; "
                        "that original status is preserved on any relationship."
                    ),
                    line_number=candidate.line_number,
                    input_id=input_id,
                )
            )

        seed_definition_ids: list[str] = []
        parameter_name: str | None = None
        anchor_node_ids: list[int] = []
        anchor_ambiguous = False

        if (
            candidate.variable_name is not None
            and candidate.handler_name is not None
            and candidate.input_type is not InputType.REQUEST_OBJECT
        ):
            candidates = [
                function
                for function in functions_by_file.get(candidate.source_file, [])
                if function.definition.name == candidate.handler_name
                and candidate.variable_name in function.all_parameters
            ]
            if len(candidates) == 1:
                seed_definition_ids = [candidates[0].definition.definition_id]
                parameter_name = candidate.variable_name
            elif len(candidates) > 1:
                seed_definition_ids = sorted(
                    function.definition.definition_id for function in candidates
                )
                parameter_name = candidate.variable_name
                anchor_ambiguous = True
                issues.append(
                    _issue(
                        candidate.source_file,
                        FlowIssueCategory.AMBIGUOUS_EVIDENCE_LOCATION,
                        (
                            f"{len(candidates)} local definitions declare the input "
                            "parameter; all are retained as ambiguous propagation seeds."
                        ),
                        line_number=candidate.line_number,
                        input_id=input_id,
                    )
                )

        if not seed_definition_ids and candidate.input_type is not InputType.REQUEST_OBJECT:
            anchor_nodes, match_ambiguous = _match_input_anchor(parsed, candidate)
            anchor_ambiguous = anchor_ambiguous or match_ambiguous
            for node in anchor_nodes:
                anchor_node_ids.append(id(node))
                input_anchors.setdefault(id(node), []).append(input_id)
            if anchor_nodes:
                enclosing = {
                    function.definition.definition_id
                    for function in functions_by_file.get(candidate.source_file, [])
                    if any(
                        function.definition.line_number
                        <= node.lineno
                        <= function.definition.end_line_number
                        for node in anchor_nodes
                    )
                }
                if len(enclosing) == 1:
                    seed_definition_ids = [enclosing.pop()]
                elif len(enclosing) > 1:
                    seed_definition_ids = sorted(enclosing)
                    anchor_ambiguous = True
                    issues.append(
                        _issue(
                            candidate.source_file,
                            FlowIssueCategory.AMBIGUOUS_EVIDENCE_LOCATION,
                            (
                                "The input expression could be associated with multiple "
                                "local definitions on the same line."
                            ),
                            line_number=candidate.line_number,
                            input_id=input_id,
                        )
                    )
            if not anchor_nodes:
                issues.append(
                    _issue(
                        candidate.source_file,
                        FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                        (
                            "The recorded input expression could not be matched to a "
                            "parsed AST expression, so no propagation seed was created."
                        ),
                        line_number=candidate.line_number,
                        input_id=input_id,
                    )
                )
            elif match_ambiguous:
                issues.append(
                    _issue(
                        candidate.source_file,
                        FlowIssueCategory.AMBIGUOUS_EVIDENCE_LOCATION,
                        (
                            "Several parsed expressions match the input evidence on "
                            "this line; all are treated as the same evidence anchor."
                        ),
                        line_number=candidate.line_number,
                        input_id=input_id,
                    )
                )

        if seed_definition_ids:
            functions_with_inputs.update(seed_definition_ids)
            if parameter_name is not None:
                for definition_id in seed_definition_ids:
                    parameter_seeds.setdefault(definition_id, {}).setdefault(
                        parameter_name,
                        set(),
                    ).add(input_id)

        input_evidence[input_id] = _InputEvidence(
            input_id=input_id,
            index=index,
            candidate=candidate,
            seed_definition_ids=tuple(sorted(seed_definition_ids)),
            parameter_name=parameter_name,
            anchor_node_ids=tuple(sorted(anchor_node_ids)),
            anchor_ambiguous=anchor_ambiguous,
        )

    operation_entries = list(enumerate(sensitive_operations.operations))
    operation_entries.sort(key=lambda item: (_operation_sort_key(item[1]), item[0]))
    for index, candidate in operation_entries:
        operation_id = f"operations[{index}]"
        extension = _extension(candidate.source_file, None)
        if extension not in _PYTHON_EXTENSIONS:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.UNSUPPORTED_LANGUAGE,
                    (
                        "Input-to-operation propagation currently supports Python "
                        "source only; this evidence is preserved without a flow edge."
                    ),
                    line_number=candidate.line_number,
                    operation_id=operation_id,
                )
            )
            operation_evidence[operation_id] = _OperationEvidence(
                operation_id=operation_id,
                index=index,
                candidate=candidate,
                definition_ids=(),
                anchor_node_ids=(),
                anchor_ambiguous=False,
            )
            continue

        parsed = parsed_files.get(candidate.source_file)
        if parsed is None:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                    "The sensitive-operation evidence source file was not parsed.",
                    line_number=candidate.line_number,
                    operation_id=operation_id,
                )
            )
            operation_evidence[operation_id] = _OperationEvidence(
                operation_id=operation_id,
                index=index,
                candidate=candidate,
                definition_ids=(),
                anchor_node_ids=(),
                anchor_ambiguous=False,
            )
            continue

        if candidate.resolution_status is OperationResolutionStatus.UNRESOLVED:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.UNRESOLVED_OPERATION_EVIDENCE,
                    (
                        "The operation evidence is unresolved in its source analysis; "
                        "that original status is preserved on any relationship."
                    ),
                    line_number=candidate.line_number,
                    operation_id=operation_id,
                )
            )

        anchor_calls, anchor_ambiguous = _match_operation_anchor(parsed, candidate)
        anchor_node_ids = [id(node) for node in anchor_calls]
        for node_id in anchor_node_ids:
            operation_anchors.setdefault(node_id, []).append(operation_id)
        definition_ids: list[str] = []
        for node in anchor_calls:
            enclosing = _innermost_function(
                functions_by_file,
                candidate.source_file,
                node.lineno,
            )
            if enclosing is not None:
                definition_ids.append(enclosing.definition.definition_id)
        definition_ids = sorted(set(definition_ids))
        if definition_ids:
            functions_with_operations.update(definition_ids)
        if not anchor_calls:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                    (
                        "The recorded operation expression could not be matched to a "
                        "parsed AST call, so no propagation sink was created."
                    ),
                    line_number=candidate.line_number,
                    operation_id=operation_id,
                )
            )
        if anchor_ambiguous:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.AMBIGUOUS_EVIDENCE_LOCATION,
                    (
                        "Several parsed calls match the operation evidence on this "
                        "line; the recorded status is preserved as ambiguous."
                    ),
                    line_number=candidate.line_number,
                    operation_id=operation_id,
                )
            )
        elif anchor_calls and not definition_ids:
            issues.append(
                _issue(
                    candidate.source_file,
                    FlowIssueCategory.EVIDENCE_NOT_LOCATED,
                    (
                        "The operation call is outside every inspected local function "
                        "definition; module-level flow is not modeled."
                    ),
                    line_number=candidate.line_number,
                    operation_id=operation_id,
                )
            )

        operation_evidence[operation_id] = _OperationEvidence(
            operation_id=operation_id,
            index=index,
            candidate=candidate,
            definition_ids=tuple(definition_ids),
            anchor_node_ids=tuple(sorted(anchor_node_ids)),
            anchor_ambiguous=anchor_ambiguous,
        )

    return (
        input_evidence,
        operation_evidence,
        {key: tuple(sorted(value)) for key, value in input_anchors.items()},
        {key: tuple(sorted(value)) for key, value in operation_anchors.items()},
        parameter_seeds,
        frozenset(functions_with_inputs),
        frozenset(functions_with_operations),
    )


def _merge_taint(left: dict[str, _FlowPath], right: dict[str, _FlowPath]) -> dict[str, _FlowPath]:
    merged = dict(left)
    for input_id, path in right.items():
        existing = merged.get(input_id)
        if existing is None or _path_key(path) < _path_key(existing):
            merged[input_id] = path
    return merged


def _path_key(path: _FlowPath) -> tuple[object, ...]:
    return (
        bool(path.unsupported_reasons),
        len(path.steps),
        tuple(step.kind.value for step in path.steps),
        tuple(step.source_file for step in path.steps),
        tuple(step.line_number for step in path.steps),
        tuple(step.variable_name or "" for step in path.steps),
    )


def _append_step(path: _FlowPath, step: PropagationStep) -> _FlowPath:
    return _FlowPath(
        steps=(*path.steps, step),
        call_ids=path.call_ids,
        ambiguous_definition_ids=path.ambiguous_definition_ids,
        unsupported_reasons=path.unsupported_reasons,
    )


def _merge_paths(paths: list[_FlowPath]) -> _FlowPath | None:
    if not paths:
        return None
    ordered = sorted(paths, key=_path_key)
    chosen = ordered[0]
    call_ids = tuple(sorted({call_id for path in paths for call_id in path.call_ids}))
    ambiguous = tuple(
        sorted({definition_id for path in paths for definition_id in path.ambiguous_definition_ids})
    )
    unsupported = tuple(sorted({reason for path in paths for reason in path.unsupported_reasons}))
    return _FlowPath(
        steps=chosen.steps,
        call_ids=call_ids,
        ambiguous_definition_ids=ambiguous,
        unsupported_reasons=unsupported,
    )


def _copy_taint(value: dict[str, _FlowPath]) -> dict[str, _FlowPath]:
    return dict(value)


def _copy_env(env: dict[str, dict[str, _FlowPath]]) -> dict[str, dict[str, _FlowPath]]:
    return {name: _copy_taint(taint) for name, taint in env.items()}


def _merge_env(
    left: dict[str, dict[str, _FlowPath]],
    right: dict[str, dict[str, _FlowPath]],
) -> dict[str, dict[str, _FlowPath]]:
    merged = {name: _copy_taint(taint) for name, taint in left.items()}
    for name, taint in right.items():
        if name in merged:
            merged[name] = _merge_taint(merged[name], taint)
        else:
            merged[name] = _copy_taint(taint)
    return merged


class _FlowAnalyzer:
    """Bounded, context-sensitive, may-flow analysis over the local call graph."""

    def __init__(
        self,
        context: _AnalysisContext,
        issues: list[InputOperationIssue],
        *,
        max_depth: int,
        max_states: int,
    ) -> None:
        self.context = context
        self.issues = issues
        self.max_depth = max_depth
        self.max_states = max_states
        self.memo: dict[tuple[object, ...], _Summary] = {}
        self.stack: set[tuple[object, ...]] = set()
        self.states: int = 0
        self.depth_limited: bool = False
        self.state_limited: bool = False
        self._reported_calls: set[tuple[str, str]] = set()
        self._reported_unsupported: set[tuple[object, ...]] = set()
        self._reported_cycles: set[tuple[object, ...]] = set()

    def analyze_all(self) -> dict[tuple[str, str], _FlowPath]:
        seeds = self.context.parameter_seeds
        initial = set(seeds) | set(self.context.functions_with_inputs)
        initial |= set(self.context.functions_with_operations)
        hits: dict[tuple[str, str], _FlowPath] = {}
        for definition_id in sorted(initial):
            parameter_taint = {
                parameter: frozenset(input_ids)
                for parameter, input_ids in seeds.get(definition_id, {}).items()
                if input_ids
            }
            summary = self._analyze_state(definition_id, parameter_taint, depth=0)
            for key, path in summary.operations.items():
                hits[key] = _merge_paths([hits[key], path]) if key in hits else path
        return hits

    def _state_key(
        self,
        definition_id: str,
        parameter_taint: dict[str, frozenset[str]],
    ) -> tuple[object, ...]:
        return (
            definition_id,
            tuple(
                sorted(
                    (parameter, tuple(sorted(input_ids)))
                    for parameter, input_ids in parameter_taint.items()
                    if input_ids
                )
            ),
        )

    def _analyze_state(
        self,
        definition_id: str,
        parameter_taint: dict[str, frozenset[str]],
        *,
        depth: int,
    ) -> _Summary:
        state_key = self._state_key(definition_id, parameter_taint)
        if state_key in self.stack:
            if state_key not in self._reported_cycles:
                self._reported_cycles.add(state_key)
                function = self.context.functions.get(definition_id)
                self.issues.append(
                    _issue(
                        function.source_file if function else "<unknown>",
                        FlowIssueCategory.CYCLE_DETECTED,
                        (
                            "A recursive call reached the same definition with the same "
                            "input-taint state. Recursive return/value propagation is "
                            "bounded and stopped at this cycle."
                        ),
                        line_number=(
                            function.definition.line_number if function is not None else None
                        ),
                        definition_id=definition_id,
                    )
                )
            return _Summary()
        if state_key in self.memo:
            return self.memo[state_key]
        if depth > self.max_depth:
            self.depth_limited = True
            self.issues.append(
                _issue(
                    "<propagation>",
                    FlowIssueCategory.PROPAGATION_DEPTH_LIMIT,
                    (
                        f"Maximum interprocedural propagation depth of {self.max_depth} "
                        "was reached; deeper call relationships were not analyzed."
                    ),
                )
            )
            return _Summary()
        if self.states >= self.max_states:
            self.state_limited = True
            self.issues.append(
                _issue(
                    "<propagation>",
                    FlowIssueCategory.PROPAGATION_STATE_LIMIT,
                    (
                        f"Maximum of {self.max_states} propagation states was reached; "
                        "remaining call states were not analyzed."
                    ),
                )
            )
            return _Summary()

        function = self.context.functions.get(definition_id)
        if function is None:
            return _Summary()

        self.states += 1
        self.stack.add(state_key)
        env: dict[str, dict[str, _FlowPath]] = {}
        for parameter, input_ids in parameter_taint.items():
            argument_node = function.argument_nodes.get(parameter)
            for input_id in sorted(input_ids):
                step = self._step(
                    FlowPropagationKind.INPUT_PARAMETER,
                    function.source_file,
                    argument_node.lineno if argument_node is not None else function.node.lineno,
                    (argument_node.col_offset + 1) if argument_node is not None else None,
                    function,
                    parameter,
                    f"{parameter}: input parameter",
                    (
                        "The input evidence is declared as this function parameter. "
                        "This is a static seed, not a runtime value claim."
                    ),
                )
                env.setdefault(parameter, {})[input_id] = _FlowPath(steps=(step,))

        summary = _Summary()
        body = _FunctionBodyAnalyzer(self, function, env, summary, depth)
        body.run()
        self.stack.remove(state_key)
        self.memo[state_key] = summary
        return summary

    def _step(
        self,
        kind: FlowPropagationKind,
        source_file: str,
        line_number: int,
        column_number: int | None,
        function: _FunctionNode | None,
        variable_name: str | None,
        expression: str,
        explanation: str,
        *,
        call_id: str | None = None,
    ) -> PropagationStep:
        if len(expression) > _MAX_EXPRESSION_LENGTH:
            expression = expression[: _MAX_EXPRESSION_LENGTH - 3] + "..."
        return PropagationStep(
            step_index=0,
            kind=kind,
            source_file=source_file,
            line_number=max(1, line_number),
            column_number=column_number if column_number and column_number >= 1 else None,
            definition_id=(function.definition.definition_id if function is not None else None),
            definition_name=(function.definition.name if function is not None else None),
            call_id=call_id,
            variable_name=variable_name,
            expression=expression,
            explanation=explanation,
        )

    def _report_call(
        self,
        call: CallSite,
        category: FlowIssueCategory,
        explanation: str,
    ) -> None:
        key = (call.call_id, category.value)
        if key in self._reported_calls:
            return
        self._reported_calls.add(key)
        self.issues.append(
            _issue(
                call.source_file,
                category,
                explanation,
                line_number=call.line_number,
                call_id=call.call_id,
                definition_id=call.caller_definition_id,
            )
        )

    def _report_unsupported(
        self,
        source_file: str,
        line_number: int,
        definition_id: str | None,
        explanation: str,
    ) -> None:
        key = (source_file, line_number, definition_id or "", explanation)
        if key in self._reported_unsupported:
            return
        self._reported_unsupported.add(key)
        self.issues.append(
            _issue(
                source_file,
                FlowIssueCategory.UNSUPPORTED_PROPAGATION,
                explanation,
                line_number=line_number,
                definition_id=definition_id,
            )
        )


class _FunctionBodyAnalyzer:
    """Flow-sensitive may-analysis for one function body and one input state."""

    def __init__(
        self,
        analyzer: _FlowAnalyzer,
        function: _FunctionNode,
        env: dict[str, dict[str, _FlowPath]],
        summary: _Summary,
        depth: int,
    ) -> None:
        self.analyzer = analyzer
        self.context = analyzer.context
        self.function = function
        self.env = env
        self.summary = summary
        self.depth = depth

    def run(self) -> None:
        self._exec_block(self.function.node.body, self.env)

    def _exec_block(
        self,
        statements: list[ast.stmt],
        env: dict[str, dict[str, _FlowPath]],
    ) -> bool:
        reachable = True
        for statement in statements:
            if not reachable:
                break
            reachable = self._exec_statement(statement, env)
        return reachable

    def _exec_statement(
        self,
        statement: ast.stmt,
        env: dict[str, dict[str, _FlowPath]],
    ) -> bool:
        if isinstance(statement, ast.Assign):
            taint = self._eval(statement.value, env)
            for target in statement.targets:
                self._assign(target, taint, env, statement)
            return True
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                taint = self._eval(statement.value, env)
                self._assign(statement.target, taint, env, statement)
            return True
        if isinstance(statement, ast.AugAssign):
            current = self._eval(statement.target, env)
            value = self._eval(statement.value, env)
            taint = self._derive(_merge_taint(current, value), statement)
            self._assign(statement.target, taint, env, statement)
            return True
        if isinstance(statement, ast.Return):
            taint = self._eval(statement.value, env) if statement.value is not None else {}
            for input_id, path in taint.items():
                step = self.analyzer._step(
                    FlowPropagationKind.RETURN_VALUE,
                    self.function.source_file,
                    statement.lineno,
                    statement.col_offset + 1,
                    self.function,
                    None,
                    _safe_display(statement.value),
                    "The function returns a value derived from this input.",
                )
                returned = _append_step(path, step)
                existing = self.summary.returns.get(input_id)
                if existing is None or _path_key(returned) < _path_key(existing):
                    self.summary.returns[input_id] = returned
            return False
        if isinstance(statement, ast.Expr):
            self._eval(statement.value, env)
            return True
        if isinstance(statement, ast.If):
            self._eval(statement.test, env)
            body_env = _copy_env(env)
            body_reachable = self._exec_block(statement.body, body_env)
            else_env = _copy_env(env)
            else_reachable = self._exec_block(statement.orelse, else_env)
            if not body_reachable and not else_reachable:
                return False
            if body_reachable and else_reachable:
                env.clear()
                env.update(_merge_env(body_env, else_env))
            elif body_reachable:
                env.clear()
                env.update(body_env)
            else:
                env.clear()
                env.update(else_env)
            return True
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            iter_taint = self._eval(statement.iter, env)
            body_env = _copy_env(env)
            if iter_taint:
                self._assign_iteration_target(statement.target, iter_taint, body_env, statement)
            body_reachable = self._exec_block(statement.body, body_env)
            else_env = _copy_env(env)
            else_reachable = self._exec_block(statement.orelse, else_env)
            merged = _merge_env(env, body_env if body_reachable else {})
            if else_reachable:
                merged = _merge_env(merged, else_env)
            env.clear()
            env.update(merged)
            return True
        if isinstance(statement, ast.While):
            self._eval(statement.test, env)
            body_env = _copy_env(env)
            body_reachable = self._exec_block(statement.body, body_env)
            else_env = _copy_env(env)
            else_reachable = self._exec_block(statement.orelse, else_env)
            merged = _merge_env(env, body_env if body_reachable else {})
            if else_reachable:
                merged = _merge_env(merged, else_env)
            env.clear()
            env.update(merged)
            return True
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self._eval(item.context_expr, env)
            return self._exec_block(statement.body, env)
        if isinstance(statement, (ast.Try, ast.TryStar)):
            body_env = _copy_env(env)
            body_reachable = self._exec_block(statement.body, body_env)
            else_env = _copy_env(body_env) if body_reachable else {}
            else_reachable = body_reachable and self._exec_block(statement.orelse, else_env)
            branches: list[dict[str, dict[str, _FlowPath]]] = []
            if else_reachable:
                branches.append(else_env)
            for handler in statement.handlers:
                handler_env = _copy_env(env)
                if handler.type is not None:
                    self._eval(handler.type, handler_env)
                if self._exec_block(handler.body, handler_env):
                    branches.append(handler_env)
            if not branches:
                return False
            merged = branches[0]
            for branch in branches[1:]:
                merged = _merge_env(merged, branch)
            env.clear()
            env.update(merged)
            if self._exec_block(statement.finalbody, env):
                return True
            return False
        if isinstance(statement, ast.Match):
            self._eval(statement.subject, env)
            branches = []
            for case in statement.cases:
                case_env = _copy_env(env)
                if case.guard is not None:
                    self._eval(case.guard, case_env)
                if self._exec_block(case.body, case_env):
                    branches.append(case_env)
            if not branches:
                return False
            merged = branches[0]
            for branch in branches[1:]:
                merged = _merge_env(merged, branch)
            env.clear()
            env.update(merged)
            return True
        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
                else:
                    self._eval(target, env)
            return True
        if isinstance(statement, (ast.Raise, ast.Assert)):
            if isinstance(statement, ast.Raise):
                if statement.exc is not None:
                    self._eval(statement.exc, env)
                if statement.cause is not None:
                    self._eval(statement.cause, env)
            else:
                self._eval(statement.test, env)
                if statement.msg is not None:
                    self._eval(statement.msg, env)
            return True
        if isinstance(statement, ast.Import):
            return True
        if isinstance(statement, ast.ImportFrom):
            return True
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return True
        return True

    def _assign(
        self,
        target: ast.expr,
        taint: dict[str, _FlowPath],
        env: dict[str, dict[str, _FlowPath]],
        statement: ast.stmt,
    ) -> None:
        if isinstance(target, ast.Name):
            if not taint:
                env.pop(target.id, None)
                return
            assigned: dict[str, _FlowPath] = {}
            for input_id, path in taint.items():
                step = self.analyzer._step(
                    FlowPropagationKind.VARIABLE_ASSIGNMENT,
                    self.function.source_file,
                    target.lineno,
                    target.col_offset + 1,
                    self.function,
                    target.id,
                    target.id,
                    (
                        f"A value derived from the input is assigned to local variable "
                        f"'{target.id}'."
                    ),
                )
                assigned[input_id] = _append_step(path, step)
            env[target.id] = assigned
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if taint:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    statement.lineno,
                    self.function.definition.definition_id,
                    (
                        "A tainted value is unpacked into several targets. Element-wise "
                        "mapping is not modeled, so no propagation edge is invented."
                    ),
                )
            for element in target.elts:
                if isinstance(element, ast.Name):
                    env.pop(element.id, None)
            return
        if isinstance(target, ast.Starred):
            if taint:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    statement.lineno,
                    self.function.definition.definition_id,
                    "Starred assignment targets are not modeled.",
                )
            if isinstance(target.value, ast.Name):
                env.pop(target.value.id, None)
            return
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            if taint:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    statement.lineno,
                    self.function.definition.definition_id,
                    (
                        "A tainted value is stored into an object attribute or item. "
                        "Field and container-element flow are not modeled."
                    ),
                )
            return

    def _assign_iteration_target(
        self,
        target: ast.expr,
        taint: dict[str, _FlowPath],
        env: dict[str, dict[str, _FlowPath]],
        statement: ast.stmt,
    ) -> None:
        if isinstance(target, ast.Name):
            self._assign(target, taint, env, statement)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            self.analyzer._report_unsupported(
                self.function.source_file,
                statement.lineno,
                self.function.definition.definition_id,
                (
                    "A tainted iterable is unpacked into a loop target. Element-wise "
                    "mapping is not modeled."
                ),
            )
            for element in target.elts:
                if isinstance(element, ast.Name):
                    env.pop(element.id, None)
            return
        self.analyzer._report_unsupported(
            self.function.source_file,
            statement.lineno,
            self.function.definition.definition_id,
            "A tainted loop target is not a simple local name.",
        )

    def _derive(self, taint: dict[str, _FlowPath], node: ast.AST) -> dict[str, _FlowPath]:
        if not taint:
            return {}
        derived: dict[str, _FlowPath] = {}
        for input_id, path in taint.items():
            step = self.analyzer._step(
                FlowPropagationKind.DERIVED_EXPRESSION,
                self.function.source_file,
                getattr(node, "lineno", self.function.node.lineno),
                getattr(node, "col_offset", 0) + 1,
                self.function,
                None,
                _safe_display(node),
                "A value is derived from the input by a supported expression form.",
            )
            derived[input_id] = _append_step(path, step)
        return derived

    def _eval(
        self,
        node: ast.AST | None,
        env: dict[str, dict[str, _FlowPath]],
    ) -> dict[str, _FlowPath]:
        if node is None:
            return {}
        input_ids = self.context.input_anchors.get(id(node))
        if input_ids:
            taint: dict[str, _FlowPath] = {}
            for input_id in input_ids:
                evidence = self.context.input_evidence.get(input_id)
                if evidence is None:
                    continue
                candidate = evidence.candidate
                step = self.analyzer._step(
                    FlowPropagationKind.INPUT_ACCESS,
                    candidate.source_file,
                    candidate.line_number,
                    getattr(node, "col_offset", 0) + 1,
                    self.function,
                    candidate.variable_name,
                    candidate.declaration_or_access,
                    (
                        "This expression matches recorded input evidence. The access is "
                        "a static source location, not a runtime value."
                    ),
                )
                taint[input_id] = _FlowPath(steps=(step,))
            return taint
        if isinstance(node, ast.Name):
            return _copy_taint(env.get(node.id, {}))
        if isinstance(node, ast.Constant):
            return {}
        if isinstance(node, ast.Attribute):
            base = self._eval(node.value, env)
            if base:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    node.lineno,
                    self.function.definition.definition_id,
                    (
                        "A tainted value is read through an object attribute. Field "
                        "sensitivity and object state are not modeled, so propagation "
                        "stops here rather than inventing a field edge."
                    ),
                )
            return {}
        if isinstance(node, ast.Subscript):
            base = _merge_taint(self._eval(node.value, env), self._eval(node.slice, env))
            if base:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    node.lineno,
                    self.function.definition.definition_id,
                    (
                        "A tainted value is read through a container subscript. "
                        "Element-level flow is not modeled, so propagation stops here."
                    ),
                )
            return {}
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)
        if isinstance(node, ast.BinOp):
            return self._derive(
                _merge_taint(self._eval(node.left, env), self._eval(node.right, env)),
                node,
            )
        if isinstance(node, ast.BoolOp):
            taint: dict[str, _FlowPath] = {}
            for value in node.values:
                taint = _merge_taint(taint, self._eval(value, env))
            return self._derive(taint, node)
        if isinstance(node, ast.UnaryOp):
            return self._derive(self._eval(node.operand, env), node)
        if isinstance(node, ast.IfExp):
            return self._derive(
                _merge_taint(
                    _merge_taint(self._eval(node.test, env), self._eval(node.body, env)),
                    self._eval(node.orelse, env),
                ),
                node,
            )
        if isinstance(node, ast.Compare):
            taint = self._eval(node.left, env)
            for comparator in node.comparators:
                taint = _merge_taint(taint, self._eval(comparator, env))
            return self._derive(taint, node)
        if isinstance(node, ast.NamedExpr):
            taint = self._eval(node.value, env)
            self._assign(node.target, taint, env, node)
            return taint
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            taint: dict[str, _FlowPath] = {}
            for element in node.elts:
                taint = _merge_taint(taint, self._eval(element, env))
            return self._derive(taint, node)
        if isinstance(node, ast.Dict):
            taint: dict[str, _FlowPath] = {}
            for key, value in zip(node.keys, node.values, strict=False):
                if key is not None:
                    taint = _merge_taint(taint, self._eval(key, env))
                taint = _merge_taint(taint, self._eval(value, env))
            return self._derive(taint, node)
        if isinstance(node, ast.JoinedStr):
            taint: dict[str, _FlowPath] = {}
            for value in node.values:
                taint = _merge_taint(taint, self._eval(value, env))
            return self._derive(taint, node)
        if isinstance(node, ast.FormattedValue):
            return self._derive(self._eval(node.value, env), node)
        if isinstance(node, ast.Await):
            return self._eval(node.value, env)
        if isinstance(node, ast.Starred):
            return self._eval(node.value, env)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            taint = self._eval(node.elt, env)
            for generator in node.generators:
                taint = _merge_taint(taint, self._eval(generator.iter, env))
            return self._derive(taint, node)
        if isinstance(node, ast.DictComp):
            taint = _merge_taint(self._eval(node.key, env), self._eval(node.value, env))
            for generator in node.generators:
                taint = _merge_taint(taint, self._eval(generator.iter, env))
            return self._derive(taint, node)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            taint = self._eval(node.value, env)
            if taint:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    getattr(node, "lineno", self.function.node.lineno),
                    self.function.definition.definition_id,
                    "Generator yield propagation is not modeled.",
                )
            return taint
        return {}

    def _eval_call(
        self,
        node: ast.Call,
        env: dict[str, dict[str, _FlowPath]],
    ) -> dict[str, _FlowPath]:
        call = self.context.call_index.get(
            (self.function.source_file, node.lineno, node.col_offset + 1)
        )
        operation_ids = self.context.operation_anchors.get(id(node), ())
        for operation_id in operation_ids:
            self._record_operation_hit(operation_id, node, env, call)

        if call is None:
            tainted_arguments = self._argument_taint(node, env)
            if tainted_arguments and not operation_ids:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    node.lineno,
                    self.function.definition.definition_id,
                    (
                        "A tainted value is passed to a call with no resolved local "
                        "call-site evidence; no local propagation edge was invented."
                    ),
                )
            return {}

        if isinstance(node.func, (ast.Call, ast.Subscript, ast.Lambda)):
            tainted_arguments = self._argument_taint(node, env)
            if tainted_arguments and not operation_ids:
                self.analyzer._report_unsupported(
                    self.function.source_file,
                    node.lineno,
                    self.function.definition.definition_id,
                    (
                        "The call target is a dynamic expression. Propagation through "
                        "dynamic dispatch is unsupported and is not inferred."
                    ),
                )
            return {}

        if call.resolution_status is CallResolutionStatus.UNRESOLVED:
            tainted_arguments = self._argument_taint(node, env)
            if tainted_arguments and not operation_ids:
                self.analyzer._report_call(
                    call,
                    FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION,
                    (
                        "A tainted argument is passed to an unresolved local call. "
                        "The callee is unknown, so no propagation edge is invented."
                    ),
                )
            return {}
        if call.resolution_status is CallResolutionStatus.EXTERNAL:
            # Evaluate the receiver and arguments so nested operation anchors
            # (for example ``db.execute(value).fetchall()``) are still observed,
            # but never propagate an external return value.
            self._argument_taint(node, env)
            return {}
        if call.resolution_status not in {
            CallResolutionStatus.RESOLVED,
            CallResolutionStatus.AMBIGUOUS,
        }:
            return {}

        result: dict[str, _FlowPath] = {}
        for target_id in call.target_definition_ids:
            target = self.context.functions.get(target_id)
            if target is None:
                self.analyzer._report_call(
                    call,
                    FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION,
                    (
                        "A resolved call target has no parsed definition, so that "
                        "target's dataflow was not analyzed."
                    ),
                )
                continue
            parameter_paths = self._bind_arguments(node, target, call, env)
            if not parameter_paths:
                parameter_taint: dict[str, frozenset[str]] = {}
            else:
                parameter_taint = {
                    parameter: frozenset(paths)
                    for parameter, paths in parameter_paths.items()
                    if paths
                }

            if call.resolution_status is CallResolutionStatus.AMBIGUOUS:
                tainted_parameters = any(parameter_taint.values())
                if tainted_parameters and not operation_ids:
                    self.analyzer._report_call(
                        call,
                        FlowIssueCategory.AMBIGUOUS_CALL_PROPAGATION,
                        (
                            "A tainted argument reaches an ambiguous local call. Every "
                            "candidate target is analyzed, and the relationship is "
                            "retained as ambiguous rather than selecting one target."
                        ),
                    )

            summary = self.analyzer._analyze_state(
                target_id,
                parameter_taint,
                depth=self.depth + 1,
            )
            for (operation_id, input_id), path in summary.operations.items():
                merged = self._combine_callee_path(
                    path,
                    input_id,
                    parameter_paths,
                    call,
                    add_call_to_flow=True,
                )
                key = (operation_id, input_id)
                existing = self.summary.operations.get(key)
                self.summary.operations[key] = (
                    _merge_paths([existing, merged]) if existing is not None else merged
                )
            for input_id, path in summary.returns.items():
                merged = self._combine_return_path(path, input_id, parameter_paths, call, node)
                existing = result.get(input_id)
                if existing is None or _path_key(merged) < _path_key(existing):
                    result[input_id] = merged
        return result

    def _argument_taint(
        self,
        node: ast.Call,
        env: dict[str, dict[str, _FlowPath]],
    ) -> dict[str, _FlowPath]:
        taint: dict[str, _FlowPath] = {}
        if isinstance(node.func, ast.Attribute):
            taint = _merge_taint(taint, self._eval(node.func.value, env))
        for argument in node.args:
            taint = _merge_taint(taint, self._eval(argument, env))
        for keyword in node.keywords:
            taint = _merge_taint(taint, self._eval(keyword.value, env))
        return taint

    def _record_operation_hit(
        self,
        operation_id: str,
        node: ast.Call,
        env: dict[str, dict[str, _FlowPath]],
        call: CallSite | None,
    ) -> None:
        evidence = self.context.operation_evidence.get(operation_id)
        if evidence is None:
            return
        candidate = evidence.candidate
        receiver_taint: dict[str, _FlowPath] = {}
        if isinstance(node.func, ast.Attribute):
            receiver_taint = self._eval(node.func.value, env)
        argument_taint: dict[str, _FlowPath] = {}
        for argument in node.args:
            argument_taint = _merge_taint(argument_taint, self._eval(argument, env))
        for keyword in node.keywords:
            argument_taint = _merge_taint(argument_taint, self._eval(keyword.value, env))

        for kind, taint in (
            (FlowPropagationKind.OPERATION_RECEIVER, receiver_taint),
            (FlowPropagationKind.OPERATION_ARGUMENT, argument_taint),
        ):
            for input_id, path in taint.items():
                step = self.analyzer._step(
                    kind,
                    candidate.source_file,
                    candidate.line_number,
                    node.col_offset + 1,
                    self.function,
                    candidate.operation_name,
                    candidate.declaration_or_access,
                    (
                        "The operation receives a value derived from this input. "
                        "This is a static data relationship, not proof that the "
                        "operation executes or is unsafe."
                    ),
                    call_id=call.call_id if call is not None else None,
                )
                merged = _append_step(path, step)
                key = (operation_id, input_id)
                existing = self.summary.operations.get(key)
                self.summary.operations[key] = (
                    _merge_paths([existing, merged]) if existing is not None else merged
                )

    def _bind_arguments(
        self,
        node: ast.Call,
        target: _FunctionNode,
        call: CallSite,
        env: dict[str, dict[str, _FlowPath]],
    ) -> dict[str, dict[str, _FlowPath]]:
        positional = list(target.positional)
        skip_self = False
        if (
            target.definition.kind is FunctionKind.METHOD
            and call.is_method_call
            and positional
            and positional[0] in {"self", "cls"}
        ):
            receiver = call.receiver_expression or ""
            base = receiver.split(".", 1)[0]
            if receiver in {"self", "cls"} or (base and base[:1].islower()):
                skip_self = True
        if skip_self:
            positional = positional[1:]

        paths: dict[str, dict[str, _FlowPath]] = {}
        for index, argument in enumerate(node.args):
            taint = self._eval(argument, env)
            if isinstance(argument, ast.Starred):
                parameter = target.vararg
                if taint:
                    self.analyzer._report_unsupported(
                        self.function.source_file,
                        node.lineno,
                        self.function.definition.definition_id,
                        (
                            "A tainted starred argument is passed to a local call. "
                            "Argument-to-parameter mapping is not exact."
                        ),
                    )
            elif index < len(positional):
                parameter = positional[index]
            else:
                parameter = target.vararg
            if parameter is None:
                if taint:
                    self.analyzer._report_unsupported(
                        self.function.source_file,
                        node.lineno,
                        self.function.definition.definition_id,
                        ("A tainted positional argument has no statically known callee parameter."),
                    )
                continue
            self._add_argument_path(paths, parameter, taint, node, argument, call)

        for keyword in node.keywords:
            taint = self._eval(keyword.value, env)
            if keyword.arg is None:
                parameter = target.kwarg
                if taint:
                    self.analyzer._report_unsupported(
                        self.function.source_file,
                        node.lineno,
                        self.function.definition.definition_id,
                        (
                            "A tainted keyword mapping is passed to a local call; "
                            "keyword-to-parameter mapping is not exact."
                        ),
                    )
            elif keyword.arg in target.all_parameters:
                parameter = keyword.arg
            else:
                parameter = target.kwarg
            if parameter is None:
                if taint:
                    self.analyzer._report_unsupported(
                        self.function.source_file,
                        node.lineno,
                        self.function.definition.definition_id,
                        ("A tainted keyword argument has no statically known callee parameter."),
                    )
                continue
            self._add_argument_path(
                paths,
                parameter,
                taint,
                node,
                keyword.value,
                call,
            )
        return paths

    def _add_argument_path(
        self,
        paths: dict[str, dict[str, _FlowPath]],
        parameter: str,
        taint: dict[str, _FlowPath],
        node: ast.Call,
        argument: ast.expr,
        call: CallSite,
    ) -> None:
        for input_id, path in taint.items():
            step = self.analyzer._step(
                FlowPropagationKind.ARGUMENT,
                self.function.source_file,
                node.lineno,
                node.col_offset + 1,
                self.function,
                parameter,
                _safe_display(argument),
                (
                    f"The tainted value is passed as argument '{parameter}' to the "
                    "resolved local call."
                ),
                call_id=call.call_id,
            )
            paths.setdefault(parameter, {})[input_id] = _append_step(path, step)

    def _combine_callee_path(
        self,
        path: _FlowPath,
        input_id: str,
        parameter_paths: dict[str, dict[str, _FlowPath]],
        call: CallSite,
        *,
        add_call_to_flow: bool,
    ) -> _FlowPath:
        first = path.steps[0] if path.steps else None
        parameter = (
            first.variable_name
            if first
            and first.kind in {FlowPropagationKind.PARAMETER, FlowPropagationKind.INPUT_PARAMETER}
            else None
        )
        parameter_dependent = parameter is not None and input_id in parameter_paths.get(
            parameter, {}
        )
        if parameter_dependent:
            prefix = parameter_paths[parameter][input_id]
            steps = (*prefix.steps, *path.steps)
            call_ids = (*prefix.call_ids, *path.call_ids)
        else:
            steps = path.steps
            call_ids = path.call_ids
        if add_call_to_flow and parameter_dependent:
            call_ids = (*call_ids, call.call_id)
        ambiguous = path.ambiguous_definition_ids
        if call.resolution_status is CallResolutionStatus.AMBIGUOUS:
            ambiguous = tuple(sorted({*ambiguous, *call.target_definition_ids}))
        return _FlowPath(
            steps=steps,
            call_ids=call_ids,
            ambiguous_definition_ids=ambiguous,
            unsupported_reasons=path.unsupported_reasons,
        )

    def _combine_return_path(
        self,
        path: _FlowPath,
        input_id: str,
        parameter_paths: dict[str, dict[str, _FlowPath]],
        call: CallSite,
        node: ast.Call,
    ) -> _FlowPath:
        first = path.steps[0] if path.steps else None
        parameter = (
            first.variable_name
            if first
            and first.kind in {FlowPropagationKind.PARAMETER, FlowPropagationKind.INPUT_PARAMETER}
            else None
        )
        if parameter is not None and input_id in parameter_paths.get(parameter, {}):
            prefix = parameter_paths[parameter][input_id]
            steps = (*prefix.steps, *path.steps)
        else:
            steps = path.steps
        step = self.analyzer._step(
            FlowPropagationKind.CALL_RESULT,
            self.function.source_file,
            node.lineno,
            node.col_offset + 1,
            self.function,
            None,
            f"{_safe_display(node.func)}(...)",
            "The resolved local call returns a value derived from this input.",
            call_id=call.call_id,
        )
        ambiguous = path.ambiguous_definition_ids
        if call.resolution_status is CallResolutionStatus.AMBIGUOUS:
            ambiguous = tuple(sorted({*ambiguous, *call.target_definition_ids}))
        return _FlowPath(
            steps=(*steps, step),
            call_ids=(*path.call_ids, call.call_id),
            ambiguous_definition_ids=ambiguous,
            unsupported_reasons=path.unsupported_reasons,
        )


def _reverse_call_graph(handler_calls: HandlerCallResult) -> dict[str, set[str]]:
    reverse: dict[str, set[str]] = {}
    for relationship in handler_calls.relationships:
        reverse.setdefault(relationship.callee_definition_id, set()).add(
            relationship.caller_definition_id
        )
    return reverse


def _handlers_reaching(
    definition_id: str,
    reverse: dict[str, set[str]],
) -> set[str]:
    seen = {definition_id}
    stack = [definition_id]
    while stack:
        current = stack.pop()
        for caller in sorted(reverse.get(current, ())):
            if caller not in seen:
                seen.add(caller)
                stack.append(caller)
    return seen


def _handler_references(
    definition_ids: set[str],
    handler_calls: HandlerCallResult,
) -> list[HandlerReference]:
    by_definition: dict[str, list[RouteHandler]] = {}
    for handler in handler_calls.handlers:
        for definition_id in handler.definition_ids:
            by_definition.setdefault(definition_id, []).append(handler)
    references: dict[tuple[str, str], HandlerReference] = {}
    for definition_id in sorted(definition_ids):
        for handler in by_definition.get(definition_id, []):
            reference = HandlerReference(
                handler_id=handler.handler_id,
                route_id=handler.route_id,
                handler_name=handler.handler_name,
                source_file=handler.route_source_file,
                line_number=handler.route_line_number,
                route_path=handler.route_path,
                http_method=handler.http_method,
                framework=handler.framework,
            )
            references[(reference.route_id, reference.handler_id)] = reference
    return sorted(
        references.values(),
        key=lambda item: (
            item.source_file,
            item.line_number,
            item.route_id,
            item.handler_id,
        ),
    )


def _correlation_route_maps(
    correlation: AttackSurfaceCorrelationResult,
) -> tuple[dict[tuple[object, ...], set[str]], dict[tuple[object, ...], set[str]]]:
    input_routes: dict[tuple[object, ...], set[str]] = {}
    operation_routes: dict[tuple[object, ...], set[str]] = {}
    for route in correlation.routes:
        for candidate in route.input_candidates:
            input_routes.setdefault(_input_identity(candidate), set()).add(route.route_id)
        for candidate in route.sensitive_operations:
            operation_routes.setdefault(_operation_identity(candidate), set()).add(route.route_id)
    return input_routes, operation_routes


def _relationship_status(
    path: _FlowPath,
    input_evidence: _InputEvidence,
    operation_evidence: _OperationEvidence,
    calls: dict[str, CallSite],
) -> FlowResolutionStatus:
    status = FlowResolutionStatus.RESOLVED
    if input_evidence.anchor_ambiguous or operation_evidence.anchor_ambiguous:
        status = FlowResolutionStatus.AMBIGUOUS
    if any(
        calls[call_id].resolution_status is CallResolutionStatus.AMBIGUOUS
        for call_id in path.call_ids
        if call_id in calls
    ):
        status = FlowResolutionStatus.AMBIGUOUS
    if path.ambiguous_definition_ids and status is FlowResolutionStatus.RESOLVED:
        status = FlowResolutionStatus.AMBIGUOUS
    if path.unsupported_reasons:
        status = FlowResolutionStatus.UNSUPPORTED
    return status


def _relationship_confidence(
    path: _FlowPath,
    input_evidence: _InputEvidence,
    operation_evidence: _OperationEvidence,
    calls: dict[str, CallSite],
    status: FlowResolutionStatus,
) -> float:
    values = [
        input_evidence.candidate.detection_confidence,
        operation_evidence.candidate.detection_confidence,
    ]
    values.extend(
        calls[call_id].detection_confidence for call_id in path.call_ids if call_id in calls
    )
    return max(0.0, min([*values, _STATUS_CONFIDENCE_CAP[status]]))


def _relationship_sort_key(relationship: InputOperationRelationship) -> tuple[object, ...]:
    return (
        relationship.input_source_file,
        relationship.input_line_number,
        relationship.operation_source_file,
        relationship.operation_line_number,
        relationship.relationship_id,
    )


def _flow_issue_sort_key(issue: InputOperationIssue) -> tuple[object, ...]:
    return (
        issue.source_file,
        issue.line_number or 0,
        issue.category.value,
        issue.input_id or "",
        issue.operation_id or "",
        issue.call_id or "",
        issue.definition_id or "",
        issue.explanation,
    )


def _dedupe_issues(issues: list[InputOperationIssue]) -> list[InputOperationIssue]:
    unique: dict[tuple[object, ...], InputOperationIssue] = {}
    for issue in issues:
        key = (
            issue.source_file,
            issue.line_number,
            issue.category.value,
            issue.input_id,
            issue.operation_id,
            issue.call_id,
            issue.definition_id,
            issue.explanation,
        )
        unique[key] = issue
    return sorted(unique.values(), key=_flow_issue_sort_key)


def _dedupe_source_issues(issues: list[AnalysisIssue]) -> list[AnalysisIssue]:
    unique: dict[tuple[object, ...], AnalysisIssue] = {}
    for issue in issues:
        key = (issue.source_file, issue.reason.value, issue.detail or "")
        unique[key] = issue
    return sorted(
        unique.values(),
        key=lambda item: (item.source_file, item.reason.value, item.detail or ""),
    )


def _source_statuses(
    correlation: AttackSurfaceCorrelationResult,
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
    handler_calls: HandlerCallResult,
) -> list[FlowSourceStatus]:
    correlation_discovery = all(
        status.discovery_is_complete for status in correlation.summary.source_statuses
    )
    correlation_truncation = sorted(
        {
            reason
            for status in correlation.summary.source_statuses
            for reason in status.discovery_truncation_reasons
        },
        key=lambda item: item.value,
    )
    return [
        FlowSourceStatus(
            source=FlowAnalysisSource.ATTACK_SURFACE_CORRELATION,
            is_complete=correlation.summary.is_complete,
            discovery_is_complete=correlation_discovery,
            issue_count=len(correlation.issues),
            discovery_truncation_reasons=correlation_truncation,
        ),
        FlowSourceStatus(
            source=FlowAnalysisSource.INPUT_SOURCES,
            is_complete=input_sources.summary.is_complete,
            discovery_is_complete=input_sources.summary.discovery_is_complete,
            issue_count=input_sources.summary.issue_count,
            discovery_truncation_reasons=list(input_sources.summary.discovery_truncation_reasons),
        ),
        FlowSourceStatus(
            source=FlowAnalysisSource.SENSITIVE_OPERATIONS,
            is_complete=sensitive_operations.summary.is_complete,
            discovery_is_complete=sensitive_operations.summary.discovery_is_complete,
            issue_count=sensitive_operations.summary.issue_count,
            discovery_truncation_reasons=list(
                sensitive_operations.summary.discovery_truncation_reasons
            ),
        ),
        FlowSourceStatus(
            source=FlowAnalysisSource.HANDLER_CALLS,
            is_complete=handler_calls.summary.is_complete,
            discovery_is_complete=handler_calls.summary.discovery_is_complete,
            issue_count=handler_calls.summary.issue_count,
            discovery_truncation_reasons=list(handler_calls.summary.discovery_truncation_reasons),
        ),
    ]


def _build_relationships(
    hits: dict[tuple[str, str], _FlowPath],
    context: _AnalysisContext,
    handler_calls: HandlerCallResult,
    correlation: AttackSurfaceCorrelationResult,
    *,
    max_relationships: int,
) -> tuple[list[InputOperationRelationship], bool]:
    reverse = _reverse_call_graph(handler_calls)
    calls = context.call_sites
    input_route_map, operation_route_map = _correlation_route_maps(correlation)
    relationships: list[InputOperationRelationship] = []
    limit_hit = False

    sorted_hits = sorted(
        hits.items(),
        key=lambda item: (
            context.input_evidence[item[0][1]].candidate.source_file,
            context.input_evidence[item[0][1]].candidate.line_number,
            context.operation_evidence[item[0][0]].candidate.source_file,
            context.operation_evidence[item[0][0]].candidate.line_number,
            item[0][1],
            item[0][0],
        ),
    )
    for (operation_id, input_id), path in sorted_hits:
        input_evidence = context.input_evidence.get(input_id)
        operation_evidence = context.operation_evidence.get(operation_id)
        if input_evidence is None or operation_evidence is None:
            continue
        if len(relationships) >= max_relationships:
            limit_hit = True
            break
        status = _relationship_status(path, input_evidence, operation_evidence, calls)
        confidence = _relationship_confidence(
            path,
            input_evidence,
            operation_evidence,
            calls,
            status,
        )
        input_definition_ids = set(input_evidence.seed_definition_ids)
        operation_definition_ids = set(operation_evidence.definition_ids)
        common_handlers: set[str] = set()
        for input_definition_id in input_definition_ids:
            reaching_input = _handlers_reaching(input_definition_id, reverse)
            for operation_definition_id in operation_definition_ids:
                common_handlers |= reaching_input & _handlers_reaching(
                    operation_definition_id, reverse
                )
        handler_references = _handler_references(common_handlers, handler_calls)
        route_ids = sorted({reference.route_id for reference in handler_references})
        if not route_ids:
            input_routes = input_route_map.get(
                _input_identity(input_evidence.candidate),
                set(),
            )
            operation_routes = operation_route_map.get(
                _operation_identity(operation_evidence.candidate),
                set(),
            )
            route_ids = sorted(input_routes & operation_routes)

        intermediate_definitions = sorted(
            {step.definition_id for step in path.steps if step.definition_id is not None}
        )
        intermediate_calls = sorted(set(path.call_ids))
        ambiguous_definitions = sorted(set(path.ambiguous_definition_ids))
        explanation_parts = [
            (
                f"Static propagation from input evidence '{input_id}' at "
                f"{input_evidence.candidate.source_file}:"
                f"{input_evidence.candidate.line_number} to operation evidence "
                f"'{operation_id}' at {operation_evidence.candidate.source_file}:"
                f"{operation_evidence.candidate.line_number}."
            ),
            (
                f"Input evidence status: {input_evidence.candidate.resolution_status.value}; "
                f"operation evidence status: "
                f"{operation_evidence.candidate.resolution_status.value}."
            ),
        ]
        if status is FlowResolutionStatus.AMBIGUOUS:
            explanation_parts.append(
                "Ambiguity is preserved: at least one call target or evidence anchor "
                "had multiple plausible statically visible candidates."
            )
        if path.unsupported_reasons:
            explanation_parts.append(
                "Unsupported propagation patterns were encountered: "
                + "; ".join(sorted(path.unsupported_reasons))
                + "."
            )
        explanation_parts.append(
            "This is not proof of runtime execution, runtime value flow, absent "
            "validation, or exploitability."
        )
        limitations = list(_LIMITATIONS)
        if input_evidence.candidate.resolution_status is InputResolutionStatus.UNRESOLVED:
            limitations.append(
                "The original input evidence has unresolved route associations. That "
                "status is preserved separately and does not change the dataflow status."
            )
        if operation_evidence.candidate.resolution_status is OperationResolutionStatus.UNRESOLVED:
            limitations.append(
                "The original operation evidence has unresolved route associations. "
                "That status is preserved separately and does not change the dataflow status."
            )
        if input_evidence.anchor_ambiguous or operation_evidence.anchor_ambiguous:
            limitations.append(
                "At least one evidence anchor matched several parsed source locations; "
                "every candidate location was treated as part of the same evidence."
            )
        if status is FlowResolutionStatus.AMBIGUOUS:
            limitations.append(
                "One or more local call targets were ambiguous; all candidates were "
                "analyzed and no single target was selected."
            )
        if status is FlowResolutionStatus.UNSUPPORTED:
            limitations.append(
                "A supported edge could not be established for at least one intermediate pattern."
            )

        relationships.append(
            InputOperationRelationship(
                relationship_id=f"{input_id}->{operation_id}",
                input_id=input_id,
                input_index=input_evidence.index,
                input_type=input_evidence.candidate.input_type,
                input_source_file=input_evidence.candidate.source_file,
                input_line_number=input_evidence.candidate.line_number,
                input_declaration=input_evidence.candidate.declaration_or_access,
                input_resolution_status=input_evidence.candidate.resolution_status,
                input_detection_confidence=input_evidence.candidate.detection_confidence,
                operation_id=operation_id,
                operation_index=operation_evidence.index,
                operation_category=operation_evidence.candidate.operation_category,
                operation_source_file=operation_evidence.candidate.source_file,
                operation_line_number=operation_evidence.candidate.line_number,
                operation_declaration=operation_evidence.candidate.declaration_or_access,
                operation_resolution_status=operation_evidence.candidate.resolution_status,
                operation_detection_confidence=operation_evidence.candidate.detection_confidence,
                resolution_status=status,
                detection_confidence=confidence,
                route_ids=route_ids,
                handler_references=handler_references,
                intermediate_definition_ids=intermediate_definitions,
                intermediate_call_ids=intermediate_calls,
                ambiguous_definition_ids=ambiguous_definitions,
                propagation_steps=[
                    step.model_copy(update={"step_index": index})
                    for index, step in enumerate(path.steps)
                ],
                explanation=" ".join(explanation_parts),
                limitations=limitations,
            )
        )
    relationships.sort(key=_relationship_sort_key)
    return relationships, limit_hit


def _truncation_reasons(
    correlation: AttackSurfaceCorrelationResult,
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
    handler_calls: HandlerCallResult,
) -> list[DiscoveryTruncationReason]:
    reasons = {
        *input_sources.summary.discovery_truncation_reasons,
        *sensitive_operations.summary.discovery_truncation_reasons,
        *handler_calls.summary.discovery_truncation_reasons,
        *(
            reason
            for status in correlation.summary.source_statuses
            for reason in status.discovery_truncation_reasons
        ),
    }
    return sorted(reasons, key=lambda item: item.value)


def analyze_input_operation_flow(
    root: Path,
    inventory: RepositoryDiscoveryResult,
    attack_surface_correlation: AttackSurfaceCorrelationResult,
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
    handler_calls: HandlerCallResult,
    *,
    max_source_file_size_bytes: int | None = None,
    max_source_files: int | None = None,
    max_propagation_depth: int | None = None,
    max_propagation_states: int | None = None,
    max_relationships: int | None = None,
) -> InputOperationFlowResult:
    """Establish deterministic static input-to-operation relationships.

    The repository root is revalidated against ``REPOSITORY_ALLOWED_ROOTS`` and
    must match every consumed analysis result. Only inventoried Python source
    files referenced by the existing evidence or call graph are parsed. Repository
    code is never executed, imported, or invoked.
    """
    resolved_root = _resolve_flow_root(
        root,
        inventory,
        attack_surface_correlation,
        input_sources,
        sensitive_operations,
        handler_calls,
    )

    max_size = (
        settings.input_operation_source_max_size_bytes
        if max_source_file_size_bytes is None
        else max_source_file_size_bytes
    )
    max_files = (
        settings.input_operation_max_source_files if max_source_files is None else max_source_files
    )
    depth_limit = (
        settings.input_operation_max_propagation_depth
        if max_propagation_depth is None
        else max_propagation_depth
    )
    state_limit = (
        settings.input_operation_max_propagation_states
        if max_propagation_states is None
        else max_propagation_states
    )
    relationship_limit = (
        settings.input_operation_max_relationships
        if max_relationships is None
        else max_relationships
    )
    if any(
        value < 0 for value in (max_size, max_files, depth_limit, state_limit, relationship_limit)
    ):
        raise InputOperationFlowError("Analysis limits must not be negative")

    issues: list[InputOperationIssue] = []
    sorted_inputs = sorted(input_sources.inputs, key=_input_sort_key)
    sorted_operations = sorted(sensitive_operations.operations, key=_operation_sort_key)
    if not sorted_inputs:
        issues.append(
            _issue(
                _REPOSITORY_ROOT_LABEL,
                FlowIssueCategory.NO_INPUT_EVIDENCE,
                "No input-source evidence was supplied; no relationships can be established.",
            )
        )
    if not sorted_operations:
        issues.append(
            _issue(
                _REPOSITORY_ROOT_LABEL,
                FlowIssueCategory.NO_SENSITIVE_OPERATION_EVIDENCE,
                (
                    "No sensitive-operation evidence was supplied; no relationships "
                    "can be established."
                ),
            )
        )

    relevant_files: set[str] = set()
    for candidate in sorted_inputs:
        if _extension(candidate.source_file, None) in _PYTHON_EXTENSIONS:
            relevant_files.add(candidate.source_file)
    for candidate in sorted_operations:
        if _extension(candidate.source_file, None) in _PYTHON_EXTENSIONS:
            relevant_files.add(candidate.source_file)
    for definition in handler_calls.definitions:
        if _extension(definition.source_file, None) in _PYTHON_EXTENSIONS:
            relevant_files.add(definition.source_file)

    parsed_files: dict[str, _ParsedFile] = {}
    source_issues: list[AnalysisIssue] = []
    inspected = 0
    source_limit_hit = False
    if sorted_inputs or sorted_operations:
        parsed_files, source_issues, inspected, source_limit_hit = _load_parsed_files(
            resolved_root,
            inventory,
            relevant_files,
            max_size=max_size,
            max_files=max_files,
        )

    if sorted_inputs or sorted_operations:
        functions = _build_functions(parsed_files, handler_calls, issues)
        (
            input_evidence,
            operation_evidence,
            input_anchors,
            operation_anchors,
            parameter_seeds,
            functions_with_inputs,
            functions_with_operations,
        ) = _build_evidence(
            parsed_files,
            functions,
            input_sources,
            sensitive_operations,
            issues,
        )
    else:
        functions = {}
        input_evidence = {}
        operation_evidence = {}
        input_anchors = {}
        operation_anchors = {}
        parameter_seeds = {}
        functions_with_inputs = frozenset()
        functions_with_operations = frozenset()
    context = _AnalysisContext(
        parsed_files=parsed_files,
        functions=functions,
        call_index={
            (call.source_file, call.line_number, call.column_number): call
            for call in handler_calls.calls
        },
        call_sites={call.call_id: call for call in handler_calls.calls},
        input_anchors=input_anchors,
        operation_anchors=operation_anchors,
        input_evidence=input_evidence,
        operation_evidence=operation_evidence,
        parameter_seeds=parameter_seeds,
        functions_with_inputs=functions_with_inputs,
        functions_with_operations=functions_with_operations,
    )

    hits: dict[tuple[str, str], _FlowPath] = {}
    propagation_states = 0
    depth_limited = False
    state_limited = False
    if functions:
        analyzer = _FlowAnalyzer(
            context,
            issues,
            max_depth=depth_limit,
            max_states=state_limit,
        )
        hits = analyzer.analyze_all()
        propagation_states = analyzer.states
        depth_limited = analyzer.depth_limited
        state_limited = analyzer.state_limited

    relationships, relationship_limit_hit = _build_relationships(
        hits,
        context,
        handler_calls,
        attack_surface_correlation,
        max_relationships=relationship_limit,
    )
    if relationship_limit_hit:
        issues.append(
            _issue(
                _REPOSITORY_ROOT_LABEL,
                FlowIssueCategory.RELATIONSHIP_LIMIT,
                (
                    f"Maximum of {relationship_limit} flow relationships was reached; "
                    "additional relationships were not emitted."
                ),
            )
        )

    sorted_source_issues = _dedupe_source_issues(source_issues)
    sorted_issues = _dedupe_issues(issues)
    truncation_reasons = _truncation_reasons(
        attack_surface_correlation,
        input_sources,
        sensitive_operations,
        handler_calls,
    )
    source_analysis_is_complete = (
        inventory.summary.is_complete
        and attack_surface_correlation.summary.all_sources_complete
        and input_sources.summary.is_complete
        and sensitive_operations.summary.is_complete
        and handler_calls.summary.is_complete
    )
    is_complete = (
        source_analysis_is_complete
        and not sorted_source_issues
        and not source_limit_hit
        and not depth_limited
        and not state_limited
        and not relationship_limit_hit
    )
    statuses = _source_statuses(
        attack_surface_correlation,
        input_sources,
        sensitive_operations,
        handler_calls,
    )
    summary = InputOperationFlowSummary(
        source_files_inspected=inspected,
        input_count=len(sorted_inputs),
        operation_count=len(sorted_operations),
        relationship_count=len(relationships),
        resolved_relationship_count=sum(
            relationship.resolution_status is FlowResolutionStatus.RESOLVED
            for relationship in relationships
        ),
        ambiguous_relationship_count=sum(
            relationship.resolution_status is FlowResolutionStatus.AMBIGUOUS
            for relationship in relationships
        ),
        unresolved_relationship_count=sum(
            relationship.resolution_status is FlowResolutionStatus.UNRESOLVED
            for relationship in relationships
        ),
        unsupported_relationship_count=sum(
            relationship.resolution_status is FlowResolutionStatus.UNSUPPORTED
            for relationship in relationships
        ),
        inputs_with_relationships=len({relationship.input_id for relationship in relationships}),
        operations_with_relationships=len(
            {relationship.operation_id for relationship in relationships}
        ),
        propagation_state_count=propagation_states,
        source_issue_count=len(sorted_source_issues),
        issue_count=len(sorted_issues),
        source_analysis_is_complete=source_analysis_is_complete,
        is_complete=is_complete,
        discovery_is_complete=inventory.summary.is_complete,
        discovery_truncation_reasons=truncation_reasons,
        max_source_files=max_files,
        max_source_file_size_bytes=max_size,
        max_propagation_depth=depth_limit,
        max_propagation_states=state_limit,
        max_relationships=relationship_limit,
        source_statuses=statuses,
    )

    return InputOperationFlowResult(
        root=str(resolved_root),
        relationships=relationships,
        source_issues=sorted_source_issues,
        issues=sorted_issues,
        summary=summary,
    )
