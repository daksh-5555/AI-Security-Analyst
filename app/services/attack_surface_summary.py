"""Deterministic, read-only summary of the completed attack-surface analyses.

The service aggregates the route inventory, route correlation, handler/call
analysis, and input-to-operation flow analysis. It does not read repository
files, parse source, build a call graph, perform dataflow analysis, execute or
import repository code, call an LLM, use the network, shell, subprocess, or Git,
or persist anything.

The summary preserves the original evidence records and identifiers. It never
converts missing evidence into a negative security conclusion: an empty
authentication collection does not mean a route is unauthenticated, and an empty
flow collection does not mean no dataflow exists. Evidence that cannot be tied
to a route remains in ``global_evidence``.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from app.schemas.attack_surface import (
    AttackSurfaceResult,
    HttpMethod,
    RouteCandidate,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.attack_surface_correlation import (
    AttackSurfaceCorrelationResult,
    CorrelatedRoute,
    CorrelationAnalysisSource,
    CorrelationIssueCategory,
    CorrelationRelationship,
    CorrelationRouteReference,
)
from app.schemas.attack_surface_summary import (
    AttackSurfaceRouteSummary,
    AttackSurfaceSummaryMetrics,
    AttackSurfaceSummaryResult,
    GlobalAttackSurfaceEvidence,
    SummaryAnalysisSource,
    SummaryIssue,
    SummaryIssueKind,
    SummarySourceStatus,
)
from app.schemas.auth_controls import AuthControlCandidate
from app.schemas.handler_calls import (
    CallRelationship,
    CallResolutionStatus,
    CallSite,
    HandlerCallIssue,
    HandlerCallIssueCategory,
    HandlerCallResult,
    HandlerResolutionStatus,
    LocalFunctionDefinition,
    RouteHandler,
)
from app.schemas.input_operation_flow import (
    FlowIssueCategory,
    FlowResolutionStatus,
    InputOperationFlowResult,
    InputOperationIssue,
    InputOperationRelationship,
)
from app.schemas.input_sources import InputCandidate
from app.schemas.sensitive_operations import SensitiveOperationCandidate
from app.services.repository_targets import (
    InvalidRepositoryLocationError,
    validate_repository_location,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)

_AMBIGUOUS_CATEGORIES = frozenset(
    {
        CorrelationIssueCategory.AMBIGUOUS_ROUTE_REFERENCE.value,
        HandlerCallIssueCategory.AMBIGUOUS_HANDLER_DEFINITION.value,
        HandlerCallIssueCategory.AMBIGUOUS_CALL.value,
        FlowIssueCategory.AMBIGUOUS_EVIDENCE_LOCATION.value,
        FlowIssueCategory.AMBIGUOUS_CALL_PROPAGATION.value,
    }
)
_UNRESOLVED_CATEGORIES = frozenset(
    {
        CorrelationIssueCategory.UNRESOLVED_ROUTE_REFERENCE.value,
        CorrelationIssueCategory.UNRESOLVED_ROUTE.value,
        HandlerCallIssueCategory.HANDLER_DEFINITION_NOT_FOUND.value,
        HandlerCallIssueCategory.UNRESOLVED_CALL.value,
        FlowIssueCategory.UNRESOLVED_INPUT_EVIDENCE.value,
        FlowIssueCategory.UNRESOLVED_OPERATION_EVIDENCE.value,
        FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION.value,
    }
)
_UNSUPPORTED_CATEGORIES = frozenset(
    {
        HandlerCallIssueCategory.UNSUPPORTED_LANGUAGE.value,
        FlowIssueCategory.UNSUPPORTED_LANGUAGE.value,
        FlowIssueCategory.UNSUPPORTED_PROPAGATION.value,
    }
)


class AttackSurfaceSummaryError(ValueError):
    """Base error for attack-surface summary operations."""


class InvalidAttackSurfaceSummaryRootError(AttackSurfaceSummaryError):
    """Raised when supplied results do not share one validated repository root."""


@dataclass(frozen=True)
class _RouteSeed:
    """Route identity from correlation or, if missing there, from extraction."""

    route_id: str
    path: str
    http_method: HttpMethod
    framework: RouteFramework
    source_file: str
    line_number: int
    handler_name: str | None
    detection_confidence: float
    resolution_status: RouteResolutionStatus
    correlated: CorrelatedRoute | None


def _normalized_root(value: str | Path) -> str:
    return os.path.normcase(os.path.normpath(str(value)))


def _resolve_summary_root(
    root: Path,
    attack_surface: AttackSurfaceResult,
    correlation: AttackSurfaceCorrelationResult,
    handler_calls: HandlerCallResult,
    input_operation_flow: InputOperationFlowResult,
) -> Path:
    try:
        resolved_root = validate_repository_location(str(root))
    except InvalidRepositoryLocationError as exc:
        raise InvalidAttackSurfaceSummaryRootError(str(exc)) from exc

    expected = _normalized_root(resolved_root)
    for label, value in (
        ("Attack surface", attack_surface.root),
        ("Attack surface correlation", correlation.root),
        ("Handler calls", handler_calls.root),
        ("Input-operation flow", input_operation_flow.root),
    ):
        try:
            normalized = _normalized_root(Path(value).expanduser().resolve(strict=False))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidAttackSurfaceSummaryRootError(
                f"{label} root is not a valid filesystem path"
            ) from exc
        if normalized != expected:
            raise InvalidAttackSurfaceSummaryRootError(
                f"{label} root does not match the repository root"
            )
    return resolved_root


def _dedupe_sorted(
    items: list[_ModelT],
    sort_key,
) -> list[_ModelT]:
    unique: dict[str, _ModelT] = {}
    for item in sorted(items, key=sort_key):
        key = json.dumps(item.model_dump(mode="json"), sort_keys=True)
        unique.setdefault(key, item)
    return list(unique.values())


def _distinct_count(items: list[_ModelT]) -> int:
    return len({json.dumps(item.model_dump(mode="json"), sort_keys=True) for item in items})


def _route_candidate_id(route: RouteCandidate) -> str:
    return (
        f"{route.source_file}:{route.line_number}:"
        f"{route.http_method.value}:{route.framework.value}:{route.path}"
    )


def _route_candidate_sort_key(route: RouteCandidate) -> tuple[object, ...]:
    return (
        route.source_file,
        route.line_number,
        route.path,
        route.http_method.value,
        route.framework.value,
        route.handler_name or "",
        route.detection_confidence,
    )


def _correlated_route_sort_key(route: CorrelatedRoute) -> tuple[object, ...]:
    return (
        route.source_file,
        route.line_number,
        route.path,
        route.http_method.value,
        route.framework.value,
        route.route_id,
    )


def _route_seed_sort_key(seed: _RouteSeed) -> tuple[object, ...]:
    return (
        seed.source_file,
        seed.line_number,
        seed.path,
        seed.http_method.value,
        seed.framework.value,
        seed.route_id,
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


def _definition_sort_key(definition: LocalFunctionDefinition) -> tuple[object, ...]:
    return (
        definition.source_file,
        definition.line_number,
        definition.column_number,
        definition.definition_id,
    )


def _call_sort_key(call: CallSite) -> tuple[object, ...]:
    return (call.source_file, call.line_number, call.column_number, call.call_id)


def _call_relationship_sort_key(relationship: CallRelationship) -> tuple[object, ...]:
    return (
        relationship.source_file,
        relationship.line_number,
        relationship.caller_definition_id,
        relationship.callee_definition_id,
        relationship.relationship_id,
    )


def _flow_relationship_sort_key(
    relationship: InputOperationRelationship,
) -> tuple[object, ...]:
    return (
        relationship.input_source_file,
        relationship.input_line_number,
        relationship.operation_source_file,
        relationship.operation_line_number,
        relationship.relationship_id,
    )


def _control_sort_key(control: AuthControlCandidate) -> tuple[object, ...]:
    return (
        control.source_file,
        control.line_number,
        control.control_type.value,
        control.framework.value,
        control.mechanism,
        control.symbol_name or "",
        control.scope_type.value,
        control.declaration or "",
        control.evidence,
        control.classification_rule,
    )


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


def _correlation_relationship_sort_key(
    relationship: CorrelationRelationship,
) -> tuple[object, ...]:
    return (
        relationship.route_id,
        relationship.relationship_type.value,
        relationship.evidence_source.value,
        relationship.evidence_index,
        relationship.evidence_identifier,
        relationship.resolution_status.value,
    )


def _summary_issue_key(issue: SummaryIssue) -> tuple[object, ...]:
    return (
        issue.kind,
        issue.category,
        issue.route_id,
        issue.route_path,
        issue.route_http_method,
        issue.route_framework,
        issue.route_resolution_status,
        issue.source_file,
        issue.line_number,
        issue.handler_id,
        issue.call_id,
        issue.definition_id,
        issue.input_id,
        issue.operation_id,
        issue.relationship_id,
        issue.evidence_identifier,
        issue.detail,
        issue.explanation,
    )


def _summary_issue_sort_key(issue: SummaryIssue) -> tuple[object, ...]:
    return (
        issue.source_file or "",
        issue.line_number or 0,
        issue.kind.value,
        issue.category,
        issue.route_id or "",
        issue.route_path or "",
        issue.explanation,
    )


def _build_route_seeds(
    attack_surface: AttackSurfaceResult,
    correlation: AttackSurfaceCorrelationResult,
) -> list[_RouteSeed]:
    seeds: dict[str, _RouteSeed] = {}
    for route in sorted(correlation.routes, key=_correlated_route_sort_key):
        seeds.setdefault(
            route.route_id,
            _RouteSeed(
                route_id=route.route_id,
                path=route.path,
                http_method=route.http_method,
                framework=route.framework,
                source_file=route.source_file,
                line_number=route.line_number,
                handler_name=route.handler_name,
                detection_confidence=route.detection_confidence,
                resolution_status=route.resolution_status,
                correlated=route,
            ),
        )

    for route in sorted(attack_surface.routes, key=_route_candidate_sort_key):
        route_id = _route_candidate_id(route)
        seeds.setdefault(
            route_id,
            _RouteSeed(
                route_id=route_id,
                path=route.path,
                http_method=route.http_method,
                framework=route.framework,
                source_file=route.source_file,
                line_number=route.line_number,
                handler_name=route.handler_name,
                detection_confidence=route.detection_confidence,
                resolution_status=route.resolution_status,
                correlated=None,
            ),
        )

    return sorted(seeds.values(), key=_route_seed_sort_key)


def _unique_route_id(route_ids: list[str], known_route_ids: set[str]) -> str | None:
    matches = {route_id for route_id in route_ids if route_id in known_route_ids}
    return next(iter(matches)) if len(matches) == 1 else None


def _route_reference_route_id(
    reference: CorrelationRouteReference | None,
    route_ids_by_identity: dict[tuple[str, str, str], list[str]],
) -> str | None:
    if reference is None:
        return None
    matches = route_ids_by_identity.get(
        (reference.path, reference.http_method.value, reference.framework.value),
        [],
    )
    return matches[0] if len(matches) == 1 else None


def _build_issues(
    attack_surface: AttackSurfaceResult,
    correlation: AttackSurfaceCorrelationResult,
    handler_calls: HandlerCallResult,
    input_operation_flow: InputOperationFlowResult,
    route_ids: set[str],
    route_ids_by_identity: dict[tuple[str, str, str], list[str]],
    handler_route_ids: dict[str, str],
    call_route_ids: dict[str, str],
    definition_route_ids: dict[str, str],
) -> list[SummaryIssue]:
    issues: list[SummaryIssue] = []

    for issue in attack_surface.issues:
        issues.append(
            SummaryIssue(
                issue_id="pending",
                origins=[SummaryAnalysisSource.ATTACK_SURFACE],
                kind=SummaryIssueKind.INSPECTION,
                category=issue.reason.value,
                source_file=issue.source_file,
                detail=issue.detail,
                explanation=issue.detail or issue.reason.value,
            )
        )

    for issue in correlation.issues:
        route_id = _route_reference_route_id(issue.route, route_ids_by_identity)
        issues.append(
            SummaryIssue(
                issue_id="pending",
                origins=[SummaryAnalysisSource.ATTACK_SURFACE_CORRELATION],
                kind=SummaryIssueKind.CORRELATION,
                category=issue.category.value,
                route_id=route_id,
                route_path=issue.route.path if issue.route else None,
                route_http_method=issue.route.http_method if issue.route else None,
                route_framework=issue.route.framework if issue.route else None,
                route_resolution_status=issue.route.resolution_status if issue.route else None,
                source_file=issue.source_file,
                evidence_identifier=issue.evidence_identifier,
                explanation=issue.explanation,
            )
        )

    for issue in handler_calls.issues:
        issues.append(
            SummaryIssue(
                issue_id="pending",
                origins=[SummaryAnalysisSource.HANDLER_CALLS],
                kind=SummaryIssueKind.INSPECTION,
                category=issue.reason.value,
                source_file=issue.source_file,
                detail=issue.detail,
                explanation=issue.detail or issue.reason.value,
            )
        )

    for issue in handler_calls.call_issues:
        route_id = _handler_call_issue_route_id(
            issue,
            route_ids,
            handler_route_ids,
            call_route_ids,
            definition_route_ids,
        )
        issues.append(
            SummaryIssue(
                issue_id="pending",
                origins=[SummaryAnalysisSource.HANDLER_CALLS],
                kind=SummaryIssueKind.HANDLER_CALL,
                category=issue.category.value,
                route_id=route_id,
                source_file=issue.source_file,
                line_number=issue.line_number,
                handler_id=issue.handler_id,
                call_id=issue.call_id,
                definition_id=issue.definition_id,
                explanation=issue.explanation,
            )
        )

    for issue in input_operation_flow.source_issues:
        issues.append(
            SummaryIssue(
                issue_id="pending",
                origins=[SummaryAnalysisSource.INPUT_OPERATION_FLOW],
                kind=SummaryIssueKind.INSPECTION,
                category=issue.reason.value,
                source_file=issue.source_file,
                detail=issue.detail,
                explanation=issue.detail or issue.reason.value,
            )
        )

    for issue in input_operation_flow.issues:
        route_id = _flow_issue_route_id(issue, call_route_ids, definition_route_ids)
        issues.append(
            SummaryIssue(
                issue_id="pending",
                origins=[SummaryAnalysisSource.INPUT_OPERATION_FLOW],
                kind=SummaryIssueKind.INPUT_OPERATION_FLOW,
                category=issue.category.value,
                route_id=route_id,
                source_file=issue.source_file,
                line_number=issue.line_number,
                input_id=issue.input_id,
                operation_id=issue.operation_id,
                call_id=issue.call_id,
                definition_id=issue.definition_id,
                explanation=issue.explanation,
            )
        )

    unique: dict[tuple[object, ...], SummaryIssue] = {}
    for issue in issues:
        key = _summary_issue_key(issue)
        existing = unique.get(key)
        if existing is None:
            unique[key] = issue
            continue
        origins = sorted(
            {*existing.origins, *issue.origins},
            key=lambda item: item.value,
        )
        unique[key] = existing.model_copy(update={"origins": origins})

    ordered = sorted(unique.values(), key=_summary_issue_sort_key)
    return [
        issue.model_copy(update={"issue_id": f"issues[{index}]"})
        for index, issue in enumerate(ordered)
    ]


def _handler_call_issue_route_id(
    issue: HandlerCallIssue,
    route_ids: set[str],
    handler_route_ids: dict[str, str],
    call_route_ids: dict[str, str],
    definition_route_ids: dict[str, str],
) -> str | None:
    if issue.handler_id is not None:
        direct = handler_route_ids.get(issue.handler_id)
        if direct is not None:
            return direct
        if issue.handler_id in route_ids:
            return issue.handler_id
    if issue.call_id is not None and issue.call_id in call_route_ids:
        return call_route_ids[issue.call_id]
    if issue.definition_id is not None:
        return definition_route_ids.get(issue.definition_id)
    return None


def _flow_issue_route_id(
    issue: InputOperationIssue,
    call_route_ids: dict[str, str],
    definition_route_ids: dict[str, str],
) -> str | None:
    if issue.call_id is not None and issue.call_id in call_route_ids:
        return call_route_ids[issue.call_id]
    if issue.definition_id is not None:
        return definition_route_ids.get(issue.definition_id)
    return None


def _build_route_summaries(
    seeds: list[_RouteSeed],
    handlers: list[RouteHandler],
    definitions: list[LocalFunctionDefinition],
    calls: list[CallSite],
    call_relationships: list[CallRelationship],
    flow_relationships: list[InputOperationRelationship],
    issues: list[SummaryIssue],
) -> list[AttackSurfaceRouteSummary]:
    handlers_by_route: dict[str, list[RouteHandler]] = {}
    for handler in handlers:
        handlers_by_route.setdefault(handler.route_id, []).append(handler)

    definitions_by_id = {definition.definition_id: definition for definition in definitions}
    definitions_by_route: dict[str, list[LocalFunctionDefinition]] = {}
    for definition in definitions:
        for route_id in definition.route_ids:
            definitions_by_route.setdefault(route_id, []).append(definition)

    calls_by_caller: dict[str, list[CallSite]] = {}
    for call in calls:
        calls_by_caller.setdefault(call.caller_definition_id, []).append(call)

    relationships_by_caller: dict[str, list[CallRelationship]] = {}
    for relationship in call_relationships:
        relationships_by_caller.setdefault(relationship.caller_definition_id, []).append(
            relationship
        )

    flow_by_route: dict[str, list[InputOperationRelationship]] = {}
    for relationship in flow_relationships:
        route_ids = set(relationship.route_ids)
        route_ids.update(reference.route_id for reference in relationship.handler_references)
        for route_id in sorted(route_ids):
            flow_by_route.setdefault(route_id, []).append(relationship)

    issues_by_route: dict[str, list[SummaryIssue]] = {}
    for issue in issues:
        if issue.route_id is not None:
            issues_by_route.setdefault(issue.route_id, []).append(issue)

    summaries: list[AttackSurfaceRouteSummary] = []
    for seed in seeds:
        correlated = seed.correlated
        route_handlers = _dedupe_sorted(
            list(handlers_by_route.get(seed.route_id, [])),
            _handler_sort_key,
        )

        definition_ids = {
            definition_id for handler in route_handlers for definition_id in handler.definition_ids
        }
        definition_ids.update(
            definition.definition_id for definition in definitions_by_route.get(seed.route_id, [])
        )
        route_definitions = _dedupe_sorted(
            [
                definitions_by_id[definition_id]
                for definition_id in definition_ids
                if definition_id in definitions_by_id
            ],
            _definition_sort_key,
        )

        route_calls: list[CallSite] = []
        route_relationships: list[CallRelationship] = []
        for definition in route_definitions:
            route_calls.extend(calls_by_caller.get(definition.definition_id, []))
            route_relationships.extend(relationships_by_caller.get(definition.definition_id, []))

        summaries.append(
            AttackSurfaceRouteSummary(
                route_id=seed.route_id,
                path=seed.path,
                http_method=seed.http_method,
                framework=seed.framework,
                source_file=seed.source_file,
                line_number=seed.line_number,
                handler_name=seed.handler_name,
                detection_confidence=seed.detection_confidence,
                resolution_status=seed.resolution_status,
                authentication_controls=_dedupe_sorted(
                    list(correlated.authentication_controls) if correlated else [],
                    _control_sort_key,
                ),
                authorization_controls=_dedupe_sorted(
                    list(correlated.authorization_controls) if correlated else [],
                    _control_sort_key,
                ),
                input_candidates=_dedupe_sorted(
                    list(correlated.input_candidates) if correlated else [],
                    _input_sort_key,
                ),
                sensitive_operations=_dedupe_sorted(
                    list(correlated.sensitive_operations) if correlated else [],
                    _operation_sort_key,
                ),
                correlation_relationships=_dedupe_sorted(
                    list(correlated.relationships) if correlated else [],
                    _correlation_relationship_sort_key,
                ),
                handlers=route_handlers,
                handler_definitions=route_definitions,
                call_sites=_dedupe_sorted(route_calls, _call_sort_key),
                call_relationships=_dedupe_sorted(
                    route_relationships,
                    _call_relationship_sort_key,
                ),
                input_operation_relationships=_dedupe_sorted(
                    list(flow_by_route.get(seed.route_id, [])),
                    _flow_relationship_sort_key,
                ),
                issue_ids=[issue.issue_id for issue in issues_by_route.get(seed.route_id, [])],
            )
        )
    return summaries


def _build_global_evidence(
    routes: list[AttackSurfaceRouteSummary],
    handlers: list[RouteHandler],
    definitions: list[LocalFunctionDefinition],
    calls: list[CallSite],
    call_relationships: list[CallRelationship],
    flow_relationships: list[InputOperationRelationship],
) -> GlobalAttackSurfaceEvidence:
    attached_handler_ids = {handler.handler_id for route in routes for handler in route.handlers}
    attached_definition_ids = {
        definition.definition_id for route in routes for definition in route.handler_definitions
    }
    attached_call_ids = {call.call_id for route in routes for call in route.call_sites}
    attached_relationship_ids = {
        relationship.relationship_id
        for route in routes
        for relationship in route.call_relationships
    }
    attached_flow_ids = {
        relationship.relationship_id
        for route in routes
        for relationship in route.input_operation_relationships
    }

    return GlobalAttackSurfaceEvidence(
        unlinked_handlers=[
            handler for handler in handlers if handler.handler_id not in attached_handler_ids
        ],
        unassociated_definitions=[
            definition
            for definition in definitions
            if definition.definition_id not in attached_definition_ids
        ],
        unassociated_call_sites=[call for call in calls if call.call_id not in attached_call_ids],
        unassociated_call_relationships=[
            relationship
            for relationship in call_relationships
            if relationship.relationship_id not in attached_relationship_ids
        ],
        unassociated_input_operation_relationships=[
            relationship
            for relationship in flow_relationships
            if relationship.relationship_id not in attached_flow_ids
        ],
    )


def _source_statuses(
    attack_surface: AttackSurfaceResult,
    correlation: AttackSurfaceCorrelationResult,
    handler_calls: HandlerCallResult,
    input_operation_flow: InputOperationFlowResult,
) -> list[SummarySourceStatus]:
    statuses: list[SummarySourceStatus] = [
        SummarySourceStatus(
            source=SummaryAnalysisSource.ATTACK_SURFACE,
            is_complete=attack_surface.summary.is_complete,
            discovery_is_complete=attack_surface.summary.discovery_is_complete,
            issue_count=attack_surface.summary.issue_count,
            discovery_truncation_reasons=list(attack_surface.summary.discovery_truncation_reasons),
        )
    ]

    for status in correlation.summary.source_statuses:
        if status.source is CorrelationAnalysisSource.ATTACK_SURFACE:
            continue
        statuses.append(
            SummarySourceStatus(
                source=SummaryAnalysisSource(status.source.value),
                is_complete=status.is_complete,
                discovery_is_complete=status.discovery_is_complete,
                issue_count=status.issue_count,
                discovery_truncation_reasons=list(status.discovery_truncation_reasons),
            )
        )

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
    statuses.append(
        SummarySourceStatus(
            source=SummaryAnalysisSource.ATTACK_SURFACE_CORRELATION,
            is_complete=correlation.summary.is_complete,
            discovery_is_complete=correlation_discovery,
            issue_count=correlation.summary.issue_count,
            discovery_truncation_reasons=correlation_truncation,
        )
    )

    statuses.append(
        SummarySourceStatus(
            source=SummaryAnalysisSource.HANDLER_CALLS,
            is_complete=handler_calls.summary.is_complete,
            discovery_is_complete=handler_calls.summary.discovery_is_complete,
            route_analysis_is_complete=handler_calls.summary.route_analysis_is_complete,
            issue_count=(
                handler_calls.summary.issue_count + handler_calls.summary.call_issue_count
            ),
            discovery_truncation_reasons=list(handler_calls.summary.discovery_truncation_reasons),
            route_analysis_truncation_reasons=list(
                handler_calls.summary.route_analysis_truncation_reasons
            ),
        )
    )

    statuses.append(
        SummarySourceStatus(
            source=SummaryAnalysisSource.INPUT_OPERATION_FLOW,
            is_complete=input_operation_flow.summary.is_complete,
            discovery_is_complete=input_operation_flow.summary.discovery_is_complete,
            issue_count=(
                input_operation_flow.summary.source_issue_count
                + input_operation_flow.summary.issue_count
            ),
            discovery_truncation_reasons=list(
                input_operation_flow.summary.discovery_truncation_reasons
            ),
        )
    )
    return statuses


def _resolution_counts(
    items: list[_ModelT],
    status_field: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        status = getattr(item, status_field)
        value = status.value if hasattr(status, "value") else str(status)
        counts[value] = counts.get(value, 0) + 1
    return counts


def _build_metrics(
    routes: list[AttackSurfaceRouteSummary],
    global_evidence: GlobalAttackSurfaceEvidence,
    issues: list[SummaryIssue],
    handlers: list[RouteHandler],
    definitions: list[LocalFunctionDefinition],
    calls: list[CallSite],
    call_relationships: list[CallRelationship],
    flow_relationships: list[InputOperationRelationship],
    source_statuses: list[SummarySourceStatus],
    all_sources_complete: bool,
) -> AttackSurfaceSummaryMetrics:
    authentication = [control for route in routes for control in route.authentication_controls]
    authorization = [control for route in routes for control in route.authorization_controls]
    inputs = [candidate for route in routes for candidate in route.input_candidates]
    operations = [operation for route in routes for operation in route.sensitive_operations]

    handler_statuses = _resolution_counts(handlers, "resolution_status")
    call_statuses = _resolution_counts(calls, "resolution_status")
    call_relationship_statuses = _resolution_counts(
        call_relationships,
        "resolution_status",
    )
    flow_statuses = _resolution_counts(flow_relationships, "resolution_status")

    discovery_truncation = sorted(
        {reason for status in source_statuses for reason in status.discovery_truncation_reasons},
        key=lambda item: item.value,
    )
    route_analysis_truncation = sorted(
        {
            reason
            for status in source_statuses
            for reason in status.route_analysis_truncation_reasons
        },
        key=lambda item: item.value,
    )

    return AttackSurfaceSummaryMetrics(
        route_count=len(routes),
        routes_with_handlers=sum(bool(route.handlers) for route in routes),
        routes_without_handlers=sum(not route.handlers for route in routes),
        routes_with_resolved_handlers=sum(
            any(
                handler.resolution_status is HandlerResolutionStatus.RESOLVED
                for handler in route.handlers
            )
            for route in routes
        ),
        routes_with_ambiguous_handlers=sum(
            any(
                handler.resolution_status is HandlerResolutionStatus.AMBIGUOUS
                for handler in route.handlers
            )
            for route in routes
        ),
        routes_with_unresolved_handlers=sum(
            any(
                handler.resolution_status is HandlerResolutionStatus.UNRESOLVED
                for handler in route.handlers
            )
            for route in routes
        ),
        routes_with_authentication=sum(bool(route.authentication_controls) for route in routes),
        routes_with_authorization=sum(bool(route.authorization_controls) for route in routes),
        routes_with_inputs=sum(bool(route.input_candidates) for route in routes),
        routes_with_sensitive_operations=sum(bool(route.sensitive_operations) for route in routes),
        routes_with_input_operation_relationships=sum(
            bool(route.input_operation_relationships) for route in routes
        ),
        routes_with_multiple_evidence_categories=sum(
            sum(
                (
                    bool(route.authentication_controls),
                    bool(route.authorization_controls),
                    bool(route.input_candidates),
                    bool(route.sensitive_operations),
                )
            )
            >= 2
            for route in routes
        ),
        authentication_control_count=_distinct_count(authentication),
        authorization_control_count=_distinct_count(authorization),
        input_count=_distinct_count(inputs),
        sensitive_operation_count=_distinct_count(operations),
        correlation_relationship_count=sum(
            len(route.correlation_relationships) for route in routes
        ),
        handler_count=len(handlers),
        handler_resolved_count=handler_statuses.get(HandlerResolutionStatus.RESOLVED.value, 0),
        handler_ambiguous_count=handler_statuses.get(HandlerResolutionStatus.AMBIGUOUS.value, 0),
        handler_unresolved_count=handler_statuses.get(HandlerResolutionStatus.UNRESOLVED.value, 0),
        definition_count=len(definitions),
        call_count=len(calls),
        call_resolved_count=call_statuses.get(CallResolutionStatus.RESOLVED.value, 0),
        call_ambiguous_count=call_statuses.get(CallResolutionStatus.AMBIGUOUS.value, 0),
        call_unresolved_count=call_statuses.get(CallResolutionStatus.UNRESOLVED.value, 0),
        call_external_count=call_statuses.get(CallResolutionStatus.EXTERNAL.value, 0),
        call_relationship_count=len(call_relationships),
        call_relationship_resolved_count=call_relationship_statuses.get(
            CallResolutionStatus.RESOLVED.value, 0
        ),
        call_relationship_ambiguous_count=call_relationship_statuses.get(
            CallResolutionStatus.AMBIGUOUS.value, 0
        ),
        call_relationship_unresolved_count=call_relationship_statuses.get(
            CallResolutionStatus.UNRESOLVED.value, 0
        ),
        call_relationship_external_count=call_relationship_statuses.get(
            CallResolutionStatus.EXTERNAL.value, 0
        ),
        input_operation_relationship_count=len(flow_relationships),
        input_operation_resolved_count=flow_statuses.get(FlowResolutionStatus.RESOLVED.value, 0),
        input_operation_ambiguous_count=flow_statuses.get(FlowResolutionStatus.AMBIGUOUS.value, 0),
        input_operation_unresolved_count=flow_statuses.get(
            FlowResolutionStatus.UNRESOLVED.value, 0
        ),
        input_operation_unsupported_count=flow_statuses.get(
            FlowResolutionStatus.UNSUPPORTED.value, 0
        ),
        unassociated_input_operation_relationship_count=len(
            global_evidence.unassociated_input_operation_relationships
        ),
        issue_count=len(issues),
        inspection_issue_count=sum(issue.kind is SummaryIssueKind.INSPECTION for issue in issues),
        correlation_issue_count=sum(issue.kind is SummaryIssueKind.CORRELATION for issue in issues),
        handler_call_issue_count=sum(
            issue.kind is SummaryIssueKind.HANDLER_CALL for issue in issues
        ),
        input_operation_issue_count=sum(
            issue.kind is SummaryIssueKind.INPUT_OPERATION_FLOW for issue in issues
        ),
        unresolved_issue_count=sum(issue.category in _UNRESOLVED_CATEGORIES for issue in issues),
        ambiguous_issue_count=sum(issue.category in _AMBIGUOUS_CATEGORIES for issue in issues),
        unsupported_issue_count=sum(issue.category in _UNSUPPORTED_CATEGORIES for issue in issues),
        all_sources_complete=all_sources_complete,
        is_complete=all_sources_complete,
        discovery_is_complete=all(status.discovery_is_complete for status in source_statuses),
        route_analysis_is_complete=all(
            status.route_analysis_is_complete
            for status in source_statuses
            if status.route_analysis_is_complete is not None
        ),
        discovery_truncation_reasons=discovery_truncation,
        route_analysis_truncation_reasons=route_analysis_truncation,
        source_statuses=source_statuses,
    )


def summarize_attack_surface(
    root: Path,
    attack_surface: AttackSurfaceResult,
    correlation: AttackSurfaceCorrelationResult,
    handler_calls: HandlerCallResult,
    input_operation_flow: InputOperationFlowResult,
) -> AttackSurfaceSummaryResult:
    """Consolidate the four completed analyses without performing new analysis.

    The repository root is validated against the configured allowed roots and
    must match every supplied analysis result. Evidence is sorted, deduplicated,
    and grouped by the route identifiers already recorded by the earlier phases.
    Nothing in the input results is mutated.
    """
    resolved_root = _resolve_summary_root(
        root,
        attack_surface,
        correlation,
        handler_calls,
        input_operation_flow,
    )

    seeds = _build_route_seeds(attack_surface, correlation)
    route_ids = {seed.route_id for seed in seeds}
    route_ids_by_identity: dict[tuple[str, str, str], list[str]] = {}
    for seed in seeds:
        route_ids_by_identity.setdefault(
            (seed.path, seed.http_method.value, seed.framework.value),
            [],
        ).append(seed.route_id)
    for matches in route_ids_by_identity.values():
        matches.sort()

    handlers = _dedupe_sorted(list(handler_calls.handlers), _handler_sort_key)
    definitions = _dedupe_sorted(
        list(handler_calls.definitions),
        _definition_sort_key,
    )
    calls = _dedupe_sorted(list(handler_calls.calls), _call_sort_key)
    call_relationships = _dedupe_sorted(
        list(handler_calls.relationships),
        _call_relationship_sort_key,
    )
    flow_relationships = _dedupe_sorted(
        list(input_operation_flow.relationships),
        _flow_relationship_sort_key,
    )
    definitions_by_id = {definition.definition_id: definition for definition in definitions}
    handler_route_ids = {handler.handler_id: handler.route_id for handler in handlers}
    definition_route_ids = {
        definition.definition_id: _unique_route_id(definition.route_ids, route_ids)
        for definition in definitions
    }
    definition_route_ids = {
        definition_id: route_id
        for definition_id, route_id in definition_route_ids.items()
        if route_id is not None
    }
    call_route_ids: dict[str, str] = {}
    for call in calls:
        definition = definitions_by_id.get(call.caller_definition_id)
        if definition is None:
            continue
        route_id = _unique_route_id(definition.route_ids, route_ids)
        if route_id is not None:
            call_route_ids[call.call_id] = route_id

    issues = _build_issues(
        attack_surface,
        correlation,
        handler_calls,
        input_operation_flow,
        route_ids,
        route_ids_by_identity,
        handler_route_ids,
        call_route_ids,
        definition_route_ids,
    )

    routes = _build_route_summaries(
        seeds,
        handlers,
        definitions,
        calls,
        call_relationships,
        flow_relationships,
        issues,
    )
    global_evidence = _build_global_evidence(
        routes,
        handlers,
        definitions,
        calls,
        call_relationships,
        flow_relationships,
    )
    source_statuses = _source_statuses(
        attack_surface,
        correlation,
        handler_calls,
        input_operation_flow,
    )
    all_sources_complete = (
        attack_surface.summary.is_complete
        and correlation.summary.is_complete
        and handler_calls.summary.is_complete
        and input_operation_flow.summary.is_complete
    )
    metrics = _build_metrics(
        routes,
        global_evidence,
        issues,
        handlers,
        definitions,
        calls,
        call_relationships,
        flow_relationships,
        source_statuses,
        all_sources_complete,
    )

    return AttackSurfaceSummaryResult(
        root=str(resolved_root),
        routes=routes,
        global_evidence=global_evidence,
        issues=issues,
        summary=metrics,
    )
