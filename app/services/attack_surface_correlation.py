"""Deterministic, read-only correlation of route-oriented attack-surface evidence.

The service combines the results of the route, authentication/authorization,
input-source, and sensitive-operation analyses. It performs no filesystem access,
no repository traversal, no source-code execution or imports, no network, shell,
subprocess, or Git calls, and no persistence.

Correlation is evidence aggregation, not vulnerability detection. A relationship
means only that an earlier analysis recorded the association. It does not prove
reachability, dataflow, enforcement, parameterization, sanitization, or
exploitability. In particular, co-occurrence of inputs and sensitive operations on
one route does not establish that an input reaches an operation, and the absence
of an authentication candidate does not establish that a route is unauthenticated.

Route identity comes exclusively from the earlier ``AssociatedRoute`` records:
path, HTTP method, and framework. Those references do not carry a source file or
line number, so when duplicate route declarations share all three values the
relationship is preserved as ambiguous rather than guessed. Evidence source files
are preserved on every relationship, but they are not used to break ties: an
application-, router-, or controller-scoped candidate can legitimately apply to
routes declared in several files.
"""

import json
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from pydantic import BaseModel

from app.schemas.attack_surface import (
    AttackSurfaceResult,
    RouteCandidate,
    RouteResolutionStatus,
)
from app.schemas.attack_surface_correlation import (
    AttackSurfaceCorrelationResult,
    AttackSurfaceCorrelationSummary,
    CorrelatedRoute,
    CorrelationAnalysisSource,
    CorrelationEvidenceSource,
    CorrelationIssue,
    CorrelationIssueCategory,
    CorrelationRelationship,
    CorrelationRelationshipType,
    CorrelationResolutionStatus,
    CorrelationRouteReference,
    CorrelationSourceStatus,
)
from app.schemas.auth_controls import (
    AssociatedRoute,
    AuthControlCandidate,
    AuthControlResult,
    ControlType,
)
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.input_sources import InputCandidate, InputSourceResult
from app.schemas.sensitive_operations import (
    SensitiveOperationCandidate,
    SensitiveOperationResult,
)

_SEVERITY: dict[CorrelationResolutionStatus, int] = {
    CorrelationResolutionStatus.RESOLVED: 0,
    CorrelationResolutionStatus.AMBIGUOUS: 1,
    CorrelationResolutionStatus.UNRESOLVED: 2,
}


class AttackSurfaceCorrelationError(ValueError):
    """Base error for attack-surface correlation operations."""


class InvalidCorrelationRootError(AttackSurfaceCorrelationError):
    """Raised when the supplied analysis results do not share one root."""


@dataclass
class _RouteBucket:
    """A route declaration and the evidence attached to it during correlation."""

    route: RouteCandidate
    route_id: str
    authentication_controls: dict[int, AuthControlCandidate] = field(default_factory=dict)
    authorization_controls: dict[int, AuthControlCandidate] = field(default_factory=dict)
    input_candidates: dict[int, InputCandidate] = field(default_factory=dict)
    sensitive_operations: dict[int, SensitiveOperationCandidate] = field(default_factory=dict)
    relationships: dict[tuple[str, str, int], CorrelationRelationship] = field(default_factory=dict)


_BucketIndex = dict[tuple[str, str, str], list[_RouteBucket]]
_EvidenceT = TypeVar("_EvidenceT")
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _normalized_root(value: str) -> str:
    return os.path.normcase(os.path.normpath(value))


def _resolve_correlation_root(
    attack_surface: AttackSurfaceResult,
    auth_controls: AuthControlResult,
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
) -> str:
    roots = [
        ("Attack surface", attack_surface.root),
        ("Authentication controls", auth_controls.root),
        ("Input sources", input_sources.root),
        ("Sensitive operations", sensitive_operations.root),
    ]
    expected = _normalized_root(attack_surface.root)
    for label, value in roots[1:]:
        if _normalized_root(value) != expected:
            raise InvalidCorrelationRootError(
                f"{label} root does not match the attack surface root"
            )
    return attack_surface.root


def _dedupe_sorted(
    items: Iterable[_ModelT],
    sort_key: Callable[[_ModelT], tuple[object, ...]],
) -> list[_ModelT]:
    unique: dict[str, _ModelT] = {}
    for item in sorted(items, key=sort_key):
        key = json.dumps(item.model_dump(mode="json"), sort_keys=True)
        unique.setdefault(key, item)
    return list(unique.values())


def _route_sort_key(route: RouteCandidate) -> tuple[object, ...]:
    return (
        route.source_file,
        route.line_number,
        route.path,
        route.http_method.value,
        route.framework.value,
        route.handler_name or "",
        route.resolution_status.value,
        route.detection_confidence,
    )


def _route_identity_values(
    path: str,
    http_method: str,
    framework: str,
) -> tuple[str, str, str]:
    return path, http_method, framework


def _route_identity(route: RouteCandidate) -> tuple[str, str, str]:
    return _route_identity_values(
        route.path,
        route.http_method.value,
        route.framework.value,
    )


def _reference_identity(reference: AssociatedRoute) -> tuple[str, str, str]:
    return _route_identity_values(
        reference.path,
        reference.http_method.value,
        reference.framework.value,
    )


def _route_id(route: RouteCandidate) -> str:
    return (
        f"{route.source_file}:{route.line_number}:"
        f"{route.http_method.value}:{route.framework.value}:{route.path}"
    )


def _route_reference(
    value: RouteCandidate | AssociatedRoute,
) -> CorrelationRouteReference:
    return CorrelationRouteReference(
        path=value.path,
        http_method=value.http_method,
        framework=value.framework,
        resolution_status=value.resolution_status,
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


def _unique_references(
    references: Iterable[AssociatedRoute],
) -> list[AssociatedRoute]:
    unique: dict[tuple[str, str, str, str], AssociatedRoute] = {}
    for reference in references:
        key = (
            reference.path,
            reference.http_method.value,
            reference.framework.value,
            reference.resolution_status.value,
        )
        unique[key] = reference
    return [unique[key] for key in sorted(unique)]


def _relationship_sort_key(
    relationship: CorrelationRelationship,
) -> tuple[object, ...]:
    return (
        relationship.relationship_type.value,
        relationship.evidence_source.value,
        relationship.evidence_index,
        relationship.resolution_status.value,
        relationship.route_id,
    )


def _issue_sort_key(issue: CorrelationIssue) -> tuple[object, ...]:
    return (
        issue.source_file or "",
        issue.route.path if issue.route else "",
        issue.route.http_method.value if issue.route else "",
        issue.route.framework.value if issue.route else "",
        issue.category.value,
        issue.evidence_source.value if issue.evidence_source else "",
        issue.evidence_identifier or "",
        issue.explanation,
    )


def _issue_dedupe_key(issue: CorrelationIssue) -> tuple[object, ...]:
    return (
        issue.source_file,
        issue.category,
        issue.route.path if issue.route else None,
        issue.route.http_method if issue.route else None,
        issue.route.framework if issue.route else None,
        issue.route.resolution_status if issue.route else None,
        issue.evidence_source,
        issue.evidence_identifier,
        issue.explanation,
    )


def _dedupe_issues(issues: Iterable[CorrelationIssue]) -> list[CorrelationIssue]:
    unique: dict[tuple[object, ...], CorrelationIssue] = {}
    for issue in sorted(issues, key=_issue_sort_key):
        unique.setdefault(_issue_dedupe_key(issue), issue)
    return sorted(unique.values(), key=_issue_sort_key)


def _control_context(control: AuthControlCandidate) -> str:
    return (
        f"Control scope '{control.scope_type.value}' and declaration evidence are "
        "preserved; a declared control is not proof of enforcement."
    )


def _input_context(_candidate: InputCandidate) -> str:
    return (
        "Co-occurrence on the same route does not establish dataflow between this "
        "input and any sensitive operation."
    )


def _operation_context(_candidate: SensitiveOperationCandidate) -> str:
    return (
        "Co-occurrence on the same route does not establish dataflow from any "
        "input to this operation."
    )


def _unresolved_route_explanation(
    reference: AssociatedRoute,
    route: RouteCandidate,
) -> str:
    reference_unresolved = reference.resolution_status is RouteResolutionStatus.UNRESOLVED
    route_unresolved = route.resolution_status is RouteResolutionStatus.UNRESOLVED
    if reference_unresolved and route_unresolved:
        detail = (
            "Both the associated-route reference and the matched route declaration are unresolved."
        )
    elif reference_unresolved:
        detail = "The associated-route reference is unresolved."
    else:
        detail = "The matched route declaration is unresolved."
    return (
        f"{detail} The relationship is preserved as unresolved without inferring "
        "a concrete route path."
    )


def _correlate_group(
    buckets: _BucketIndex,
    entries: Sequence[tuple[int, _EvidenceT]],
    *,
    source: CorrelationEvidenceSource,
    relationship_type: CorrelationRelationshipType,
    source_file: Callable[[_EvidenceT], str],
    line_number: Callable[[_EvidenceT], int],
    associated_routes: Callable[[_EvidenceT], list[AssociatedRoute]],
    attach: Callable[[_RouteBucket, int, _EvidenceT], None],
    context: Callable[[_EvidenceT], str],
    issues: list[CorrelationIssue],
) -> tuple[int, int]:
    missing_route_count = 0
    unassociated_count = 0

    for index, evidence in entries:
        identifier = f"{source.value}[{index}]"
        evidence_file = source_file(evidence)
        evidence_line = line_number(evidence)
        references = _unique_references(associated_routes(evidence))

        if not references:
            issues.append(
                CorrelationIssue(
                    source_file=evidence_file,
                    route=None,
                    category=CorrelationIssueCategory.UNASSOCIATED_EVIDENCE,
                    explanation=(
                        "The candidate has no associated route reference in its "
                        "source analysis. It is preserved as unresolved evidence "
                        "and is not assigned to a route by name similarity."
                    ),
                    evidence_source=source,
                    evidence_identifier=identifier,
                )
            )
            unassociated_count += 1
            continue

        for reference in references:
            matches = buckets.get(_reference_identity(reference), [])
            if not matches:
                issues.append(
                    CorrelationIssue(
                        source_file=evidence_file,
                        route=_route_reference(reference),
                        category=CorrelationIssueCategory.UNRESOLVED_ROUTE_REFERENCE,
                        explanation=(
                            f"The associated route reference '{reference.path}' "
                            f"({reference.http_method.value}, "
                            f"{reference.framework.value}) matched no route candidate "
                            "with the same path, HTTP method, and framework. No route "
                            "identity was invented."
                        ),
                        evidence_source=source,
                        evidence_identifier=identifier,
                    )
                )
                missing_route_count += 1
                continue

            ambiguous = len(matches) > 1
            if ambiguous:
                issues.append(
                    CorrelationIssue(
                        source_file=evidence_file,
                        route=_route_reference(reference),
                        category=CorrelationIssueCategory.AMBIGUOUS_ROUTE_REFERENCE,
                        explanation=(
                            f"The associated route reference '{reference.path}' "
                            f"({reference.http_method.value}, "
                            f"{reference.framework.value}) matched {len(matches)} "
                            "route declarations with identical path, HTTP method, and "
                            "framework. The reference does not carry source file or "
                            "line, so the specific declaration cannot be distinguished."
                        ),
                        evidence_source=source,
                        evidence_identifier=identifier,
                    )
                )

            for bucket in matches:
                route_unresolved = (
                    reference.resolution_status is RouteResolutionStatus.UNRESOLVED
                    or bucket.route.resolution_status is RouteResolutionStatus.UNRESOLVED
                )
                if route_unresolved:
                    status = CorrelationResolutionStatus.UNRESOLVED
                    explanation = _unresolved_route_explanation(reference, bucket.route)
                    issues.append(
                        CorrelationIssue(
                            source_file=bucket.route.source_file,
                            route=_route_reference(bucket.route),
                            category=CorrelationIssueCategory.UNRESOLVED_ROUTE,
                            explanation=(
                                f"{explanation} The evidence reference is '{identifier}'."
                            ),
                            evidence_source=source,
                            evidence_identifier=identifier,
                        )
                    )
                elif ambiguous:
                    status = CorrelationResolutionStatus.AMBIGUOUS
                    explanation = (
                        f"The associated route reference '{reference.path}' "
                        f"({reference.http_method.value}, "
                        f"{reference.framework.value}) matched {len(matches)} route "
                        "declarations with identical path, HTTP method, and framework. "
                        "The relationship is retained as ambiguous and the specific "
                        f"declaration was not guessed. {context(evidence)}"
                    )
                else:
                    status = CorrelationResolutionStatus.RESOLVED
                    explanation = (
                        "The associated route reference matched exactly one route "
                        "declaration by path, HTTP method, and framework. "
                        f"{context(evidence)}"
                    )

                relationship = CorrelationRelationship(
                    relationship_type=relationship_type,
                    evidence_source=source,
                    evidence_identifier=identifier,
                    evidence_index=index,
                    evidence_source_file=evidence_file,
                    evidence_line_number=evidence_line,
                    route_id=bucket.route_id,
                    resolution_status=status,
                    explanation=explanation,
                )
                attach(bucket, index, evidence)

                key = (relationship_type.value, source.value, index)
                existing = bucket.relationships.get(key)
                if existing is None or _SEVERITY[status] > _SEVERITY[existing.resolution_status]:
                    bucket.relationships[key] = relationship

    return missing_route_count, unassociated_count


def _source_status(
    source: CorrelationAnalysisSource,
    *,
    is_complete: bool,
    discovery_is_complete: bool,
    issue_count: int,
    truncation_reasons: Sequence[DiscoveryTruncationReason],
) -> CorrelationSourceStatus:
    return CorrelationSourceStatus(
        source=source,
        is_complete=is_complete,
        discovery_is_complete=discovery_is_complete,
        issue_count=issue_count,
        discovery_truncation_reasons=list(truncation_reasons),
    )


def correlate_attack_surface(
    attack_surface: AttackSurfaceResult,
    auth_controls: AuthControlResult,
    input_sources: InputSourceResult,
    sensitive_operations: SensitiveOperationResult,
) -> AttackSurfaceCorrelationResult:
    """Combine the four completed analyses into a route-oriented view.

    The four results must share the same repository root. Correlation uses only
    the relationships already recorded by the earlier analyses; it never rereads
    repository files or re-extracts routes, controls, inputs, or operations.
    """
    root = _resolve_correlation_root(
        attack_surface,
        auth_controls,
        input_sources,
        sensitive_operations,
    )

    routes = _dedupe_sorted(attack_surface.routes, _route_sort_key)
    controls = _dedupe_sorted(auth_controls.controls, _control_sort_key)
    inputs = _dedupe_sorted(input_sources.inputs, _input_sort_key)
    operations = _dedupe_sorted(
        sensitive_operations.operations,
        _operation_sort_key,
    )

    buckets = [_RouteBucket(route=route, route_id=_route_id(route)) for route in routes]
    buckets_by_identity: _BucketIndex = {}
    for bucket in buckets:
        buckets_by_identity.setdefault(_route_identity(bucket.route), []).append(bucket)

    control_entries = list(enumerate(controls))
    authentication_entries = [
        (index, control)
        for index, control in control_entries
        if control.control_type is ControlType.AUTHENTICATION
    ]
    authorization_entries = [
        (index, control)
        for index, control in control_entries
        if control.control_type is ControlType.AUTHORIZATION
    ]

    issues: list[CorrelationIssue] = []

    missing_authentication, unassociated_authentication = _correlate_group(
        buckets_by_identity,
        authentication_entries,
        source=CorrelationEvidenceSource.AUTH_CONTROLS,
        relationship_type=CorrelationRelationshipType.ROUTE_TO_AUTH_CONTROL,
        source_file=lambda control: control.source_file,
        line_number=lambda control: control.line_number,
        associated_routes=lambda control: control.associated_routes,
        attach=lambda bucket, index, control: bucket.authentication_controls.__setitem__(
            index, control
        ),
        context=_control_context,
        issues=issues,
    )
    missing_authorization, unassociated_authorization = _correlate_group(
        buckets_by_identity,
        authorization_entries,
        source=CorrelationEvidenceSource.AUTH_CONTROLS,
        relationship_type=CorrelationRelationshipType.ROUTE_TO_AUTHORIZATION_CONTROL,
        source_file=lambda control: control.source_file,
        line_number=lambda control: control.line_number,
        associated_routes=lambda control: control.associated_routes,
        attach=lambda bucket, index, control: bucket.authorization_controls.__setitem__(
            index, control
        ),
        context=_control_context,
        issues=issues,
    )
    missing_inputs, unassociated_inputs = _correlate_group(
        buckets_by_identity,
        list(enumerate(inputs)),
        source=CorrelationEvidenceSource.INPUT_SOURCES,
        relationship_type=CorrelationRelationshipType.ROUTE_TO_INPUT,
        source_file=lambda candidate: candidate.source_file,
        line_number=lambda candidate: candidate.line_number,
        associated_routes=lambda candidate: candidate.associated_routes,
        attach=lambda bucket, index, candidate: bucket.input_candidates.__setitem__(
            index, candidate
        ),
        context=_input_context,
        issues=issues,
    )
    missing_operations, unassociated_operations = _correlate_group(
        buckets_by_identity,
        list(enumerate(operations)),
        source=CorrelationEvidenceSource.SENSITIVE_OPERATIONS,
        relationship_type=(CorrelationRelationshipType.ROUTE_TO_SENSITIVE_OPERATION),
        source_file=lambda candidate: candidate.source_file,
        line_number=lambda candidate: candidate.line_number,
        associated_routes=lambda candidate: candidate.associated_routes,
        attach=lambda bucket, index, candidate: bucket.sensitive_operations.__setitem__(
            index, candidate
        ),
        context=_operation_context,
        issues=issues,
    )

    correlated_routes = [
        CorrelatedRoute(
            route_id=bucket.route_id,
            path=bucket.route.path,
            http_method=bucket.route.http_method,
            framework=bucket.route.framework,
            source_file=bucket.route.source_file,
            line_number=bucket.route.line_number,
            handler_name=bucket.route.handler_name,
            detection_confidence=bucket.route.detection_confidence,
            resolution_status=bucket.route.resolution_status,
            authentication_controls=[
                control for _, control in sorted(bucket.authentication_controls.items())
            ],
            authorization_controls=[
                control for _, control in sorted(bucket.authorization_controls.items())
            ],
            input_candidates=[
                candidate for _, candidate in sorted(bucket.input_candidates.items())
            ],
            sensitive_operations=[
                operation for _, operation in sorted(bucket.sensitive_operations.items())
            ],
            relationships=sorted(
                bucket.relationships.values(),
                key=_relationship_sort_key,
            ),
        )
        for bucket in buckets
    ]

    sorted_issues = _dedupe_issues(issues)

    unresolved_relationship_count = sum(
        1
        for route in correlated_routes
        for relationship in route.relationships
        if relationship.resolution_status is CorrelationResolutionStatus.UNRESOLVED
    )
    ambiguous_relationship_count = sum(
        1
        for route in correlated_routes
        for relationship in route.relationships
        if relationship.resolution_status is CorrelationResolutionStatus.AMBIGUOUS
    )
    unresolved_association_count = (
        unresolved_relationship_count
        + missing_authentication
        + missing_authorization
        + missing_inputs
        + missing_operations
        + unassociated_authentication
        + unassociated_authorization
        + unassociated_inputs
        + unassociated_operations
    )

    source_statuses = [
        _source_status(
            CorrelationAnalysisSource.ATTACK_SURFACE,
            is_complete=attack_surface.summary.is_complete,
            discovery_is_complete=attack_surface.summary.discovery_is_complete,
            issue_count=len(attack_surface.issues),
            truncation_reasons=attack_surface.summary.discovery_truncation_reasons,
        ),
        _source_status(
            CorrelationAnalysisSource.AUTH_CONTROLS,
            is_complete=auth_controls.summary.is_complete,
            discovery_is_complete=auth_controls.summary.discovery_is_complete,
            issue_count=len(auth_controls.issues),
            truncation_reasons=auth_controls.summary.discovery_truncation_reasons,
        ),
        _source_status(
            CorrelationAnalysisSource.INPUT_SOURCES,
            is_complete=input_sources.summary.is_complete,
            discovery_is_complete=input_sources.summary.discovery_is_complete,
            issue_count=len(input_sources.issues),
            truncation_reasons=input_sources.summary.discovery_truncation_reasons,
        ),
        _source_status(
            CorrelationAnalysisSource.SENSITIVE_OPERATIONS,
            is_complete=sensitive_operations.summary.is_complete,
            discovery_is_complete=(sensitive_operations.summary.discovery_is_complete),
            issue_count=len(sensitive_operations.issues),
            truncation_reasons=(sensitive_operations.summary.discovery_truncation_reasons),
        ),
    ]
    all_sources_complete = all(status.is_complete for status in source_statuses)

    summary = AttackSurfaceCorrelationSummary(
        total_route_count=len(correlated_routes),
        routes_with_authentication=sum(
            bool(route.authentication_controls) for route in correlated_routes
        ),
        routes_with_authorization=sum(
            bool(route.authorization_controls) for route in correlated_routes
        ),
        routes_with_inputs=sum(bool(route.input_candidates) for route in correlated_routes),
        routes_with_sensitive_operations=sum(
            bool(route.sensitive_operations) for route in correlated_routes
        ),
        routes_with_multiple_evidence_categories=sum(
            sum(
                bool(collection)
                for collection in (
                    route.authentication_controls,
                    route.authorization_controls,
                    route.input_candidates,
                    route.sensitive_operations,
                )
            )
            >= 2
            for route in correlated_routes
        ),
        relationship_count=sum(len(route.relationships) for route in correlated_routes),
        unresolved_association_count=unresolved_association_count,
        ambiguous_association_count=ambiguous_relationship_count,
        issue_count=len(sorted_issues),
        all_sources_complete=all_sources_complete,
        is_complete=all_sources_complete and not sorted_issues,
        source_statuses=source_statuses,
    )

    return AttackSurfaceCorrelationResult(
        root=root,
        routes=correlated_routes,
        issues=sorted_issues,
        summary=summary,
    )
