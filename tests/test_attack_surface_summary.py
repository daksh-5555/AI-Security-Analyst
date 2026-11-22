import copy
from pathlib import Path

import pytest

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
    CorrelationSourceStatus,
)
from app.schemas.attack_surface_summary import SummaryAnalysisSource
from app.schemas.auth_controls import (
    AssociatedRoute,
    AuthControlCandidate,
    ControlResolutionStatus,
    ControlScopeType,
    ControlType,
)
from app.schemas.enums import DiscoveryTruncationReason
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
from app.schemas.input_operation_flow import (
    FlowIssueCategory,
    FlowPropagationKind,
    FlowResolutionStatus,
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
    InputType,
)
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
    SensitiveOperationCandidate,
)
from app.services.attack_surface_summary import (
    InvalidAttackSurfaceSummaryRootError,
    summarize_attack_surface,
)


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    allowed = tmp_path / "repositories"
    allowed.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])
    target = allowed / "project"
    target.mkdir()
    return target


def route(
    path: str = "/items",
    *,
    method: HttpMethod = HttpMethod.GET,
    framework: RouteFramework = RouteFramework.FASTAPI,
    source_file: str = "app.py",
    line_number: int = 10,
    handler_name: str | None = "handler",
    resolution: RouteResolutionStatus = RouteResolutionStatus.RESOLVED,
    confidence: float = 0.9,
) -> RouteCandidate:
    return RouteCandidate(
        path=path,
        http_method=method,
        framework=framework,
        source_file=source_file,
        line_number=line_number,
        handler_name=handler_name,
        detection_confidence=confidence,
        resolution_status=resolution,
    )


def route_id(value: RouteCandidate) -> str:
    return (
        f"{value.source_file}:{value.line_number}:"
        f"{value.http_method.value}:{value.framework.value}:{value.path}"
    )


def assoc(value: RouteCandidate) -> AssociatedRoute:
    return AssociatedRoute(
        path=value.path,
        http_method=value.http_method,
        framework=value.framework,
        resolution_status=value.resolution_status,
    )


def control(
    value: RouteCandidate,
    *,
    control_type: ControlType = ControlType.AUTHENTICATION,
    symbol_name: str = "require_auth",
    resolution: ControlResolutionStatus = ControlResolutionStatus.RESOLVED,
    confidence: float = 0.9,
) -> AuthControlCandidate:
    return AuthControlCandidate(
        control_type=control_type,
        framework=value.framework,
        mechanism="dependency",
        declaration=f"Depends({symbol_name})",
        source_file=value.source_file,
        line_number=value.line_number,
        symbol_name=symbol_name,
        scope_type=ControlScopeType.ROUTE,
        associated_routes=[assoc(value)],
        resolution_status=resolution,
        detection_confidence=confidence,
        evidence="Control declaration was observed.",
        classification_rule="Deterministic control rule.",
    )


def input_candidate(
    value: RouteCandidate,
    *,
    resolution: InputResolutionStatus = InputResolutionStatus.RESOLVED,
    confidence: float = 0.8,
    line_number: int = 20,
) -> InputCandidate:
    return InputCandidate(
        input_type=InputType.QUERY,
        framework=value.framework,
        source_file=value.source_file,
        line_number=line_number,
        parameter_name="q",
        variable_name="q",
        handler_name=value.handler_name,
        associated_routes=[assoc(value)],
        declaration_or_access="request.query_params",
        resolution_status=resolution,
        detection_confidence=confidence,
        evidence="Input access was observed.",
        classification_rule="Deterministic input rule.",
    )


def operation(
    value: RouteCandidate,
    *,
    resolution: OperationResolutionStatus = OperationResolutionStatus.RESOLVED,
    confidence: float = 0.9,
    line_number: int = 30,
) -> SensitiveOperationCandidate:
    return SensitiveOperationCandidate(
        operation_category=OperationCategory.DATABASE_READ,
        framework_or_library="SQLAlchemy",
        operation_name="execute",
        source_file=value.source_file,
        line_number=line_number,
        enclosing_function=value.handler_name,
        receiver_name="session",
        resource_name="User",
        associated_routes=[assoc(value)],
        declaration_or_access="session.execute(statement)",
        resolution_status=resolution,
        detection_confidence=confidence,
        evidence="Operation was observed.",
        classification_rule="Deterministic operation rule.",
    )


def correlation_relationship(
    value: RouteCandidate,
    *,
    relationship_type: CorrelationRelationshipType = CorrelationRelationshipType.ROUTE_TO_INPUT,
    evidence_source: CorrelationEvidenceSource = CorrelationEvidenceSource.INPUT_SOURCES,
    evidence_identifier: str = "inputs[0]",
    evidence_index: int = 0,
    resolution: CorrelationResolutionStatus = CorrelationResolutionStatus.RESOLVED,
) -> CorrelationRelationship:
    return CorrelationRelationship(
        relationship_type=relationship_type,
        evidence_source=evidence_source,
        evidence_identifier=evidence_identifier,
        evidence_index=evidence_index,
        evidence_source_file=value.source_file,
        evidence_line_number=value.line_number,
        route_id=route_id(value),
        resolution_status=resolution,
        explanation="Evidence was associated by the correlation analysis.",
    )


def correlated_route(
    value: RouteCandidate,
    *,
    authentication: list[AuthControlCandidate] | None = None,
    authorization: list[AuthControlCandidate] | None = None,
    inputs: list[InputCandidate] | None = None,
    operations: list[SensitiveOperationCandidate] | None = None,
    relationships: list[CorrelationRelationship] | None = None,
) -> CorrelatedRoute:
    return CorrelatedRoute(
        route_id=route_id(value),
        path=value.path,
        http_method=value.http_method,
        framework=value.framework,
        source_file=value.source_file,
        line_number=value.line_number,
        handler_name=value.handler_name,
        detection_confidence=value.detection_confidence,
        resolution_status=value.resolution_status,
        authentication_controls=list(authentication or []),
        authorization_controls=list(authorization or []),
        input_candidates=list(inputs or []),
        sensitive_operations=list(operations or []),
        relationships=list(relationships or []),
    )


def correlation_source_status(
    source: CorrelationAnalysisSource,
    *,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    issue_count: int = 0,
    truncation: list[DiscoveryTruncationReason] | None = None,
) -> CorrelationSourceStatus:
    return CorrelationSourceStatus(
        source=source,
        is_complete=is_complete,
        discovery_is_complete=discovery_is_complete,
        issue_count=issue_count,
        discovery_truncation_reasons=list(truncation or []),
    )


def attack_result(
    value: RouteCandidate | list[RouteCandidate],
    *,
    issues: list[AnalysisIssue] | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
) -> AttackSurfaceResult:
    routes = [value] if isinstance(value, RouteCandidate) else list(value)
    source_issues = list(issues or [])
    return AttackSurfaceResult(
        root=str(Path.cwd()),
        routes=routes,
        issues=source_issues,
        summary=AttackSurfaceSummary(
            source_files_inspected=1,
            route_count=len(routes),
            resolved_route_count=sum(
                item.resolution_status is RouteResolutionStatus.RESOLVED for item in routes
            ),
            unresolved_route_count=sum(
                item.resolution_status is RouteResolutionStatus.UNRESOLVED for item in routes
            ),
            issue_count=len(source_issues),
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=list(truncation or []),
        ),
    )


def correlation_result(
    routes: list[CorrelatedRoute],
    *,
    issues: list[CorrelationIssue] | None = None,
    source_statuses: list[CorrelationSourceStatus] | None = None,
    all_sources_complete: bool = True,
    is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
    root: str | None = None,
) -> AttackSurfaceCorrelationResult:
    correlation_issues = list(issues or [])
    statuses = list(source_statuses or [])
    if not statuses:
        statuses = [
            correlation_source_status(source)
            for source in (
                CorrelationAnalysisSource.ATTACK_SURFACE,
                CorrelationAnalysisSource.AUTH_CONTROLS,
                CorrelationAnalysisSource.INPUT_SOURCES,
                CorrelationAnalysisSource.SENSITIVE_OPERATIONS,
            )
        ]
    return AttackSurfaceCorrelationResult(
        root=root or str(Path.cwd()),
        routes=list(routes),
        issues=correlation_issues,
        summary=AttackSurfaceCorrelationSummary(
            total_route_count=len(routes),
            routes_with_authentication=sum(bool(item.authentication_controls) for item in routes),
            routes_with_authorization=sum(bool(item.authorization_controls) for item in routes),
            routes_with_inputs=sum(bool(item.input_candidates) for item in routes),
            routes_with_sensitive_operations=sum(
                bool(item.sensitive_operations) for item in routes
            ),
            routes_with_multiple_evidence_categories=sum(
                sum(
                    (
                        bool(item.authentication_controls),
                        bool(item.authorization_controls),
                        bool(item.input_candidates),
                        bool(item.sensitive_operations),
                    )
                )
                >= 2
                for item in routes
            ),
            relationship_count=sum(len(item.relationships) for item in routes),
            unresolved_association_count=0,
            ambiguous_association_count=0,
            issue_count=len(correlation_issues),
            all_sources_complete=all_sources_complete,
            is_complete=is_complete,
            source_statuses=statuses,
        ),
    )


def handler(
    value: RouteCandidate,
    *,
    definition_ids: list[str] | None = None,
    status: HandlerResolutionStatus = HandlerResolutionStatus.RESOLVED,
    confidence: float = 0.9,
) -> RouteHandler:
    return RouteHandler(
        handler_id=route_id(value),
        route_id=route_id(value),
        route_path=value.path,
        http_method=value.http_method,
        framework=value.framework,
        route_source_file=value.source_file,
        route_line_number=value.line_number,
        route_resolution_status=value.resolution_status,
        handler_name=value.handler_name,
        definition_ids=list(definition_ids or []),
        resolution_status=status,
        detection_confidence=confidence,
        explanation="Handler resolution was recorded.",
    )


def definition(
    definition_id: str = "app.py:5:1:function:handler",
    *,
    name: str = "handler",
    route_ids: list[str] | None = None,
    confidence: float = 0.9,
) -> LocalFunctionDefinition:
    return LocalFunctionDefinition(
        definition_id=definition_id,
        name=name,
        qualified_name=name,
        kind=FunctionKind.FUNCTION,
        source_file="app.py",
        line_number=5,
        column_number=1,
        end_line_number=15,
        is_async=False,
        parameter_count=1,
        is_route_handler=bool(route_ids),
        route_ids=list(route_ids or []),
        detection_confidence=confidence,
    )


def call_site(
    caller_definition_id: str = "app.py:5:1:function:handler",
    *,
    call_id: str = "app.py:8:3:call:handler",
    status: CallResolutionStatus = CallResolutionStatus.RESOLVED,
    target_definition_ids: list[str] | None = None,
    confidence: float = 0.8,
) -> CallSite:
    return CallSite(
        call_id=call_id,
        caller_definition_id=caller_definition_id,
        caller_name="handler",
        caller_kind=FunctionKind.FUNCTION,
        source_file="app.py",
        line_number=8,
        column_number=3,
        callee_expression="helper",
        callee_name="helper",
        is_method_call=False,
        resolution_status=status,
        target_definition_ids=list(target_definition_ids or []),
        detection_confidence=confidence,
        explanation="Call resolution was recorded.",
    )


def call_relationship(
    *,
    relationship_id: str = "call-1",
    caller_definition_id: str = "app.py:5:1:function:handler",
    callee_definition_id: str = "app.py:20:1:function:helper",
    call_id: str = "app.py:8:3:call:handler",
    status: CallResolutionStatus = CallResolutionStatus.RESOLVED,
) -> CallRelationship:
    return CallRelationship(
        relationship_id=relationship_id,
        relationship_type=CallRelationshipType.HANDLER_TO_FUNCTION,
        caller_definition_id=caller_definition_id,
        callee_definition_id=callee_definition_id,
        call_id=call_id,
        source_file="app.py",
        line_number=8,
        resolution_status=status,
        detection_confidence=0.8,
        explanation="Local call relationship was recorded.",
    )


def handler_result(
    value: RouteCandidate | None = None,
    *,
    handlers: list[RouteHandler] | None = None,
    definitions: list[LocalFunctionDefinition] | None = None,
    calls: list[CallSite] | None = None,
    relationships: list[CallRelationship] | None = None,
    issues: list[AnalysisIssue] | None = None,
    call_issues: list[HandlerCallIssue] | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    route_analysis_is_complete: bool = True,
    discovery_truncation: list[DiscoveryTruncationReason] | None = None,
    route_analysis_truncation: list[DiscoveryTruncationReason] | None = None,
) -> HandlerCallResult:
    route_handlers = list(handlers or [])
    if value is not None and not route_handlers:
        route_handlers = [handler(value, definition_ids=[])]
    route_definitions = list(definitions or [])
    route_calls = list(calls or [])
    route_relationships = list(relationships or [])
    source_issues = list(issues or [])
    handler_issues = list(call_issues or [])
    return HandlerCallResult(
        root=str(Path.cwd()),
        handlers=route_handlers,
        definitions=route_definitions,
        calls=route_calls,
        relationships=route_relationships,
        issues=source_issues,
        call_issues=handler_issues,
        summary=HandlerCallSummary(
            source_files_inspected=1,
            route_handler_count=len(route_handlers),
            resolved_handler_count=sum(
                item.resolution_status is HandlerResolutionStatus.RESOLVED
                for item in route_handlers
            ),
            ambiguous_handler_count=sum(
                item.resolution_status is HandlerResolutionStatus.AMBIGUOUS
                for item in route_handlers
            ),
            unresolved_handler_count=sum(
                item.resolution_status is HandlerResolutionStatus.UNRESOLVED
                for item in route_handlers
            ),
            definition_count=len(route_definitions),
            function_definition_count=sum(
                item.kind is FunctionKind.FUNCTION for item in route_definitions
            ),
            method_definition_count=sum(
                item.kind is FunctionKind.METHOD for item in route_definitions
            ),
            nested_function_definition_count=sum(
                item.kind is FunctionKind.NESTED_FUNCTION for item in route_definitions
            ),
            call_site_count=len(route_calls),
            resolved_call_count=sum(
                item.resolution_status is CallResolutionStatus.RESOLVED for item in route_calls
            ),
            ambiguous_call_count=sum(
                item.resolution_status is CallResolutionStatus.AMBIGUOUS for item in route_calls
            ),
            unresolved_call_count=sum(
                item.resolution_status is CallResolutionStatus.UNRESOLVED for item in route_calls
            ),
            external_call_count=sum(
                item.resolution_status is CallResolutionStatus.EXTERNAL for item in route_calls
            ),
            recursive_call_count=sum(item.is_recursive for item in route_calls),
            relationship_count=len(route_relationships),
            issue_count=len(source_issues),
            call_issue_count=len(handler_issues),
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            route_analysis_is_complete=route_analysis_is_complete,
            discovery_truncation_reasons=list(discovery_truncation or []),
            route_analysis_truncation_reasons=list(route_analysis_truncation or []),
        ),
    )


def handler_reference(value: RouteCandidate) -> HandlerReference:
    return HandlerReference(
        handler_id=route_id(value),
        route_id=route_id(value),
        handler_name=value.handler_name,
        source_file=value.source_file,
        line_number=value.line_number,
        route_path=value.path,
        http_method=value.http_method,
        framework=value.framework,
    )


def flow_relationship(
    value: RouteCandidate | None = None,
    *,
    relationship_id: str = "inputs[0]->operations[0]",
    route_ids: list[str] | None = None,
    status: FlowResolutionStatus = FlowResolutionStatus.RESOLVED,
    input_resolution: InputResolutionStatus = InputResolutionStatus.RESOLVED,
    operation_resolution: OperationResolutionStatus = OperationResolutionStatus.RESOLVED,
    confidence: float = 0.8,
) -> InputOperationRelationship:
    references = [handler_reference(value)] if value is not None else []
    return InputOperationRelationship(
        relationship_id=relationship_id,
        input_id="inputs[0]",
        input_index=0,
        input_type=InputType.QUERY,
        input_source_file="app.py",
        input_line_number=20,
        input_declaration="request.query_params",
        input_resolution_status=input_resolution,
        input_detection_confidence=0.8,
        operation_id="operations[0]",
        operation_index=0,
        operation_category=OperationCategory.DATABASE_READ,
        operation_source_file="app.py",
        operation_line_number=30,
        operation_declaration="session.execute(statement)",
        operation_resolution_status=operation_resolution,
        operation_detection_confidence=0.9,
        resolution_status=status,
        detection_confidence=confidence,
        route_ids=list(route_ids or []),
        handler_references=references,
        intermediate_definition_ids=["app.py:5:1:function:handler"],
        intermediate_call_ids=["app.py:8:3:call:handler"],
        ambiguous_definition_ids=[],
        propagation_steps=[
            PropagationStep(
                step_index=0,
                kind=FlowPropagationKind.INPUT_ACCESS,
                source_file="app.py",
                line_number=20,
                column_number=3,
                definition_id="app.py:5:1:function:handler",
                definition_name="handler",
                expression="request.query_params",
                explanation="The input access was observed.",
            )
        ],
        explanation="A supported propagation path was recorded.",
        limitations=["Static analysis only."],
    )


def flow_issue(
    *,
    category: FlowIssueCategory = FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION,
    source_file: str = "app.py",
    line_number: int | None = 10,
    input_id: str | None = None,
    operation_id: str | None = None,
    call_id: str | None = None,
    definition_id: str | None = None,
    explanation: str = "A flow pattern could not be analyzed cleanly.",
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


def flow_result(
    relationships: list[InputOperationRelationship] | None = None,
    *,
    source_issues: list[AnalysisIssue] | None = None,
    issues: list[InputOperationIssue] | None = None,
    is_complete: bool = True,
    source_analysis_is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
) -> InputOperationFlowResult:
    flow_relationships = list(relationships or [])
    source_problems = list(source_issues or [])
    flow_issues = list(issues or [])
    return InputOperationFlowResult(
        root=str(Path.cwd()),
        relationships=flow_relationships,
        source_issues=source_problems,
        issues=flow_issues,
        summary=InputOperationFlowSummary(
            source_files_inspected=1,
            input_count=1,
            operation_count=1,
            relationship_count=len(flow_relationships),
            resolved_relationship_count=sum(
                item.resolution_status is FlowResolutionStatus.RESOLVED
                for item in flow_relationships
            ),
            ambiguous_relationship_count=sum(
                item.resolution_status is FlowResolutionStatus.AMBIGUOUS
                for item in flow_relationships
            ),
            unresolved_relationship_count=sum(
                item.resolution_status is FlowResolutionStatus.UNRESOLVED
                for item in flow_relationships
            ),
            unsupported_relationship_count=sum(
                item.resolution_status is FlowResolutionStatus.UNSUPPORTED
                for item in flow_relationships
            ),
            inputs_with_relationships=len({item.input_id for item in flow_relationships}),
            operations_with_relationships=len({item.operation_id for item in flow_relationships}),
            propagation_state_count=1,
            source_issue_count=len(source_problems),
            issue_count=len(flow_issues),
            source_analysis_is_complete=source_analysis_is_complete,
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=list(truncation or []),
            max_source_files=1,
            max_source_file_size_bytes=1,
            max_propagation_depth=1,
            max_propagation_states=1,
            max_relationships=1,
        ),
    )


def build(
    repository: Path,
    *,
    attack: AttackSurfaceResult,
    correlation: AttackSurfaceCorrelationResult,
    handler_calls: HandlerCallResult,
    flow: InputOperationFlowResult,
):
    attack = attack.model_copy(update={"root": str(repository.resolve())})
    correlation = correlation.model_copy(update={"root": str(repository.resolve())})
    handler_calls = handler_calls.model_copy(update={"root": str(repository.resolve())})
    flow = flow.model_copy(update={"root": str(repository.resolve())})
    return summarize_attack_surface(
        repository,
        attack,
        correlation,
        handler_calls,
        flow,
    )


def test_route_with_all_evidence_categories(repository: Path) -> None:
    value = route()
    auth = control(value)
    authz = control(value, control_type=ControlType.AUTHORIZATION, symbol_name="require_scope")
    query = input_candidate(value)
    read = operation(value)
    relationship = correlation_relationship(value)
    handler_value = handler(value, definition_ids=["app.py:5:1:function:handler"])
    handler_definition = definition(route_ids=[route_id(value)])
    call = call_site(target_definition_ids=["app.py:20:1:function:helper"])
    call_relation = call_relationship()
    flow = flow_relationship(value, route_ids=[route_id(value)])

    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result(
            [
                correlated_route(
                    value,
                    authentication=[auth],
                    authorization=[authz],
                    inputs=[query],
                    operations=[read],
                    relationships=[relationship],
                )
            ]
        ),
        handler_calls=handler_result(
            handlers=[handler_value],
            definitions=[handler_definition],
            calls=[call],
            relationships=[call_relation],
        ),
        flow=flow_result([flow]),
    )

    assert len(result.routes) == 1
    summary = result.routes[0]
    assert summary.route_id == route_id(value)
    assert summary.path == "/items"
    assert summary.http_method is HttpMethod.GET
    assert summary.framework is RouteFramework.FASTAPI
    assert summary.source_file == "app.py"
    assert summary.line_number == 10
    assert summary.handler_name == "handler"
    assert summary.detection_confidence == 0.9
    assert summary.authentication_controls == [auth]
    assert summary.authorization_controls == [authz]
    assert summary.input_candidates == [query]
    assert summary.sensitive_operations == [read]
    assert summary.correlation_relationships == [relationship]
    assert summary.handlers == [handler_value]
    assert summary.handler_definitions == [handler_definition]
    assert summary.call_sites == [call]
    assert summary.call_relationships == [call_relation]
    assert summary.input_operation_relationships == [flow]
    assert result.summary.routes_with_multiple_evidence_categories == 1
    assert result.summary.routes_with_input_operation_relationships == 1


def test_multiple_routes_are_ordered(repository: Path) -> None:
    first = route("/z", line_number=20)
    second = route("/a", line_number=10)
    result = build(
        repository,
        attack=attack_result([first, second]),
        correlation=correlation_result([correlated_route(first), correlated_route(second)]),
        handler_calls=handler_result(),
        flow=flow_result(),
    )

    assert [item.path for item in result.routes] == ["/a", "/z"]
    assert result.summary.route_count == 2


def test_route_without_handler(repository: Path) -> None:
    value = route()
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(),
        flow=flow_result(),
    )

    assert result.routes[0].handlers == []
    assert result.routes[0].handler_definitions == []
    assert result.summary.routes_without_handlers == 1
    assert result.summary.routes_with_handlers == 0


def test_route_with_ambiguous_handler(repository: Path) -> None:
    value = route()
    ambiguous = handler(
        value,
        definition_ids=["app.py:5:1:function:handler", "app.py:7:1:function:handler"],
        status=HandlerResolutionStatus.AMBIGUOUS,
        confidence=0.5,
    )
    first = definition("app.py:5:1:function:handler", route_ids=[route_id(value)])
    second = definition(
        "app.py:7:1:function:handler",
        route_ids=[route_id(value)],
    )
    issue = HandlerCallIssue(
        source_file="app.py",
        line_number=10,
        category=HandlerCallIssueCategory.AMBIGUOUS_HANDLER_DEFINITION,
        handler_id=route_id(value),
        explanation="Two local definitions matched the handler name.",
    )
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(
            handlers=[ambiguous],
            definitions=[first, second],
            call_issues=[issue],
        ),
        flow=flow_result(),
    )

    assert result.routes[0].handlers == [ambiguous]
    assert {item.definition_id for item in result.routes[0].handler_definitions} == {
        first.definition_id,
        second.definition_id,
    }
    assert result.summary.handler_ambiguous_count == 1
    assert result.summary.routes_with_ambiguous_handlers == 1
    assert result.summary.ambiguous_issue_count == 1


def test_route_without_input_operation_relationships(repository: Path) -> None:
    value = route()
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(),
        flow=flow_result(),
    )

    assert result.routes[0].input_operation_relationships == []
    assert result.summary.input_operation_relationship_count == 0
    assert result.summary.routes_with_input_operation_relationships == 0
    assert result.summary.is_complete is True


def test_resolved_input_operation_relationship(repository: Path) -> None:
    value = route()
    relationship = flow_relationship(value, route_ids=[route_id(value)])
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(),
        flow=flow_result([relationship]),
    )

    assert result.routes[0].input_operation_relationships == [relationship]
    assert result.summary.input_operation_resolved_count == 1
    assert result.summary.input_operation_ambiguous_count == 0
    assert result.summary.input_operation_unresolved_count == 0


def test_ambiguous_and_unresolved_flow_relationships(repository: Path) -> None:
    value = route()
    ambiguous = flow_relationship(
        value,
        relationship_id="inputs[0]->operations[0]",
        route_ids=[route_id(value)],
        status=FlowResolutionStatus.AMBIGUOUS,
    )
    unresolved = flow_relationship(
        value,
        relationship_id="inputs[1]->operations[0]",
        route_ids=[route_id(value)],
        status=FlowResolutionStatus.UNRESOLVED,
    )
    issues = [
        flow_issue(category=FlowIssueCategory.AMBIGUOUS_CALL_PROPAGATION),
        flow_issue(category=FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION),
    ]
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(),
        flow=flow_result([ambiguous, unresolved], issues=issues),
    )

    assert result.routes[0].input_operation_relationships == [ambiguous, unresolved]
    assert result.summary.input_operation_ambiguous_count == 1
    assert result.summary.input_operation_unresolved_count == 1
    assert result.summary.ambiguous_issue_count == 1
    assert result.summary.unresolved_issue_count == 1


def test_unassociated_evidence_is_retained_globally(repository: Path) -> None:
    value = route()
    missing_route = "missing.py:1:1:GET:fastapi:/missing"
    unlinked_handler = handler(
        route("/missing", source_file="missing.py", line_number=1),
        definition_ids=["missing.py:2:1:function:missing"],
    )
    unlinked_definition = definition(
        "missing.py:2:1:function:missing",
        name="missing",
        route_ids=[missing_route],
    )
    unlinked_call = call_site(
        caller_definition_id="missing.py:2:1:function:missing",
        call_id="missing.py:3:1:call:missing",
    )
    unlinked_relationship = call_relationship(
        relationship_id="missing-rel",
        caller_definition_id="missing.py:2:1:function:missing",
        call_id="missing.py:3:1:call:missing",
    )
    unassociated_flow = flow_relationship(
        relationship_id="inputs[1]->operations[1]",
        route_ids=[missing_route],
    )
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(
            handlers=[unlinked_handler],
            definitions=[unlinked_definition],
            calls=[unlinked_call],
            relationships=[unlinked_relationship],
        ),
        flow=flow_result([unassociated_flow]),
    )

    assert result.global_evidence.unlinked_handlers == [unlinked_handler]
    assert result.global_evidence.unassociated_definitions == [unlinked_definition]
    assert result.global_evidence.unassociated_call_sites == [unlinked_call]
    assert result.global_evidence.unassociated_call_relationships == [unlinked_relationship]
    assert result.global_evidence.unassociated_input_operation_relationships == [unassociated_flow]
    assert result.routes[0].handlers == []
    assert result.summary.unassociated_input_operation_relationship_count == 1


def test_missing_evidence_categories_are_empty_not_negative(repository: Path) -> None:
    value = route()
    handler_value = handler(value, definition_ids=[])
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(handlers=[handler_value]),
        flow=flow_result(),
    )

    entry = result.routes[0]
    assert entry.handlers == [handler_value]
    assert entry.authentication_controls == []
    assert entry.authorization_controls == []
    assert entry.input_candidates == []
    assert entry.sensitive_operations == []
    assert entry.input_operation_relationships == []
    assert result.summary.authentication_control_count == 0
    assert result.summary.routes_with_authentication == 0


def test_empty_analysis_results(repository: Path) -> None:
    result = build(
        repository,
        attack=attack_result([]),
        correlation=correlation_result([]),
        handler_calls=handler_result(),
        flow=flow_result(),
    )

    assert result.routes == []
    assert result.issues == []
    assert result.global_evidence.unlinked_handlers == []
    assert result.summary.route_count == 0
    assert result.summary.handler_count == 0
    assert result.summary.input_operation_relationship_count == 0
    assert result.summary.issue_count == 0
    assert result.summary.is_complete is True
    assert len(result.summary.source_statuses) == 7


def test_incomplete_source_analysis_is_propagated(repository: Path) -> None:
    value = route()
    result = build(
        repository,
        attack=attack_result(value, is_complete=False),
        correlation=correlation_result(
            [correlated_route(value)],
            all_sources_complete=False,
            is_complete=False,
        ),
        handler_calls=handler_result(),
        flow=flow_result(),
    )

    status = next(
        item
        for item in result.summary.source_statuses
        if item.source is SummaryAnalysisSource.ATTACK_SURFACE
    )
    assert status.is_complete is False
    assert result.summary.all_sources_complete is False
    assert result.summary.is_complete is False


def test_truncation_reasons_are_propagated(repository: Path) -> None:
    value = route()
    statuses = [
        correlation_source_status(
            CorrelationAnalysisSource.ATTACK_SURFACE,
            truncation=[DiscoveryTruncationReason.MAX_FILE_COUNT],
        ),
        correlation_source_status(
            CorrelationAnalysisSource.AUTH_CONTROLS,
            truncation=[DiscoveryTruncationReason.MAX_DEPTH],
        ),
        correlation_source_status(CorrelationAnalysisSource.INPUT_SOURCES),
        correlation_source_status(CorrelationAnalysisSource.SENSITIVE_OPERATIONS),
    ]
    result = build(
        repository,
        attack=attack_result(
            value,
            truncation=[DiscoveryTruncationReason.MAX_FILE_COUNT],
        ),
        correlation=correlation_result(
            [correlated_route(value)],
            source_statuses=statuses,
        ),
        handler_calls=handler_result(
            discovery_truncation=[DiscoveryTruncationReason.MAX_TOTAL_SIZE],
            route_analysis_truncation=[DiscoveryTruncationReason.MAX_FILE_COUNT],
        ),
        flow=flow_result(truncation=[DiscoveryTruncationReason.MAX_DEPTH]),
    )

    assert set(result.summary.discovery_truncation_reasons) == {
        DiscoveryTruncationReason.MAX_FILE_COUNT,
        DiscoveryTruncationReason.MAX_DEPTH,
        DiscoveryTruncationReason.MAX_TOTAL_SIZE,
    }
    assert result.summary.route_analysis_truncation_reasons == [
        DiscoveryTruncationReason.MAX_FILE_COUNT
    ]


def test_issue_aggregation_and_deduplication(repository: Path) -> None:
    value = route()
    duplicate = AnalysisIssue(
        source_file="app.py",
        reason=AnalysisIssueReason.INVALID_SYNTAX,
        detail="The source file could not be parsed.",
    )
    correlation_issue = CorrelationIssue(
        source_file="app.py",
        category=CorrelationIssueCategory.UNASSOCIATED_EVIDENCE,
        explanation="Evidence had no matching route.",
        evidence_source=CorrelationEvidenceSource.INPUT_SOURCES,
        evidence_identifier="inputs[3]",
    )
    call_issue = HandlerCallIssue(
        source_file="app.py",
        line_number=10,
        category=HandlerCallIssueCategory.MISSING_HANDLER_NAME,
        handler_id=route_id(value),
        explanation="No handler name was recorded.",
    )
    flow_problem = flow_issue(
        category=FlowIssueCategory.UNSUPPORTED_PROPAGATION,
        explanation="The propagation pattern is not supported.",
    )
    result = build(
        repository,
        attack=attack_result(value, issues=[duplicate, duplicate]),
        correlation=correlation_result(
            [correlated_route(value)],
            issues=[correlation_issue],
        ),
        handler_calls=handler_result(
            handlers=[handler(value, definition_ids=[])],
            issues=[duplicate],
            call_issues=[call_issue],
        ),
        flow=flow_result(issues=[flow_problem, flow_problem]),
    )

    assert result.summary.issue_count == 4
    assert result.summary.inspection_issue_count == 1
    merged = next(
        item for item in result.issues if item.category == AnalysisIssueReason.INVALID_SYNTAX.value
    )
    assert merged.origins == [
        SummaryAnalysisSource.ATTACK_SURFACE,
        SummaryAnalysisSource.HANDLER_CALLS,
    ]
    assert result.summary.correlation_issue_count == 1
    assert result.summary.handler_call_issue_count == 1
    assert result.summary.input_operation_issue_count == 1
    assert result.summary.unsupported_issue_count == 1


def test_exact_summary_counts(repository: Path) -> None:
    first = route("/one", line_number=10)
    second = route("/two", line_number=20)
    auth = control(first)
    query = input_candidate(first)
    read = operation(first)
    first_handler = handler(first, definition_ids=["app.py:5:1:function:handler"])
    second_handler = handler(
        second,
        definition_ids=["app.py:5:1:function:handler"],
        status=HandlerResolutionStatus.UNRESOLVED,
        confidence=0.3,
    )
    handler_definition = definition(route_ids=[route_id(first), route_id(second)])
    resolved_call = call_site(target_definition_ids=["app.py:20:1:function:helper"])
    unresolved_call = call_site(
        call_id="app.py:9:3:call:handler",
        status=CallResolutionStatus.UNRESOLVED,
    )
    resolved_relationship = call_relationship()
    ambiguous_relationship = call_relationship(
        relationship_id="call-2",
        status=CallResolutionStatus.AMBIGUOUS,
    )
    resolved_flow = flow_relationship(first, route_ids=[route_id(first)])
    unsupported_flow = flow_relationship(
        second,
        relationship_id="inputs[1]->operations[1]",
        route_ids=[route_id(second)],
        status=FlowResolutionStatus.UNSUPPORTED,
    )
    result = build(
        repository,
        attack=attack_result([first, second]),
        correlation=correlation_result(
            [
                correlated_route(
                    first,
                    authentication=[auth],
                    inputs=[query],
                    operations=[read],
                ),
                correlated_route(second),
            ]
        ),
        handler_calls=handler_result(
            handlers=[first_handler, second_handler],
            definitions=[handler_definition],
            calls=[resolved_call, unresolved_call],
            relationships=[resolved_relationship, ambiguous_relationship],
        ),
        flow=flow_result([resolved_flow, unsupported_flow]),
    )

    summary = result.summary
    assert summary.route_count == 2
    assert summary.routes_with_handlers == 2
    assert summary.routes_without_handlers == 0
    assert summary.routes_with_resolved_handlers == 1
    assert summary.routes_with_ambiguous_handlers == 0
    assert summary.routes_with_unresolved_handlers == 1
    assert summary.routes_with_authentication == 1
    assert summary.routes_with_authorization == 0
    assert summary.routes_with_inputs == 1
    assert summary.routes_with_sensitive_operations == 1
    assert summary.routes_with_input_operation_relationships == 2
    assert summary.authentication_control_count == 1
    assert summary.authorization_control_count == 0
    assert summary.input_count == 1
    assert summary.sensitive_operation_count == 1
    assert summary.handler_count == 2
    assert summary.handler_resolved_count == 1
    assert summary.handler_ambiguous_count == 0
    assert summary.handler_unresolved_count == 1
    assert summary.definition_count == 1
    assert summary.call_count == 2
    assert summary.call_resolved_count == 1
    assert summary.call_unresolved_count == 1
    assert summary.call_relationship_count == 2
    assert summary.call_relationship_resolved_count == 1
    assert summary.call_relationship_ambiguous_count == 1
    assert summary.input_operation_relationship_count == 2
    assert summary.input_operation_resolved_count == 1
    assert summary.input_operation_unsupported_count == 1
    assert summary.issue_count == 0


def test_deterministic_ordering_and_repeatability(repository: Path) -> None:
    first = route("/a", line_number=10)
    second = route("/b", line_number=20)
    query = input_candidate(first, line_number=40)
    read = operation(first, line_number=50)
    auth = control(first)
    relationship = flow_relationship(first, route_ids=[route_id(first)])
    attack = attack_result([second, first])
    correlation = correlation_result(
        [
            correlated_route(second),
            correlated_route(first, authentication=[auth], inputs=[query], operations=[read]),
        ]
    )
    handlers = handler_result()

    first_result = build(
        repository,
        attack=attack,
        correlation=correlation,
        handler_calls=handlers,
        flow=flow_result([relationship]),
    )
    second_result = build(
        repository,
        attack=attack,
        correlation=correlation,
        handler_calls=handlers,
        flow=flow_result([relationship]),
    )

    assert first_result.model_dump(mode="json") == second_result.model_dump(mode="json")
    assert [item.path for item in first_result.routes] == ["/a", "/b"]
    assert first_result.routes[0].authentication_controls == [auth]
    assert first_result.routes[0].input_candidates == [query]
    assert first_result.routes[0].sensitive_operations == [read]


def test_repository_root_mismatch_is_rejected(repository: Path) -> None:
    value = route()
    attack = attack_result(value).model_copy(update={"root": str(repository.resolve())})
    correlation = correlation_result([correlated_route(value)]).model_copy(
        update={"root": str(repository.parent.resolve())}
    )
    handler_calls = handler_result().model_copy(update={"root": str(repository.resolve())})
    flow = flow_result().model_copy(update={"root": str(repository.resolve())})

    with pytest.raises(InvalidAttackSurfaceSummaryRootError):
        summarize_attack_surface(repository, attack, correlation, handler_calls, flow)


def test_inputs_are_not_mutated(repository: Path) -> None:
    value = route()
    auth = control(value)
    query = input_candidate(value)
    read = operation(value)
    handler_value = handler(value, definition_ids=["app.py:5:1:function:handler"])
    handler_definition = definition(route_ids=[route_id(value)])
    flow = flow_relationship(value, route_ids=[route_id(value)])
    attack = attack_result(value)
    correlation = correlation_result(
        [
            correlated_route(
                value,
                authentication=[auth],
                inputs=[query],
                operations=[read],
            )
        ]
    )
    handler_calls = handler_result(
        handlers=[handler_value],
        definitions=[handler_definition],
    )
    flow_analysis = flow_result([flow])
    originals = [
        copy.deepcopy(item) for item in (attack, correlation, handler_calls, flow_analysis)
    ]

    build(
        repository,
        attack=attack,
        correlation=correlation,
        handler_calls=handler_calls,
        flow=flow_analysis,
    )

    assert [item.model_dump(mode="json") for item in originals] == [
        item.model_dump(mode="json") for item in (attack, correlation, handler_calls, flow_analysis)
    ]


def test_original_evidence_identifiers_and_confidence_are_preserved(
    repository: Path,
) -> None:
    value = route()
    query = input_candidate(value, confidence=0.73)
    read = operation(value, confidence=0.61)
    handler_value = handler(
        value,
        definition_ids=["app.py:5:1:function:handler"],
        confidence=0.84,
    )
    handler_definition = definition(route_ids=[route_id(value)], confidence=0.77)
    call = call_site(
        call_id="app.py:8:3:call:handler",
        target_definition_ids=["app.py:20:1:function:helper"],
        confidence=0.66,
    )
    flow = flow_relationship(
        value,
        relationship_id="inputs[7]->operations[9]",
        route_ids=[route_id(value)],
        confidence=0.55,
    )
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result(
            [correlated_route(value, inputs=[query], operations=[read])]
        ),
        handler_calls=handler_result(
            handlers=[handler_value],
            definitions=[handler_definition],
            calls=[call],
        ),
        flow=flow_result([flow]),
    )

    entry = result.routes[0]
    assert entry.input_candidates[0].detection_confidence == 0.73
    assert entry.sensitive_operations[0].detection_confidence == 0.61
    assert entry.handlers[0].handler_id == route_id(value)
    assert entry.handlers[0].detection_confidence == 0.84
    assert entry.handler_definitions[0].definition_id == handler_definition.definition_id
    assert entry.handler_definitions[0].detection_confidence == 0.77
    assert entry.call_sites[0].call_id == "app.py:8:3:call:handler"
    assert entry.call_sites[0].detection_confidence == 0.66
    assert entry.input_operation_relationships[0].relationship_id == ("inputs[7]->operations[9]")
    assert entry.input_operation_relationships[0].input_detection_confidence == 0.8
    assert entry.input_operation_relationships[0].operation_detection_confidence == 0.9
    assert entry.input_operation_relationships[0].detection_confidence == 0.55


def test_unresolved_evidence_is_preserved(repository: Path) -> None:
    value = route()
    query = input_candidate(value, resolution=InputResolutionStatus.UNRESOLVED)
    read = operation(value, resolution=OperationResolutionStatus.UNRESOLVED)
    unresolved_handler = handler(
        value,
        definition_ids=[],
        status=HandlerResolutionStatus.UNRESOLVED,
        confidence=0.2,
    )
    unresolved_definition = definition(
        "app.py:5:1:function:handler",
        route_ids=[route_id(value)],
    )
    unresolved_call = call_site(
        status=CallResolutionStatus.UNRESOLVED,
        confidence=0.1,
    )
    unresolved_flow = flow_relationship(
        value,
        route_ids=[route_id(value)],
        status=FlowResolutionStatus.UNRESOLVED,
        input_resolution=InputResolutionStatus.UNRESOLVED,
        operation_resolution=OperationResolutionStatus.UNRESOLVED,
        confidence=0.15,
    )
    flow_problem = flow_issue(
        category=FlowIssueCategory.UNRESOLVED_INPUT_EVIDENCE,
        input_id="inputs[0]",
        explanation="Input evidence could not be resolved.",
    )
    result = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result(
            [correlated_route(value, inputs=[query], operations=[read])]
        ),
        handler_calls=handler_result(
            handlers=[unresolved_handler],
            definitions=[unresolved_definition],
            calls=[unresolved_call],
        ),
        flow=flow_result([unresolved_flow], issues=[flow_problem]),
    )

    entry = result.routes[0]
    assert entry.input_candidates[0].resolution_status is InputResolutionStatus.UNRESOLVED
    assert entry.sensitive_operations[0].resolution_status is (OperationResolutionStatus.UNRESOLVED)
    assert entry.handlers[0].resolution_status is HandlerResolutionStatus.UNRESOLVED
    assert entry.handlers[0].detection_confidence == 0.2
    assert entry.call_sites[0].resolution_status is CallResolutionStatus.UNRESOLVED
    assert entry.call_sites[0].detection_confidence == 0.1
    assert entry.input_operation_relationships[0].resolution_status is (
        FlowResolutionStatus.UNRESOLVED
    )
    assert entry.input_operation_relationships[0].detection_confidence == 0.15
    assert result.summary.unresolved_issue_count == 1


def test_overall_completeness_semantics(repository: Path) -> None:
    value = route()
    unresolved_flow = flow_relationship(
        value,
        route_ids=[route_id(value)],
        status=FlowResolutionStatus.UNRESOLVED,
    )
    complete = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(),
        flow=flow_result(
            [unresolved_flow],
            issues=[flow_issue(category=FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION)],
        ),
    )

    assert complete.summary.all_sources_complete is True
    assert complete.summary.is_complete is True
    assert complete.summary.discovery_is_complete is True
    assert complete.summary.route_analysis_is_complete is True

    incomplete = build(
        repository,
        attack=attack_result(value),
        correlation=correlation_result([correlated_route(value)]),
        handler_calls=handler_result(is_complete=False),
        flow=flow_result(),
    )

    assert incomplete.summary.all_sources_complete is False
    assert incomplete.summary.is_complete is False
