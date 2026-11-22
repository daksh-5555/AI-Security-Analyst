import copy
from pathlib import Path

import pytest

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
    CorrelationEvidenceSource,
    CorrelationIssueCategory,
    CorrelationRelationshipType,
    CorrelationResolutionStatus,
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
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.input_sources import (
    InputCandidate,
    InputResolutionStatus,
    InputSourceResult,
    InputSourceSummary,
    InputType,
)
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
    SensitiveOperationCandidate,
    SensitiveOperationResult,
    SensitiveOperationSummary,
)
from app.services.attack_surface_correlation import (
    InvalidCorrelationRootError,
    correlate_attack_surface,
)

ROOT = str(Path.cwd() / "repository")


def assoc(
    path: str,
    *,
    method: HttpMethod = HttpMethod.GET,
    framework: RouteFramework = RouteFramework.FASTAPI,
    resolution: RouteResolutionStatus = RouteResolutionStatus.RESOLVED,
) -> AssociatedRoute:
    return AssociatedRoute(
        path=path,
        http_method=method,
        framework=framework,
        resolution_status=resolution,
    )


def route(
    path: str,
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


def control(
    *,
    control_type: ControlType = ControlType.AUTHENTICATION,
    routes: list[AssociatedRoute] | None = None,
    scope: ControlScopeType = ControlScopeType.ROUTE,
    source_file: str = "app.py",
    line_number: int = 10,
    symbol_name: str | None = "require_auth",
    framework: RouteFramework = RouteFramework.FASTAPI,
    mechanism: str = "dependency",
    declaration: str | None = "Depends(require_auth)",
    resolution: ControlResolutionStatus = ControlResolutionStatus.RESOLVED,
    confidence: float = 0.9,
) -> AuthControlCandidate:
    return AuthControlCandidate(
        control_type=control_type,
        framework=framework,
        mechanism=mechanism,
        declaration=declaration,
        source_file=source_file,
        line_number=line_number,
        symbol_name=symbol_name,
        scope_type=scope,
        associated_routes=list(routes or []),
        resolution_status=resolution,
        detection_confidence=confidence,
        evidence="Control declaration was observed.",
        classification_rule="Deterministic control rule.",
    )


def input_candidate(
    *,
    routes: list[AssociatedRoute] | None = None,
    input_type: InputType = InputType.QUERY,
    parameter_name: str | None = "q",
    variable_name: str | None = "q",
    handler_name: str | None = "handler",
    source_file: str = "app.py",
    line_number: int = 20,
    framework: RouteFramework = RouteFramework.FASTAPI,
    resolution: InputResolutionStatus = InputResolutionStatus.RESOLVED,
    confidence: float = 0.8,
) -> InputCandidate:
    return InputCandidate(
        input_type=input_type,
        framework=framework,
        source_file=source_file,
        line_number=line_number,
        parameter_name=parameter_name,
        variable_name=variable_name,
        handler_name=handler_name,
        associated_routes=list(routes or []),
        declaration_or_access="request.query_params",
        resolution_status=resolution,
        detection_confidence=confidence,
        evidence="Input access was observed.",
        classification_rule="Deterministic input rule.",
    )


def operation(
    *,
    routes: list[AssociatedRoute] | None = None,
    category: OperationCategory = OperationCategory.DATABASE_READ,
    operation_name: str = "execute",
    library: str = "SQLAlchemy",
    enclosing_function: str | None = "handler",
    enclosing_class: str | None = None,
    receiver_name: str | None = "session",
    resource_name: str | None = "User",
    source_file: str = "app.py",
    line_number: int = 30,
    resolution: OperationResolutionStatus = OperationResolutionStatus.RESOLVED,
    confidence: float = 0.9,
) -> SensitiveOperationCandidate:
    return SensitiveOperationCandidate(
        operation_category=category,
        framework_or_library=library,
        operation_name=operation_name,
        source_file=source_file,
        line_number=line_number,
        enclosing_function=enclosing_function,
        enclosing_class=enclosing_class,
        receiver_name=receiver_name,
        resource_name=resource_name,
        associated_routes=list(routes or []),
        declaration_or_access=operation_name,
        resolution_status=resolution,
        detection_confidence=confidence,
        evidence="Operation was observed.",
        classification_rule="Deterministic operation rule.",
    )


def attack_result(
    routes: list[RouteCandidate],
    *,
    issues: list[AnalysisIssue] | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
    root: str = ROOT,
) -> AttackSurfaceResult:
    source_issues = list(issues or [])
    return AttackSurfaceResult(
        root=root,
        routes=list(routes),
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


def auth_result(
    controls: list[AuthControlCandidate],
    *,
    issues: list[AnalysisIssue] | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
    root: str = ROOT,
) -> AuthControlResult:
    source_issues = list(issues or [])
    return AuthControlResult(
        root=root,
        controls=list(controls),
        issues=source_issues,
        summary=AuthControlSummary(
            source_files_inspected=1,
            authentication_control_count=sum(
                item.control_type is ControlType.AUTHENTICATION for item in controls
            ),
            authorization_control_count=sum(
                item.control_type is ControlType.AUTHORIZATION for item in controls
            ),
            route_association_count=sum(len(item.associated_routes) for item in controls),
            unresolved_scope_count=sum(
                item.scope_type is ControlScopeType.UNKNOWN for item in controls
            ),
            issue_count=len(source_issues),
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=list(truncation or []),
        ),
    )


def input_result(
    inputs: list[InputCandidate],
    *,
    issues: list[AnalysisIssue] | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
    root: str = ROOT,
) -> InputSourceResult:
    source_issues = list(issues or [])
    return InputSourceResult(
        root=root,
        inputs=list(inputs),
        issues=source_issues,
        summary=InputSourceSummary(
            source_files_inspected=1,
            input_count=len(inputs),
            named_parameter_count=sum(item.parameter_name is not None for item in inputs),
            route_association_count=sum(len(item.associated_routes) for item in inputs),
            unresolved_association_count=sum(
                item.resolution_status is InputResolutionStatus.UNRESOLVED for item in inputs
            ),
            issue_count=len(source_issues),
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=list(truncation or []),
        ),
    )


def operation_result(
    operations: list[SensitiveOperationCandidate],
    *,
    issues: list[AnalysisIssue] | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation: list[DiscoveryTruncationReason] | None = None,
    root: str = ROOT,
) -> SensitiveOperationResult:
    source_issues = list(issues or [])
    database_categories = {
        OperationCategory.DATABASE_READ,
        OperationCategory.DATABASE_WRITE,
        OperationCategory.DATABASE_DELETE,
        OperationCategory.DATABASE_EXECUTE,
        OperationCategory.DATABASE_TRANSACTION,
    }
    filesystem_categories = {
        OperationCategory.FILE_READ,
        OperationCategory.FILE_WRITE,
        OperationCategory.FILE_DELETE,
        OperationCategory.FILE_METADATA,
        OperationCategory.FILE_UPLOAD,
    }
    return SensitiveOperationResult(
        root=root,
        operations=list(operations),
        issues=source_issues,
        summary=SensitiveOperationSummary(
            source_files_inspected=1,
            operation_count=len(operations),
            database_operation_count=sum(
                item.operation_category in database_categories for item in operations
            ),
            filesystem_operation_count=sum(
                item.operation_category in filesystem_categories for item in operations
            ),
            process_execution_count=sum(
                item.operation_category is OperationCategory.PROCESS_EXECUTION
                for item in operations
            ),
            other_sensitive_operation_count=sum(
                item.operation_category not in database_categories | filesystem_categories
                and item.operation_category is not OperationCategory.PROCESS_EXECUTION
                for item in operations
            ),
            route_association_count=sum(len(item.associated_routes) for item in operations),
            unresolved_association_count=sum(
                item.resolution_status is OperationResolutionStatus.UNRESOLVED
                for item in operations
            ),
            issue_count=len(source_issues),
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=list(truncation or []),
        ),
    )


def correlate(
    *,
    routes: list[RouteCandidate] | None = None,
    controls: list[AuthControlCandidate] | None = None,
    inputs: list[InputCandidate] | None = None,
    operations: list[SensitiveOperationCandidate] | None = None,
    attack: AttackSurfaceResult | None = None,
    auth: AuthControlResult | None = None,
    input_source: InputSourceResult | None = None,
    operation_source: SensitiveOperationResult | None = None,
):
    return correlate_attack_surface(
        attack or attack_result(list(routes or [])),
        auth or auth_result(list(controls or [])),
        input_source or input_result(list(inputs or [])),
        operation_source or operation_result(list(operations or [])),
    )


def test_route_with_all_four_evidence_categories() -> None:
    routes = [route("/items", handler_name="list_items")]
    authentication = control(routes=[assoc("/items")])
    authorization = control(
        control_type=ControlType.AUTHORIZATION,
        routes=[assoc("/items")],
        scope=ControlScopeType.ROUTE,
        symbol_name="require_permission",
        declaration="Depends(require_permission)",
    )
    query = input_candidate(routes=[assoc("/items")], parameter_name="q")
    read = operation(routes=[assoc("/items")])

    result = correlate(
        routes=routes,
        controls=[authentication, authorization],
        inputs=[query],
        operations=[read],
    )

    assert len(result.routes) == 1
    entry = result.routes[0]
    assert entry.path == "/items"
    assert entry.http_method is HttpMethod.GET
    assert entry.framework is RouteFramework.FASTAPI
    assert entry.source_file == "app.py"
    assert entry.line_number == 10
    assert entry.handler_name == "list_items"
    assert entry.resolution_status is RouteResolutionStatus.RESOLVED
    assert entry.authentication_controls == [authentication]
    assert entry.authorization_controls == [authorization]
    assert entry.input_candidates == [query]
    assert entry.sensitive_operations == [read]
    assert {item.relationship_type for item in entry.relationships} == {
        CorrelationRelationshipType.ROUTE_TO_AUTH_CONTROL,
        CorrelationRelationshipType.ROUTE_TO_AUTHORIZATION_CONTROL,
        CorrelationRelationshipType.ROUTE_TO_INPUT,
        CorrelationRelationshipType.ROUTE_TO_SENSITIVE_OPERATION,
    }
    assert all(
        item.resolution_status is CorrelationResolutionStatus.RESOLVED
        for item in entry.relationships
    )
    assert result.issues == []
    assert result.summary.total_route_count == 1
    assert result.summary.routes_with_authentication == 1
    assert result.summary.routes_with_authorization == 1
    assert result.summary.routes_with_inputs == 1
    assert result.summary.routes_with_sensitive_operations == 1
    assert result.summary.routes_with_multiple_evidence_categories == 1
    assert result.summary.relationship_count == 4
    assert result.summary.unresolved_association_count == 0
    assert result.summary.ambiguous_association_count == 0
    assert result.summary.issue_count == 0
    assert result.summary.all_sources_complete is True
    assert result.summary.is_complete is True


def test_route_with_authentication_but_no_inputs() -> None:
    authentication = control(routes=[assoc("/admin")])
    result = correlate(
        routes=[route("/admin")],
        controls=[authentication],
    )

    entry = result.routes[0]
    assert entry.authentication_controls == [authentication]
    assert entry.input_candidates == []
    assert entry.sensitive_operations == []
    assert result.summary.routes_with_authentication == 1
    assert result.summary.routes_with_inputs == 0
    assert result.summary.relationship_count == 1


def test_route_with_inputs_but_no_authentication_control() -> None:
    query = input_candidate(routes=[assoc("/search")])
    result = correlate(routes=[route("/search")], inputs=[query])

    entry = result.routes[0]
    assert entry.authentication_controls == []
    assert entry.authorization_controls == []
    assert entry.input_candidates == [query]
    assert result.issues == []
    assert result.summary.routes_with_authentication == 0
    assert result.summary.routes_with_inputs == 1
    assert result.summary.unresolved_association_count == 0
    assert {item.relationship_type for item in entry.relationships} == {
        CorrelationRelationshipType.ROUTE_TO_INPUT
    }


def test_route_with_sensitive_operations_but_no_inputs() -> None:
    write = operation(
        routes=[assoc("/files")],
        category=OperationCategory.FILE_WRITE,
        operation_name="write_text",
        library="pathlib",
        receiver_name="path",
        resource_name=None,
    )
    result = correlate(routes=[route("/files")], operations=[write])

    entry = result.routes[0]
    assert entry.input_candidates == []
    assert entry.sensitive_operations == [write]
    assert result.summary.routes_with_inputs == 0
    assert result.summary.routes_with_sensitive_operations == 1
    assert result.summary.relationship_count == 1


def test_multiple_http_methods_on_same_path() -> None:
    get_route = route("/items", method=HttpMethod.GET, handler_name="get_items")
    post_route = route(
        "/items",
        method=HttpMethod.POST,
        line_number=20,
        handler_name="create_item",
    )
    get_input = input_candidate(
        routes=[assoc("/items", method=HttpMethod.GET)],
        handler_name="get_items",
    )
    post_operation = operation(
        routes=[assoc("/items", method=HttpMethod.POST)],
        category=OperationCategory.DATABASE_WRITE,
        operation_name="create",
        enclosing_function="create_item",
    )

    result = correlate(
        routes=[post_route, get_route],
        inputs=[get_input],
        operations=[post_operation],
    )

    assert [(item.path, item.http_method) for item in result.routes] == [
        ("/items", HttpMethod.GET),
        ("/items", HttpMethod.POST),
    ]
    assert result.routes[0].input_candidates == [get_input]
    assert result.routes[0].sensitive_operations == []
    assert result.routes[1].input_candidates == []
    assert result.routes[1].sensitive_operations == [post_operation]
    assert result.summary.total_route_count == 2
    assert result.summary.relationship_count == 2
    assert result.summary.unresolved_association_count == 0


def test_duplicate_route_declarations_are_ambiguous_not_merged() -> None:
    first = route("/items", source_file="a.py", line_number=10)
    second = route("/items", source_file="b.py", line_number=30)
    query = input_candidate(routes=[assoc("/items")])

    result = correlate(routes=[second, first], inputs=[query])

    assert len(result.routes) == 2
    assert result.routes[0].source_file == "a.py"
    assert result.routes[1].source_file == "b.py"
    assert all(item.input_candidates == [query] for item in result.routes)
    assert all(
        item.relationships[0].resolution_status is CorrelationResolutionStatus.AMBIGUOUS
        for item in result.routes
    )
    assert result.summary.ambiguous_association_count == 2
    assert result.summary.unresolved_association_count == 0
    ambiguous_issues = [
        issue
        for issue in result.issues
        if issue.category is CorrelationIssueCategory.AMBIGUOUS_ROUTE_REFERENCE
    ]
    assert len(ambiguous_issues) == 1
    assert ambiguous_issues[0].source_file == "app.py"
    assert ambiguous_issues[0].route is not None
    assert ambiguous_issues[0].route.path == "/items"
    assert "2 route declarations" in ambiguous_issues[0].explanation


def test_multiple_controls_associated_with_one_route() -> None:
    first = control(routes=[assoc("/items")], line_number=10)
    second = control(
        routes=[assoc("/items")],
        source_file="other.py",
        line_number=12,
        symbol_name="verify_token",
    )
    authorization = control(
        control_type=ControlType.AUTHORIZATION,
        routes=[assoc("/items")],
        line_number=14,
        symbol_name="require_role",
        declaration="Depends(require_role)",
    )

    result = correlate(
        routes=[route("/items")],
        controls=[authorization, second, first],
    )

    entry = result.routes[0]
    assert entry.authentication_controls == [first, second]
    assert entry.authorization_controls == [authorization]
    assert len(entry.relationships) == 3
    assert result.summary.relationship_count == 3
    assert result.summary.routes_with_multiple_evidence_categories == 1


def test_multiple_input_parameters_associated_with_one_route() -> None:
    named = input_candidate(
        routes=[assoc("/search")],
        parameter_name="q",
        variable_name="query",
        line_number=20,
    )
    unnamed = input_candidate(
        routes=[assoc("/search")],
        input_type=InputType.FORM,
        parameter_name=None,
        variable_name=None,
        line_number=21,
    )

    result = correlate(routes=[route("/search")], inputs=[unnamed, named])

    entry = result.routes[0]
    assert [item.parameter_name for item in entry.input_candidates] == ["q", None]
    assert [item.variable_name for item in entry.input_candidates] == [
        "query",
        None,
    ]
    assert len(entry.relationships) == 2
    assert result.summary.routes_with_inputs == 1


def test_multiple_sensitive_operations_associated_with_one_route() -> None:
    read = operation(routes=[assoc("/run")], line_number=30)
    process = operation(
        routes=[assoc("/run")],
        category=OperationCategory.PROCESS_EXECUTION,
        operation_name="run",
        library="subprocess",
        receiver_name="subprocess",
        resource_name=None,
        line_number=31,
    )

    result = correlate(routes=[route("/run")], operations=[process, read])

    entry = result.routes[0]
    assert [item.operation_category for item in entry.sensitive_operations] == [
        OperationCategory.DATABASE_READ,
        OperationCategory.PROCESS_EXECUTION,
    ]
    assert len(entry.relationships) == 2
    assert result.summary.routes_with_sensitive_operations == 1
    assert result.summary.relationship_count == 2


def test_unresolved_route_association_is_preserved_as_issue() -> None:
    query = input_candidate(routes=[assoc("/missing")])
    result = correlate(routes=[route("/items")], inputs=[query])

    assert len(result.routes) == 1
    assert result.routes[0].input_candidates == []
    assert result.routes[0].relationships == []
    assert result.summary.relationship_count == 0
    assert result.summary.unresolved_association_count == 1
    assert result.summary.ambiguous_association_count == 0

    issues = [
        issue
        for issue in result.issues
        if issue.category is CorrelationIssueCategory.UNRESOLVED_ROUTE_REFERENCE
    ]
    assert len(issues) == 1
    assert issues[0].source_file == "app.py"
    assert issues[0].route is not None
    assert issues[0].route.path == "/missing"
    assert issues[0].evidence_source is CorrelationEvidenceSource.INPUT_SOURCES
    assert "matched no route candidate" in issues[0].explanation


def test_unassociated_evidence_is_preserved_as_issue() -> None:
    orphan = input_candidate(routes=[])
    result = correlate(routes=[route("/items")], inputs=[orphan])

    assert result.routes[0].input_candidates == []
    assert result.summary.unresolved_association_count == 1
    issues = [
        issue
        for issue in result.issues
        if issue.category is CorrelationIssueCategory.UNASSOCIATED_EVIDENCE
    ]
    assert len(issues) == 1
    assert issues[0].source_file == "app.py"
    assert issues[0].route is None
    assert issues[0].evidence_identifier == "input_sources[0]"
    assert "not assigned to a route" in issues[0].explanation


def test_unresolved_route_candidate_is_not_treated_as_resolved() -> None:
    unresolved_route = route(
        "/maybe",
        resolution=RouteResolutionStatus.UNRESOLVED,
        handler_name=None,
    )
    read = operation(routes=[assoc("/maybe")])

    result = correlate(routes=[unresolved_route], operations=[read])

    entry = result.routes[0]
    assert entry.resolution_status is RouteResolutionStatus.UNRESOLVED
    assert entry.sensitive_operations == [read]
    assert entry.relationships[0].resolution_status is (CorrelationResolutionStatus.UNRESOLVED)
    assert result.summary.unresolved_association_count == 1
    unresolved_issues = [
        issue
        for issue in result.issues
        if issue.category is CorrelationIssueCategory.UNRESOLVED_ROUTE
    ]
    assert len(unresolved_issues) == 1
    assert unresolved_issues[0].route is not None
    assert unresolved_issues[0].route.resolution_status is (RouteResolutionStatus.UNRESOLVED)
    assert "without inferring a concrete route path" in (unresolved_issues[0].explanation)


def test_application_router_and_controller_scope_controls_are_preserved() -> None:
    application = control(
        routes=[assoc("/items")],
        scope=ControlScopeType.APPLICATION,
        mechanism="app middleware",
        declaration="app.use(require_auth)",
        source_file="server.js",
        framework=RouteFramework.EXPRESS,
    )
    router = control(
        routes=[assoc("/items")],
        scope=ControlScopeType.ROUTER,
        mechanism="router middleware",
        declaration="router.use(require_auth)",
        source_file="server.js",
        line_number=11,
        framework=RouteFramework.EXPRESS,
    )
    controller = control(
        routes=[assoc("/items")],
        scope=ControlScopeType.CONTROLLER,
        mechanism="controller guard",
        declaration="@UseGuards(AuthGuard)",
        source_file="items.controller.ts",
        line_number=12,
        framework=RouteFramework.NESTJS,
    )

    result = correlate(
        routes=[route("/items")],
        controls=[controller, router, application],
    )

    entry = result.routes[0]
    assert [item.scope_type for item in entry.authentication_controls] == [
        ControlScopeType.CONTROLLER,
        ControlScopeType.APPLICATION,
        ControlScopeType.ROUTER,
    ]
    assert [item.declaration for item in entry.authentication_controls] == [
        "@UseGuards(AuthGuard)",
        "app.use(require_auth)",
        "router.use(require_auth)",
    ]
    assert len(entry.relationships) == 3


def test_one_control_can_associate_with_multiple_routes() -> None:
    application_control = control(
        routes=[assoc("/items"), assoc("/orders")],
        scope=ControlScopeType.APPLICATION,
        source_file="app.py",
        line_number=5,
        mechanism="app middleware",
    )

    result = correlate(
        routes=[route("/items"), route("/orders", line_number=20)],
        controls=[application_control],
    )

    assert result.summary.total_route_count == 2
    assert result.summary.routes_with_authentication == 2
    assert result.summary.relationship_count == 2
    assert result.summary.unresolved_association_count == 0
    for entry in result.routes:
        assert entry.authentication_controls == [application_control]
        assert len(entry.relationships) == 1
        assert (
            entry.relationships[0].relationship_type
            is CorrelationRelationshipType.ROUTE_TO_AUTH_CONTROL
        )


def test_control_evidence_details_and_confidence_are_preserved() -> None:
    authentication = control(
        routes=[assoc("/items")],
        declaration="Depends(require_auth)",
        confidence=0.73,
        mechanism="dependency",
    )
    result = correlate(routes=[route("/items")], controls=[authentication])

    preserved = result.routes[0].authentication_controls[0]
    assert preserved.declaration == "Depends(require_auth)"
    assert preserved.detection_confidence == pytest.approx(0.73)
    assert preserved.mechanism == "dependency"
    assert preserved.evidence == authentication.evidence
    assert preserved.classification_rule == authentication.classification_rule
    assert preserved.source_file == "app.py"
    assert preserved.line_number == 10


def test_same_handler_input_and_operation_cooccurrence_without_dataflow() -> None:
    shared_handler = "view_item"
    query = input_candidate(
        routes=[assoc("/items")],
        handler_name=shared_handler,
        variable_name="item_id",
    )
    read = operation(
        routes=[assoc("/items")],
        enclosing_function=shared_handler,
        resource_name="Item",
    )

    result = correlate(
        routes=[route("/items", handler_name=shared_handler)],
        inputs=[query],
        operations=[read],
    )

    entry = result.routes[0]
    assert entry.input_candidates == [query]
    assert entry.sensitive_operations == [read]
    for relationship in entry.relationships:
        assert "does not establish dataflow" in relationship.explanation
    assert entry.input_candidates[0].detection_confidence == pytest.approx(0.8)
    assert entry.sensitive_operations[0].detection_confidence == pytest.approx(0.9)


def test_missing_evidence_categories_produce_empty_collections() -> None:
    result = correlate(routes=[route("/items")])

    entry = result.routes[0]
    assert entry.authentication_controls == []
    assert entry.authorization_controls == []
    assert entry.input_candidates == []
    assert entry.sensitive_operations == []
    assert entry.relationships == []
    assert result.issues == []
    assert result.summary.total_route_count == 1
    assert result.summary.routes_with_authentication == 0
    assert result.summary.routes_with_authorization == 0
    assert result.summary.routes_with_inputs == 0
    assert result.summary.routes_with_sensitive_operations == 0
    assert result.summary.routes_with_multiple_evidence_categories == 0
    assert result.summary.relationship_count == 0
    assert result.summary.unresolved_association_count == 0
    assert result.summary.ambiguous_association_count == 0
    assert result.summary.issue_count == 0


def test_empty_analysis_results() -> None:
    result = correlate()

    assert result.routes == []
    assert result.issues == []
    assert result.summary.total_route_count == 0
    assert result.summary.relationship_count == 0
    assert result.summary.unresolved_association_count == 0
    assert result.summary.ambiguous_association_count == 0
    assert result.summary.issue_count == 0
    assert result.summary.all_sources_complete is True
    assert result.summary.is_complete is True
    assert len(result.summary.source_statuses) == 4


def test_incomplete_discovery_propagation() -> None:
    source_issue = AnalysisIssue(
        source_file="broken.py",
        reason=AnalysisIssueReason.INVALID_SYNTAX,
    )
    result = correlate(
        attack=attack_result([], is_complete=False, discovery_is_complete=False),
        auth=auth_result([], is_complete=True),
        input_source=input_result(
            [],
            issues=[source_issue],
            is_complete=False,
            discovery_is_complete=False,
        ),
        operation_source=operation_result([]),
    )

    statuses = {item.source.value: item for item in result.summary.source_statuses}
    assert statuses["attack_surface"].is_complete is False
    assert statuses["attack_surface"].discovery_is_complete is False
    assert statuses["auth_controls"].is_complete is True
    assert statuses["input_sources"].is_complete is False
    assert statuses["input_sources"].discovery_is_complete is False
    assert statuses["input_sources"].issue_count == 1
    assert result.summary.all_sources_complete is False
    assert result.summary.is_complete is False


def test_truncation_information_is_preserved_per_source() -> None:
    result = correlate(
        attack=attack_result(
            [],
            truncation=[DiscoveryTruncationReason.MAX_FILE_COUNT],
        ),
        auth=auth_result(
            [],
            truncation=[DiscoveryTruncationReason.MAX_TOTAL_SIZE],
        ),
        input_source=input_result(
            [],
            truncation=[DiscoveryTruncationReason.MAX_DEPTH],
        ),
        operation_source=operation_result(
            [],
            truncation=[DiscoveryTruncationReason.MAX_FILE_COUNT],
        ),
    )

    statuses = {item.source.value: item for item in result.summary.source_statuses}
    assert statuses["attack_surface"].discovery_truncation_reasons == [
        DiscoveryTruncationReason.MAX_FILE_COUNT
    ]
    assert statuses["auth_controls"].discovery_truncation_reasons == [
        DiscoveryTruncationReason.MAX_TOTAL_SIZE
    ]
    assert statuses["input_sources"].discovery_truncation_reasons == [
        DiscoveryTruncationReason.MAX_DEPTH
    ]
    assert statuses["sensitive_operations"].discovery_truncation_reasons == [
        DiscoveryTruncationReason.MAX_FILE_COUNT
    ]


def test_deterministic_ordering() -> None:
    routes = [
        route("/z", source_file="z.py", line_number=10),
        route("/a", source_file="a.py", line_number=20),
        route("/m", source_file="m.py", line_number=5),
    ]
    controls = [
        control(routes=[assoc("/m")], line_number=40),
        control(routes=[assoc("/a")], line_number=20),
        control(routes=[assoc("/z")], line_number=10),
    ]
    inputs = [
        input_candidate(routes=[assoc("/m")], parameter_name="m", line_number=3),
        input_candidate(routes=[assoc("/a")], parameter_name="a", line_number=2),
        input_candidate(routes=[assoc("/z")], parameter_name="z", line_number=1),
    ]
    operations = [
        operation(routes=[assoc("/m")], operation_name="m", line_number=3),
        operation(routes=[assoc("/a")], operation_name="a", line_number=2),
        operation(routes=[assoc("/z")], operation_name="z", line_number=1),
    ]

    first = correlate(
        routes=list(reversed(routes)),
        controls=list(reversed(controls)),
        inputs=list(reversed(inputs)),
        operations=list(reversed(operations)),
    )
    second = correlate(
        routes=routes,
        controls=controls,
        inputs=inputs,
        operations=operations,
    )

    assert first.model_dump() == second.model_dump()
    assert [item.source_file for item in first.routes] == ["a.py", "m.py", "z.py"]
    for entry in first.routes:
        relationship_keys = [
            (
                item.relationship_type.value,
                item.evidence_source.value,
                item.evidence_index,
            )
            for item in entry.relationships
        ]
        assert relationship_keys == sorted(relationship_keys)

    assert [item.explanation for item in first.issues] == sorted(
        item.explanation for item in first.issues
    )


def test_original_inputs_are_not_mutated() -> None:
    routes = [route("/items")]
    controls = [control(routes=[assoc("/items")])]
    inputs = [input_candidate(routes=[assoc("/items")])]
    operations = [operation(routes=[assoc("/items")])]
    attack = attack_result(routes)
    auth = auth_result(controls)
    input_source = input_result(inputs)
    operation_source = operation_result(operations)

    snapshots = [
        copy.deepcopy(item.model_dump()) for item in (attack, auth, input_source, operation_source)
    ]

    correlate_attack_surface(attack, auth, input_source, operation_source)

    assert [
        item.model_dump() for item in (attack, auth, input_source, operation_source)
    ] == snapshots


def test_summary_counts_are_correct() -> None:
    all_categories = control(
        routes=[assoc("/all")],
        source_file="all.py",
        line_number=10,
    )
    all_authorization = control(
        control_type=ControlType.AUTHORIZATION,
        routes=[assoc("/all")],
        source_file="all.py",
        line_number=11,
    )
    all_input = input_candidate(
        routes=[assoc("/all")],
        source_file="all.py",
        line_number=12,
    )
    all_operation = operation(
        routes=[assoc("/all")],
        source_file="all.py",
        line_number=13,
    )
    partial_control = control(
        routes=[assoc("/partial")],
        source_file="partial.py",
        line_number=10,
    )
    partial_input = input_candidate(
        routes=[assoc("/partial")],
        source_file="partial.py",
        line_number=11,
    )

    result = correlate(
        routes=[
            route("/all", source_file="all.py", line_number=1),
            route("/partial", source_file="partial.py", line_number=1),
            route("/empty", source_file="empty.py", line_number=1),
        ],
        controls=[all_categories, all_authorization, partial_control],
        inputs=[all_input, partial_input],
        operations=[all_operation],
    )

    assert result.summary.total_route_count == 3
    assert result.summary.routes_with_authentication == 2
    assert result.summary.routes_with_authorization == 1
    assert result.summary.routes_with_inputs == 2
    assert result.summary.routes_with_sensitive_operations == 1
    assert result.summary.routes_with_multiple_evidence_categories == 2
    assert result.summary.relationship_count == 6
    assert result.summary.unresolved_association_count == 0
    assert result.summary.ambiguous_association_count == 0
    assert result.summary.issue_count == 0
    assert result.summary.is_complete is True


def test_exact_duplicate_routes_are_deduplicated() -> None:
    duplicate = route("/items")
    result = correlate(routes=[duplicate, duplicate.model_copy(deep=True)])

    assert len(result.routes) == 1
    assert result.summary.total_route_count == 1


def test_mismatched_roots_are_rejected() -> None:
    attack = attack_result([route("/items")])
    auth = auth_result([], root=str(Path.cwd() / "other"))
    input_source = input_result([])
    operation_source = operation_result([])

    with pytest.raises(InvalidCorrelationRootError):
        correlate_attack_surface(
            attack,
            auth,
            input_source,
            operation_source,
        )
