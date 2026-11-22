import copy
import json
import textwrap
from pathlib import Path, PurePosixPath

import pytest

from app.core.config import settings
from app.schemas.attack_surface import (
    AnalysisIssue,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    HttpMethod,
    RouteCandidate,
    RouteFramework,
    RouteResolutionStatus,
)
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.handler_calls import (
    CallRelationshipType,
    CallResolutionStatus,
    FunctionKind,
    HandlerCallIssueCategory,
    HandlerResolutionStatus,
)
from app.schemas.repository_discovery import (
    DiscoveryLimits,
    DiscoverySummary,
    FileInventoryEntry,
    RepositoryDiscoveryResult,
)
from app.schemas.technology import (
    TechnologyDetectionResult,
    TechnologyDetectionSummary,
)
from app.services.attack_surface import identify_attack_surface
from app.services.handler_calls import (
    InvalidHandlerCallRootError,
    analyze_handler_calls,
)
from app.services.repository_discovery import discover_repository


@pytest.fixture
def allowed_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


@pytest.fixture
def repository(allowed_root: Path) -> Path:
    repository = allowed_root / "project"
    repository.mkdir()
    return repository


def source(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"Line containing {needle!r} was not found")


def manual_inventory(
    root: Path,
    relative_paths: list[str],
    *,
    is_complete: bool = True,
    truncation_reasons: list[DiscoveryTruncationReason] | None = None,
) -> RepositoryDiscoveryResult:
    files: list[FileInventoryEntry] = []
    total_size_bytes = 0
    for relative_path in relative_paths:
        path = root / relative_path
        try:
            size_bytes = path.lstat().st_size
        except OSError:
            size_bytes = 0
        suffix = PurePosixPath(relative_path.replace("\\", "/")).suffix
        files.append(
            FileInventoryEntry(
                relative_path=relative_path,
                extension=suffix[1:].lower() if suffix else None,
                size_bytes=size_bytes,
            )
        )
        total_size_bytes += size_bytes

    return RepositoryDiscoveryResult(
        root=str(root.resolve()),
        files=sorted(files, key=lambda entry: entry.relative_path),
        skipped=[],
        summary=DiscoverySummary(
            directory_count=0,
            file_count=len(files),
            total_size_bytes=total_size_bytes,
            skipped_count=0,
            is_complete=is_complete,
            truncation_reasons=list(truncation_reasons or []),
            limits=DiscoveryLimits(
                max_file_count=settings.repository_max_file_count,
                max_depth=settings.repository_max_depth,
                max_total_size_bytes=settings.repository_max_total_size_bytes,
            ),
        ),
    )


def manual_technologies(root: Path) -> TechnologyDetectionResult:
    return TechnologyDetectionResult(
        root=str(root.resolve()),
        detections=[],
        issues=[],
        summary=TechnologyDetectionSummary(
            detection_count=0,
            language_count=0,
            framework_count=0,
            library_count=0,
            database_count=0,
            infrastructure_count=0,
            build_tool_count=0,
            manifest_files_read=0,
            issue_count=0,
            discovery_is_complete=True,
            discovery_truncation_reasons=[],
        ),
    )


def manual_attack_surface(
    root: Path,
    routes: list[RouteCandidate],
    *,
    root_value: str | None = None,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
    truncation_reasons: list[DiscoveryTruncationReason] | None = None,
    issues: list[AnalysisIssue] | None = None,
) -> AttackSurfaceResult:
    source_issues = list(issues or [])
    return AttackSurfaceResult(
        root=root_value or str(root.resolve()),
        routes=list(routes),
        issues=source_issues,
        summary=AttackSurfaceSummary(
            source_files_inspected=1,
            route_count=len(routes),
            resolved_route_count=sum(
                route.resolution_status is RouteResolutionStatus.RESOLVED for route in routes
            ),
            unresolved_route_count=sum(
                route.resolution_status is RouteResolutionStatus.UNRESOLVED for route in routes
            ),
            issue_count=len(source_issues),
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=list(truncation_reasons or []),
        ),
    )


def route_candidate(
    path: str,
    *,
    handler_name: str | None,
    source_file: str = "app.py",
    line_number: int = 1,
    method: HttpMethod = HttpMethod.GET,
    framework: RouteFramework = RouteFramework.FASTAPI,
    resolution: RouteResolutionStatus = RouteResolutionStatus.RESOLVED,
    confidence: float = 0.95,
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


def analyze(
    repository: Path,
    *,
    routes: list[RouteCandidate] | None = None,
    inventory: RepositoryDiscoveryResult | None = None,
    technologies: TechnologyDetectionResult | None = None,
    attack_surface: AttackSurfaceResult | None = None,
) -> object:
    resolved_inventory = inventory or discover_repository(repository)
    resolved_technologies = technologies or manual_technologies(repository)
    if attack_surface is not None:
        resolved_surface = attack_surface
    elif routes is not None:
        resolved_surface = manual_attack_surface(repository, routes)
    else:
        resolved_surface = identify_attack_surface(
            repository,
            resolved_inventory,
            resolved_technologies,
        )
    return analyze_handler_calls(
        repository,
        resolved_inventory,
        resolved_technologies,
        resolved_surface,
    )


def definition_by_name(result: object, name: str) -> object:
    matches = [definition for definition in result.definitions if definition.name == name]
    assert matches, name
    return matches[0]


def test_real_attack_surface_route_handler_is_resolved(repository: Path) -> None:
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/items")
        def list_items():
            return []
        """
    )
    write_text(repository / "app.py", text)

    result = analyze(repository)

    assert len(result.handlers) == 1
    handler = result.handlers[0]
    assert handler.route_path == "/items"
    assert handler.handler_name == "list_items"
    assert handler.resolution_status is HandlerResolutionStatus.RESOLVED
    assert len(handler.definition_ids) == 1
    definition = definition_by_name(result, "list_items")
    assert definition.is_route_handler is True
    assert definition.route_ids == [handler.route_id]


def test_handler_with_no_local_calls(repository: Path) -> None:
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/items")
        def handler():
            return 1
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[
            route_candidate(
                "/items",
                handler_name="handler",
                line_number=line_of(text, "@app.get"),
            )
        ],
    )

    assert len(result.handlers) == 1
    assert result.handlers[0].resolution_status is HandlerResolutionStatus.RESOLVED
    assert result.calls == []
    assert result.relationships == []
    assert result.call_issues == []
    assert result.summary.call_site_count == 0
    assert result.summary.relationship_count == 0


def test_handler_calling_one_local_function(repository: Path) -> None:
    text = source(
        """
        from fastapi import FastAPI

        app = FastAPI()

        def helper(value):
            return value

        @app.get("/items")
        def handler():
            return helper(1)
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[
            route_candidate(
                "/items",
                handler_name="handler",
                line_number=line_of(text, "@app.get"),
            )
        ],
    )

    helper = definition_by_name(result, "helper")
    assert len(result.calls) == 1
    call = result.calls[0]
    assert call.caller_name == "handler"
    assert call.callee_name == "helper"
    assert call.callee_expression == "helper"
    assert call.source_file == "app.py"
    assert call.line_number == line_of(text, "helper(1)")
    assert call.resolution_status is CallResolutionStatus.RESOLVED
    assert call.target_definition_ids == [helper.definition_id]
    assert call.is_recursive is False

    assert len(result.relationships) == 1
    relationship = result.relationships[0]
    assert relationship.relationship_type is CallRelationshipType.HANDLER_TO_FUNCTION
    assert relationship.caller_definition_id == (
        definition_by_name(result, "handler").definition_id
    )
    assert relationship.callee_definition_id == helper.definition_id
    assert relationship.source_file == "app.py"
    assert relationship.line_number == line_of(text, "helper(1)")
    assert relationship.resolution_status is CallResolutionStatus.RESOLVED
    assert result.call_issues == []


def test_multiple_local_function_calls(repository: Path) -> None:
    text = source(
        """
        def first():
            return 1

        def second():
            return 2

        def handler():
            first()
            second()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    assert [call.callee_name for call in result.calls] == ["first", "second"]
    assert all(call.resolution_status is CallResolutionStatus.RESOLVED for call in result.calls)
    assert len(result.relationships) == 2
    assert all(
        relationship.relationship_type is CallRelationshipType.HANDLER_TO_FUNCTION
        for relationship in result.relationships
    )
    assert result.summary.resolved_call_count == 2
    assert result.summary.relationship_count == 2


def test_nested_local_function_calls(repository: Path) -> None:
    text = source(
        """
        def final_step():
            return 2

        def middle_step():
            return final_step()

        def handler():
            return middle_step()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    relationships = {item.relationship_type for item in result.relationships}
    assert relationships == {
        CallRelationshipType.HANDLER_TO_FUNCTION,
        CallRelationshipType.FUNCTION_TO_FUNCTION,
    }
    middle = definition_by_name(result, "middle_step")
    final = definition_by_name(result, "final_step")
    assert any(
        item.caller_definition_id == middle.definition_id
        and item.callee_definition_id == final.definition_id
        for item in result.relationships
    )
    assert result.summary.relationship_count == 2


def test_nested_lexical_function_calls(repository: Path) -> None:
    text = source(
        """
        def handler():
            def first():
                return second()

            def second():
                return 1

            return first()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    first = definition_by_name(result, "first")
    second = definition_by_name(result, "second")
    assert first.kind is FunctionKind.NESTED_FUNCTION
    assert second.kind is FunctionKind.NESTED_FUNCTION
    assert first.parent_definition_id == (definition_by_name(result, "handler").definition_id)
    calls = {call.callee_name: call for call in result.calls}
    assert calls["first"].target_definition_ids == [first.definition_id]
    assert calls["second"].target_definition_ids == [second.definition_id]
    relationship_types = {item.relationship_type for item in result.relationships}
    assert relationship_types == {
        CallRelationshipType.HANDLER_TO_FUNCTION,
        CallRelationshipType.FUNCTION_TO_FUNCTION,
    }


def test_local_import_is_not_visible_to_other_functions(repository: Path) -> None:
    write_text(
        repository / "pkg" / "__init__.py",
        "",
    )
    write_text(
        repository / "pkg" / "helpers.py",
        source(
            """
            def helper():
                return 1
            """
        ),
    )
    text = source(
        """
        def other():
            from pkg.helpers import helper
            return helper()

        def handler():
            return helper()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    calls = {call.caller_name: call for call in result.calls}
    assert calls["other"].resolution_status is CallResolutionStatus.RESOLVED
    assert calls["handler"].resolution_status is CallResolutionStatus.UNRESOLVED
    assert any(
        issue.category is HandlerCallIssueCategory.UNRESOLVED_CALL
        and issue.call_id == calls["handler"].call_id
        for issue in result.call_issues
    )


def test_function_to_function_call(repository: Path) -> None:
    text = source(
        """
        def leaf():
            return 1

        def branch():
            return leaf()

        def unrelated():
            return 2
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(repository, routes=[])

    branch = definition_by_name(result, "branch")
    leaf = definition_by_name(result, "leaf")
    assert len(result.relationships) == 1
    relationship = result.relationships[0]
    assert relationship.relationship_type is CallRelationshipType.FUNCTION_TO_FUNCTION
    assert relationship.caller_definition_id == branch.definition_id
    assert relationship.callee_definition_id == leaf.definition_id
    assert definition_by_name(result, "unrelated").is_route_handler is False


def test_method_calls_through_local_instance(repository: Path) -> None:
    text = source(
        """
        class Service:
            def run(self):
                return 1

        def handler():
            service = Service()
            return service.run()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    method = definition_by_name(result, "run")
    assert method.kind is FunctionKind.METHOD
    assert method.class_name == "Service"
    call = next(item for item in result.calls if item.callee_name == "run")
    assert call.is_method_call is True
    assert call.receiver_expression == "service"
    assert call.resolution_status is CallResolutionStatus.RESOLVED
    assert call.target_definition_ids == [method.definition_id]
    relationship = next(
        item for item in result.relationships if item.callee_definition_id == method.definition_id
    )
    assert relationship.relationship_type is CallRelationshipType.HANDLER_TO_METHOD
    construction = next(item for item in result.calls if item.callee_name == "Service")
    assert construction.resolution_status is CallResolutionStatus.EXTERNAL


def test_self_method_call(repository: Path) -> None:
    text = source(
        """
        class Controller:
            def handler(self):
                return self.helper()

            def helper(self):
                return 1
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    handler = definition_by_name(result, "handler")
    helper = definition_by_name(result, "helper")
    assert handler.kind is FunctionKind.METHOD
    assert result.handlers[0].resolution_status is HandlerResolutionStatus.RESOLVED
    call = result.calls[0]
    assert call.callee_expression == "self.helper"
    assert call.receiver_expression == "self"
    assert call.target_definition_ids == [helper.definition_id]
    relationship = result.relationships[0]
    assert relationship.relationship_type is CallRelationshipType.HANDLER_TO_METHOD
    assert relationship.is_recursive is False


def test_multiple_definitions_with_same_name_are_ambiguous(repository: Path) -> None:
    text = source(
        """
        def helper():
            return 1

        def helper():
            return 2

        def handler():
            return helper()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    helpers = [definition for definition in result.definitions if definition.name == "helper"]
    assert len(helpers) == 2
    call = result.calls[0]
    assert call.resolution_status is CallResolutionStatus.AMBIGUOUS
    assert set(call.target_definition_ids) == {definition.definition_id for definition in helpers}
    assert len(result.relationships) == 2
    assert all(
        item.resolution_status is CallResolutionStatus.AMBIGUOUS for item in result.relationships
    )
    assert any(
        issue.category is HandlerCallIssueCategory.AMBIGUOUS_CALL for issue in result.call_issues
    )


def test_ambiguous_handler_definition(repository: Path) -> None:
    text = source(
        """
        def handler():
            return 1

        def handler():
            return 2
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    handler = result.handlers[0]
    assert handler.resolution_status is HandlerResolutionStatus.AMBIGUOUS
    assert len(handler.definition_ids) == 2
    assert any(
        issue.category is HandlerCallIssueCategory.AMBIGUOUS_HANDLER_DEFINITION
        for issue in result.call_issues
    )


def test_unresolved_call_is_preserved(repository: Path) -> None:
    text = source(
        """
        def handler():
            return unknown_helper()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    call = result.calls[0]
    assert call.callee_name == "unknown_helper"
    assert call.resolution_status is CallResolutionStatus.UNRESOLVED
    assert call.target_definition_ids == []
    assert result.relationships == []
    issue = next(
        item
        for item in result.call_issues
        if item.category is HandlerCallIssueCategory.UNRESOLVED_CALL
    )
    assert issue.call_id == call.call_id
    assert "not guessed" in issue.explanation
    assert result.summary.unresolved_call_count == 1


def test_external_library_and_builtin_calls(repository: Path) -> None:
    text = source(
        """
        import requests

        def handler():
            print("value")
            return requests.get("https://example.test")
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    assert [call.callee_expression for call in result.calls] == [
        "print",
        "requests.get",
    ]
    assert all(call.resolution_status is CallResolutionStatus.EXTERNAL for call in result.calls)
    assert result.relationships == []
    assert result.call_issues == []
    assert result.summary.external_call_count == 2
    assert all("example.test" not in call.callee_expression for call in result.calls)


def test_recursive_call(repository: Path) -> None:
    text = source(
        """
        def handler(depth):
            if depth:
                return handler(depth - 1)
            return 0
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    handler = definition_by_name(result, "handler")
    call = result.calls[0]
    assert call.target_definition_ids == [handler.definition_id]
    assert call.is_recursive is True
    assert call.resolution_status is CallResolutionStatus.RESOLVED
    relationship = result.relationships[0]
    assert relationship.is_recursive is True
    assert relationship.relationship_type is CallRelationshipType.HANDLER_TO_FUNCTION
    assert result.summary.recursive_call_count == 1


def test_cross_file_call_through_relative_import(repository: Path) -> None:
    write_text(repository / "pkg" / "__init__.py", "")
    write_text(
        repository / "pkg" / "helpers.py",
        source(
            """
            def helper(value):
                return value
            """
        ),
    )
    text = source(
        """
        from fastapi import FastAPI
        from .helpers import helper

        app = FastAPI()

        @app.get("/items")
        def handler():
            return helper(1)
        """
    )
    write_text(repository / "pkg" / "main.py", text)
    result = analyze(
        repository,
        routes=[
            route_candidate(
                "/items",
                handler_name="handler",
                source_file="pkg/main.py",
                line_number=line_of(text, "@app.get"),
            )
        ],
    )

    helper = definition_by_name(result, "helper")
    assert helper.source_file == "pkg/helpers.py"
    call = result.calls[0]
    assert call.source_file == "pkg/main.py"
    assert call.resolution_status is CallResolutionStatus.RESOLVED
    assert call.target_definition_ids == [helper.definition_id]
    relationship = result.relationships[0]
    assert relationship.caller_definition_id == (
        definition_by_name(result, "handler").definition_id
    )
    assert relationship.callee_definition_id == helper.definition_id


def test_ambiguous_receiver_resolution(repository: Path) -> None:
    text = source(
        """
        class First:
            def run(self):
                return 1

        class Second:
            def run(self):
                return 2

        def handler():
            service = First()
            service = Second()
            return service.run()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    call = next(item for item in result.calls if item.callee_name == "run")
    assert call.resolution_status is CallResolutionStatus.AMBIGUOUS
    assert len(call.target_definition_ids) == 2
    assert (
        len(
            [
                item
                for item in result.relationships
                if item.callee_definition_id in call.target_definition_ids
            ]
        )
        == 2
    )
    assert any(
        issue.category is HandlerCallIssueCategory.AMBIGUOUS_CALL for issue in result.call_issues
    )


def test_route_without_handler_name_and_missing_definition(repository: Path) -> None:
    text = source(
        """
        def other():
            return 1
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[
            route_candidate("/missing-name", handler_name=None, line_number=5),
            route_candidate("/missing-definition", handler_name="absent", line_number=6),
        ],
    )

    assert [handler.resolution_status for handler in result.handlers] == [
        HandlerResolutionStatus.UNRESOLVED,
        HandlerResolutionStatus.UNRESOLVED,
    ]
    categories = {issue.category for issue in result.call_issues}
    assert HandlerCallIssueCategory.MISSING_HANDLER_NAME in categories
    assert HandlerCallIssueCategory.HANDLER_DEFINITION_NOT_FOUND in categories


def test_unsupported_language_handler_is_not_guessed(repository: Path) -> None:
    write_text(repository / "server.js", "function handler() { return 1; }\n")
    result = analyze(
        repository,
        routes=[
            route_candidate(
                "/items",
                handler_name="handler",
                source_file="server.js",
                framework=RouteFramework.EXPRESS,
            )
        ],
    )

    assert result.handlers[0].resolution_status is HandlerResolutionStatus.UNRESOLVED
    assert result.handlers[0].definition_ids == []
    assert any(
        issue.category is HandlerCallIssueCategory.UNSUPPORTED_LANGUAGE
        for issue in result.call_issues
    )


def test_deterministic_output(repository: Path) -> None:
    text = source(
        """
        def helper_a():
            return 1

        def helper_b():
            return 2

        def handler():
            helper_a()
            helper_b()
        """
    )
    write_text(repository / "app.py", text)
    routes = [route_candidate("/items", handler_name="handler")]
    first = analyze(repository, routes=list(routes))
    second = analyze(repository, routes=list(reversed(routes)))

    assert first.model_dump() == second.model_dump()

    call_keys = [(item.source_file, item.line_number, item.column_number) for item in first.calls]
    assert call_keys == sorted(call_keys)
    relationship_keys = [
        (item.source_file, item.line_number, item.callee_definition_id)
        for item in first.relationships
    ]
    assert relationship_keys == sorted(relationship_keys)
    definition_keys = [
        (item.source_file, item.line_number, item.column_number) for item in first.definitions
    ]
    assert definition_keys == sorted(definition_keys)


def test_repository_root_mismatch_is_rejected(
    repository: Path,
    tmp_path: Path,
) -> None:
    inventory = discover_repository(repository)
    technologies = manual_technologies(repository)
    attack_surface = manual_attack_surface(
        repository,
        [],
        root_value=str(tmp_path / "other"),
    )

    with pytest.raises(InvalidHandlerCallRootError):
        analyze_handler_calls(
            repository,
            inventory,
            technologies,
            attack_surface,
        )


def test_empty_repository_and_empty_results(repository: Path) -> None:
    result = analyze(repository, routes=[])

    assert result.handlers == []
    assert result.definitions == []
    assert result.calls == []
    assert result.relationships == []
    assert result.issues == []
    assert result.call_issues == []
    assert result.summary.route_handler_count == 0
    assert result.summary.definition_count == 0
    assert result.summary.call_site_count == 0
    assert result.summary.relationship_count == 0
    assert result.summary.is_complete is True


def test_original_inputs_are_not_mutated(repository: Path) -> None:
    text = source(
        """
        def helper():
            return 1

        def handler():
            return helper()
        """
    )
    write_text(repository / "app.py", text)
    inventory = discover_repository(repository)
    technologies = manual_technologies(repository)
    attack_surface = manual_attack_surface(
        repository,
        [route_candidate("/items", handler_name="handler")],
    )
    snapshots = [
        copy.deepcopy(item.model_dump()) for item in (inventory, technologies, attack_surface)
    ]

    analyze_handler_calls(
        repository,
        inventory,
        technologies,
        attack_surface,
    )

    assert [item.model_dump() for item in (inventory, technologies, attack_surface)] == snapshots


def test_incomplete_discovery_and_truncation_are_propagated(
    repository: Path,
) -> None:
    write_text(repository / "app.py", "def handler():\n    return 1\n")
    inventory = manual_inventory(
        repository,
        ["app.py"],
        is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_FILE_COUNT],
    )
    technologies = manual_technologies(repository)
    attack_surface = manual_attack_surface(
        repository,
        [route_candidate("/items", handler_name="handler")],
    )

    result = analyze_handler_calls(
        repository,
        inventory,
        technologies,
        attack_surface,
    )

    assert result.summary.discovery_is_complete is False
    assert result.summary.discovery_truncation_reasons == [DiscoveryTruncationReason.MAX_FILE_COUNT]
    assert result.summary.is_complete is False


def test_incomplete_route_analysis_and_truncation_are_propagated(
    repository: Path,
) -> None:
    write_text(repository / "app.py", "def handler():\n    return 1\n")
    inventory = discover_repository(repository)
    technologies = manual_technologies(repository)
    attack_surface = manual_attack_surface(
        repository,
        [route_candidate("/items", handler_name="handler")],
        is_complete=False,
        discovery_is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_TOTAL_SIZE],
    )

    result = analyze_handler_calls(
        repository,
        inventory,
        technologies,
        attack_surface,
    )

    assert result.summary.route_analysis_is_complete is False
    assert result.summary.route_analysis_truncation_reasons == [
        DiscoveryTruncationReason.MAX_TOTAL_SIZE
    ]
    assert result.summary.is_complete is False


def test_schema_round_trip(repository: Path) -> None:
    text = source(
        """
        def helper():
            return 1

        def handler():
            return helper()
        """
    )
    write_text(repository / "app.py", text)
    result = analyze(
        repository,
        routes=[route_candidate("/items", handler_name="handler")],
    )

    payload = json.loads(result.model_dump_json())
    assert payload["summary"]["relationship_count"] == 1
    assert payload["relationships"][0]["relationship_type"] == "handler_to_function"
    assert payload["calls"][0]["resolution_status"] == "resolved"
