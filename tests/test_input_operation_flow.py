import copy
import textwrap
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import pytest

from app.core.config import settings
from app.schemas.attack_surface import (
    AnalysisIssueReason,
    HttpMethod,
    RouteFramework,
)
from app.schemas.attack_surface_correlation import AttackSurfaceCorrelationResult
from app.schemas.enums import DiscoveryTruncationReason
from app.schemas.handler_calls import HandlerCallResult
from app.schemas.input_operation_flow import (
    FlowIssueCategory,
    FlowPropagationKind,
    FlowResolutionStatus,
    InputOperationFlowResult,
)
from app.schemas.input_sources import (
    InputCandidate,
    InputResolutionStatus,
    InputSourceResult,
    InputSourceSummary,
    InputType,
)
from app.schemas.repository_discovery import (
    DiscoveryLimits,
    DiscoverySummary,
    FileInventoryEntry,
    RepositoryDiscoveryResult,
)
from app.schemas.sensitive_operations import (
    OperationCategory,
    OperationResolutionStatus,
    SensitiveOperationCandidate,
    SensitiveOperationResult,
    SensitiveOperationSummary,
)
from app.services.attack_surface import identify_attack_surface
from app.services.attack_surface_correlation import correlate_attack_surface
from app.services.auth_controls import identify_auth_controls
from app.services.handler_calls import analyze_handler_calls
from app.services.input_operation_flow import (
    InputOperationFlowError,
    InvalidInputOperationRootError,
    analyze_input_operation_flow,
)
from app.services.input_sources import identify_input_sources
from app.services.repository_discovery import discover_repository
from app.services.sensitive_operations import identify_sensitive_operations
from app.services.technology_detector import detect_technologies


@pytest.fixture
def allowed_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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


def write_requirements(repository: Path, *names: str) -> Path:
    return write_text(repository / "requirements.txt", "\n".join(names) + "\n")


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


def input_result(
    root: Path,
    inputs: list[InputCandidate],
    *,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
) -> InputSourceResult:
    return InputSourceResult(
        root=str(root.resolve()),
        inputs=list(inputs),
        issues=[],
        summary=InputSourceSummary(
            source_files_inspected=1,
            input_count=len(inputs),
            named_parameter_count=sum(item.parameter_name is not None for item in inputs),
            route_association_count=sum(len(item.associated_routes) for item in inputs),
            unresolved_association_count=sum(
                item.resolution_status is InputResolutionStatus.UNRESOLVED for item in inputs
            ),
            issue_count=0,
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=[],
        ),
    )


def operation_result(
    root: Path,
    operations: list[SensitiveOperationCandidate],
    *,
    is_complete: bool = True,
    discovery_is_complete: bool = True,
) -> SensitiveOperationResult:
    database_categories = {
        OperationCategory.DATABASE_READ,
        OperationCategory.DATABASE_WRITE,
        OperationCategory.DATABASE_DELETE,
        OperationCategory.DATABASE_EXECUTE,
        OperationCategory.DATABASE_TRANSACTION,
    }
    return SensitiveOperationResult(
        root=str(root.resolve()),
        operations=list(operations),
        issues=[],
        summary=SensitiveOperationSummary(
            source_files_inspected=1,
            operation_count=len(operations),
            database_operation_count=sum(
                item.operation_category in database_categories for item in operations
            ),
            filesystem_operation_count=0,
            process_execution_count=0,
            other_sensitive_operation_count=0,
            route_association_count=sum(len(item.associated_routes) for item in operations),
            unresolved_association_count=sum(
                item.resolution_status is OperationResolutionStatus.UNRESOLVED
                for item in operations
            ),
            issue_count=0,
            is_complete=is_complete,
            discovery_is_complete=discovery_is_complete,
            discovery_truncation_reasons=[],
        ),
    )


@dataclass
class Run:
    result: InputOperationFlowResult
    inventory: RepositoryDiscoveryResult
    correlation: AttackSurfaceCorrelationResult
    inputs: InputSourceResult
    operations: SensitiveOperationResult
    calls: HandlerCallResult


def run_analysis(
    repository: Path,
    *,
    inventory: RepositoryDiscoveryResult | None = None,
    inputs: InputSourceResult | None = None,
    operations: SensitiveOperationResult | None = None,
    **kwargs: object,
) -> Run:
    resolved_inventory = inventory or discover_repository(repository)
    technologies = detect_technologies(repository, resolved_inventory)
    surface = identify_attack_surface(repository, resolved_inventory, technologies)
    controls = identify_auth_controls(repository, resolved_inventory, technologies, surface)
    resolved_inputs = inputs or identify_input_sources(
        repository,
        resolved_inventory,
        technologies,
        surface,
    )
    resolved_operations = operations or identify_sensitive_operations(
        repository,
        resolved_inventory,
        technologies,
        surface,
    )
    calls = analyze_handler_calls(repository, resolved_inventory, technologies, surface)
    correlation = correlate_attack_surface(
        surface,
        controls,
        resolved_inputs,
        resolved_operations,
    )
    result = analyze_input_operation_flow(
        repository,
        resolved_inventory,
        correlation,
        resolved_inputs,
        resolved_operations,
        calls,
        **kwargs,
    )
    return Run(
        result=result,
        inventory=resolved_inventory,
        correlation=correlation,
        inputs=resolved_inputs,
        operations=resolved_operations,
        calls=calls,
    )


def flask_source(body: str) -> str:
    return source(
        f"""
        import sqlite3

        from flask import Flask, request

        app = Flask(__name__)

        {body}
        """
    )


def categories(run: Run) -> set[FlowIssueCategory]:
    return {issue.category for issue in run.result.issues}


def test_input_directly_reaching_sensitive_operation(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/direct")
        def handler():
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(request.args.get("q"))
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert len(run.result.relationships) == 1
    relationship = run.result.relationships[0]
    assert relationship.relationship_id == "inputs[0]->operations[0]"
    assert relationship.resolution_status is FlowResolutionStatus.RESOLVED
    assert relationship.input_id == "inputs[0]"
    assert relationship.operation_id == "operations[0]"
    assert relationship.input_line_number == line_of(text, 'request.args.get("q")')
    assert relationship.operation_line_number == line_of(
        text, 'cursor.execute(request.args.get("q"))'
    )
    assert [step.kind for step in relationship.propagation_steps] == [
        FlowPropagationKind.INPUT_ACCESS,
        FlowPropagationKind.OPERATION_ARGUMENT,
    ]
    assert relationship.route_ids
    assert relationship.route_ids == [run.calls.handlers[0].route_id]
    assert relationship.detection_confidence <= relationship.input_detection_confidence
    assert relationship.detection_confidence <= relationship.operation_detection_confidence
    assert run.result.summary.relationship_count == 1
    assert run.result.summary.resolved_relationship_count == 1


def test_input_assigned_to_local_variable_before_use(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/assigned")
        def handler():
            q = request.args.get("q")
            statement = q
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(statement)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert len(run.result.relationships) == 1
    steps = run.result.relationships[0].propagation_steps
    assignment = next(
        step
        for step in steps
        if step.kind is FlowPropagationKind.VARIABLE_ASSIGNMENT
        and step.variable_name == "statement"
    )
    assert assignment.line_number == line_of(text, "statement = q")


def test_multiple_local_variable_assignments(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/chained")
        def handler():
            q = request.args.get("q")
            first = q
            second = first
            third = second
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(third)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert len(run.result.relationships) == 1
    names = [
        step.variable_name
        for step in run.result.relationships[0].propagation_steps
        if step.kind is FlowPropagationKind.VARIABLE_ASSIGNMENT
    ]
    assert names == ["q", "first", "second", "third"]


def test_input_passed_as_direct_function_argument(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def save(cursor, value):
            cursor.execute(value)

        @app.route("/argument")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            save(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert len(run.result.relationships) == 1
    relationship = run.result.relationships[0]
    kinds = [step.kind for step in relationship.propagation_steps]
    assert FlowPropagationKind.ARGUMENT in kinds
    assert relationship.intermediate_call_ids
    assert any(
        definition_id.endswith(":function:save")
        for definition_id in relationship.intermediate_definition_ids
    )


def test_argument_to_parameter_propagation(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def save(cursor, value):
            cursor.execute(value)

        @app.route("/parameter")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            save(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    relationship = run.result.relationships[0]
    parameter_step = next(
        step
        for step in relationship.propagation_steps
        if step.kind is FlowPropagationKind.INPUT_PARAMETER
    )
    assert parameter_step.variable_name == "value"
    assert parameter_step.definition_name == "save"
    assert parameter_step.line_number == line_of(text, "def save(cursor, value)")


def test_multi_function_propagation_across_resolved_calls(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def leaf(cursor, value):
            cursor.execute(value)

        def middle(cursor, value):
            leaf(cursor, value)

        @app.route("/chain")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            middle(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert len(run.result.relationships) == 1
    relationship = run.result.relationships[0]
    names = {
        step.definition_name
        for step in relationship.propagation_steps
        if step.definition_name is not None
    }
    assert names == {"handler", "middle", "leaf"}
    assert len(relationship.intermediate_call_ids) == 2
    assert relationship.resolution_status is FlowResolutionStatus.RESOLVED


def test_multiple_inputs_reaching_one_sensitive_operation(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/combined")
        def handler():
            first = request.args.get("first")
            second = request.args.get("second")
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(first + second)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.summary.input_count == 2
    assert run.result.summary.operation_count == 1
    assert run.result.summary.relationship_count == 2
    assert {relationship.input_id for relationship in run.result.relationships} == {
        "inputs[0]",
        "inputs[1]",
    }
    assert {relationship.operation_id for relationship in run.result.relationships} == {
        "operations[0]"
    }
    assert run.result.summary.operations_with_relationships == 1


def test_one_input_reaching_multiple_sensitive_operations(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/multiple")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(q)
            cursor.executemany(q, [])
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.summary.input_count == 1
    assert run.result.summary.operation_count == 2
    assert run.result.summary.relationship_count == 2
    assert {relationship.input_id for relationship in run.result.relationships} == {"inputs[0]"}
    assert len({relationship.operation_id for relationship in run.result.relationships}) == 2
    assert run.result.summary.inputs_with_relationships == 1


def test_co_occurrence_without_dataflow(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/cooccurrence")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute("SELECT 1")
            return q
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.summary.input_count == 1
    assert run.result.summary.operation_count == 1
    assert run.result.relationships == []
    assert run.result.summary.relationship_count == 0


def test_independent_input_and_operation_branches(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/branches")
        def handler():
            if request.args.get("flag"):
                value = request.args.get("q")
                print(value)
            else:
                cursor = sqlite3.connect("app.db").cursor()
                cursor.execute("SELECT 1")
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.summary.input_count >= 1
    assert run.result.summary.operation_count == 1
    assert run.result.relationships == []


def test_ambiguous_function_calls_are_preserved(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def save(cursor, value):
            cursor.execute(value)

        def save(cursor, value):
            cursor.execute(value)

        @app.route("/ambiguous")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            save(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.summary.operation_count == 2
    assert run.result.summary.relationship_count == 2
    assert run.result.summary.ambiguous_relationship_count == 2
    for relationship in run.result.relationships:
        assert relationship.resolution_status is FlowResolutionStatus.AMBIGUOUS
        assert len(relationship.ambiguous_definition_ids) == 2
    assert FlowIssueCategory.AMBIGUOUS_CALL_PROPAGATION in categories(run)


def test_unresolved_function_calls_do_not_invent_edges(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/unresolved")
        def handler():
            q = request.args.get("q")
            unknown_function(q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.relationships == []
    assert FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION in categories(run)
    assert any(
        issue.call_id is not None
        for issue in run.result.issues
        if issue.category is FlowIssueCategory.UNRESOLVED_CALL_PROPAGATION
    )


def test_unsupported_dynamic_propagation_is_reported(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def get_callback():
            return print

        @app.route("/dynamic")
        def handler():
            q = request.args.get("q")
            get_callback()(q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.relationships == []
    assert FlowIssueCategory.UNSUPPORTED_PROPAGATION in categories(run)


def test_recursive_calls_and_cycles_are_bounded(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def recurse(cursor, value, depth):
            cursor.execute(value)
            if depth:
                recurse(cursor, value, depth - 1)

        @app.route("/recursive")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            recurse(cursor, q, 2)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    assert run.result.summary.relationship_count == 1
    relationship = run.result.relationships[0]
    assert relationship.resolution_status is FlowResolutionStatus.RESOLVED
    assert FlowIssueCategory.CYCLE_DETECTED in categories(run)


def test_cross_file_propagation_through_resolved_call(repository: Path) -> None:
    write_requirements(repository, "flask")
    write_text(repository / "pkg" / "__init__.py", "")
    write_text(
        repository / "pkg" / "helpers.py",
        source(
            """
            import sqlite3

            def save(cursor, value):
                cursor.execute(value)
            """
        ),
    )
    text = source(
        """
        import sqlite3

        from flask import Flask, request

        from .helpers import save

        app = Flask(__name__)

        @app.route("/cross-file")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            save(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "pkg" / "main.py", text)

    run = run_analysis(repository)

    assert len(run.result.relationships) == 1
    relationship = run.result.relationships[0]
    assert relationship.input_source_file == "pkg/main.py"
    assert relationship.operation_source_file == "pkg/helpers.py"
    assert relationship.resolution_status is FlowResolutionStatus.RESOLVED
    assert any(
        definition_id.endswith(":function:save")
        for definition_id in relationship.intermediate_definition_ids
    )


def test_missing_input_or_operation_evidence(repository: Path) -> None:
    write_text(
        repository / "app.py",
        source(
            """
            def plain():
                return 1
            """
        ),
    )

    run = run_analysis(repository)

    assert run.result.relationships == []
    assert run.result.summary.input_count == 0
    assert run.result.summary.operation_count == 0
    assert FlowIssueCategory.NO_INPUT_EVIDENCE in categories(run)
    assert FlowIssueCategory.NO_SENSITIVE_OPERATION_EVIDENCE in categories(run)
    repository_wide = [
        issue
        for issue in run.result.issues
        if issue.category
        in {
            FlowIssueCategory.NO_INPUT_EVIDENCE,
            FlowIssueCategory.NO_SENSITIVE_OPERATION_EVIDENCE,
        }
    ]
    # Repository-wide issues must use a relative label, never the absolute root.
    assert {issue.source_file for issue in repository_wide} == {"."}
    assert all(run.result.root not in issue.source_file for issue in run.result.issues)


def test_unresolved_source_evidence_is_preserved(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/unresolved-evidence")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    inputs = input_result(
        repository,
        [
            InputCandidate(
                input_type=InputType.QUERY,
                framework=RouteFramework.FLASK,
                source_file="app.py",
                line_number=line_of(text, 'request.args.get("q")'),
                parameter_name="q",
                handler_name="handler",
                declaration_or_access="request.args.get('q')",
                resolution_status=InputResolutionStatus.UNRESOLVED,
                detection_confidence=0.80,
                evidence="Manual unresolved input evidence.",
                classification_rule="Test fixture.",
            )
        ],
    )
    operations = operation_result(
        repository,
        [
            SensitiveOperationCandidate(
                operation_category=OperationCategory.DATABASE_EXECUTE,
                framework_or_library="sqlite3",
                operation_name="execute",
                source_file="app.py",
                line_number=line_of(text, "cursor.execute(q)"),
                enclosing_function="handler",
                receiver_name="cursor",
                declaration_or_access="cursor.execute",
                resolution_status=OperationResolutionStatus.UNRESOLVED,
                detection_confidence=0.85,
                evidence="Manual unresolved operation evidence.",
                classification_rule="Test fixture.",
            )
        ],
    )

    run = run_analysis(repository, inputs=inputs, operations=operations)

    assert len(run.result.relationships) == 1
    relationship = run.result.relationships[0]
    assert relationship.resolution_status is FlowResolutionStatus.RESOLVED
    assert relationship.input_resolution_status is InputResolutionStatus.UNRESOLVED
    assert relationship.operation_resolution_status is OperationResolutionStatus.UNRESOLVED
    assert relationship.detection_confidence <= 0.80
    assert relationship.detection_confidence <= 0.85
    assert FlowIssueCategory.UNRESOLVED_INPUT_EVIDENCE in categories(run)
    assert FlowIssueCategory.UNRESOLVED_OPERATION_EVIDENCE in categories(run)


def test_deterministic_output(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def save(cursor, value):
            cursor.execute(value)

        @app.route("/deterministic")
        def handler():
            first = request.args.get("first")
            second = request.args.get("second")
            cursor = sqlite3.connect("app.db").cursor()
            save(cursor, first)
            save(cursor, second)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    first = run_analysis(repository)
    second = run_analysis(repository)

    assert first.result.model_dump(mode="json") == second.result.model_dump(mode="json")
    ordering = [
        (
            relationship.input_source_file,
            relationship.input_line_number,
            relationship.operation_source_file,
            relationship.operation_line_number,
            relationship.relationship_id,
        )
        for relationship in first.result.relationships
    ]
    assert ordering == sorted(ordering)


def test_repository_root_mismatch_is_rejected(
    allowed_root: Path,
    repository: Path,
) -> None:
    write_requirements(repository, "flask")
    write_text(
        repository / "app.py",
        flask_source(
            """
            @app.route("/root")
            def handler():
                return "ok"
            """
        ),
    )
    run = run_analysis(repository)
    other = allowed_root / "other"
    other.mkdir()

    with pytest.raises(InvalidInputOperationRootError):
        analyze_input_operation_flow(
            other,
            run.inventory,
            run.correlation,
            run.inputs,
            run.operations,
            run.calls,
        )


def test_inputs_are_not_mutated(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def save(cursor, value):
            cursor.execute(value)

        @app.route("/mutation")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            save(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)
    before = {
        "inventory": copy.deepcopy(run.inventory.model_dump(mode="json")),
        "correlation": copy.deepcopy(run.correlation.model_dump(mode="json")),
        "inputs": copy.deepcopy(run.inputs.model_dump(mode="json")),
        "operations": copy.deepcopy(run.operations.model_dump(mode="json")),
        "calls": copy.deepcopy(run.calls.model_dump(mode="json")),
    }

    analyze_input_operation_flow(
        repository,
        run.inventory,
        run.correlation,
        run.inputs,
        run.operations,
        run.calls,
    )

    assert run.inventory.model_dump(mode="json") == before["inventory"]
    assert run.correlation.model_dump(mode="json") == before["correlation"]
    assert run.inputs.model_dump(mode="json") == before["inputs"]
    assert run.operations.model_dump(mode="json") == before["operations"]
    assert run.calls.model_dump(mode="json") == before["calls"]


def test_incomplete_discovery_and_truncation_are_propagated(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.route("/incomplete")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)
    inventory = manual_inventory(
        repository,
        ["app.py", "requirements.txt"],
        is_complete=False,
        truncation_reasons=[DiscoveryTruncationReason.MAX_FILE_COUNT],
    )

    run = run_analysis(repository, inventory=inventory)

    assert run.result.summary.discovery_is_complete is False
    assert run.result.summary.is_complete is False
    assert (
        DiscoveryTruncationReason.MAX_FILE_COUNT in run.result.summary.discovery_truncation_reasons
    )
    assert any(
        status.source.value == "input_sources" and status.is_complete is False
        for status in run.result.summary.source_statuses
    )


def test_resource_limits_are_enforced(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        def leaf(cursor, value):
            cursor.execute(value)

        def middle(cursor, value):
            leaf(cursor, value)

        @app.route("/limits")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            middle(cursor, q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    file_limited = run_analysis(repository, max_source_files=0)
    assert file_limited.result.relationships == []
    assert file_limited.result.summary.is_complete is False
    assert any(
        issue.reason is AnalysisIssueReason.MAX_SOURCE_FILES
        for issue in file_limited.result.source_issues
    )

    relationship_limited = run_analysis(repository, max_relationships=0)
    assert relationship_limited.result.relationships == []
    assert relationship_limited.result.summary.is_complete is False
    assert FlowIssueCategory.RELATIONSHIP_LIMIT in categories(relationship_limited)
    assert {
        issue.source_file
        for issue in relationship_limited.result.issues
        if issue.category is FlowIssueCategory.RELATIONSHIP_LIMIT
    } == {"."}

    depth_limited = run_analysis(repository, max_propagation_depth=1)
    assert depth_limited.result.relationships == []
    assert depth_limited.result.summary.is_complete is False
    assert FlowIssueCategory.PROPAGATION_DEPTH_LIMIT in categories(depth_limited)

    state_limited = run_analysis(repository, max_propagation_states=0)
    assert state_limited.result.relationships == []
    assert state_limited.result.summary.is_complete is False
    assert FlowIssueCategory.PROPAGATION_STATE_LIMIT in categories(state_limited)


def test_negative_limits_are_rejected(repository: Path) -> None:
    write_requirements(repository, "flask")
    write_text(
        repository / "app.py",
        flask_source(
            """
            @app.route("/negative")
            def handler():
                return "ok"
            """
        ),
    )
    run = run_analysis(repository)

    with pytest.raises(InputOperationFlowError):
        analyze_input_operation_flow(
            repository,
            run.inventory,
            run.correlation,
            run.inputs,
            run.operations,
            run.calls,
            max_source_files=-1,
        )


def test_http_method_and_framework_are_preserved(repository: Path) -> None:
    write_requirements(repository, "flask")
    text = flask_source(
        """
        @app.post("/preserved")
        def handler():
            q = request.args.get("q")
            cursor = sqlite3.connect("app.db").cursor()
            cursor.execute(q)
            return "ok"
        """
    )
    write_text(repository / "app.py", text)

    run = run_analysis(repository)

    relationship = run.result.relationships[0]
    assert relationship.handler_references
    reference = relationship.handler_references[0]
    assert reference.http_method is HttpMethod.POST
    assert reference.framework is RouteFramework.FLASK
    assert reference.route_path == "/preserved"
    assert reference.route_id == run.calls.handlers[0].route_id


def test_attack_surface_result_type_is_not_reinterpreted(repository: Path) -> None:
    write_requirements(repository, "flask")
    write_text(
        repository / "app.py",
        flask_source(
            """
            @app.route("/surface")
            def handler():
                return "ok"
            """
        ),
    )
    run = run_analysis(repository)

    assert isinstance(run.result, InputOperationFlowResult)
    assert isinstance(run.correlation, AttackSurfaceCorrelationResult)
