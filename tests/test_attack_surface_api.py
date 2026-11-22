import hashlib
import logging
import re
import shutil
import textwrap
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import event, func, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import get_current_principal
from app.core.config import settings
from app.db.session import get_db
from app.main import app
from app.models.analysis_run import AnalysisRun
from app.schemas.attack_surface_summary import (
    AttackSurfaceRouteSummary,
    AttackSurfaceSummaryMetrics,
    AttackSurfaceSummaryResponse,
    GlobalAttackSurfaceEvidence,
    SummaryIssue,
    SummarySourceStatus,
)
from app.services import attack_surface_reporting
from app.services.analysis_admission import ANALYSIS_RUN_SCOPE, analysis_admission
from app.services.attack_surface import InvalidAttackSurfaceRootError
from app.services.attack_surface_correlation import InvalidCorrelationRootError
from app.services.attack_surface_summary import InvalidAttackSurfaceSummaryRootError
from app.services.auth_controls import InvalidAuthControlRootError
from app.services.handler_calls import InvalidHandlerCallRootError
from app.services.input_operation_flow import InvalidInputOperationRootError
from app.services.input_sources import InvalidInputSourceRootError
from app.services.sensitive_operations import InvalidSensitiveOperationRootError
from app.services.technology_detector import InvalidTechnologyDetectionRootError

SUMMARY_PATH = "/api/v1/assessments/{assessment_id}/attack-surface/summary"

pytestmark = pytest.mark.usefixtures("assessment_client")

SOURCE = textwrap.dedent(
    """
    import sqlite3

    from fastapi import Depends, FastAPI, Request

    app = FastAPI()

    def get_current_user():
        return {}

    @app.get("/items")
    def read_items(request: Request, user=Depends(get_current_user)):
        q = request.query_params.get("q")
        cursor = sqlite3.connect("app.db").cursor()
        cursor.execute(q)
        return []
    """
).lstrip()


def line_of(needle: str) -> int:
    for index, line in enumerate(SOURCE.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"Line containing {needle!r} was not found")


def summary_url(assessment_id: object) -> str:
    return SUMMARY_PATH.format(assessment_id=assessment_id)


@pytest.fixture
def allowed_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    allowed = tmp_path / "repositories"
    allowed.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [allowed])
    return allowed


@pytest.fixture
def repository(allowed_root: Path) -> Path:
    target = allowed_root / "project"
    target.mkdir()
    (target / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (target / "app.py").write_text(SOURCE, encoding="utf-8")
    return target


@pytest.fixture
def empty_repository(allowed_root: Path) -> Path:
    target = allowed_root / "empty"
    target.mkdir()
    return target


async def create_assessment(
    client: httpx.AsyncClient,
    repository: Path | None = None,
) -> str:
    response = await client.post(
        "/api/v1/assessments",
        json={"assessment_type": "repository"},
    )
    assert response.status_code == 201
    assessment_id = response.json()["id"]

    if repository is not None:
        response = await client.post(
            f"/api/v1/assessments/{assessment_id}/repository",
            json={"source_kind": "local_path", "location": str(repository)},
        )
        assert response.status_code == 201

    return assessment_id


async def get_summary(
    client: httpx.AsyncClient,
    repository: Path,
) -> httpx.Response:
    assessment_id = await create_assessment(client, repository)
    response = await client.get(summary_url(assessment_id))
    assert response.status_code == 200, response.text
    return response


def table_snapshot(engine: Engine) -> dict[str, list[dict[str, object]]]:
    with engine.connect() as connection:
        table_names = inspect(connection).get_table_names()
        return {
            table_name: [
                dict(row._mapping)
                for row in connection.execute(text(f'SELECT * FROM "{table_name}" ORDER BY 1'))
            ]
            for table_name in table_names
        }


def repository_snapshot(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.relative_to(root).as_posix(): (
            path.stat().st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


_WRITE_STATEMENT = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|TRUNCATE|VACUUM|ATTACH|DETACH)\b",
    re.IGNORECASE,
)


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.mark.anyio
async def test_successful_summary_response_structure(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    response = await get_summary(client, repository)
    body = response.json()

    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    assert set(body) == set(AttackSurfaceSummaryResponse.model_fields)
    assert body["repository"] == "project"
    assert "root" not in body
    assert set(body["routes"][0]) == set(AttackSurfaceRouteSummary.model_fields)
    assert set(body["global_evidence"]) == set(GlobalAttackSurfaceEvidence.model_fields)
    assert set(body["summary"]) == set(AttackSurfaceSummaryMetrics.model_fields)
    assert body["issues"]
    assert set(body["issues"][0]) == set(SummaryIssue.model_fields)
    assert body["summary"]["source_statuses"]
    assert set(body["summary"]["source_statuses"][0]) == set(SummarySourceStatus.model_fields)


@pytest.mark.anyio
async def test_nested_evidence_is_preserved(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    body = (await get_summary(client, repository)).json()
    route = body["routes"][0]

    assert route["path"] == "/items"
    assert route["source_file"] == "app.py"
    assert route["line_number"] == line_of('@app.get("/items")')
    assert route["handler_name"] == "read_items"

    authentication = route["authentication_controls"][0]
    assert authentication["control_type"] == "authentication"
    assert authentication["mechanism"] == "Depends"
    assert authentication["symbol_name"] == "get_current_user"
    assert authentication["source_file"] == "app.py"
    assert authentication["line_number"] == line_of("def read_items")
    assert authentication["resolution_status"] == "resolved"
    assert [item["path"] for item in authentication["associated_routes"]] == ["/items"]

    query = next(item for item in route["input_candidates"] if item["input_type"] == "query")
    assert query["parameter_name"] == "q"
    assert query["declaration_or_access"] == "request.query_params.get('q')"
    assert query["source_file"] == "app.py"
    assert query["line_number"] == line_of('request.query_params.get("q")')
    assert query["resolution_status"] == "resolved"
    assert [item["path"] for item in query["associated_routes"]] == ["/items"]

    operation = route["sensitive_operations"][0]
    assert operation["operation_category"] == "database_execute"
    assert operation["operation_name"] == "execute"
    assert operation["source_file"] == "app.py"
    assert operation["line_number"] == line_of("cursor.execute(q)")
    assert operation["resolution_status"] == "resolved"

    handler = route["handlers"][0]
    assert handler["handler_name"] == "read_items"
    assert handler["route_path"] == "/items"
    assert handler["resolution_status"] == "resolved"
    assert handler["definition_ids"]
    assert handler["detection_confidence"] > 0.0

    definition_names = {item["name"] for item in route["handler_definitions"]}
    assert "read_items" in definition_names
    assert all(item["source_file"] == "app.py" for item in route["handler_definitions"])

    assert route["call_sites"]
    assert any(call["callee_expression"] == "cursor.execute" for call in route["call_sites"])
    assert all(call["source_file"] == "app.py" for call in route["call_sites"])

    relationship = route["input_operation_relationships"][0]
    assert relationship["relationship_id"] == "inputs[1]->operations[0]"
    assert relationship["input_id"] == "inputs[1]"
    assert relationship["input_type"] == "query"
    assert relationship["input_source_file"] == "app.py"
    assert relationship["input_line_number"] == line_of('request.query_params.get("q")')
    assert relationship["operation_id"] == "operations[0]"
    assert relationship["operation_category"] == "database_execute"
    assert relationship["operation_source_file"] == "app.py"
    assert relationship["operation_line_number"] == line_of("cursor.execute(q)")
    assert relationship["resolution_status"] == "resolved"
    assert relationship["route_ids"] == [route["route_id"]]
    assert relationship["handler_references"][0]["route_id"] == route["route_id"]
    assert [step["kind"] for step in relationship["propagation_steps"]] == [
        "input_access",
        "variable_assignment",
        "operation_argument",
    ]

    correlation_identifiers = {
        item["evidence_identifier"] for item in route["correlation_relationships"]
    }
    assert "auth_controls[0]" in correlation_identifiers
    assert "input_sources[1]" in correlation_identifiers
    assert "sensitive_operations[0]" in correlation_identifiers
    assert all(
        item["evidence_source_file"] == "app.py" for item in route["correlation_relationships"]
    )


@pytest.mark.anyio
async def test_global_unassociated_evidence_is_retained(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    body = (await get_summary(client, repository)).json()
    global_evidence = body["global_evidence"]

    assert global_evidence["unlinked_handlers"] == []
    assert global_evidence["unassociated_call_sites"] == []
    assert global_evidence["unassociated_call_relationships"] == []
    assert global_evidence["unassociated_input_operation_relationships"] == []

    definitions = global_evidence["unassociated_definitions"]
    assert [item["name"] for item in definitions] == ["get_current_user"]
    assert definitions[0]["source_file"] == "app.py"
    assert definitions[0]["is_route_handler"] is False
    assert definitions[0]["route_ids"] == []


@pytest.mark.anyio
async def test_metrics_and_completeness_metadata(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    body = (await get_summary(client, repository)).json()
    summary = body["summary"]

    assert summary["route_count"] == 1
    assert summary["routes_with_handlers"] == 1
    assert summary["routes_with_resolved_handlers"] == 1
    assert summary["routes_with_authentication"] == 1
    assert summary["routes_with_authorization"] == 0
    assert summary["routes_with_inputs"] == 1
    assert summary["routes_with_sensitive_operations"] == 1
    assert summary["routes_with_input_operation_relationships"] == 1
    assert summary["routes_with_multiple_evidence_categories"] == 1

    assert summary["authentication_control_count"] == 1
    assert summary["input_count"] == 2
    assert summary["sensitive_operation_count"] == 1
    assert summary["input_operation_relationship_count"] == 1
    assert summary["input_operation_resolved_count"] == 1
    assert summary["handler_count"] == 1
    assert summary["handler_resolved_count"] == 1

    assert summary["issue_count"] == len(body["issues"])
    assert summary["handler_call_issue_count"] == summary["issue_count"]
    assert summary["inspection_issue_count"] == 0
    assert summary["correlation_issue_count"] == 0

    assert summary["all_sources_complete"] is True
    assert summary["is_complete"] is True
    assert summary["discovery_is_complete"] is True
    assert summary["route_analysis_is_complete"] is True
    assert summary["discovery_truncation_reasons"] == []
    assert summary["route_analysis_truncation_reasons"] == []

    assert [status["source"] for status in summary["source_statuses"]] == [
        "attack_surface",
        "auth_controls",
        "input_sources",
        "sensitive_operations",
        "attack_surface_correlation",
        "handler_calls",
        "input_operation_flow",
    ]
    assert all(status["is_complete"] for status in summary["source_statuses"])
    assert all(status["discovery_is_complete"] for status in summary["source_statuses"])


@pytest.mark.anyio
async def test_enum_values_are_json_serialized(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    body = (await get_summary(client, repository)).json()
    route = body["routes"][0]

    assert route["http_method"] == "GET"
    assert route["framework"] == "fastapi"
    assert route["resolution_status"] == "resolved"
    assert route["handlers"][0]["resolution_status"] == "resolved"
    assert route["sensitive_operations"][0]["operation_category"] == "database_execute"
    assert route["input_operation_relationships"][0]["resolution_status"] == "resolved"
    assert body["summary"]["source_statuses"][0]["source"] == "attack_surface"

    for value in (
        route["http_method"],
        route["framework"],
        route["resolution_status"],
        route["handlers"][0]["resolution_status"],
        route["input_operation_relationships"][0]["resolution_status"],
    ):
        assert isinstance(value, str)


@pytest.mark.anyio
async def test_optional_fields_serialize_as_null(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    body = (await get_summary(client, repository)).json()
    route = body["routes"][0]

    request_object = next(
        item for item in route["input_candidates"] if item["input_type"] == "request_object"
    )
    assert "parameter_name" in request_object
    assert request_object["parameter_name"] is None
    assert request_object["handler_name"] == "read_items"

    attack_surface_status = body["summary"]["source_statuses"][0]
    assert "route_analysis_is_complete" in attack_surface_status
    assert attack_surface_status["route_analysis_is_complete"] is None

    handler_call_issue = next(issue for issue in body["issues"] if issue["kind"] == "handler_call")
    assert "detail" in handler_call_issue
    assert handler_call_issue["detail"] is None


@pytest.mark.anyio
async def test_missing_assessment_returns_404(client: httpx.AsyncClient) -> None:
    response = await client.get(summary_url(uuid.uuid4()))

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_missing_repository_target_returns_404(
    client: httpx.AsyncClient,
) -> None:
    assessment_id = await create_assessment(client)
    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 404
    assert response.json() == {"detail": "Repository target not found"}


@pytest.mark.anyio
async def test_invalid_assessment_uuid_returns_422(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(summary_url("not-a-uuid"))

    assert response.status_code == 422
    assert "detail" in response.json()


@pytest.mark.anyio
async def test_stale_repository_location_returns_422(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment_id = await create_assessment(client, repository)
    shutil.rmtree(repository)

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 422
    assert response.json() == {"detail": "Registered repository target is no longer valid"}


@pytest.mark.anyio
async def test_repeated_requests_are_deterministic(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment_id = await create_assessment(client, repository)

    first = await client.get(summary_url(assessment_id))
    second = await client.get(summary_url(assessment_id))

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert first.headers["cache-control"] == "no-store"
    assert second.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_request_issues_no_database_writes_or_repository_changes(
    client: httpx.AsyncClient,
    repository: Path,
    db_engine: Engine,
) -> None:
    assessment_id = await create_assessment(client, repository)
    database_before = table_snapshot(db_engine)
    files_before = repository_snapshot(repository)
    statements: list[str] = []

    def record_statement(
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        statements.append(statement)

    event.listen(db_engine, "before_cursor_execute", record_statement)
    try:
        response = await client.get(summary_url(assessment_id))
    finally:
        event.remove(db_engine, "before_cursor_execute", record_statement)

    assert response.status_code == 200
    assert table_snapshot(db_engine) == database_before
    assert repository_snapshot(repository) == files_before
    assert any(statement.lstrip().upper().startswith("SELECT") for statement in statements)
    assert [statement for statement in statements if _WRITE_STATEMENT.match(statement)] == []


@pytest.mark.anyio
async def test_repository_changes_are_reflected_on_next_request(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment_id = await create_assessment(client, repository)

    first = await client.get(summary_url(assessment_id))
    assert first.status_code == 200
    assert [route["path"] for route in first.json()["routes"]] == ["/items"]

    source = (repository / "app.py").read_text(encoding="utf-8")
    (repository / "app.py").write_text(
        source + '\n\n@app.get("/added")\ndef added():\n    return []\n',
        encoding="utf-8",
    )

    second = await client.get(summary_url(assessment_id))
    assert second.status_code == 200
    assert [route["path"] for route in second.json()["routes"]] == ["/items", "/added"]
    assert second.json()["summary"]["route_count"] == 2


@pytest.mark.anyio
async def test_empty_repository_returns_valid_empty_summary(
    client: httpx.AsyncClient,
    empty_repository: Path,
) -> None:
    body = (await get_summary(client, empty_repository)).json()

    assert body["routes"] == []
    assert body["global_evidence"] == {
        "unlinked_handlers": [],
        "unassociated_definitions": [],
        "unassociated_call_sites": [],
        "unassociated_call_relationships": [],
        "unassociated_input_operation_relationships": [],
    }
    assert {issue["category"] for issue in body["issues"]} == {
        "no_input_evidence",
        "no_sensitive_operation_evidence",
    }
    assert body["summary"]["route_count"] == 0
    assert body["summary"]["issue_count"] == len(body["issues"])
    assert body["summary"]["is_complete"] is True
    assert body["summary"]["discovery_truncation_reasons"] == []
    assert len(body["summary"]["source_statuses"]) == 7


@pytest.mark.anyio
async def test_repository_outside_allowed_roots_returns_422(
    client: httpx.AsyncClient,
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await create_assessment(client, repository)
    other_root = tmp_path / "other"
    other_root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [other_root])

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 422
    assert response.json() == {"detail": "Registered repository target is no longer valid"}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_repository_target_replaced_by_file_returns_422(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment_id = await create_assessment(client, repository)
    shutil.rmtree(repository)
    repository.write_text("not a directory", encoding="utf-8")

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 422
    assert response.json() == {"detail": "Registered repository target is no longer valid"}


@pytest.mark.anyio
async def test_truncated_discovery_metadata_is_preserved(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "repository_max_file_count", 1)

    body = (await get_summary(client, repository)).json()
    summary = body["summary"]

    assert summary["discovery_is_complete"] is False
    assert summary["is_complete"] is False
    assert "max_file_count" in summary["discovery_truncation_reasons"]
    assert any(
        "max_file_count" in status["discovery_truncation_reasons"]
        for status in summary["source_statuses"]
    )


@pytest.mark.anyio
async def test_database_connection_is_released_before_analysis(
    client: httpx.AsyncClient,
    repository: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_checkouts: list[int] = []
    original = attack_surface_reporting.detect_technologies

    def spy(*args: object, **kwargs: object) -> object:
        observed_checkouts.append(db_engine.pool.checkedout())
        return original(*args, **kwargs)

    monkeypatch.setattr(attack_surface_reporting, "detect_technologies", spy)

    assessment_id = await create_assessment(client, repository)
    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 200
    assert observed_checkouts == [0]


LATER_STAGE_ROOT_ERRORS = [
    ("detect_technologies", InvalidTechnologyDetectionRootError),
    ("identify_attack_surface", InvalidAttackSurfaceRootError),
    ("identify_auth_controls", InvalidAuthControlRootError),
    ("identify_input_sources", InvalidInputSourceRootError),
    ("identify_sensitive_operations", InvalidSensitiveOperationRootError),
    ("correlate_attack_surface", InvalidCorrelationRootError),
    ("analyze_handler_calls", InvalidHandlerCallRootError),
    ("analyze_input_operation_flow", InvalidInputOperationRootError),
    ("summarize_attack_surface", InvalidAttackSurfaceSummaryRootError),
]


@pytest.mark.anyio
@pytest.mark.parametrize(("stage_name", "error_type"), LATER_STAGE_ROOT_ERRORS)
async def test_later_stage_root_validation_error_returns_422(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage_name: str,
    error_type: type[Exception],
) -> None:
    assessment_id = await create_assessment(client, repository)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise error_type("Repository root is no longer valid")

    monkeypatch.setattr(attack_surface_reporting, stage_name, fail)

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 422
    assert response.json() == {"detail": "Registered repository target is no longer valid"}
    assert response.headers["cache-control"] == "no-store"


def test_openapi_documents_summary_responses() -> None:
    operation = app.openapi()["paths"][SUMMARY_PATH]["get"]
    expected_descriptions = {
        "200": (
            "The recalculated attack-surface summary, or with source=persisted the "
            "summary stored by the newest completed analysis run."
        ),
        "404": (
            "Assessment or registered repository target not found, or "
            "(source=persisted) no completed run has stored a summary."
        ),
        "422": "Invalid assessment identifier or repository location.",
        "504": "The analysis deadline expired while generating the summary.",
        "500": "Unexpected failure while generating the summary.",
    }

    assert set(expected_descriptions) <= set(operation["responses"])
    for status_code, description in expected_descriptions.items():
        assert operation["responses"][status_code]["description"] == description
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/AttackSurfaceSummaryResponse"
    )


@pytest.mark.anyio
async def test_cache_control_is_applied_to_error_responses(
    client: httpx.AsyncClient,
) -> None:
    validation_response = await client.get(summary_url("not-a-uuid"))
    missing_response = await client.get(summary_url(uuid.uuid4()))

    assert validation_response.status_code == 422
    assert missing_response.status_code == 404
    assert validation_response.headers["cache-control"] == "no-store"
    assert missing_response.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_cache_control_is_not_applied_to_unrelated_endpoints(
    client: httpx.AsyncClient,
) -> None:
    health_response = await client.get("/health")
    assessments_response = await client.get("/api/v1/assessments")

    assert health_response.status_code == 200
    assert assessments_response.status_code == 200
    assert health_response.headers.get("cache-control") is None
    assert assessments_response.headers.get("cache-control") is None


@pytest.mark.anyio
async def test_pre_handler_summary_failure_receives_no_store() -> None:
    def fail_before_handler() -> None:
        raise RuntimeError("database unavailable")

    app.dependency_overrides[get_db] = fail_before_handler
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as test_client:
            response = await test_client.get(summary_url(uuid.uuid4()))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_summary_enforces_execution_deadline_with_sanitized_504(
    client: httpx.AsyncClient,
    repository: Path,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_execution_timeout_seconds", 0)
    assessment_id = await create_assessment(client, repository)

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 504
    assert response.json() == {"detail": "Analysis timed out"}
    assert response.headers["cache-control"] == "no-store"
    assert "Traceback" not in response.text
    assert "C:\\" not in response.text

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRun)) == 0


@pytest.mark.anyio
async def test_unrelated_value_error_is_not_mapped_to_422(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = uuid.UUID(await create_assessment(client))

    def fail(_db: object, _assessment_id: uuid.UUID) -> None:
        raise ValueError("repository root is no longer valid")

    monkeypatch.setattr(
        attack_surface_reporting,
        "summarize_assessment_repository",
        fail,
    )

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 500
    assert response.json() == {"detail": "Attack surface summary could not be generated"}
    assert response.headers["cache-control"] == "no-store"
    assert "repository root" not in response.text


@pytest.mark.anyio
async def test_unexpected_analysis_error_is_logged_and_response_is_sanitized(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = uuid.UUID(await create_assessment(client))

    def fail(_db: object, _assessment_id: uuid.UUID) -> None:
        raise RuntimeError("internal path C:\\secret\\repository")

    monkeypatch.setattr(
        attack_surface_reporting,
        "summarize_assessment_repository",
        fail,
    )

    capture = _CaptureHandler()
    logger = logging.getLogger("app.api.attack_surface")
    logger.addHandler(capture)
    try:
        response = await client.get(summary_url(assessment_id))
    finally:
        logger.removeHandler(capture)

    assert response.status_code == 500
    assert response.json() == {"detail": "Attack surface summary could not be generated"}
    assert "secret" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text
    assert response.headers["cache-control"] == "no-store"

    assert len(capture.records) == 1
    assert capture.records[0].name == "app.api.attack_surface"
    assert str(assessment_id) in capture.records[0].getMessage()
    assert capture.records[0].exc_info is not None
    assert capture.records[0].exc_info[0] is RuntimeError


def current_principal_user_id() -> uuid.UUID:
    """Return the user id installed by the assessment_client fixture."""
    return app.dependency_overrides[get_current_principal]().user_id


@pytest.mark.anyio
async def test_summary_global_capacity_saturation_returns_503(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment_id = await create_assessment(client, repository)
    analysis_admission.reset(global_limit=1, per_user_limit=1, queue_wait_seconds=0)
    try:
        with analysis_admission.global_slot():
            response = await client.get(summary_url(assessment_id))
    finally:
        analysis_admission.reset()

    assert response.status_code == 503
    assert response.json() == {"detail": "Analysis capacity is temporarily unavailable"}
    assert response.headers["retry-after"] == "1"
    assert response.headers["cache-control"] == "no-store"
    assert analysis_admission.active_global == 0


@pytest.mark.anyio
async def test_summary_does_not_consume_the_per_user_run_quota(
    client: httpx.AsyncClient,
    repository: Path,
) -> None:
    assessment_id = await create_assessment(client, repository)
    user_id = current_principal_user_id()
    analysis_admission.reset(per_user_limit=1)

    with analysis_admission.run_slot(user_id):
        response = await client.get(summary_url(assessment_id))
        assert analysis_admission.active_for_user(user_id) == 1

    assert response.status_code == 200
    assert analysis_admission.active_for_user(user_id) == 0


@pytest.mark.anyio
async def test_summary_rate_limit_is_independent_from_the_run_scope(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 1)
    assessment_id = await create_assessment(client, repository)
    user_id = current_principal_user_id()

    first = await client.get(summary_url(assessment_id))
    second = await client.get(summary_url(assessment_id))

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == {"detail": "Analysis request rate limit exceeded"}
    assert int(second.headers["retry-after"]) >= 1

    # The run scope has its own counter and is still available.
    analysis_admission.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id)


@pytest.mark.anyio
async def test_summary_releases_global_capacity_after_failure(
    client: httpx.AsyncClient,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await create_assessment(client, repository)

    def fail(_db: object, _assessment_id: uuid.UUID) -> None:
        raise RuntimeError("pipeline failure")

    monkeypatch.setattr(
        attack_surface_reporting,
        "summarize_assessment_repository",
        fail,
    )

    response = await client.get(summary_url(assessment_id))

    assert response.status_code == 500
    assert response.json() == {"detail": "Attack surface summary could not be generated"}
    assert analysis_admission.active_global == 0
