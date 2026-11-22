import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, inspect, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.constants import REPOSITORY_LOCATION_INVALID_DETAIL
from app.core.config import settings
from app.db.session import create_db_engine
from app.models.assessment import AssessmentJob
from app.models.repository_target import RepositoryTarget
from app.schemas.enums import RepositorySourceKind

ASSESSMENTS_URL = "/api/v1/assessments"
PROJECT_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.usefixtures("assessment_client")


@pytest.fixture
def repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    return root


async def create_assessment(
    client: httpx.AsyncClient,
    assessment_type: str = "repository",
) -> dict[str, Any]:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": assessment_type},
    )
    assert response.status_code == 201
    return response.json()


async def register_target(
    client: httpx.AsyncClient,
    assessment_id: str | uuid.UUID,
    location: str | Path,
    source_kind: str = "local_path",
) -> httpx.Response:
    return await client.post(
        f"{ASSESSMENTS_URL}/{assessment_id}/repository",
        json={"source_kind": source_kind, "location": str(location)},
    )


@pytest.mark.anyio
async def test_register_and_retrieve_repository_target(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    repository = repository_root / "project"
    repository.mkdir()

    response = await register_target(client, assessment["id"], repository)

    assert response.status_code == 201
    body = response.json()
    assert body["assessment_id"] == assessment["id"]
    assert body["source_kind"] == "local_path"
    assert body["location"] == "project"
    created_at = datetime.fromisoformat(body["created_at"])
    updated_at = datetime.fromisoformat(body["updated_at"])
    assert created_at.tzinfo is not None
    assert updated_at.tzinfo is not None
    assert updated_at >= created_at

    fetched = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/repository")
    assert fetched.status_code == 200
    assert fetched.json() == body

    with session_factory() as session:
        stored = session.scalar(
            select(RepositoryTarget).where(
                RepositoryTarget.assessment_id == uuid.UUID(assessment["id"])
            )
        )
        assert stored is not None
        assert stored.source_kind is RepositorySourceKind.LOCAL_PATH
        assert stored.location == str(repository.resolve())
        assert stored.created_at == created_at
        assert stored.updated_at == updated_at


@pytest.mark.anyio
async def test_repository_targets_are_isolated_between_assessments(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    first = await create_assessment(client)
    second = await create_assessment(client)
    first_repository = repository_root / "first"
    second_repository = repository_root / "second"
    first_repository.mkdir()
    second_repository.mkdir()

    first_response = await register_target(client, first["id"], first_repository)
    second_response = await register_target(client, second["id"], second_repository)

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    first_body = first_response.json()
    second_body = second_response.json()

    assert first_body["assessment_id"] == first["id"]
    assert second_body["assessment_id"] == second["id"]
    assert first_body["location"] == "first"
    assert second_body["location"] == "second"
    assert first_body["id"] != second_body["id"]

    first_fetch = await client.get(f"{ASSESSMENTS_URL}/{first['id']}/repository")
    second_fetch = await client.get(f"{ASSESSMENTS_URL}/{second['id']}/repository")
    assert first_fetch.status_code == 200
    assert second_fetch.status_code == 200
    assert first_fetch.json() == first_body
    assert second_fetch.json() == second_body


@pytest.mark.anyio
async def test_repository_response_never_discloses_absolute_path(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    repository = repository_root / "project"
    repository.mkdir()

    response = await register_target(client, assessment["id"], repository)

    assert response.status_code == 201
    assert response.json()["location"] == "project"
    assert str(repository.resolve()) not in response.text
    assert str(repository_root.resolve()) not in response.text


@pytest.mark.anyio
async def test_repository_registration_error_does_not_echo_absolute_path(
    client: httpx.AsyncClient,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    outside = tmp_path / "outside"
    outside.mkdir()

    response = await register_target(client, assessment["id"], outside)

    assert response.status_code == 422
    assert response.json() == {"detail": REPOSITORY_LOCATION_INVALID_DETAIL}
    assert str(outside.resolve()) not in response.text
    assert str(repository_root.resolve()) not in response.text


@pytest.mark.anyio
async def test_register_target_for_unknown_assessment_returns_404(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    repository = repository_root / "project"
    repository.mkdir()

    response = await register_target(client, uuid.uuid4(), repository)

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_register_target_for_non_repository_assessment_returns_409(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client, "web_security")
    repository = repository_root / "project"
    repository.mkdir()

    response = await register_target(client, assessment["id"], repository)

    assert response.status_code == 409
    assert response.json() == {"detail": "Assessment is not a repository assessment"}


@pytest.mark.anyio
async def test_duplicate_repository_target_returns_409(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    repository = repository_root / "project"
    repository.mkdir()

    first = await register_target(client, assessment["id"], repository)
    second = await register_target(client, assessment["id"], repository)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json() == {"detail": "Repository target is already registered"}

    with session_factory() as session:
        count = session.scalar(select(func.count()).select_from(RepositoryTarget))
    assert count == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "statuses",
    [
        ("running",),
        ("running", "completed"),
        ("running", "failed"),
    ],
)
async def test_register_target_for_non_queued_assessment_returns_409(
    client: httpx.AsyncClient,
    repository_root: Path,
    statuses: tuple[str, ...],
) -> None:
    assessment = await create_assessment(client)
    for next_status in statuses:
        response = await client.patch(
            f"{ASSESSMENTS_URL}/{assessment['id']}/status",
            json={"status": next_status},
        )
        assert response.status_code == 200

    repository = repository_root / "project"
    repository.mkdir()

    response = await register_target(client, assessment["id"], repository)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Assessment must be queued to register a repository target"
    }


@pytest.mark.anyio
async def test_register_nonexistent_directory_returns_422(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    missing = repository_root / "missing"

    response = await register_target(client, assessment["id"], missing)

    assert response.status_code == 422
    assert response.json() == {"detail": REPOSITORY_LOCATION_INVALID_DETAIL}


@pytest.mark.anyio
async def test_register_file_instead_of_directory_returns_422(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    file_path = repository_root / "file.txt"
    file_path.write_text("not a repository", encoding="utf-8")

    response = await register_target(client, assessment["id"], file_path)

    assert response.status_code == 422
    assert response.json() == {"detail": REPOSITORY_LOCATION_INVALID_DETAIL}


@pytest.mark.anyio
async def test_register_path_outside_allowed_roots_returns_422(
    client: httpx.AsyncClient,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    outside = tmp_path / "outside"
    outside.mkdir()

    response = await register_target(client, assessment["id"], outside)

    assert response.status_code == 422
    assert response.json() == {"detail": REPOSITORY_LOCATION_INVALID_DETAIL}


@pytest.mark.anyio
async def test_register_path_traversal_returns_422(
    client: httpx.AsyncClient,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    outside = tmp_path / "outside"
    outside.mkdir()
    traversal = repository_root / ".." / "outside"

    response = await register_target(client, assessment["id"], traversal)

    assert response.status_code == 422
    assert response.json() == {"detail": REPOSITORY_LOCATION_INVALID_DETAIL}


@pytest.mark.anyio
async def test_register_symlink_escape_returns_422(
    client: httpx.AsyncClient,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = repository_root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    response = await register_target(client, assessment["id"], link)

    assert response.status_code == 422
    assert response.json() == {"detail": REPOSITORY_LOCATION_INVALID_DETAIL}


@pytest.mark.anyio
async def test_get_missing_repository_target_returns_404(
    client: httpx.AsyncClient,
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)

    response = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/repository")

    assert response.status_code == 404
    assert response.json() == {"detail": "Repository target not found"}


@pytest.mark.anyio
async def test_get_repository_target_for_unknown_assessment_returns_404(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"{ASSESSMENTS_URL}/{uuid.uuid4()}/repository")

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"source_kind": "local_path"},
        {"source_kind": "git_url", "location": "somewhere"},
        {"source_kind": "local_path", "location": ""},
        {"source_kind": "local_path", "location": "x" * 4097},
        {"source_kind": "local_path", "location": "somewhere", "extra": True},
        {"source_kind": "local_path", "location": 123},
    ],
)
async def test_repository_target_request_validation(
    client: httpx.AsyncClient,
    repository_root: Path,
    payload: dict[str, Any],
) -> None:
    assessment = await create_assessment(client)

    response = await client.post(
        f"{ASSESSMENTS_URL}/{assessment['id']}/repository",
        json=payload,
    )

    assert response.status_code == 422

    target = await client.get(f"{ASSESSMENTS_URL}/{assessment['id']}/repository")
    assert target.status_code == 404


@pytest.mark.anyio
async def test_deleting_assessment_cascades_to_repository_target(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    repository_root: Path,
) -> None:
    assessment = await create_assessment(client)
    repository = repository_root / "project"
    repository.mkdir()
    response = await register_target(client, assessment["id"], repository)
    assert response.status_code == 201

    assessment_id = uuid.UUID(assessment["id"])
    with session_factory() as session:
        session.execute(delete(AssessmentJob).where(AssessmentJob.id == assessment_id))
        session.commit()

        remaining = session.scalar(select(func.count()).select_from(RepositoryTarget))
    assert remaining == 0


def test_repository_targets_migration_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "repository_targets" in inspector.get_table_names()
        columns = {column["name"] for column in inspector.get_columns("repository_targets")}
        assert columns == {
            "id",
            "assessment_id",
            "source_kind",
            "location",
            "created_at",
            "updated_at",
        }
        unique_constraints = inspector.get_unique_constraints("repository_targets")
        assert any(
            constraint["column_names"] == ["assessment_id"] for constraint in unique_constraints
        )
        foreign_keys = inspector.get_foreign_keys("repository_targets")
        assert any(
            foreign_key["referred_table"] == "assessment_jobs"
            and foreign_key["constrained_columns"] == ["assessment_id"]
            and foreign_key["options"].get("ondelete") == "CASCADE"
            for foreign_key in foreign_keys
        )
        check_constraints = inspector.get_check_constraints("repository_targets")
        assert any("source_kind" in constraint["sqltext"] for constraint in check_constraints)
    finally:
        engine.dispose()

    command.downgrade(config, "0002")

    engine = create_db_engine(database_url)
    try:
        assert "repository_targets" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert "repository_targets" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


@pytest.mark.anyio
async def test_rejected_locations_are_indistinguishable(
    client: httpx.AsyncClient,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    """Responses must not reveal whether a server path exists or what it is."""
    outside_directory = tmp_path / "outside-directory"
    outside_directory.mkdir()
    outside_file = tmp_path / "outside-file.txt"
    outside_file.write_text("x", encoding="utf-8")
    inside_file = repository_root / "inside-file.txt"
    inside_file.write_text("x", encoding="utf-8")
    candidates = [
        tmp_path / "does-not-exist",
        outside_directory,
        outside_file,
        repository_root / "missing",
        inside_file,
    ]

    responses = []
    for location in candidates:
        assessment = await create_assessment(client)
        responses.append(await register_target(client, assessment["id"], location))

    assert {response.status_code for response in responses} == {422}
    assert {response.text for response in responses} == {
        f'{{"detail":"{REPOSITORY_LOCATION_INVALID_DETAIL}"}}'
    }
