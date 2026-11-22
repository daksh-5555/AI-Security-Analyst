import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.assessment import AssessmentJob
from app.schemas.enums import AssessmentStatus, AssessmentType

ASSESSMENTS_URL = "/api/v1/assessments"

pytestmark = pytest.mark.usefixtures("assessment_client")


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


@pytest.mark.anyio
async def test_create_assessment_persists_queued_job(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": "repository"},
    )

    assert response.status_code == 201
    body = response.json()
    assessment_id = uuid.UUID(body["id"])
    created_at = datetime.fromisoformat(body["created_at"])
    updated_at = datetime.fromisoformat(body["updated_at"])

    assert body["assessment_type"] == "repository"
    assert body["status"] == "queued"
    assert created_at.tzinfo is not None
    assert updated_at.tzinfo is not None
    assert updated_at >= created_at

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)

        assert stored is not None
        assert stored.assessment_type is AssessmentType.REPOSITORY
        assert stored.status is AssessmentStatus.QUEUED
        assert stored.created_at == created_at
        assert stored.updated_at == updated_at


@pytest.mark.anyio
async def test_get_assessment_by_id(client: httpx.AsyncClient) -> None:
    created = await create_assessment(client, "web_security")

    response = await client.get(f"{ASSESSMENTS_URL}/{created['id']}")

    assert response.status_code == 200
    assert response.json() == created


@pytest.mark.anyio
async def test_get_unknown_assessment_returns_404(client: httpx.AsyncClient) -> None:
    response = await client.get(f"{ASSESSMENTS_URL}/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_invalid_assessment_type_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        ASSESSMENTS_URL,
        json={"assessment_type": "network"},
    )

    assert response.status_code == 422
    assert (await client.get(ASSESSMENTS_URL)).json() == []


@pytest.mark.anyio
async def test_target_url_is_not_accepted(client: httpx.AsyncClient) -> None:
    response = await client.post(
        ASSESSMENTS_URL,
        json={
            "assessment_type": "web_security",
            "target_url": "https://example.com",
        },
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_list_assessments_is_newest_first_and_paginates(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    created = [
        await create_assessment(client, assessment_type)
        for assessment_type in ("repository", "web_security", "performance")
    ]

    with session_factory() as session:
        for index, item in enumerate(created):
            stored = session.get(AssessmentJob, uuid.UUID(item["id"]))
            assert stored is not None

            timestamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=index)
            stored.created_at = timestamp
            stored.updated_at = timestamp

        session.commit()

    first_page = await client.get(ASSESSMENTS_URL, params={"limit": 2, "offset": 0})
    second_page = await client.get(ASSESSMENTS_URL, params={"limit": 2, "offset": 2})

    assert first_page.status_code == 200
    assert second_page.status_code == 200

    first_ids = [item["id"] for item in first_page.json()]
    second_ids = [item["id"] for item in second_page.json()]
    expected_ids = [item["id"] for item in reversed(created)]

    assert first_ids + second_ids == expected_ids
    assert len(first_ids) == 2
    assert len(second_ids) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
    ],
)
async def test_list_assessments_rejects_out_of_bounds_pagination(
    client: httpx.AsyncClient,
    params: dict[str, int],
) -> None:
    response = await client.get(ASSESSMENTS_URL, params=params)

    assert response.status_code == 422


@pytest.mark.anyio
async def test_each_test_uses_an_isolated_database(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        count = session.scalar(select(func.count()).select_from(AssessmentJob))

    assert count == 0
    assert (await client.get(ASSESSMENTS_URL)).json() == []
