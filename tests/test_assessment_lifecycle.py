import uuid
from datetime import datetime
from typing import Any

import httpx
import pytest
from db_triggers import create_failure_trigger
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.models.assessment import AssessmentJob
from app.models.assessment_status_history import AssessmentStatusHistory
from app.schemas.enums import AssessmentStatus, AssessmentType
from app.services import assessments as assessment_service

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


async def patch_status(
    client: httpx.AsyncClient,
    assessment_id: str,
    status: str,
    reason: str | None = None,
) -> httpx.Response:
    payload: dict[str, Any] = {"status": status}
    if reason is not None:
        payload["reason"] = reason

    return await client.patch(
        f"{ASSESSMENTS_URL}/{assessment_id}/status",
        json=payload,
    )


async def move_through(
    client: httpx.AsyncClient,
    assessment_id: str,
    statuses: tuple[str, ...],
) -> str:
    current_status = "queued"
    for next_status in statuses:
        response = await patch_status(client, assessment_id, next_status)
        assert response.status_code == 200
        current_status = response.json()["status"]
    return current_status


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (("running",), "running"),
        (("running", "completed"), "completed"),
        (("running", "failed"), "failed"),
    ],
)
async def test_permitted_status_transitions(
    client: httpx.AsyncClient,
    statuses: tuple[str, ...],
    expected: str,
) -> None:
    created = await create_assessment(client)

    final_status = await move_through(client, created["id"], statuses)

    assert final_status == expected
    retrieved = await client.get(f"{ASSESSMENTS_URL}/{created['id']}")
    assert retrieved.json()["status"] == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("initial_statuses", "requested"),
    [
        ((), "queued"),
        ((), "completed"),
        ((), "failed"),
        (("running",), "queued"),
        (("running",), "running"),
        (("running", "completed"), "queued"),
        (("running", "completed"), "running"),
        (("running", "completed"), "completed"),
        (("running", "completed"), "failed"),
        (("running", "failed"), "queued"),
        (("running", "failed"), "running"),
        (("running", "failed"), "completed"),
        (("running", "failed"), "failed"),
    ],
)
async def test_rejected_status_transitions(
    client: httpx.AsyncClient,
    initial_statuses: tuple[str, ...],
    requested: str,
) -> None:
    created = await create_assessment(client)
    current_status = await move_through(client, created["id"], initial_statuses)

    response = await patch_status(
        client,
        created["id"],
        requested,
        reason="This transition must not be recorded.",
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": f"Invalid status transition from '{current_status}' to '{requested}'"
    }

    retrieved = await client.get(f"{ASSESSMENTS_URL}/{created['id']}")
    assert retrieved.json()["status"] == current_status

    history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")
    assert len(history.json()) == len(initial_statuses)


@pytest.mark.anyio
async def test_unknown_assessment_status_update_returns_404(
    client: httpx.AsyncClient,
) -> None:
    response = await patch_status(client, str(uuid.uuid4()), "running")

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_unknown_assessment_history_returns_404(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(f"{ASSESSMENTS_URL}/{uuid.uuid4()}/history")

    assert response.status_code == 404
    assert response.json() == {"detail": "Assessment not found"}


@pytest.mark.anyio
async def test_history_records_successful_transitions(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    created = await create_assessment(client, "web_security")
    empty_history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")
    assert empty_history.status_code == 200
    assert empty_history.json() == []

    first = await patch_status(
        client,
        created["id"],
        "running",
        reason="Worker claimed the job.",
    )
    second = await patch_status(
        client,
        created["id"],
        "failed",
        reason="Runtime probe failed.",
    )

    assert first.status_code == 200
    assert second.status_code == 200

    response = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")

    assert response.status_code == 200
    entries = response.json()
    assert [(entry["previous_status"], entry["new_status"]) for entry in entries] == [
        ("queued", "running"),
        ("running", "failed"),
    ]
    assert [entry["reason"] for entry in entries] == [
        "Worker claimed the job.",
        "Runtime probe failed.",
    ]
    assert all(entry["assessment_id"] == created["id"] for entry in entries)
    assert len({entry["id"] for entry in entries}) == 2

    changed_at = [datetime.fromisoformat(entry["changed_at"]) for entry in entries]
    assert all(value.tzinfo is not None for value in changed_at)
    assert changed_at == sorted(changed_at)
    assert entries[0]["changed_at"] == first.json()["updated_at"]
    assert entries[1]["changed_at"] == second.json()["updated_at"]

    retrieved = await client.get(f"{ASSESSMENTS_URL}/{created['id']}")
    assert retrieved.status_code == 200
    assert retrieved.json()["status"] == "failed"
    assert retrieved.json()["updated_at"] == second.json()["updated_at"]

    with session_factory() as session:
        stored = session.get(AssessmentJob, uuid.UUID(created["id"]))
        assert stored is not None
        assert stored.status is AssessmentStatus.FAILED
        assert stored.updated_at == datetime.fromisoformat(second.json()["updated_at"])

        history_count = session.scalar(select(func.count()).select_from(AssessmentStatusHistory))
        assert history_count == 2

        records = list(
            session.scalars(
                select(AssessmentStatusHistory).order_by(
                    AssessmentStatusHistory.changed_at.asc(),
                    AssessmentStatusHistory.id.asc(),
                )
            ).all()
        )
        assert [(record.previous_status, record.new_status) for record in records] == [
            (AssessmentStatus.QUEUED, AssessmentStatus.RUNNING),
            (AssessmentStatus.RUNNING, AssessmentStatus.FAILED),
        ]


@pytest.mark.anyio
async def test_rejected_transition_does_not_write_history(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
) -> None:
    created = await create_assessment(client)

    rejected = await patch_status(client, created["id"], "completed")
    assert rejected.status_code == 422

    history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")
    assert history.json() == []

    accepted = await patch_status(client, created["id"], "running")
    assert accepted.status_code == 200

    rejected_from_running = await patch_status(client, created["id"], "queued")
    assert rejected_from_running.status_code == 422

    history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")
    assert len(history.json()) == 1

    with session_factory() as session:
        history_count = session.scalar(select(func.count()).select_from(AssessmentStatusHistory))
    assert history_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"status": "paused"},
        {"status": "running", "reason": ""},
        {"status": "running", "reason": "x" * 501},
        {"status": "running", "updated_at": "2026-01-01T00:00:00Z"},
        {"status": "running", "created_at": "2026-01-01T00:00:00Z"},
        {"status": "running", "assessment_type": "repository"},
    ],
)
async def test_status_update_request_validation(
    client: httpx.AsyncClient,
    payload: dict[str, Any],
) -> None:
    created = await create_assessment(client)

    response = await client.patch(
        f"{ASSESSMENTS_URL}/{created['id']}/status",
        json=payload,
    )

    assert response.status_code == 422

    retrieved = await client.get(f"{ASSESSMENTS_URL}/{created['id']}")
    assert retrieved.json()["status"] == "queued"

    history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")
    assert history.json() == []


@pytest.mark.anyio
async def test_reason_maximum_length_is_accepted(client: httpx.AsyncClient) -> None:
    created = await create_assessment(client)
    reason = "x" * 500

    response = await patch_status(client, created["id"], "running", reason=reason)
    assert response.status_code == 200

    history = await client.get(f"{ASSESSMENTS_URL}/{created['id']}/history")
    assert history.json()[0]["reason"] == reason


def test_history_write_failure_rolls_back_status_change(
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        assessment = assessment_service.create_assessment(
            session,
            AssessmentType.REPOSITORY,
        )
        assessment_id = assessment.id

    with db_engine.begin() as connection:
        create_failure_trigger(
            connection,
            "fail_assessment_history_insert",
            table="assessment_status_history",
            event="INSERT",
            message="forced history failure",
        )

    with session_factory() as session:
        assessment = session.get(AssessmentJob, assessment_id)
        assert assessment is not None
        with pytest.raises(DBAPIError, match="forced history failure"):
            assessment_service.apply_status_change(
                session,
                assessment,
                AssessmentStatus.RUNNING,
            )

    with session_factory() as session:
        stored = session.get(AssessmentJob, assessment_id)
        history_count = session.scalar(select(func.count()).select_from(AssessmentStatusHistory))

        assert stored is not None
        assert stored.status is AssessmentStatus.QUEUED
        assert stored.updated_at == stored.created_at
        assert history_count == 0
