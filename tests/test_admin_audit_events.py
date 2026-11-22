"""Admin audit-event query API regression tests."""

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from auth_helpers import remove_role
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import decode_access_token
from app.models.assessment import AssessmentJob
from app.models.audit_event import AuditEvent
from app.models.user_session import UserSession
from app.schemas.enums import (
    AssessmentStatus,
    AssessmentType,
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    RoleName,
)
from app.services.audit import record_audit_event
from app.services.audit_queries import DEFAULT_LIMIT, MAX_LIMIT, list_audit_events

AUDIT_URL = "/api/v1/admin/audit-events"
FORBIDDEN = {"detail": "Administrator access required"}
AUTH_FAILURE = {"detail": "Invalid or expired access token"}
APPROVED_FIELDS = {
    "id",
    "actor_user_id",
    "assessment_id",
    "resource_type",
    "resource_id",
    "action",
    "outcome",
    "occurred_at",
}

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
T1 = datetime(2026, 1, 1, 11, 0, tzinfo=UTC)
T2 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def add_event(
    session_factory: sessionmaker[Session],
    *,
    action: AuditAction = AuditAction.ASSESSMENT_CREATED,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    actor_user_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    occurred_at: datetime = T0,
    resource_type: AuditResourceType = AuditResourceType.ASSESSMENT,
    resource_id: uuid.UUID | None = None,
) -> uuid.UUID:
    with session_factory() as session:
        event = record_audit_event(
            session,
            action=action,
            outcome=outcome,
            resource_type=resource_type,
            resource_id=resource_id,
            assessment_id=assessment_id,
            actor_user_id=actor_user_id,
            occurred_at=occurred_at,
            context={"secret": "must-not-leak"},
        )
        session.commit()
        return event.id


def add_events(
    session_factory: sessionmaker[Session],
    count: int,
    *,
    occurred_at: datetime = T0,
) -> list[uuid.UUID]:
    with session_factory() as session:
        events = [
            record_audit_event(
                session,
                action=AuditAction.ASSESSMENT_CREATED,
                outcome=AuditOutcome.SUCCESS,
                resource_type=AuditResourceType.ASSESSMENT,
                occurred_at=occurred_at,
                context={"secret": "must-not-leak"},
            )
            for _ in range(count)
        ]
        session.commit()
        return [event.id for event in events]


def create_assessment_row(session_factory: sessionmaker[Session]) -> uuid.UUID:
    now = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    with session_factory() as session:
        assessment = AssessmentJob(
            assessment_type=AssessmentType.REPOSITORY,
            status=AssessmentStatus.QUEUED,
            created_at=now,
            updated_at=now,
        )
        session.add(assessment)
        session.commit()
        return assessment.id


@pytest.mark.anyio
async def test_unauthenticated_request_is_rejected(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get(AUDIT_URL)

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.anyio
async def test_invalid_access_token_is_rejected(
    client: httpx.AsyncClient,
    configure_jwt: None,
) -> None:
    response = await client.get(
        AUDIT_URL,
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE


@pytest.mark.anyio
async def test_revoked_session_is_rejected(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    token = headers["Authorization"].removeprefix("Bearer ")
    session_id = decode_access_token(token).sid

    with session_factory() as session:
        user_session = session.get(UserSession, session_id)
        assert user_session is not None
        user_session.revoked_at = datetime.now(UTC)
        session.commit()

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE


@pytest.mark.anyio
async def test_viewer_is_forbidden(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.VIEWER)

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.anyio
async def test_security_analyst_is_forbidden(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.SECURITY_ANALYST)

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 403
    assert response.json() == FORBIDDEN


@pytest.mark.anyio
async def test_admin_receives_approved_fields_and_deterministic_order(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    admin_id, headers = make_assessment_principal(role=RoleName.ADMIN)
    first_id = add_event(session_factory, actor_user_id=admin_id, occurred_at=T0)
    second_id = add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_LIFECYCLE_CHANGED,
        actor_user_id=admin_id,
        occurred_at=T1,
    )

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert [item["id"] for item in body["items"]] == [str(second_id), str(first_id)]

    item = body["items"][0]
    assert set(item) == APPROVED_FIELDS
    assert item["actor_user_id"] == str(admin_id)
    assert item["action"] == "assessment.lifecycle_changed"
    assert "context" not in item
    assert "must-not-leak" not in response.text


@pytest.mark.anyio
async def test_filter_by_action(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_event(session_factory, action=AuditAction.ASSESSMENT_CREATED, occurred_at=T0)
    add_event(session_factory, action=AuditAction.ASSESSMENT_CREATED, occurred_at=T1)
    add_event(session_factory, action=AuditAction.ANALYSIS_RUN_STARTED, occurred_at=T2)

    response = await client.get(
        AUDIT_URL,
        params={"action": AuditAction.ASSESSMENT_CREATED.value},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {item["action"] for item in body["items"]} == {"assessment.created"}


@pytest.mark.anyio
async def test_filter_by_outcome(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_event(session_factory, outcome=AuditOutcome.SUCCESS, occurred_at=T0)
    add_event(session_factory, outcome=AuditOutcome.DENIED, occurred_at=T1)

    response = await client.get(
        AUDIT_URL,
        params={"outcome": AuditOutcome.DENIED.value},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["outcome"] == "denied"


@pytest.mark.anyio
async def test_filter_by_actor(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    first_actor, headers = make_assessment_principal(role=RoleName.ADMIN)
    second_actor, _ = make_assessment_principal(role=RoleName.VIEWER)
    add_event(session_factory, actor_user_id=first_actor, occurred_at=T0)
    add_event(session_factory, actor_user_id=second_actor, occurred_at=T1)

    response = await client.get(
        AUDIT_URL,
        params={"actor_user_id": str(first_actor)},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["actor_user_id"] == str(first_actor)


@pytest.mark.anyio
async def test_filter_by_assessment(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    assessment_id = create_assessment_row(session_factory)
    add_event(session_factory, assessment_id=assessment_id, occurred_at=T0)
    add_event(session_factory, occurred_at=T1)

    response = await client.get(
        AUDIT_URL,
        params={"assessment_id": str(assessment_id)},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["assessment_id"] == str(assessment_id)


@pytest.mark.anyio
async def test_filter_by_time_bounds_are_inclusive_and_exclusive(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_event(session_factory, occurred_at=T0)
    add_event(session_factory, occurred_at=T1)
    add_event(session_factory, occurred_at=T2)

    from_response = await client.get(
        AUDIT_URL,
        params={"from_time": T1.isoformat()},
        headers=headers,
    )
    to_response = await client.get(
        AUDIT_URL,
        params={"to_time": T1.isoformat()},
        headers=headers,
    )

    assert from_response.status_code == 200
    assert from_response.json()["total"] == 2
    assert to_response.status_code == 200
    assert to_response.json()["total"] == 1


@pytest.mark.anyio
async def test_combined_filters_and_total_after_filtering(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    first_actor, headers = make_assessment_principal(role=RoleName.ADMIN)
    second_actor, _ = make_assessment_principal(role=RoleName.VIEWER)
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_CREATED,
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=first_actor,
        occurred_at=T0,
    )
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_CREATED,
        outcome=AuditOutcome.DENIED,
        actor_user_id=first_actor,
        occurred_at=T1,
    )
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_CREATED,
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=second_actor,
        occurred_at=T2,
    )
    add_event(
        session_factory,
        action=AuditAction.ANALYSIS_RUN_STARTED,
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=first_actor,
        occurred_at=T2,
    )

    response = await client.get(
        AUDIT_URL,
        params={
            "action": AuditAction.ASSESSMENT_CREATED.value,
            "outcome": AuditOutcome.SUCCESS.value,
            "actor_user_id": str(first_actor),
            "from_time": T0.isoformat(),
            "to_time": T2.isoformat(),
        },
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1


@pytest.mark.anyio
async def test_empty_result_set(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_event(session_factory, occurred_at=T0)

    response = await client.get(
        AUDIT_URL,
        params={"actor_user_id": str(uuid.uuid4())},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


@pytest.mark.anyio
async def test_invalid_time_range_is_rejected(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)

    equal = await client.get(
        AUDIT_URL,
        params={"from_time": T1.isoformat(), "to_time": T1.isoformat()},
        headers=headers,
    )
    reversed_range = await client.get(
        AUDIT_URL,
        params={"from_time": T2.isoformat(), "to_time": T1.isoformat()},
        headers=headers,
    )

    assert equal.status_code == 422
    assert equal.json() == {"detail": "from_time must be earlier than to_time"}
    assert reversed_range.status_code == 422
    assert reversed_range.json() == {"detail": "from_time must be earlier than to_time"}


@pytest.mark.anyio
async def test_invalid_filter_values_are_rejected(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)

    bad_action = await client.get(AUDIT_URL, params={"action": "not.an.action"}, headers=headers)
    bad_uuid = await client.get(AUDIT_URL, params={"actor_user_id": "not-a-uuid"}, headers=headers)
    bad_resource = await client.get(
        AUDIT_URL,
        params={"resource_id": "not-a-uuid"},
        headers=headers,
    )
    bad_time = await client.get(AUDIT_URL, params={"from_time": "not-a-time"}, headers=headers)

    assert bad_action.status_code == 422
    assert bad_uuid.status_code == 422
    assert bad_resource.status_code == 422
    assert bad_time.status_code == 422


@pytest.mark.anyio
async def test_default_pagination_is_bounded(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_events(session_factory, 55)

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 55
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert len(body["items"]) == 50


@pytest.mark.anyio
async def test_pagination_limit_is_enforced(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_event(session_factory)

    too_large = await client.get(AUDIT_URL, params={"limit": 101}, headers=headers)
    zero = await client.get(AUDIT_URL, params={"limit": 0}, headers=headers)
    maximum = await client.get(AUDIT_URL, params={"limit": 100}, headers=headers)

    assert too_large.status_code == 422
    assert zero.status_code == 422
    assert maximum.status_code == 200
    assert maximum.json()["limit"] == 100


@pytest.mark.anyio
async def test_offset_selects_the_next_page(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    oldest = add_event(session_factory, occurred_at=T0)
    middle = add_event(session_factory, occurred_at=T1)
    newest = add_event(session_factory, occurred_at=T2)

    response = await client.get(
        AUDIT_URL,
        params={"limit": 1, "offset": 1},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["limit"] == 1
    assert body["offset"] == 1
    assert [item["id"] for item in body["items"]] == [str(middle)]
    assert {str(oldest), str(newest)}.isdisjoint({item["id"] for item in body["items"]})


@pytest.mark.anyio
async def test_equal_timestamps_use_id_desc_as_tie_breaker(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    ids = add_events(session_factory, 5, occurred_at=T1)

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 200
    returned = [item["id"] for item in response.json()["items"]]
    assert returned == sorted((str(event_id) for event_id in ids), reverse=True)


@pytest.mark.anyio
async def test_endpoint_exposes_no_write_operations(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)

    for method in ("post", "put", "patch", "delete"):
        response = await client.request(method, AUDIT_URL, headers=headers)
        assert response.status_code == 405


@pytest.mark.anyio
async def test_query_does_not_mutate_audit_records(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    add_event(session_factory, occurred_at=T0)
    add_event(session_factory, occurred_at=T1, action=AuditAction.ASSESSMENT_ACCESS_DENIED)

    def snapshot() -> list[tuple[object, ...]]:
        with session_factory() as session:
            rows = session.execute(
                select(
                    AuditEvent.id,
                    AuditEvent.action,
                    AuditEvent.outcome,
                    AuditEvent.occurred_at,
                ).order_by(AuditEvent.id)
            )
            return [tuple(row) for row in rows]

    before = snapshot()
    response = await client.get(AUDIT_URL, headers=headers)
    after = snapshot()

    assert response.status_code == 200
    assert before == after


@pytest.mark.anyio
async def test_audit_endpoint_does_not_change_assessment_authorization(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, admin_headers = make_assessment_principal(role=RoleName.ADMIN)
    _, viewer_headers = make_assessment_principal(role=RoleName.VIEWER)

    allowed = await client.get(AUDIT_URL, headers=admin_headers)
    denied = await client.post(
        "/api/v1/assessments",
        json={"assessment_type": "repository"},
        headers=viewer_headers,
    )

    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Insufficient permissions for this assessment operation"}


@pytest.mark.anyio
async def test_resource_id_returns_denied_attempt_with_null_fk(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    assessment_id = create_assessment_row(session_factory)
    denied_id = add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        assessment_id=None,
        resource_id=assessment_id,
        occurred_at=T0,
    )

    response = await client.get(
        AUDIT_URL,
        params={"resource_id": str(assessment_id)},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert [item["id"] for item in body["items"]] == [str(denied_id)]
    assert body["items"][0]["resource_id"] == str(assessment_id)
    assert body["items"][0]["assessment_id"] is None


@pytest.mark.anyio
async def test_assessment_id_excludes_denied_attempt_with_null_fk(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    assessment_id = create_assessment_row(session_factory)
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        assessment_id=None,
        resource_id=assessment_id,
        occurred_at=T0,
    )

    response = await client.get(
        AUDIT_URL,
        params={"assessment_id": str(assessment_id)},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


@pytest.mark.anyio
async def test_assessment_id_still_returns_successful_events(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    assessment_id = create_assessment_row(session_factory)
    created_id = add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_CREATED,
        outcome=AuditOutcome.SUCCESS,
        assessment_id=assessment_id,
        resource_id=assessment_id,
        occurred_at=T0,
    )
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        assessment_id=None,
        resource_id=assessment_id,
        occurred_at=T1,
    )

    response = await client.get(
        AUDIT_URL,
        params={"assessment_id": str(assessment_id)},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert [item["id"] for item in body["items"]] == [str(created_id)]


@pytest.mark.anyio
async def test_combined_filters_with_resource_id(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    first_actor, headers = make_assessment_principal(role=RoleName.ADMIN)
    other_actor, _ = make_assessment_principal(role=RoleName.VIEWER)
    assessment_x = create_assessment_row(session_factory)
    assessment_y = create_assessment_row(session_factory)
    target_id = add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        actor_user_id=first_actor,
        assessment_id=None,
        resource_id=assessment_x,
        occurred_at=T0,
    )
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        actor_user_id=first_actor,
        assessment_id=None,
        resource_id=assessment_y,
        occurred_at=T0,
    )
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_ACCESS_DENIED,
        outcome=AuditOutcome.DENIED,
        actor_user_id=other_actor,
        assessment_id=None,
        resource_id=assessment_x,
        occurred_at=T0,
    )
    add_event(
        session_factory,
        action=AuditAction.ASSESSMENT_CREATED,
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=first_actor,
        assessment_id=assessment_x,
        resource_id=assessment_x,
        occurred_at=T0,
    )

    response = await client.get(
        AUDIT_URL,
        params={
            "action": AuditAction.ASSESSMENT_ACCESS_DENIED.value,
            "outcome": AuditOutcome.DENIED.value,
            "actor_user_id": str(first_actor),
            "resource_id": str(assessment_x),
            "from_time": T0.isoformat(),
            "to_time": T1.isoformat(),
        },
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert [item["id"] for item in body["items"]] == [str(target_id)]


@pytest.mark.anyio
async def test_admin_audit_response_is_not_cacheable(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)

    response = await client.get(AUDIT_URL, headers=headers)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.anyio
async def test_role_downgrade_after_token_issuance_is_forbidden(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    admin_id, headers = make_assessment_principal(role=RoleName.ADMIN)
    before = await client.get(AUDIT_URL, headers=headers)
    assert before.status_code == 200

    remove_role(session_factory, admin_id, RoleName.ADMIN)

    after = await client.get(AUDIT_URL, headers=headers)

    assert after.status_code == 403
    assert after.json() == FORBIDDEN


def test_service_rejects_invalid_pagination_bounds(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        for limit in (0, -1, MAX_LIMIT + 1):
            with pytest.raises(ValueError, match="limit must be between"):
                list_audit_events(session, limit=limit)
        with pytest.raises(ValueError, match="offset must be zero or greater"):
            list_audit_events(session, offset=-1)

        assert list_audit_events(session, limit=DEFAULT_LIMIT) == ([], 0)
        assert list_audit_events(session, limit=MAX_LIMIT, offset=0) == ([], 0)
