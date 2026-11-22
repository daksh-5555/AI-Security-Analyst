"""Security-monitoring repeated-denial detection tests."""

import uuid
from datetime import UTC, datetime, timedelta, timezone

import httpx
import pytest
from auth_helpers import create_user, remove_role
from sqlalchemy import event, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.constants import MONITORING_TIME_OUT_OF_RANGE_DETAIL
from app.core.security import decode_access_token
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.user_session import UserSession
from app.schemas.enums import (
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    RoleName,
)
from app.schemas.security_monitoring import MAX_WINDOW
from app.services.audit import record_audit_event
from app.services.security_monitoring import list_denial_patterns

URL = "/api/v1/admin/security-monitoring/denial-patterns"
FORBIDDEN = {"detail": "Administrator access required"}
AUTH_FAILURE = {"detail": "Invalid or expired access token"}

START = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
END = datetime(2026, 1, 1, 11, 0, tzinfo=UTC)


def window_params(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "from_time": START.isoformat(),
        "to_time": END.isoformat(),
    }
    params.update(overrides)
    return params


def add_event(
    session_factory: sessionmaker[Session],
    *,
    actor_user_id: uuid.UUID | None = None,
    resource_id: uuid.UUID | None = None,
    resource_type: AuditResourceType = AuditResourceType.ASSESSMENT,
    action: AuditAction = AuditAction.ASSESSMENT_ACCESS_DENIED,
    outcome: AuditOutcome = AuditOutcome.DENIED,
    occurred_at: datetime = START,
    context: dict[str, object] | None = None,
) -> uuid.UUID:
    with session_factory() as session:
        audit_event = record_audit_event(
            session,
            action=action,
            outcome=outcome,
            resource_type=resource_type,
            resource_id=resource_id,
            assessment_id=None,
            actor_user_id=actor_user_id,
            occurred_at=occurred_at,
            context=context,
        )
        session.commit()
        return audit_event.id


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@pytest.fixture
def make_actor(
    session_factory: sessionmaker[Session],
    low_cost_argon2: None,
):
    def _make() -> uuid.UUID:
        return create_user(
            session_factory,
            email=f"monitor-{uuid.uuid4().hex}@example.com",
            is_email_verified=True,
        )

    return _make


@pytest.fixture
def admin_headers(make_assessment_principal) -> dict[str, str]:
    _, headers = make_assessment_principal(role=RoleName.ADMIN)
    return headers


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_unauthenticated_request_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get(URL, params=window_params())

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.anyio
async def test_invalid_access_token_is_rejected(
    client: httpx.AsyncClient,
    configure_jwt: None,
) -> None:
    response = await client.get(
        URL,
        params=window_params(),
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE


@pytest.mark.anyio
async def test_viewer_is_forbidden(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.VIEWER)

    response = await client.get(URL, params=window_params(), headers=headers)

    assert response.status_code == 403
    assert response.json() == FORBIDDEN


@pytest.mark.anyio
async def test_security_analyst_is_forbidden(
    client: httpx.AsyncClient,
    make_assessment_principal,
) -> None:
    _, headers = make_assessment_principal(role=RoleName.SECURITY_ANALYST)

    response = await client.get(URL, params=window_params(), headers=headers)

    assert response.status_code == 403
    assert response.json() == FORBIDDEN


@pytest.mark.anyio
async def test_admin_can_access_monitoring(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    response = await client.get(URL, params=window_params(), headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["min_attempts"] == 5
    assert body["total"] == 0
    assert body["patterns"] == []
    assert parse_time(body["from_time"]) == START
    assert parse_time(body["to_time"]) == END


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

    response = await client.get(URL, params=window_params(), headers=headers)

    assert response.status_code == 401
    assert response.json() == AUTH_FAILURE


@pytest.mark.anyio
async def test_admin_role_removed_after_token_is_forbidden(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_assessment_principal,
) -> None:
    admin_id, headers = make_assessment_principal(role=RoleName.ADMIN)
    before = await client.get(URL, params=window_params(), headers=headers)
    assert before.status_code == 200

    remove_role(session_factory, admin_id, RoleName.ADMIN)

    after = await client.get(URL, params=window_params(), headers=headers)

    assert after.status_code == 403
    assert after.json() == FORBIDDEN


# ---------------------------------------------------------------------------
# Detection correctness
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_repeated_denials_form_one_group_with_correct_aggregates(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    add_event(session_factory, actor_user_id=actor, resource_id=target, occurred_at=START)
    add_event(
        session_factory,
        actor_user_id=actor,
        resource_id=target,
        occurred_at=START + timedelta(minutes=10),
    )
    add_event(
        session_factory,
        actor_user_id=actor,
        resource_id=target,
        occurred_at=START + timedelta(minutes=20),
    )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    pattern = body["patterns"][0]
    assert set(pattern) == {
        "actor_user_id",
        "resource_type",
        "resource_id",
        "action",
        "attempt_count",
        "first_seen",
        "last_seen",
    }
    assert pattern["actor_user_id"] == str(actor)
    assert pattern["resource_type"] == AuditResourceType.ASSESSMENT.value
    assert pattern["resource_id"] == str(target)
    assert pattern["action"] == AuditAction.ASSESSMENT_ACCESS_DENIED.value
    assert pattern["attempt_count"] == 3
    assert parse_time(pattern["first_seen"]) == START
    assert parse_time(pattern["last_seen"]) == START + timedelta(minutes=20)


@pytest.mark.anyio
async def test_groups_below_threshold_are_excluded(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for minute in (0, 1):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
        )

    response = await client.get(
        URL,
        params=window_params(min_attempts=3),
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert response.json()["total"] == 0
    assert response.json()["patterns"] == []


@pytest.mark.anyio
async def test_successful_events_are_excluded(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for minute in (0, 1, 2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
        )
    for minute in (3, 4, 5):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            outcome=AuditOutcome.SUCCESS,
            occurred_at=START + timedelta(minutes=minute),
        )

    counted = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )
    raised_threshold = await client.get(
        URL,
        params=window_params(min_attempts=4),
        headers=admin_headers,
    )

    assert counted.status_code == 200
    assert counted.json()["total"] == 1
    assert counted.json()["patterns"][0]["attempt_count"] == 3
    assert raised_threshold.status_code == 200
    assert raised_threshold.json()["total"] == 0


@pytest.mark.anyio
async def test_different_actors_form_different_groups(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    first_actor = make_actor()
    second_actor = make_actor()
    target = uuid.uuid4()
    for actor in (first_actor, second_actor):
        for minute in (0, 1):
            add_event(
                session_factory,
                actor_user_id=actor,
                resource_id=target,
                occurred_at=START + timedelta(minutes=minute),
            )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {pattern["actor_user_id"] for pattern in body["patterns"]} == {
        str(first_actor),
        str(second_actor),
    }


@pytest.mark.anyio
async def test_different_resources_form_different_groups(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    first_target = uuid.uuid4()
    second_target = uuid.uuid4()
    for target in (first_target, second_target):
        for minute in (0, 1):
            add_event(
                session_factory,
                actor_user_id=actor,
                resource_id=target,
                occurred_at=START + timedelta(minutes=minute),
            )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {pattern["resource_id"] for pattern in body["patterns"]} == {
        str(first_target),
        str(second_target),
    }


@pytest.mark.anyio
async def test_different_actions_form_different_groups(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for action in (
        AuditAction.ASSESSMENT_ACCESS_DENIED,
        AuditAction.ASSESSMENT_LIFECYCLE_DENIED,
    ):
        for minute in (0, 1):
            add_event(
                session_factory,
                actor_user_id=actor,
                resource_id=target,
                action=action,
                occurred_at=START + timedelta(minutes=minute),
            )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {pattern["action"] for pattern in body["patterns"]} == {
        AuditAction.ASSESSMENT_ACCESS_DENIED.value,
        AuditAction.ASSESSMENT_LIFECYCLE_DENIED.value,
    }


@pytest.mark.anyio
async def test_different_resource_types_form_different_groups(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for resource_type in (
        AuditResourceType.ASSESSMENT,
        AuditResourceType.REPOSITORY_TARGET,
    ):
        for minute in (0, 1):
            add_event(
                session_factory,
                actor_user_id=actor,
                resource_id=target,
                resource_type=resource_type,
                occurred_at=START + timedelta(minutes=minute),
            )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {pattern["resource_type"] for pattern in body["patterns"]} == {
        AuditResourceType.ASSESSMENT.value,
        AuditResourceType.REPOSITORY_TARGET.value,
    }


@pytest.mark.anyio
async def test_null_actors_are_grouped_without_inventing_identity(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for minute in (0, 1, 2):
        add_event(
            session_factory,
            actor_user_id=None,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
        )
    for minute in (3, 4):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
        )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    null_group = next(pattern for pattern in body["patterns"] if pattern["actor_user_id"] is None)
    assert null_group["attempt_count"] == 3
    attributed_group = next(
        pattern for pattern in body["patterns"] if pattern["actor_user_id"] is not None
    )
    assert attributed_group["actor_user_id"] == str(actor)
    assert attributed_group["attempt_count"] == 2
    assert "unknown" not in response.text.lower()


@pytest.mark.anyio
async def test_ordering_uses_count_then_last_seen(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    high_count_target = uuid.uuid4()
    later_target = uuid.uuid4()
    earlier_target = uuid.uuid4()
    for minute in (0, 1, 2, 3, 4):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=high_count_target,
            occurred_at=START + timedelta(minutes=minute),
        )
    for minute in (15, 18, 20):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=later_target,
            occurred_at=START + timedelta(minutes=minute),
        )
    for minute in (5, 8, 10):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=earlier_target,
            occurred_at=START + timedelta(minutes=minute),
        )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    patterns = response.json()["patterns"]
    assert [pattern["attempt_count"] for pattern in patterns] == [5, 3, 3]
    assert [pattern["resource_id"] for pattern in patterns] == [
        str(high_count_target),
        str(later_target),
        str(earlier_target),
    ]


@pytest.mark.anyio
async def test_ordering_tie_breakers_are_deterministic_and_null_last(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    first_actor, second_actor = sorted([make_actor(), make_actor()])
    targets = {
        first_actor: uuid.uuid4(),
        second_actor: uuid.uuid4(),
        None: uuid.uuid4(),
    }
    for actor, target in targets.items():
        for minute in (0, 1):
            add_event(
                session_factory,
                actor_user_id=actor,
                resource_id=target,
                occurred_at=START + timedelta(minutes=minute),
            )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert [pattern["actor_user_id"] for pattern in response.json()["patterns"]] == [
        str(first_actor),
        str(second_actor),
        None,
    ]


@pytest.mark.anyio
async def test_time_window_is_inclusive_at_start_and_exclusive_at_end(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    add_event(
        session_factory,
        actor_user_id=actor,
        resource_id=target,
        occurred_at=START - timedelta(seconds=1),
    )
    add_event(
        session_factory,
        actor_user_id=actor,
        resource_id=target,
        occurred_at=START - timedelta(seconds=1),
    )
    for _ in range(2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START,
        )
    for _ in range(2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=END,
        )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["patterns"][0]["attempt_count"] == 2
    assert parse_time(body["patterns"][0]["first_seen"]) == START
    assert parse_time(body["patterns"][0]["last_seen"]) == START


@pytest.mark.anyio
async def test_non_utc_offset_window_is_normalized(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    local_offset = timezone(timedelta(hours=2))
    for _ in range(2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START,
        )
    for _ in range(2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=END,
        )

    response = await client.get(
        URL,
        params={
            "from_time": START.astimezone(local_offset).isoformat(),
            "to_time": END.astimezone(local_offset).isoformat(),
            "min_attempts": 2,
        },
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["patterns"][0]["attempt_count"] == 2
    assert parse_time(body["patterns"][0]["first_seen"]) == START
    assert parse_time(body["patterns"][0]["last_seen"]) == START
    assert parse_time(body["from_time"]) == START
    assert parse_time(body["to_time"]) == END
    assert "+02:00" not in body["from_time"]
    assert "+02:00" not in body["to_time"]


@pytest.mark.anyio
async def test_limit_bounds_patterns_but_not_total(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    for index in range(3):
        target = uuid.uuid4()
        for minute in range(index + 2):
            add_event(
                session_factory,
                actor_user_id=actor,
                resource_id=target,
                occurred_at=START + timedelta(minutes=minute),
            )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2, limit=1),
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert len(body["patterns"]) == 1
    assert body["patterns"][0]["attempt_count"] == 4


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_missing_time_bounds_are_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    missing_start = await client.get(
        URL,
        params={"to_time": END.isoformat()},
        headers=admin_headers,
    )
    missing_end = await client.get(
        URL,
        params={"from_time": START.isoformat()},
        headers=admin_headers,
    )

    assert missing_start.status_code == 422
    assert missing_end.status_code == 422


@pytest.mark.anyio
async def test_naive_datetimes_are_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    response = await client.get(
        URL,
        params={
            "from_time": START.replace(tzinfo=None).isoformat(),
            "to_time": END.isoformat(),
        },
        headers=admin_headers,
    )
    assert response.status_code == 422

    response = await client.get(
        URL,
        params={
            "from_time": START.isoformat(),
            "to_time": END.replace(tzinfo=None).isoformat(),
        },
        headers=admin_headers,
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_invalid_time_range_is_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    response = await client.get(
        URL,
        params={
            "from_time": END.isoformat(),
            "to_time": START.isoformat(),
        },
        headers=admin_headers,
    )
    equal = await client.get(
        URL,
        params={
            "from_time": START.isoformat(),
            "to_time": START.isoformat(),
        },
        headers=admin_headers,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "from_time must be earlier than to_time"}
    assert equal.status_code == 422


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("from_time", "to_time"),
    [
        ("0001-01-01T00:00:00+23:59", "0001-01-02T00:00:00+23:59"),
        ("0001-01-01T00:00:00+23:59", "0001-01-01T23:59:59+23:59"),
        ("9999-12-30T23:59:59-23:59", "9999-12-31T23:59:59-23:59"),
    ],
)
async def test_out_of_range_time_bounds_are_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    from_time: str,
    to_time: str,
) -> None:
    response = await client.get(
        URL,
        params={"from_time": from_time, "to_time": to_time},
        headers=admin_headers,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": MONITORING_TIME_OUT_OF_RANGE_DETAIL}
    assert "Internal Server Error" not in response.text
    assert "OverflowError" not in response.text
    assert "date value out of range" not in response.text


@pytest.mark.anyio
async def test_representable_extreme_offset_is_accepted_and_normalized(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    response = await client.get(
        URL,
        params={
            "from_time": "0001-01-02T00:00:00+23:59",
            "to_time": "0001-01-03T00:00:00+23:59",
        },
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert parse_time(body["from_time"]) == datetime(1, 1, 1, 0, 1, tzinfo=UTC)
    assert parse_time(body["to_time"]) == datetime(1, 1, 2, 0, 1, tzinfo=UTC)


@pytest.mark.anyio
async def test_window_longer_than_30_days_is_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    too_long = await client.get(
        URL,
        params={
            "from_time": START.isoformat(),
            "to_time": (START + MAX_WINDOW + timedelta(seconds=1)).isoformat(),
        },
        headers=admin_headers,
    )
    exactly_thirty_days = await client.get(
        URL,
        params={
            "from_time": START.isoformat(),
            "to_time": (START + MAX_WINDOW).isoformat(),
        },
        headers=admin_headers,
    )

    assert too_long.status_code == 422
    assert too_long.json() == {"detail": "Time window must not exceed 30 days"}
    assert exactly_thirty_days.status_code == 200


@pytest.mark.anyio
async def test_invalid_attempt_threshold_is_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    too_low = await client.get(
        URL,
        params=window_params(min_attempts=1),
        headers=admin_headers,
    )
    too_high = await client.get(
        URL,
        params=window_params(min_attempts=1001),
        headers=admin_headers,
    )
    not_an_integer = await client.get(
        URL,
        params=window_params(min_attempts="many"),
        headers=admin_headers,
    )

    assert too_low.status_code == 422
    assert too_high.status_code == 422
    assert not_an_integer.status_code == 422


@pytest.mark.anyio
async def test_invalid_limit_is_rejected(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    too_low = await client.get(
        URL,
        params=window_params(limit=0),
        headers=admin_headers,
    )
    too_high = await client.get(
        URL,
        params=window_params(limit=101),
        headers=admin_headers,
    )

    assert too_low.status_code == 422
    assert too_high.status_code == 422


# ---------------------------------------------------------------------------
# Security and architecture
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_response_never_exposes_context_or_sensitive_values(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for minute in (0, 1):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
            context={
                "token": "secret-token-value",
                "password": "hunter2",
                "path": "C:\\secret\\repository",
            },
        )

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert "secret-token-value" not in response.text
    assert "hunter2" not in response.text
    assert "C:\\\\secret" not in response.text
    assert "context" not in response.json()["patterns"][0]


@pytest.mark.anyio
async def test_query_does_not_mutate_audit_rows(
    client: httpx.AsyncClient,
    session_factory: sessionmaker[Session],
    make_actor,
    admin_headers: dict[str, str],
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for minute in (0, 1, 2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
        )

    snapshot_columns = (
        AuditEvent.id,
        AuditEvent.actor_user_id,
        AuditEvent.resource_type,
        AuditEvent.resource_id,
        AuditEvent.action,
        AuditEvent.outcome,
        AuditEvent.occurred_at,
        AuditEvent.context,
    )
    with session_factory() as session:
        before = session.execute(select(*snapshot_columns).order_by(AuditEvent.id)).all()

    response = await client.get(
        URL,
        params=window_params(min_attempts=2),
        headers=admin_headers,
    )

    assert response.status_code == 200
    with session_factory() as session:
        after = session.execute(select(*snapshot_columns).order_by(AuditEvent.id)).all()
    assert after == before


def test_endpoint_exposes_only_get() -> None:
    operations = app.openapi()["paths"][URL]

    assert set(operations) == {"get"}


@pytest.mark.anyio
async def test_monitoring_response_is_not_cacheable(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    response = await client.get(URL, params=window_params(), headers=admin_headers)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_aggregation_is_performed_in_the_database(
    session_factory: sessionmaker[Session],
    make_actor,
) -> None:
    actor = make_actor()
    target = uuid.uuid4()
    for minute in (0, 1, 2):
        add_event(
            session_factory,
            actor_user_id=actor,
            resource_id=target,
            occurred_at=START + timedelta(minutes=minute),
        )

    statements: list[str] = []

    with session_factory() as session:
        engine = session.get_bind()

        def capture(
            _conn: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", capture)
        try:
            patterns, total = list_denial_patterns(
                session,
                from_time=START,
                to_time=END,
                min_attempts=2,
                limit=50,
            )
        finally:
            event.remove(engine, "before_cursor_execute", capture)

    assert total == 1
    assert patterns[0].attempt_count == 3
    aggregated = [statement for statement in statements if "GROUP BY" in statement.upper()]
    assert aggregated
    sql = aggregated[0].upper()
    for token in ("GROUP BY", "COUNT(", "MIN(", "MAX(", "HAVING"):
        assert token in sql
    assert "CONTEXT" not in sql
    assert all("UPDATE" not in statement.upper() for statement in statements)
    assert all("DELETE" not in statement.upper() for statement in statements)


def test_service_rejects_invalid_arguments(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        invalid_calls = (
            {"from_time": START.replace(tzinfo=None), "to_time": END},
            {"from_time": START, "to_time": END.replace(tzinfo=None)},
            {"from_time": END, "to_time": START},
            {"from_time": START, "to_time": START + MAX_WINDOW + timedelta(seconds=1)},
            {"from_time": START, "to_time": END, "min_attempts": 1},
            {"from_time": START, "to_time": END, "min_attempts": 1001},
            {"from_time": START, "to_time": END, "limit": 0},
            {"from_time": START, "to_time": END, "limit": 101},
        )
        for kwargs in invalid_calls:
            with pytest.raises(ValueError):
                list_denial_patterns(session, **kwargs)

        assert list_denial_patterns(session, from_time=START, to_time=END) == ([], 0)


def test_service_rejects_out_of_range_time_bounds(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        with pytest.raises(ValueError, match="outside the supported datetime range"):
            list_denial_patterns(
                session,
                from_time=datetime.fromisoformat("0001-01-01T00:00:00+23:59"),
                to_time=datetime.fromisoformat("0001-01-02T00:00:00+23:59"),
            )
