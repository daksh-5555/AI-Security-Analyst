"""Validation errors must never echo submitted values on any route."""

import httpx
import pytest

PROBE = "SUBMITTED-VALUE-MUST-NOT-ECHO-7f3c"

pytestmark = pytest.mark.usefixtures("assessment_client")


def _assert_sanitized(response: httpx.Response) -> None:
    assert response.status_code == 422
    assert PROBE not in response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    for error in detail:
        assert "input" not in error
        # Clients can still identify the failing field and reason.
        assert {"loc", "msg", "type"} <= set(error)


@pytest.mark.anyio
async def test_assessment_body_validation_does_not_echo_input(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/assessments", json={"assessment_type": PROBE})
    _assert_sanitized(response)


@pytest.mark.anyio
async def test_repository_body_validation_does_not_echo_location(
    client: httpx.AsyncClient,
) -> None:
    created = await client.post("/api/v1/assessments", json={"assessment_type": "repository"})
    assert created.status_code == 201
    response = await client.post(
        f"/api/v1/assessments/{created.json()['id']}/repository",
        json={"source_kind": PROBE, "location": f"/srv/{PROBE}"},
    )
    _assert_sanitized(response)


@pytest.mark.anyio
async def test_query_and_path_validation_does_not_echo_input(client: httpx.AsyncClient) -> None:
    _assert_sanitized(await client.get(f"/api/v1/assessments?limit={PROBE}"))
    _assert_sanitized(await client.get(f"/api/v1/assessments/{PROBE}"))
    created = await client.post("/api/v1/assessments", json={"assessment_type": "repository"})
    assert created.status_code == 201
    _assert_sanitized(
        await client.get(
            f"/api/v1/assessments/{created.json()['id']}/findings?analysis_run_id={PROBE}"
        )
    )


@pytest.mark.anyio
async def test_auth_validation_still_does_not_echo_secrets(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": PROBE, "unexpected": PROBE},
    )
    _assert_sanitized(response)
