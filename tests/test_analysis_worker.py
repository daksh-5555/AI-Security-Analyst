"""Durable background execution: queue, claim, lease, cancel, recover, retry (M8, ADR-0011)."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app import worker as worker_cli
from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment_finding import AssessmentFinding
from app.models.audit_event import AuditEvent
from app.schemas.enums import AnalysisRunStatus, AuditAction
from app.services import analysis_execution
from app.services.analysis_execution_context import AnalysisExecutionAbortedError
from app.services.analysis_worker import (
    AnalysisWorker,
    claim_next_run,
    recover_stale_runs,
)

pytestmark = pytest.mark.usefixtures("assessment_client")

URL = "/api/v1/assessments"
SOURCE = (
    "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/direct")\ndef handler():\n'
    '    cursor = sqlite3.connect("app.db").cursor()\n'
    '    cursor.execute(request.args.get("q"))\n    return "ok"\n'
)


@pytest.fixture
def repositories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repositories"
    root.mkdir()
    monkeypatch.setattr(settings, "repository_allowed_roots", [root])
    monkeypatch.setattr(
        settings, "evidence_fingerprint_key", SecretStr("test-only-fingerprint-key-" + "w" * 32)
    )
    monkeypatch.setattr(settings, "analysis_async_enabled", True)
    return root


def make_repository(root: Path, name: str = "project") -> Path:
    repo = root / name
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (repo / "app.py").write_text(SOURCE, encoding="utf-8")
    return repo


async def new_assessment(client: httpx.AsyncClient, repo: Path) -> str:
    assessment_id = (await client.post(URL, json={"assessment_type": "repository"})).json()["id"]
    response = await client.post(
        f"{URL}/{assessment_id}/repository",
        json={"source_kind": "local_path", "location": str(repo)},
    )
    assert response.status_code == 201
    return assessment_id


async def enqueue(client: httpx.AsyncClient, assessment_id: str) -> dict:
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs?mode=async")
    assert response.status_code == 202, response.text
    assert response.headers["Location"].endswith(response.json()["id"])
    return response.json()


async def get_run(client: httpx.AsyncClient, assessment_id: str, run_id: str) -> dict:
    response = await client.get(f"{URL}/{assessment_id}/analysis-runs/{run_id}")
    assert response.status_code == 200
    return response.json()


def audit_actions(session_factory: sessionmaker[Session], run_id: str) -> list[AuditAction]:
    with session_factory() as session:
        return list(
            session.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.resource_id == uuid.UUID(run_id))
                .order_by(AuditEvent.occurred_at, AuditEvent.id)
            )
        )


def finding_count(session_factory: sessionmaker[Session], run_id: str) -> int:
    with session_factory() as session:
        return session.scalar(
            select(func.count(AssessmentFinding.id)).where(
                AssessmentFinding.analysis_run_id == uuid.UUID(run_id)
            )
        )


def far_future() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=settings.analysis_stale_after_seconds + 60)


# --- API: async mode, quota, cancellation ---------------------------------------


@pytest.mark.anyio
async def test_async_mode_is_refused_unless_enabled(
    client: httpx.AsyncClient, repositories: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    monkeypatch.setattr(settings, "analysis_async_enabled", False)
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs?mode=async")
    assert response.status_code == 400
    assert response.json()["detail"] == "Asynchronous analysis is not enabled"
    runs = await client.get(f"{URL}/{assessment_id}/analysis-runs")
    assert runs.json() == []


@pytest.mark.anyio
async def test_async_run_is_queued_then_completed_by_the_worker(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    assert queued["status"] == "queued"
    assert queued["stage"] == "queued" and queued["attempts"] == 0
    assert queued["completed_at"] is None and queued["findings_count"] == 0

    # Only one active (queued or running) run per assessment.
    duplicate = await client.post(f"{URL}/{assessment_id}/analysis-runs?mode=async")
    assert duplicate.status_code == 409
    sync_duplicate = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert sync_duplicate.status_code == 409

    ran = AnalysisWorker(db_engine, worker_id="worker-a").run_once()
    assert str(ran) == queued["id"]

    done = await get_run(client, assessment_id, queued["id"])
    assert done["status"] == "completed"
    assert done["stage"] == "completed" and done["attempts"] == 1
    assert done["error_code"] is None and done["findings_count"] > 0
    assert done["analysis_metadata"]["completeness"]["static_analysis_is_complete"] is True
    assert audit_actions(session_factory, queued["id"]) == [
        AuditAction.ANALYSIS_RUN_QUEUED,
        AuditAction.ANALYSIS_RUN_STARTED,
        AuditAction.ANALYSIS_RUN_COMPLETED,
    ]
    with session_factory() as session:
        run = session.get(AnalysisRun, uuid.UUID(queued["id"]))
        assert run.lease_expires_at is None  # released at completion
        assert run.requested_by_user_id is not None

    # Nothing left to claim.
    assert AnalysisWorker(db_engine, worker_id="worker-b").run_once() is None


@pytest.mark.anyio
async def test_persisted_summary_matches_the_live_summary(
    client: httpx.AsyncClient, repositories: Path, db_engine: Engine
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    summary_url = f"{URL}/{assessment_id}/attack-surface/summary"

    missing = await client.get(f"{summary_url}?source=persisted")
    assert missing.status_code == 404
    assert missing.json()["detail"] == "No completed analysis run with a stored summary"

    await enqueue(client, assessment_id)
    AnalysisWorker(db_engine).run_once()

    persisted = await client.get(f"{summary_url}?source=persisted")
    live = await client.get(summary_url)  # default unchanged: recalculated
    assert persisted.status_code == live.status_code == 200
    assert persisted.json() == live.json()
    assert persisted.json()["repository"] == "project"  # never a host path
    assert (await client.get(f"{summary_url}?source=other")).status_code == 422


@pytest.mark.anyio
async def test_durable_per_user_quota_counts_queued_runs(
    client: httpx.AsyncClient, repositories: Path
) -> None:
    first = await new_assessment(client, make_repository(repositories, "one"))
    second = await new_assessment(client, make_repository(repositories, "two"))
    await enqueue(client, first)
    response = await client.post(f"{URL}/{second}/analysis-runs?mode=async")
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1


@pytest.mark.anyio
async def test_cancel_a_queued_run(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    cancel_url = f"{URL}/{assessment_id}/analysis-runs/{queued['id']}/cancel"

    response = await client.post(cancel_url)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled" and body["error_code"] == "cancelled"
    assert body["cancel_requested_at"] is not None and body["completed_at"] is not None

    assert AnalysisWorker(db_engine).run_once() is None  # never executed
    assert (await client.post(cancel_url)).status_code == 409
    assert audit_actions(session_factory, queued["id"]) == [
        AuditAction.ANALYSIS_RUN_QUEUED,
        AuditAction.ANALYSIS_RUN_CANCELLED,
    ]
    # The assessment can be analysed again.
    assert (await client.post(f"{URL}/{assessment_id}/analysis-runs?mode=async")).status_code == 202


@pytest.mark.anyio
async def test_cancel_boundaries(client: httpx.AsyncClient, repositories: Path) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    other_id = await new_assessment(client, make_repository(repositories, "other"))
    unknown = await client.post(f"{URL}/{assessment_id}/analysis-runs/{uuid.uuid4()}/cancel")
    assert unknown.status_code == 404

    finished = (await client.post(f"{URL}/{assessment_id}/analysis-runs")).json()
    assert finished["status"] == "completed"
    conflict = await client.post(f"{URL}/{assessment_id}/analysis-runs/{finished['id']}/cancel")
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "Analysis run has already finished"
    # A run is only reachable through its own assessment.
    foreign = await client.post(f"{URL}/{other_id}/analysis-runs/{finished['id']}/cancel")
    assert foreign.status_code == 404


@pytest.mark.anyio
async def test_cancel_a_running_run_stops_it_at_the_next_heartbeat(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    run_id = claim_next_run(db_engine, "worker-a")
    assert str(run_id) == queued["id"]

    response = await client.post(f"{URL}/{assessment_id}/analysis-runs/{queued['id']}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "running"  # requested, not yet stopped
    assert response.json()["cancel_requested_at"] is not None
    again = await client.post(f"{URL}/{assessment_id}/analysis-runs/{queued['id']}/cancel")
    assert again.status_code == 200  # repeating the request is harmless

    monkeypatch.setattr(settings, "analysis_heartbeat_interval_seconds", 0.05)

    def blocking_pipeline(_db, _assessment_id, *, execution_context):
        # Long-running analysis: it only stops when the heartbeat sees the request.
        assert execution_context.abort_event.wait(timeout=10)
        execution_context.check()
        raise AssertionError("unreachable")

    monkeypatch.setattr(analysis_execution, "collect_assessment_analysis", blocking_pipeline)
    with Session(bind=db_engine) as db, pytest.raises(AnalysisExecutionAbortedError):
        analysis_execution.execute_claimed_run(db, run_id, lease_owner="worker-a")

    run = await get_run(client, assessment_id, queued["id"])
    assert run["status"] == "cancelled" and run["error_code"] == "cancelled"
    assert run["findings_count"] == 0
    assert audit_actions(session_factory, queued["id"])[-1] is AuditAction.ANALYSIS_RUN_CANCELLED


@pytest.mark.anyio
async def test_synchronous_run_cancelled_mid_flight_returns_409(
    client: httpx.AsyncClient,
    repositories: Path,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    monkeypatch.setattr(settings, "analysis_heartbeat_interval_seconds", 0.05)

    def pipeline_cancelled_by_user(db, requested_id, *, execution_context):
        with session_factory() as other:
            run = other.scalar(select(AnalysisRun).where(AnalysisRun.assessment_id == requested_id))
            run.cancel_requested_at = datetime.now(UTC)
            other.commit()
        assert execution_context.abort_event.wait(timeout=10)
        execution_context.check()

    monkeypatch.setattr(
        analysis_execution, "collect_assessment_analysis", pipeline_cancelled_by_user
    )
    response = await client.post(f"{URL}/{assessment_id}/analysis-runs")
    assert response.status_code == 409
    runs = (await client.get(f"{URL}/{assessment_id}/analysis-runs")).json()
    assert [run["status"] for run in runs] == ["cancelled"]


# --- Claiming ---------------------------------------------------------------------


@pytest.mark.anyio
async def test_two_workers_never_claim_the_same_run(
    client: httpx.AsyncClient, repositories: Path, db_engine: Engine
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    await enqueue(client, assessment_id)
    barrier = threading.Barrier(4)
    claims: list[uuid.UUID | None] = []
    errors: list[BaseException] = []

    def contend(name: str) -> None:
        try:
            barrier.wait(timeout=10)
            claims.append(claim_next_run(db_engine, name))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=contend, args=(f"w{i}",)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    # SQLite may report "database is locked" to a loser; that is still not a claim.
    assert all(isinstance(error, OperationalError) for error in errors)
    assert len([claim for claim in claims if claim is not None]) == 1


@pytest.mark.anyio
async def test_claim_respects_the_global_running_cap(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_max_concurrent_jobs_per_user", 2)
    monkeypatch.setattr(settings, "analysis_worker_max_running", 1)
    first = await new_assessment(client, make_repository(repositories, "one"))
    second = await new_assessment(client, make_repository(repositories, "two"))
    first_run = await enqueue(client, first)
    await enqueue(client, second)

    assert str(claim_next_run(db_engine, "w1")) == first_run["id"]  # oldest first
    assert claim_next_run(db_engine, "w2") is None  # cap reached


# --- Crash recovery, leases, retries --------------------------------------------


@pytest.mark.anyio
async def test_crashed_worker_run_is_requeued_and_completed_without_duplicates(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    repo = make_repository(repositories)
    baseline_id = await new_assessment(client, repo)
    baseline = (await client.post(f"{URL}/{baseline_id}/analysis-runs")).json()

    assessment_id = await new_assessment(client, repo)
    queued = await enqueue(client, assessment_id)
    assert claim_next_run(db_engine, "crashed-worker") is not None  # then the process dies

    assert recover_stale_runs(db_engine).requeued == []  # lease still valid
    summary = recover_stale_runs(db_engine, now=far_future())
    assert [str(run_id) for run_id in summary.requeued] == [queued["id"]]
    requeued = await get_run(client, assessment_id, queued["id"])
    assert requeued["status"] == "queued" and requeued["error_code"] == "lease_expired_retry"

    AnalysisWorker(db_engine, worker_id="healthy-worker").run_once()
    done = await get_run(client, assessment_id, queued["id"])
    assert done["status"] == "completed" and done["attempts"] == 2
    assert done["findings_count"] == baseline["findings_count"]
    assert finding_count(session_factory, queued["id"]) == baseline["findings_count"]
    assert audit_actions(session_factory, queued["id"]).count(AuditAction.ANALYSIS_RUN_STARTED) == 2


@pytest.mark.anyio
async def test_worker_that_lost_its_lease_cannot_complete_or_fail_the_run(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    run_id = claim_next_run(db_engine, "slow-worker")
    recover_stale_runs(db_engine, now=far_future())
    assert claim_next_run(db_engine, "new-worker") == run_id

    # The slow worker wakes up and finishes its pipeline: its terminal
    # transition is refused, nothing is written, and the run stays with the
    # new owner.
    with (
        Session(bind=db_engine) as db,
        pytest.raises(analysis_execution.AnalysisRunStateConflictError),
    ):
        analysis_execution.execute_claimed_run(db, run_id, lease_owner="slow-worker")
    with session_factory() as session:
        run = session.get(AnalysisRun, run_id)
        assert run.status is AnalysisRunStatus.RUNNING and run.lease_owner == "new-worker"
    assert finding_count(session_factory, queued["id"]) == 0

    with Session(bind=db_engine) as db:
        analysis_execution.execute_claimed_run(db, run_id, lease_owner="new-worker")
    done = await get_run(client, assessment_id, queued["id"])
    assert done["status"] == "completed" and done["findings_count"] > 0
    actions = audit_actions(session_factory, queued["id"])
    assert actions.count(AuditAction.ANALYSIS_RUN_COMPLETED) == 1
    assert AuditAction.ANALYSIS_RUN_FAILED not in actions


@pytest.mark.anyio
async def test_exhausted_attempts_fail_with_lease_expired(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_worker_max_attempts", 1)
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    claim_next_run(db_engine, "crashed-worker")

    summary = recover_stale_runs(db_engine, now=far_future())
    assert [str(run_id) for run_id in summary.failed] == [queued["id"]]
    run = await get_run(client, assessment_id, queued["id"])
    assert run["status"] == "failed" and run["error_code"] == "lease_expired"
    assert run["error_message"] == "Analysis run stopped responding and its lease expired."
    assert audit_actions(session_factory, queued["id"])[-1] is AuditAction.ANALYSIS_RUN_FAILED


@pytest.mark.anyio
async def test_stale_synchronous_and_legacy_runs_are_failed_not_retried(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
) -> None:
    sync_id = await new_assessment(client, make_repository(repositories, "sync"))
    legacy_id = await new_assessment(client, make_repository(repositories, "legacy"))
    with session_factory() as session:
        sync_run = analysis_execution._start_running_run(session, uuid.UUID(sync_id))
        legacy_run = analysis_execution._start_running_run(session, uuid.UUID(legacy_id))
        legacy = session.get(AnalysisRun, legacy_run.id)
        legacy.lease_expires_at = None  # rows that predate migration 0018
        session.commit()
        sync_run_id, legacy_run_id = sync_run.id, legacy_run.id

    assert recover_stale_runs(db_engine).failed == []
    summary = recover_stale_runs(db_engine, now=far_future())
    assert set(summary.failed) == {sync_run_id, legacy_run_id} and summary.requeued == []
    with session_factory() as session:
        for run_id in (sync_run_id, legacy_run_id):
            run = session.get(AnalysisRun, run_id)
            assert run.status is AnalysisRunStatus.FAILED and run.error_code == "lease_expired"


@pytest.mark.anyio
async def test_stale_run_with_cancel_request_is_cancelled(
    client: httpx.AsyncClient, repositories: Path, db_engine: Engine
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    claim_next_run(db_engine, "crashed-worker")
    await client.post(f"{URL}/{assessment_id}/analysis-runs/{queued['id']}/cancel")

    summary = recover_stale_runs(db_engine, now=far_future())
    assert [str(run_id) for run_id in summary.cancelled] == [queued["id"]]
    assert (await get_run(client, assessment_id, queued["id"]))["status"] == "cancelled"


@pytest.mark.anyio
async def test_transient_failure_is_retried_then_succeeds(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)
    real = analysis_execution.collect_assessment_analysis
    calls = {"count": 0}

    def flaky(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OperationalError("SELECT 1", {}, Exception("database is locked"))
        return real(*args, **kwargs)

    monkeypatch.setattr(analysis_execution, "collect_assessment_analysis", flaky)
    worker = AnalysisWorker(db_engine, worker_id="w")
    worker.run_once()
    retry = await get_run(client, assessment_id, queued["id"])
    assert retry["status"] == "queued" and retry["error_code"] == "transient_retry"

    worker.run_once()
    done = await get_run(client, assessment_id, queued["id"])
    assert done["status"] == "completed" and done["attempts"] == 2


@pytest.mark.anyio
async def test_transient_failures_stop_after_max_attempts(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_worker_max_attempts", 2)
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)

    def always_locked(*_args, **_kwargs):
        raise OperationalError("SELECT 1", {}, Exception("database is locked"))

    monkeypatch.setattr(analysis_execution, "collect_assessment_analysis", always_locked)
    worker = AnalysisWorker(db_engine)
    worker.run_once()
    worker.run_once()
    run = await get_run(client, assessment_id, queued["id"])
    assert run["status"] == "failed" and run["attempts"] == 2
    assert run["error_code"] == "transient_retries_exhausted"
    assert "locked" not in run["error_message"]
    assert worker.run_once() is None
    assert audit_actions(session_factory, queued["id"])[-1] is AuditAction.ANALYSIS_RUN_FAILED


@pytest.mark.anyio
async def test_permanent_failure_is_not_retried(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)

    def broken(*_args, **_kwargs):
        raise RuntimeError("analyzer bug")

    monkeypatch.setattr(analysis_execution, "collect_assessment_analysis", broken)
    AnalysisWorker(db_engine).run_once()
    run = await get_run(client, assessment_id, queued["id"])
    assert run["status"] == "failed" and run["error_code"] == "analysis_failed"
    assert run["error_message"] == "Assessment analysis failed."  # no exception text
    assert AnalysisWorker(db_engine).run_once() is None


@pytest.mark.anyio
async def test_target_invalidated_while_queued_fails_without_analysis(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = make_repository(repositories)
    assessment_id = await new_assessment(client, repo)
    queued = await enqueue(client, assessment_id)
    for path in sorted(repo.rglob("*"), reverse=True):
        path.unlink()
    repo.rmdir()

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("analysis must not start")

    monkeypatch.setattr(analysis_execution, "collect_assessment_analysis", must_not_run)
    AnalysisWorker(db_engine).run_once()
    run = await get_run(client, assessment_id, queued["id"])
    assert run["status"] == "failed" and run["error_code"] == "target_validation_failed"
    assert run["attempts"] == 1


# --- Entry point -----------------------------------------------------------------


@pytest.mark.anyio
async def test_worker_cli_once_and_recover_only(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(worker_cli, "engine", db_engine)
    assessment_id = await new_assessment(client, make_repository(repositories))
    queued = await enqueue(client, assessment_id)

    assert worker_cli.main(["--recover-only"]) == 0
    assert (await get_run(client, assessment_id, queued["id"]))["status"] == "queued"
    assert worker_cli.main(["--once"]) == 0
    assert (await get_run(client, assessment_id, queued["id"]))["status"] == "completed"
    with pytest.raises(SystemExit):
        worker_cli.main(["--once", "--recover-only"])


@pytest.mark.anyio
async def test_claim_cap_is_exact_under_concurrent_workers(
    client: httpx.AsyncClient,
    repositories: Path,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eight workers race for six queued runs with a cap of two (M13).

    On PostgreSQL this exercises the advisory lock plus FOR UPDATE SKIP LOCKED
    path; on SQLite, serialized writes. Either way exactly two runs are claimed,
    each by one worker.
    """
    monkeypatch.setattr(settings, "analysis_max_concurrent_jobs", 8)
    monkeypatch.setattr(settings, "analysis_max_concurrent_jobs_per_user", 8)
    monkeypatch.setattr(settings, "analysis_worker_max_running", 2)
    for index in range(6):
        await enqueue(
            client, await new_assessment(client, make_repository(repositories, f"r{index}"))
        )

    barrier = threading.Barrier(8)
    claims: list[uuid.UUID] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def contend(name: str) -> None:
        try:
            barrier.wait(timeout=10)
            claimed = claim_next_run(db_engine, name)
            if claimed is not None:
                with lock:
                    claims.append(claimed)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=contend, args=(f"w{i}",)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    if db_engine.dialect.name == "postgresql":
        assert errors == []  # no lock errors: losers skip or wait, never fail
    else:
        assert all(isinstance(error, OperationalError) for error in errors)
    assert len(claims) == len(set(claims))  # never claimed twice
    with Session(bind=db_engine) as session:
        running = session.scalar(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.status == AnalysisRunStatus.RUNNING
            )
        )
    assert running == len(claims) <= 2
    if db_engine.dialect.name == "postgresql":
        assert running == 2
