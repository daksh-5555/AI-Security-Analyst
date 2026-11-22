"""Deterministic tests for the process-local analysis admission controller."""

from __future__ import annotations

import threading
import uuid

import pytest

from app.core.config import settings
from app.core.rate_limit import auth_rate_limiter
from app.services.analysis_admission import (
    ANALYSIS_RUN_SCOPE,
    ANALYSIS_SUMMARY_SCOPE,
    AnalysisAdmissionController,
    AnalysisCapacityExceeded,
    AnalysisRateLimitExceeded,
    AnalysisUserConcurrencyExceeded,
    analysis_admission,
    analysis_rate_limiter,
)
from app.services.analysis_execution_context import (
    AnalysisDeadlineExceededError,
    AnalysisExecutionAbortedError,
)


def make_controller(
    *,
    global_limit: int = 2,
    per_user_limit: int = 1,
    queue_wait_seconds: int = 0,
) -> AnalysisAdmissionController:
    return AnalysisAdmissionController(
        global_limit=global_limit,
        per_user_limit=per_user_limit,
        queue_wait_seconds=queue_wait_seconds,
    )


def test_rate_limit_allows_up_to_the_limit_and_reports_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 2)
    monkeypatch.setattr(settings, "analysis_rate_limit_window_seconds", 10)
    controller = make_controller()
    user_id = uuid.uuid4()

    controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=0.0)
    controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=1.0)

    with pytest.raises(AnalysisRateLimitExceeded) as exc_info:
        controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=2.0)

    assert exc_info.value.retry_after_seconds == 8

    # The oldest request has left the sliding window, so one slot is available.
    controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=10.0)


def test_rate_limit_scopes_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 1)
    monkeypatch.setattr(settings, "analysis_rate_limit_window_seconds", 60)
    controller = make_controller()
    user_id = uuid.uuid4()

    controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=0.0)
    with pytest.raises(AnalysisRateLimitExceeded):
        controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=0.0)

    # The summary scope has its own counter for the same user.
    controller.check_rate_limit(ANALYSIS_SUMMARY_SCOPE, user_id, now=0.0)


def test_rate_limit_identities_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 1)
    monkeypatch.setattr(settings, "analysis_rate_limit_window_seconds", 60)
    controller = make_controller()

    controller.check_rate_limit(ANALYSIS_RUN_SCOPE, uuid.uuid4(), now=0.0)
    controller.check_rate_limit(ANALYSIS_RUN_SCOPE, uuid.uuid4(), now=0.0)


def test_rules_use_explicit_analysis_settings_not_auth_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "auth_rate_limit_max_requests", 1)
    monkeypatch.setattr(settings, "auth_rate_limit_window_seconds", 1)
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 3)
    monkeypatch.setattr(settings, "analysis_rate_limit_window_seconds", 60)
    controller = make_controller()
    user_id = uuid.uuid4()

    for index in range(3):
        controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=float(index))

    with pytest.raises(AnalysisRateLimitExceeded):
        controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id, now=3.0)


def test_analysis_limiter_is_separate_from_the_auth_limiter() -> None:
    assert analysis_rate_limiter is not auth_rate_limiter
    assert analysis_admission.rate_limiter is analysis_rate_limiter


def test_per_user_quota_is_atomic_and_independent_per_user() -> None:
    controller = make_controller(per_user_limit=1)
    first_user = uuid.uuid4()
    second_user = uuid.uuid4()

    with controller.run_slot(first_user):
        assert controller.active_for_user(first_user) == 1
        with pytest.raises(AnalysisUserConcurrencyExceeded):
            with controller.run_slot(first_user):
                pytest.fail("the same user must not acquire a second slot")
        with controller.run_slot(second_user):
            assert controller.active_for_user(second_user) == 1

    assert controller.active_for_user(first_user) == 0
    assert controller.active_for_user(second_user) == 0


def test_global_capacity_is_shared_and_exhaustion_raises() -> None:
    controller = make_controller(global_limit=1, queue_wait_seconds=0)

    with controller.global_slot():
        assert controller.active_global == 1
        with pytest.raises(AnalysisCapacityExceeded) as exc_info:
            with controller.global_slot():
                pytest.fail("global capacity must not be exceeded")

    assert exc_info.value.retry_after_seconds == 1
    assert controller.active_global == 0


def test_slots_release_after_success_and_ordinary_exception() -> None:
    controller = make_controller()
    user_id = uuid.uuid4()

    with controller.global_slot():
        pass
    with controller.run_slot(user_id):
        pass
    assert controller.active_global == 0
    assert controller.active_for_user(user_id) == 0

    with pytest.raises(ValueError):
        with controller.global_slot():
            with controller.run_slot(user_id):
                raise ValueError("pipeline failure")

    assert controller.active_global == 0
    assert controller.active_for_user(user_id) == 0


@pytest.mark.parametrize(
    "error_type",
    [AnalysisDeadlineExceededError, AnalysisExecutionAbortedError],
)
def test_slots_release_after_deadline_and_abort(error_type: type[Exception]) -> None:
    controller = make_controller()
    user_id = uuid.uuid4()

    with pytest.raises(error_type):
        with controller.global_slot():
            with controller.run_slot(user_id):
                raise error_type()

    assert controller.active_global == 0
    assert controller.active_for_user(user_id) == 0


def test_leases_are_idempotent_and_cannot_underflow() -> None:
    controller = make_controller()
    user_id = uuid.uuid4()

    global_lease = controller.acquire_global()
    global_lease.release()
    global_lease.release()
    assert controller.active_global == 0

    user_lease = controller.acquire_run_slot(user_id)
    user_lease.release()
    user_lease.release()
    assert controller.active_for_user(user_id) == 0


def test_reset_refuses_to_replace_a_live_semaphore() -> None:
    controller = make_controller(global_limit=1)
    user_id = uuid.uuid4()

    with controller.global_slot():
        with pytest.raises(RuntimeError):
            controller.reset()

    with controller.run_slot(user_id):
        with pytest.raises(RuntimeError):
            controller.reset()

    controller.reset()
    assert controller.active_global == 0
    assert controller.active_for_user(user_id) == 0


def test_reset_rebuilds_from_settings_when_values_are_omitted() -> None:
    controller = make_controller(global_limit=1, per_user_limit=1, queue_wait_seconds=0)

    controller.reset()

    assert controller.global_limit == settings.analysis_max_concurrent_jobs
    assert controller.per_user_limit == settings.analysis_max_concurrent_jobs_per_user
    assert controller.queue_wait_seconds == settings.analysis_queue_wait_seconds


def test_global_wait_acquires_capacity_when_a_holder_releases() -> None:
    controller = make_controller(global_limit=1, queue_wait_seconds=5)
    acquired = threading.Event()
    failures: list[BaseException] = []

    def waiter() -> None:
        try:
            with controller.global_slot():
                acquired.set()
        except BaseException as exc:  # noqa: BLE001 - surfaced through the assertion below
            failures.append(exc)

    with controller.global_slot():
        thread = threading.Thread(target=waiter)
        thread.start()

    thread.join(timeout=10)

    assert not thread.is_alive()
    assert failures == []
    assert acquired.is_set()
    assert controller.active_global == 0


def test_concurrent_acquisitions_never_exceed_global_capacity() -> None:
    controller = make_controller(global_limit=2, per_user_limit=1, queue_wait_seconds=5)
    worker_count = 8
    start_barrier = threading.Barrier(worker_count + 1)
    pair_barrier = threading.Barrier(2)
    lock = threading.Lock()
    active = 0
    max_active = 0
    acquired = 0
    failures: list[BaseException] = []

    def worker() -> None:
        nonlocal active, max_active, acquired
        try:
            start_barrier.wait(timeout=10)
            with controller.global_slot():
                with lock:
                    active += 1
                    acquired += 1
                    max_active = max(max_active, active)
                # Two permit holders meet here, guaranteeing observable overlap.
                pair_barrier.wait(timeout=10)
                with lock:
                    active -= 1
        except BaseException as exc:  # noqa: BLE001 - surfaced through the assertion below
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    try:
        start_barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=20)
    finally:
        for thread in threads:
            thread.join(timeout=5)

    assert not any(thread.is_alive() for thread in threads)
    assert failures == []
    assert acquired == worker_count
    assert max_active <= 2
    assert controller.active_global == 0


def test_concurrent_rate_limit_checks_are_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "analysis_rate_limit_max_requests", 3)
    monkeypatch.setattr(settings, "analysis_rate_limit_window_seconds", 60)
    controller = make_controller()
    user_id = uuid.uuid4()
    worker_count = 8
    barrier = threading.Barrier(worker_count)
    lock = threading.Lock()
    allowed = 0
    rejected = 0

    def worker() -> None:
        nonlocal allowed, rejected
        barrier.wait(timeout=10)
        try:
            controller.check_rate_limit(ANALYSIS_RUN_SCOPE, user_id)
        except AnalysisRateLimitExceeded:
            with lock:
                rejected += 1
        else:
            with lock:
                allowed += 1

    threads = [threading.Thread(target=worker) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert allowed == 3
    assert rejected == worker_count - 3
