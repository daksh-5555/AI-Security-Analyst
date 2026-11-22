"""Process-local admission control for expensive analysis execution.

Both the analysis-run creation endpoint and the attack-surface summary endpoint
execute the same expensive analysis pipeline. They share the global capacity
managed here, while only analysis-run creation consumes a per-user in-flight
slot.

The controls are deliberately process-local. Every worker process keeps its own
rate-limit counters, per-user counters, and semaphore, so with ``N`` workers the
effective limits are approximately ``N`` times the configured values. Multiple
application instances multiply capacity further. There is no distributed queue,
distributed lock, or deployment-wide enforcement, and no guaranteed FIFO
ordering or strict starvation prevention.

The API routes that use this controller are synchronous, so waiting for global
capacity blocks a worker thread. The wait is bounded by
``ANALYSIS_QUEUE_WAIT_SECONDS`` and happens before the analysis execution
deadline is created, so the execution timeout measures pipeline work only. The
worst-case request duration is approximately ``queue wait + execution timeout``.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from app.core.config import settings
from app.core.rate_limit import AuthRateLimiter

ANALYSIS_RUN_SCOPE = "analysis.run"
ANALYSIS_SUMMARY_SCOPE = "analysis.summary"
EXPLANATION_SCOPE = "analysis.explanation"

_RATE_LIMIT_SCOPES = frozenset({ANALYSIS_RUN_SCOPE, ANALYSIS_SUMMARY_SCOPE, EXPLANATION_SCOPE})

# A separate limiter instance keeps analysis quotas independent from the
# authentication limiter even though both use the same sliding-window class.
analysis_rate_limiter = AuthRateLimiter()


class AnalysisAdmissionError(Exception):
    """Base class for sanitized admission rejections.

    ``retry_after_seconds`` is always a positive integer suitable for the
    ``Retry-After`` response header.
    """

    def __init__(self, message: str, retry_after_seconds: int) -> None:
        self.retry_after_seconds = max(1, int(retry_after_seconds))
        super().__init__(message)


class AnalysisRateLimitExceeded(AnalysisAdmissionError):
    """Raised when the per-user request rate limit for a scope is exhausted."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Analysis request rate limit exceeded", retry_after_seconds)


class AnalysisUserConcurrencyExceeded(AnalysisAdmissionError):
    """Raised when the user already has the maximum number of in-flight runs."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Too many concurrent analysis runs for this user", retry_after_seconds)


class AnalysisCapacityExceeded(AnalysisAdmissionError):
    """Raised when global analysis capacity cannot be acquired in time."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Analysis capacity is temporarily unavailable", retry_after_seconds)


class _GlobalLease:
    """One global permit. ``release`` is idempotent so callers cannot double-release."""

    def __init__(self, controller: AnalysisAdmissionController) -> None:
        self._controller = controller
        self._released = False

    def __enter__(self) -> _GlobalLease:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._controller._release_global()


class _UserLease:
    """One per-user in-flight slot. ``release`` is idempotent."""

    def __init__(self, controller: AnalysisAdmissionController, user_id: uuid.UUID) -> None:
        self._controller = controller
        self._user_id = user_id
        self._released = False

    def __enter__(self) -> _UserLease:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._controller._release_user(self._user_id)


class AnalysisAdmissionController:
    """Thread-safe, process-local admission controller for analysis execution."""

    def __init__(
        self,
        *,
        global_limit: int | None = None,
        per_user_limit: int | None = None,
        queue_wait_seconds: int | None = None,
        rate_limiter: AuthRateLimiter | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._global_limit = (
            settings.analysis_max_concurrent_jobs if global_limit is None else global_limit
        )
        self._per_user_limit = (
            settings.analysis_max_concurrent_jobs_per_user
            if per_user_limit is None
            else per_user_limit
        )
        self._queue_wait_seconds = (
            settings.analysis_queue_wait_seconds
            if queue_wait_seconds is None
            else queue_wait_seconds
        )
        self._validate_limits(self._global_limit, self._per_user_limit, self._queue_wait_seconds)
        self._semaphore = threading.BoundedSemaphore(self._global_limit)
        self._user_slots: dict[uuid.UUID, int] = {}
        self._active_global = 0
        self._pending_global = 0
        self._rate_limiter = rate_limiter if rate_limiter is not None else analysis_rate_limiter

    @staticmethod
    def _validate_limits(global_limit: int, per_user_limit: int, queue_wait_seconds: int) -> None:
        if global_limit < 1:
            raise ValueError("global_limit must be at least 1")
        if per_user_limit < 1:
            raise ValueError("per_user_limit must be at least 1")
        if per_user_limit > global_limit:
            raise ValueError("per_user_limit must not exceed global_limit")
        if queue_wait_seconds < 0:
            raise ValueError("queue_wait_seconds must not be negative")

    @property
    def rate_limiter(self) -> AuthRateLimiter:
        return self._rate_limiter

    @property
    def global_limit(self) -> int:
        return self._global_limit

    @property
    def per_user_limit(self) -> int:
        return self._per_user_limit

    @property
    def queue_wait_seconds(self) -> int:
        return self._queue_wait_seconds

    @property
    def active_global(self) -> int:
        """Number of global permits currently held. Test and monitoring aid."""
        with self._lock:
            return self._active_global

    def active_for_user(self, user_id: uuid.UUID) -> int:
        """Number of in-flight run slots held by ``user_id``."""
        with self._lock:
            return self._user_slots.get(user_id, 0)

    def check_rate_limit(
        self,
        scope: str,
        user_id: uuid.UUID,
        *,
        now: float | None = None,
    ) -> None:
        """Record one request for ``user_id`` or raise ``AnalysisRateLimitExceeded``.

        Explicit analysis settings are always passed to the limiter so analysis
        quotas never inherit authentication configuration.
        """
        if scope not in _RATE_LIMIT_SCOPES:
            raise ValueError(f"Unknown analysis rate-limit scope: {scope}")
        decision = self._rate_limiter.check(
            scope,
            str(user_id),
            max_requests=settings.analysis_rate_limit_max_requests,
            window_seconds=settings.analysis_rate_limit_window_seconds,
            now=now,
        )
        if not decision.allowed:
            raise AnalysisRateLimitExceeded(decision.retry_after_seconds)

    def acquire_global(self) -> _GlobalLease:
        """Acquire one global permit, waiting at most the configured interval."""
        # Track in-progress acquisitions so reset() cannot replace the semaphore
        # between a successful acquire and the active-permit increment.
        with self._lock:
            self._pending_global += 1
        try:
            if not self._semaphore.acquire(timeout=self._queue_wait_seconds):
                raise AnalysisCapacityExceeded(self._queue_retry_after())
            with self._lock:
                self._active_global += 1
        finally:
            with self._lock:
                self._pending_global -= 1
        return _GlobalLease(self)

    def _release_global(self) -> None:
        with self._lock:
            if self._active_global <= 0:
                raise RuntimeError("Global analysis capacity released without an active lease")
            self._active_global -= 1
        self._semaphore.release()

    @contextmanager
    def global_slot(self) -> Iterator[None]:
        """Context manager wrapping one global execution permit."""
        lease = self.acquire_global()
        try:
            yield
        finally:
            lease.release()

    def acquire_run_slot(self, user_id: uuid.UUID) -> _UserLease:
        """Atomically acquire one per-user in-flight slot or raise."""
        with self._lock:
            current = self._user_slots.get(user_id, 0)
            if current >= self._per_user_limit:
                raise AnalysisUserConcurrencyExceeded(self._queue_retry_after())
            self._user_slots[user_id] = current + 1
        return _UserLease(self, user_id)

    def _release_user(self, user_id: uuid.UUID) -> None:
        with self._lock:
            current = self._user_slots.get(user_id, 0)
            if current <= 0:
                raise RuntimeError("Per-user analysis slot released without an active lease")
            if current == 1:
                del self._user_slots[user_id]
            else:
                self._user_slots[user_id] = current - 1

    @contextmanager
    def run_slot(self, user_id: uuid.UUID) -> Iterator[None]:
        """Context manager wrapping one per-user run slot.

        Summary requests must never use this context manager.
        """
        lease = self.acquire_run_slot(user_id)
        try:
            yield
        finally:
            lease.release()

    def _queue_retry_after(self) -> int:
        """Bounded advisory hint; it does not predict pipeline completion."""
        return max(1, self._queue_wait_seconds)

    def reset(
        self,
        *,
        global_limit: int | None = None,
        per_user_limit: int | None = None,
        queue_wait_seconds: int | None = None,
    ) -> None:
        """Rebuild counters and capacity from settings, or from explicit values.

        Refuses to run while any lease is active so a live semaphore is never
        replaced. Intended for tests and explicit operational resets.
        """
        with self._lock:
            if (
                self._active_global != 0
                or self._pending_global != 0
                or any(count > 0 for count in self._user_slots.values())
            ):
                raise RuntimeError("Cannot reset analysis admission while slots are active")
            new_global = (
                settings.analysis_max_concurrent_jobs if global_limit is None else global_limit
            )
            new_per_user = (
                settings.analysis_max_concurrent_jobs_per_user
                if per_user_limit is None
                else per_user_limit
            )
            new_queue_wait = (
                settings.analysis_queue_wait_seconds
                if queue_wait_seconds is None
                else queue_wait_seconds
            )
            self._validate_limits(new_global, new_per_user, new_queue_wait)
            self._global_limit = new_global
            self._per_user_limit = new_per_user
            self._queue_wait_seconds = new_queue_wait
            self._semaphore = threading.BoundedSemaphore(new_global)
            self._active_global = 0
            self._pending_global = 0
            self._user_slots.clear()
            self._rate_limiter.reset()


analysis_admission = AnalysisAdmissionController()


__all__ = [
    "ANALYSIS_RUN_SCOPE",
    "ANALYSIS_SUMMARY_SCOPE",
    "AnalysisAdmissionController",
    "AnalysisAdmissionError",
    "AnalysisCapacityExceeded",
    "AnalysisRateLimitExceeded",
    "AnalysisUserConcurrencyExceeded",
    "analysis_admission",
    "analysis_rate_limiter",
]
