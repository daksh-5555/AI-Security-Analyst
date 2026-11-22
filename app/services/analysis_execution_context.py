"""Cooperative execution limits for the synchronous analysis pipeline."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class AnalysisExecutionError(RuntimeError):
    """Base class for cooperative analysis execution stops."""


class AnalysisDeadlineExceededError(AnalysisExecutionError):
    """Raised when the monotonic analysis deadline has expired."""

    def __init__(self) -> None:
        super().__init__("Analysis timed out")


class AnalysisExecutionAbortedError(AnalysisExecutionError):
    """Raised when the lease was lost or cancellation was requested."""

    def __init__(self) -> None:
        super().__init__("Analysis execution aborted")


class AnalysisExecutionContext:
    """A monotonic deadline paired with a cooperative abort signal.

    Elapsed time is measured only with the injected monotonic clock. Wall-clock
    timestamps are deliberately not consulted, so system clock adjustments
    cannot extend or shorten a run.
    """

    def __init__(
        self,
        timeout_seconds: float,
        *,
        clock: Callable[[], float] | None = None,
        abort_event: threading.Event | None = None,
    ) -> None:
        self._clock = clock or time.monotonic
        self._deadline = self._clock() + timeout_seconds
        self._timeout_seconds = timeout_seconds
        self._abort_event = abort_event if abort_event is not None else threading.Event()

    @property
    def deadline(self) -> float:
        """Monotonic instant at which execution must stop."""
        return self._deadline

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    @property
    def abort_event(self) -> threading.Event:
        """Event shared with the heartbeat thread."""
        return self._abort_event

    def remaining_seconds(self) -> float:
        """Seconds left before the deadline (never negative)."""
        return max(0.0, self._deadline - self._clock())

    def child(self, max_seconds: float | None = None) -> AnalysisExecutionContext:
        """Return a context for one bounded step of this execution.

        The child shares this context's clock and abort event, so cancellation
        propagates, and its deadline is the earlier of the parent deadline and
        ``max_seconds`` from now. A child can never outlive its parent.
        """
        remaining = self.remaining_seconds()
        budget = remaining if max_seconds is None else min(remaining, max(0.0, max_seconds))
        return AnalysisExecutionContext(budget, clock=self._clock, abort_event=self._abort_event)

    def request_abort(self) -> None:
        """Signal that the run's lease is no longer valid."""
        self._abort_event.set()

    def should_continue(self) -> bool:
        """Return whether work may continue without raising."""
        return not self._abort_event.is_set() and self._clock() < self._deadline

    def check(self) -> None:
        """Raise when execution should stop.

        An explicit abort wins over deadline expiry so lease loss is not
        misreported as a timeout.
        """
        if self._abort_event.is_set():
            raise AnalysisExecutionAbortedError
        if self._clock() >= self._deadline:
            raise AnalysisDeadlineExceededError


__all__ = [
    "AnalysisDeadlineExceededError",
    "AnalysisExecutionAbortedError",
    "AnalysisExecutionContext",
    "AnalysisExecutionError",
]
