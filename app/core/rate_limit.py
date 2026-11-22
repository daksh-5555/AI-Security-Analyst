"""Process-local in-memory rate limiting for authentication endpoints.

The limiter is intentionally simple: a sliding window of request timestamps per
``(scope, identity)`` pair. It is **not** distributed. Each worker process keeps
its own counters, so a multi-worker or multi-instance deployment only sees
per-process protection. Production deployments must add a shared limiter or
gateway-level protection; this module does not claim to provide that.

Memory is bounded without weakening enforcement. When the number of tracked
keys reaches ``max_tracked_keys``, expired keys are pruned first. Keys that still
hold events inside their window are never evicted, because evicting them would
let a client reset its own counter by flooding the limiter with new identities.
If the table is still full, a *new* identity is counted against a shared
per-scope overflow bucket instead of receiving its own entry. Under a key flood
the limiter therefore becomes stricter, never more permissive.

No third-party dependency or external store is introduced.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from app.core.config import settings

logger = logging.getLogger(__name__)

DEFAULT_MAX_TRACKED_KEYS = 10_000
OVERFLOW_IDENTITY = "__overflow__"


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of a single rate-limit check."""

    allowed: bool
    retry_after_seconds: int = 0


@dataclass
class _Bucket:
    window_seconds: float
    events: deque[float] = field(default_factory=deque)

    def expire(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.events and self.events[0] <= cutoff:
            self.events.popleft()

    def is_stale(self, now: float) -> bool:
        return not self.events or self.events[-1] <= now - self.window_seconds


class AuthRateLimiter:
    """Thread-safe, memory-bounded sliding-window limiter keyed by scope and identity."""

    def __init__(self, *, max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS) -> None:
        if max_tracked_keys < 1:
            raise ValueError("max_tracked_keys must be at least 1")
        self._max_tracked_keys = max_tracked_keys
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._overflow: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    @property
    def tracked_key_count(self) -> int:
        """Number of per-identity keys currently held (excludes overflow buckets)."""
        with self._lock:
            return len(self._buckets)

    def check(
        self,
        scope: str,
        identity: str,
        *,
        max_requests: int | None = None,
        window_seconds: int | None = None,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Record a request when allowed, otherwise report a retry delay."""
        limit, window = self._resolve(max_requests, window_seconds)
        if limit <= 0 or window <= 0:
            return RateLimitDecision(allowed=True)
        timestamp = time.monotonic() if now is None else now

        with self._lock:
            bucket = self._bucket(scope, identity, window, timestamp)
            decision = self._decide(bucket, limit, window, timestamp)
            if decision.allowed:
                bucket.events.append(timestamp)
            return decision

    def is_limited(
        self,
        scope: str,
        identity: str,
        *,
        max_requests: int,
        window_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Report whether ``identity`` has exhausted its allowance without recording."""
        if max_requests <= 0 or window_seconds <= 0:
            return RateLimitDecision(allowed=True)
        timestamp = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._existing_bucket(scope, identity)
            if bucket is None:
                return RateLimitDecision(allowed=True)
            return self._decide(bucket, max_requests, window_seconds, timestamp)

    def record(
        self,
        scope: str,
        identity: str,
        *,
        window_seconds: int,
        now: float | None = None,
    ) -> int:
        """Record one event unconditionally and return the in-window event count."""
        if window_seconds <= 0:
            return 0
        timestamp = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._bucket(scope, identity, window_seconds, timestamp)
            bucket.expire(timestamp)
            bucket.events.append(timestamp)
            return len(bucket.events)

    def clear(self, scope: str, identity: str) -> None:
        """Forget one identity's events (for example after a successful login)."""
        with self._lock:
            self._buckets.pop((scope, identity), None)

    def reset(self) -> None:
        """Clear all counters. Intended for tests and explicit operational resets."""
        with self._lock:
            self._buckets.clear()
            self._overflow.clear()

    @staticmethod
    def _resolve(max_requests: int | None, window_seconds: int | None) -> tuple[int, int]:
        limit = settings.auth_rate_limit_max_requests if max_requests is None else max_requests
        window = (
            settings.auth_rate_limit_window_seconds if window_seconds is None else window_seconds
        )
        return limit, window

    @staticmethod
    def _decide(bucket: _Bucket, limit: int, window: int, now: float) -> RateLimitDecision:
        bucket.expire(now)
        if len(bucket.events) >= limit:
            retry_after = max(1, math.ceil(window - (now - bucket.events[0])))
            return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)
        return RateLimitDecision(allowed=True)

    def _existing_bucket(self, scope: str, identity: str) -> _Bucket | None:
        bucket = self._buckets.get((scope, identity))
        if bucket is not None:
            return bucket
        # An identity routed to the overflow bucket stays subject to it.
        if len(self._buckets) >= self._max_tracked_keys:
            return self._overflow.get(scope)
        return None

    def _bucket(self, scope: str, identity: str, window: float, now: float) -> _Bucket:
        key = (scope, identity)
        bucket = self._buckets.get(key)
        if bucket is not None:
            bucket.window_seconds = window
            return bucket

        if len(self._buckets) >= self._max_tracked_keys:
            self._prune_stale_keys(now)
        if len(self._buckets) >= self._max_tracked_keys:
            overflow = self._overflow.get(scope)
            if overflow is None:
                overflow = _Bucket(window_seconds=window)
                self._overflow[scope] = overflow
                logger.warning(
                    "Rate limiter key capacity reached; new identities share an overflow bucket.",
                    extra={"security_event": "rate_limiter_overflow", "scope": scope},
                )
            overflow.window_seconds = window
            return overflow

        bucket = _Bucket(window_seconds=window)
        self._buckets[key] = bucket
        return bucket

    def _prune_stale_keys(self, now: float) -> None:
        """Drop keys whose every event is outside that key's own window."""
        stale = [key for key, bucket in self._buckets.items() if bucket.is_stale(now)]
        for key in stale:
            del self._buckets[key]
        for scope in [scope for scope, bucket in self._overflow.items() if bucket.is_stale(now)]:
            del self._overflow[scope]


auth_rate_limiter = AuthRateLimiter()
# Failed-login counters, kept separate from the per-endpoint request limiter.
login_failure_limiter = AuthRateLimiter()
# Bounds how many unauthenticated denials are written to the audit table.
unauthenticated_audit_limiter = AuthRateLimiter()
