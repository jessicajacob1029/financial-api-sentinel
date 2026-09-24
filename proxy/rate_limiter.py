"""Sliding-window rate limiter for token issuance (Phase 7C.3).

A standalone component, deliberately not folded into proxy/binding.py:
per the kickoff process for this phase, only 7C.1 (revocation) and 7C.5
(policy engine) are pre-approved to touch engine.py/binding.py's core
contracts -- everything else is additive. Rate limiting is a distinct
concern from token/JA4/jkt binding anyway (throttling vs. fingerprint-
based detection), so keeping it separate is also just good separation of
concerns (doc 04 SS8), independent of that constraint.
"""

import collections
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    attempts_in_window: int
    limit: int


class SlidingWindowRateLimiter:
    """Demo-scope: in-memory per-key deque of attempt timestamps, guarded
    by one lock. Same posture as InMemoryBindingStore -- no persistence,
    good enough for a single-process localhost demo."""

    def __init__(self, max_attempts: int, window_seconds: float) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._attempts: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def check_and_record(self, key: str, now: float | None = None) -> RateLimitResult:
        """Atomic check-and-record, same pattern as
        BindingStore.check_and_mark_dpop_jti: always records this attempt
        (whether allowed or not), so a sustained burst stays rate-limited
        rather than the window resetting on every rejected attempt."""
        now = time.time() if now is None else now
        with self._lock:
            window = self._attempts[key]
            cutoff = now - self._window_seconds
            while window and window[0] < cutoff:
                window.popleft()

            allowed = len(window) < self._max_attempts
            window.append(now)
            return RateLimitResult(allowed=allowed, attempts_in_window=len(window), limit=self._max_attempts)
