"""Step-up challenge/nonce store (Phase 7C.2).

Standalone, like rate_limiter.py and ja4_registry.py -- this is
orchestration state (which requests are mid-challenge), not part of
engine.py's decision contract. The engine never learns about challenges;
it only ever returns PASS or BLOCK. The addon is what turns a
borderline-risk PASS into "hold on, prove freshness first" by consulting
this store before forwarding -- see proxy/addon.py's docstring for why
that layering keeps engine.py's contract untouched.

Nonces are single-use (doc 04 SS4 atomicity precedent: check-and-consume
under one lock, same pattern as BindingStore.check_and_mark_dpop_jti) and
expire quickly (config.CHALLENGE_TTL_SECONDS) so a captured challenge
response can't be replayed indefinitely.
"""

import secrets
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class _Challenge:
    nonce: str
    issued_at: float


class ChallengeStore:
    def __init__(self, ttl_seconds: float) -> None:
        self._ttl_seconds = ttl_seconds
        self._challenges: dict[str, _Challenge] = {}
        self._lock = threading.Lock()

    def issue(self, jti: str, now: float | None = None) -> str:
        """A fresh nonce for this token, replacing any prior outstanding
        one (only the most recent challenge for a given jti is valid --
        no accumulating multiple live nonces per token)."""
        now = time.time() if now is None else now
        nonce = secrets.token_urlsafe(24)
        with self._lock:
            self._challenges[jti] = _Challenge(nonce=nonce, issued_at=now)
        return nonce

    def verify_and_consume(self, jti: str, presented_nonce: str | None, now: float | None = None) -> bool:
        """One-time use: a correct, unexpired nonce succeeds exactly once
        -- consumed atomically so a captured challenge-response can't be
        replayed even a second time."""
        if not presented_nonce:
            return False
        now = time.time() if now is None else now
        with self._lock:
            challenge = self._challenges.get(jti)
            if challenge is None:
                return False
            if now - challenge.issued_at > self._ttl_seconds:
                del self._challenges[jti]
                return False
            if not secrets.compare_digest(challenge.nonce, presented_nonce):
                return False
            del self._challenges[jti]
            return True
