"""In-memory binding cache (TD-5).

Binds an issued token's jti to the DPoP key thumbprint and JA4 TLS
fingerprint it was issued to, so later requests presenting that token can
be checked against what it actually was issued to.

BindingStore is an abstract interface with one in-memory implementation
behind it (doc 04 SS8: dependency inversion) so a Redis-backed store could
later be swapped in without touching engine.py or addon.py.
"""

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from config import TOKEN_TTL_SECONDS


@dataclass
class Binding:
    jti: str
    jkt: str
    ja4: str
    source_ip: str
    issued_at: int
    ja4h: str | None = None
    # Phase 7C.1: an explicitly revoked token must block immediately, not
    # merely at its natural TTL expiry -- full lifecycle, not just
    # issuance. Checked as a hard signal in engine.py, ahead of DPoP/JA4/
    # jkt, so a revoked token's block reason is always "token revoked"
    # rather than whatever else might incidentally also be wrong.
    revoked: bool = False


class BindingStore(ABC):
    @abstractmethod
    def bind(
        self,
        jti: str,
        jkt: str,
        ja4: str,
        source_ip: str,
        issued_at: int,
        ja4h: str | None = None,
    ) -> None: ...

    @abstractmethod
    def get(self, jti: str) -> Binding | None: ...

    @abstractmethod
    def seen_dpop_jti(self, jti: str) -> bool: ...

    @abstractmethod
    def mark_dpop_jti(self, jti: str) -> None: ...

    @abstractmethod
    def revoke(self, jti: str) -> bool:
        """Mark a binding revoked. Returns True if a binding for `jti`
        existed (and is now revoked), False if there was nothing to
        revoke -- lets the caller (the /oauth/revoke handler) distinguish
        "revoked" from "no such token" in its response."""
        ...


class InMemoryBindingStore(BindingStore):
    """Demo-scope store: dict + set guarded by one lock. No persistence."""

    def __init__(self) -> None:
        self._bindings: dict[str, Binding] = {}
        self._dpop_jti_seen: set[str] = set()
        self._lock = threading.Lock()

    def bind(
        self,
        jti: str,
        jkt: str,
        ja4: str,
        source_ip: str,
        issued_at: int,
        ja4h: str | None = None,
    ) -> None:
        with self._lock:
            self._bindings[jti] = Binding(
                jti=jti, jkt=jkt, ja4=ja4, source_ip=source_ip, issued_at=issued_at, ja4h=ja4h
            )

    def get(self, jti: str) -> Binding | None:
        with self._lock:
            binding = self._bindings.get(jti)
            if binding is None:
                return None
            # doc 04 SS4: a binding must not outlive the token it was
            # issued for -- don't let an expired token ride on a still-
            # cached binding.
            if time.time() - binding.issued_at > TOKEN_TTL_SECONDS:
                del self._bindings[jti]
                return None
            return binding

    def seen_dpop_jti(self, jti: str) -> bool:
        """Inspect only -- does not mark. See check_and_mark_dpop_jti for
        the atomic enforcement primitive real call sites should use."""
        with self._lock:
            return jti in self._dpop_jti_seen

    def mark_dpop_jti(self, jti: str) -> None:
        with self._lock:
            self._dpop_jti_seen.add(jti)

    def revoke(self, jti: str) -> bool:
        with self._lock:
            binding = self._bindings.get(jti)
            if binding is None:
                return False
            binding.revoked = True
            return True

    def check_and_mark_dpop_jti(self, jti: str) -> bool:
        """Atomic check-and-set: returns True if `jti` is fresh (and marks
        it seen in the same critical section), False if it was already
        seen. doc 04 SS4 requires this be atomic to avoid a race where two
        near-simultaneous replays of the same DPoP proof both pass a
        separate seen-check before either marks it. Not in the Build Spec
        SS2.3 contract's literal 4-method list; added because that split
        (seen_dpop_jti then mark_dpop_jti as two calls) can't be made
        atomic from outside the store, since callers can't reach its lock.
        """
        with self._lock:
            if jti in self._dpop_jti_seen:
                return False
            self._dpop_jti_seen.add(jti)
            return True
