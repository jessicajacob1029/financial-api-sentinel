"""Tests for proxy/binding.py (Build Spec SS2.3 acceptance criteria)."""

import time

from config import TOKEN_TTL_SECONDS
from proxy.binding import InMemoryBindingStore


def test_bind_then_get_round_trips():
    store = InMemoryBindingStore()

    store.bind(jti="tok-1", jkt="jkt-1", ja4="ja4-1", source_ip="10.0.0.1", issued_at=int(time.time()))
    binding = store.get("tok-1")

    assert binding is not None
    assert binding.jti == "tok-1"
    assert binding.jkt == "jkt-1"
    assert binding.ja4 == "ja4-1"
    assert binding.source_ip == "10.0.0.1"


def test_get_unknown_jti_returns_none():
    store = InMemoryBindingStore()

    assert store.get("never-bound") is None


def test_get_expired_binding_returns_none_and_evicts():
    store = InMemoryBindingStore()
    long_ago = int(time.time()) - TOKEN_TTL_SECONDS - 10

    store.bind(jti="tok-1", jkt="jkt-1", ja4="ja4-1", source_ip="10.0.0.1", issued_at=long_ago)

    assert store.get("tok-1") is None  # doc 04 SS4: expired bindings must not be served


def test_replay_cache_rejects_a_repeated_jti():
    store = InMemoryBindingStore()

    assert store.seen_dpop_jti("proof-1") is False
    store.mark_dpop_jti("proof-1")
    assert store.seen_dpop_jti("proof-1") is True


def test_check_and_mark_is_atomic_first_call_wins():
    store = InMemoryBindingStore()

    assert store.check_and_mark_dpop_jti("proof-1") is True  # first sighting: fresh
    assert store.check_and_mark_dpop_jti("proof-1") is False  # second sighting: replay


def test_binding_defaults_to_not_revoked():
    store = InMemoryBindingStore()
    store.bind(jti="tok-1", jkt="jkt-1", ja4="ja4-1", source_ip="10.0.0.1", issued_at=int(time.time()))

    assert store.get("tok-1").revoked is False


def test_revoke_marks_an_existing_binding():
    store = InMemoryBindingStore()
    store.bind(jti="tok-1", jkt="jkt-1", ja4="ja4-1", source_ip="10.0.0.1", issued_at=int(time.time()))

    assert store.revoke("tok-1") is True
    assert store.get("tok-1").revoked is True


def test_revoke_unknown_jti_returns_false():
    store = InMemoryBindingStore()

    assert store.revoke("never-bound") is False
