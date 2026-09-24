"""Unit tests for proxy/challenge_store.py (Phase 7C.2)."""

from proxy.challenge_store import ChallengeStore


def test_issue_then_verify_succeeds():
    store = ChallengeStore(ttl_seconds=30)

    nonce = store.issue("tok-1", now=1000.0)

    assert store.verify_and_consume("tok-1", nonce, now=1001.0) is True


def test_nonce_is_single_use():
    store = ChallengeStore(ttl_seconds=30)
    nonce = store.issue("tok-1", now=1000.0)

    assert store.verify_and_consume("tok-1", nonce, now=1001.0) is True
    assert store.verify_and_consume("tok-1", nonce, now=1002.0) is False  # already consumed


def test_wrong_nonce_fails():
    store = ChallengeStore(ttl_seconds=30)
    store.issue("tok-1", now=1000.0)

    assert store.verify_and_consume("tok-1", "not-the-real-nonce", now=1001.0) is False


def test_expired_nonce_fails():
    store = ChallengeStore(ttl_seconds=30)
    nonce = store.issue("tok-1", now=1000.0)

    assert store.verify_and_consume("tok-1", nonce, now=1031.0) is False  # 31s later, past the 30s TTL


def test_no_outstanding_challenge_fails():
    store = ChallengeStore(ttl_seconds=30)

    assert store.verify_and_consume("never-issued", "some-nonce", now=1000.0) is False


def test_missing_nonce_fails():
    store = ChallengeStore(ttl_seconds=30)
    store.issue("tok-1", now=1000.0)

    assert store.verify_and_consume("tok-1", None, now=1001.0) is False


def test_reissuing_replaces_the_prior_challenge():
    store = ChallengeStore(ttl_seconds=30)
    old_nonce = store.issue("tok-1", now=1000.0)
    new_nonce = store.issue("tok-1", now=1005.0)

    assert old_nonce != new_nonce
    assert store.verify_and_consume("tok-1", old_nonce, now=1006.0) is False
    assert store.verify_and_consume("tok-1", new_nonce, now=1006.0) is True
