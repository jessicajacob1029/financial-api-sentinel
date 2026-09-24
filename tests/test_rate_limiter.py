"""Unit tests for proxy/rate_limiter.py (Phase 7C.3)."""

from proxy.rate_limiter import SlidingWindowRateLimiter


def test_allows_up_to_the_limit():
    limiter = SlidingWindowRateLimiter(max_attempts=3, window_seconds=30)

    for _ in range(3):
        result = limiter.check_and_record("ja4-a", now=1000.0)
        assert result.allowed is True


def test_blocks_beyond_the_limit():
    limiter = SlidingWindowRateLimiter(max_attempts=3, window_seconds=30)

    for _ in range(3):
        limiter.check_and_record("ja4-a", now=1000.0)

    result = limiter.check_and_record("ja4-a", now=1000.0)

    assert result.allowed is False
    assert result.attempts_in_window == 4
    assert result.limit == 3


def test_old_attempts_fall_out_of_the_window():
    limiter = SlidingWindowRateLimiter(max_attempts=2, window_seconds=10)

    limiter.check_and_record("ja4-a", now=1000.0)
    limiter.check_and_record("ja4-a", now=1001.0)
    blocked = limiter.check_and_record("ja4-a", now=1002.0)
    assert blocked.allowed is False

    # Past the window -- the first two attempts should have expired.
    allowed_again = limiter.check_and_record("ja4-a", now=1012.0)
    assert allowed_again.allowed is True


def test_keys_are_independent():
    limiter = SlidingWindowRateLimiter(max_attempts=1, window_seconds=30)

    limiter.check_and_record("ja4-a", now=1000.0)
    result_a = limiter.check_and_record("ja4-a", now=1000.0)
    result_b = limiter.check_and_record("ja4-b", now=1000.0)

    assert result_a.allowed is False  # ja4-a is over its own limit
    assert result_b.allowed is True  # ja4-b has its own independent window
