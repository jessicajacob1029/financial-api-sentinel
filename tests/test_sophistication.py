"""Unit tests for proxy/sophistication.py (Phase 7C.7).

Acceptance (doc SS7C.7): running Script B (bearer token only, no key,
different TLS stack) and Script C (full session compromise, only IP
differs) produces visibly different sophistication scores, with the one
matching more hard signals scoring higher.
"""

from proxy.binding import Binding
from proxy.dpop import DpopResult
from proxy.engine import evaluate
from proxy.sophistication import compute_sophistication

BOUND_JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"
BOUND_JKT = "VG30sUVn0Xkm5CrHnK82euqlGb8tRwCsUfKq9aOpzy4"
BOUND_IP = "10.0.0.1"


def _binding(**overrides) -> Binding:
    defaults = dict(jti="tok-1", jkt=BOUND_JKT, ja4=BOUND_JA4, source_ip=BOUND_IP, issued_at=1_000_000)
    defaults.update(overrides)
    return Binding(**defaults)


def _dpop(**overrides) -> DpopResult:
    defaults = dict(valid=True, jkt=BOUND_JKT, jti="proof-1", reason="ok")
    defaults.update(overrides)
    return DpopResult(**defaults)


def test_full_match_scores_3_of_3_high():
    decision = evaluate(_binding(), BOUND_JA4, _dpop(), BOUND_IP, ja4h=None)

    result = compute_sophistication(decision)

    assert result.score == 3
    assert result.total == 3
    assert result.label == "high"
    assert set(result.matched_signals) == {"dpop_valid", "ja4_match", "jkt_match"}


def test_script_b_style_bearer_theft_scores_low():
    """Script B: valid-looking proof from its own forged key (dpop_valid),
    but a different TLS stack (ja4 mismatch) and no access to the real
    private key (jkt mismatch) -- matches only 1 of 3."""
    decision = evaluate(
        _binding(),
        "t13i9999h1_deadbeef0000_000000000000",
        _dpop(jkt="attacker-own-key-thumbprint"),
        BOUND_IP,
        ja4h=None,
    )

    result = compute_sophistication(decision)

    assert result.score == 1
    assert result.matched_signals == ("dpop_valid",)
    assert result.label == "low"


def test_script_c_style_session_hijack_scores_high():
    """Script C: full session compromise (real key, real TLS stack) --
    only the network path (a soft signal, not scored here) differs."""
    decision = evaluate(_binding(), BOUND_JA4, _dpop(), "203.0.113.7", ja4h=None)

    result = compute_sophistication(decision)

    assert result.score == 3
    assert result.label == "high"


def test_script_c_scores_strictly_higher_than_script_b():
    """The doc's core acceptance criterion, checked directly: the more
    sophisticated attacker (C) is demonstrably harder to catch than the
    less sophisticated one (B) -- reflected as a strictly higher score."""
    script_b = compute_sophistication(
        evaluate(
            _binding(),
            "t13i9999h1_deadbeef0000_000000000000",
            _dpop(jkt="attacker-own-key-thumbprint"),
            BOUND_IP,
            ja4h=None,
        )
    )
    script_c = compute_sophistication(evaluate(_binding(), BOUND_JA4, _dpop(), "203.0.113.7", ja4h=None))

    assert script_c.score > script_b.score


def test_invalid_dpop_and_everything_else_wrong_scores_0_trivial():
    decision = evaluate(
        _binding(),
        "t13i9999h1_deadbeef0000_000000000000",
        _dpop(valid=False, jkt=None, reason="signature verification failed"),
        "203.0.113.7",
        ja4h=None,
    )

    result = compute_sophistication(decision)

    assert result.score == 0
    assert result.matched_signals == ()
    assert result.label == "trivial"


def test_soft_signal_alone_does_not_affect_score():
    """IP roam (soft signal) with everything else matching -- still 3/3,
    since sophistication only scores the three hard, attacker-defeatable
    signals, consistent with engine.py's own hard/soft split."""
    decision = evaluate(_binding(), BOUND_JA4, _dpop(), "198.51.100.9", ja4h=None)

    result = compute_sophistication(decision)

    assert decision.outcome == "PASS"  # IP delta alone doesn't block
    assert result.score == 3
