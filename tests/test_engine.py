"""Truth-table tests for proxy/engine.py (Build Spec SS8, doc 04 SS9).

Covers every hard signal individually, the soft-signal-alone-doesn't-block
case explicitly called out in Build Spec SS2.4's acceptance criteria, the
risk-threshold-blocks case, and the fail-closed regression required by
doc 04 SS5.
"""

from proxy import engine as engine_module
from proxy.binding import Binding
from proxy.dpop import DpopResult
from proxy.engine import evaluate

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


def test_everything_matches_passes():
    decision = evaluate(_binding(), BOUND_JA4, _dpop(), BOUND_IP, ja4h=None)

    assert decision.outcome == "PASS"
    assert decision.risk_score == 0


def test_ja4_mismatch_blocks_with_reason():
    decision = evaluate(_binding(), "t13i9999h1_deadbeef0000_000000000000", _dpop(), BOUND_IP, ja4h=None)

    assert decision.outcome == "BLOCK"
    assert decision.reason == "JA4 mismatch"


def test_jkt_mismatch_blocks_with_reason():
    decision = evaluate(_binding(), BOUND_JA4, _dpop(jkt="a-different-thumbprint"), BOUND_IP, ja4h=None)

    assert decision.outcome == "BLOCK"
    assert decision.reason == "DPoP jkt mismatch"


def test_invalid_dpop_blocks_with_reason():
    decision = evaluate(
        _binding(), BOUND_JA4, _dpop(valid=False, jkt=None, reason="signature verification failed"), BOUND_IP, ja4h=None
    )

    assert decision.outcome == "BLOCK"
    assert "signature verification failed" in decision.reason


def test_ip_change_alone_does_not_block_a_legit_session():
    """Build Spec SS2.4 acceptance: soft signal alone must not block."""
    decision = evaluate(_binding(), BOUND_JA4, _dpop(), "203.0.113.5", ja4h=None)

    assert decision.outcome == "PASS"
    assert decision.ip_delta is True
    assert decision.risk_score == 1


def test_ip_change_plus_ja4h_change_crosses_threshold_and_blocks():
    binding = _binding(ja4h="ja4h-original")
    decision = evaluate(binding, BOUND_JA4, _dpop(), "203.0.113.5", ja4h="ja4h-different")

    assert decision.risk_score == 3  # ip_delta(+1) + ja4h_delta(+2) >= RISK_THRESHOLD(2)
    assert decision.outcome == "BLOCK"
    assert decision.reason == "risk threshold exceeded"


def test_hard_signal_failure_blocks_even_with_zero_risk_score():
    """A hard failure blocks regardless of the risk score, not just above threshold."""
    decision = evaluate(_binding(), "t13i0000h1_x_x", _dpop(), BOUND_IP, ja4h=None)

    assert decision.risk_score == 0
    assert decision.outcome == "BLOCK"


def test_revoked_token_blocks_even_with_everything_else_valid():
    """7C.1: an explicitly revoked token blocks on the very next request,
    even though every other signal (DPoP, JA4, jkt) still matches."""
    binding = _binding(revoked=True)

    decision = evaluate(binding, BOUND_JA4, _dpop(), BOUND_IP, ja4h=None)

    assert decision.outcome == "BLOCK"
    assert decision.reason == "token revoked"


def test_revocation_reason_wins_over_other_hard_failures():
    """Revocation is checked first -- if a request is BOTH revoked and,
    say, JA4-mismatched, the reported reason should be the explicit
    administrative one, not a coincidental technical one."""
    binding = _binding(revoked=True)

    decision = evaluate(binding, "t13i9999h1_deadbeef0000_000000000000", _dpop(), BOUND_IP, ja4h=None)

    assert decision.outcome == "BLOCK"
    assert decision.reason == "token revoked"


def test_fail_closed_on_internal_exception(monkeypatch):
    """doc 04 SS5: an exception in the engine must yield BLOCK, never PASS."""

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(engine_module, "_evaluate_inner", _boom)

    decision = evaluate(_binding(), BOUND_JA4, _dpop(), BOUND_IP, ja4h=None)

    assert decision.outcome == "BLOCK"
    assert decision.reason == "internal engine error"
