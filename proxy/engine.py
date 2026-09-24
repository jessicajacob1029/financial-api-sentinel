"""Decision engine (TD-4): hard signals block, soft signals score.

Implements the Build Spec SS4 reference algorithm exactly: any failed hard
signal (token revoked, DPoP invalid, JA4 mismatch, jkt mismatch) is an
immediate BLOCK. Soft signals (IP delta, JA4H delta) accumulate a risk
score that only blocks above the policy's risk_threshold. This split is
what lets a legitimate mobile client roam networks (IP changes, soft)
without being blocked the same way a cross-stack token replay (JA4
mismatch, hard) is.

Phase 7C.1 extends the hard-signal set with `binding.revoked` -- an
explicitly revoked token blocks immediately, on the very next request,
regardless of every other signal passing. Phase 7C.5 moves the threshold
and soft-signal weights out of hardcoded constants into proxy/policy.py's
validated, YAML-loaded POLICY. These are the only two places Phase 7 is
pre-approved to touch this module's decision logic (see
07_PHASE7_DEMO_ENHANCEMENTS.md SS5). The hard-signal set itself and the
overall hard-before-soft evaluation order are NOT policy-configurable --
see policy.yaml's header comment for why that's deliberate.
"""

import time
from dataclasses import dataclass
from typing import Literal

from proxy.binding import Binding
from proxy.dpop import DpopResult
from proxy.policy import POLICY

Outcome = Literal["PASS", "BLOCK"]


@dataclass
class Decision:
    ts: int
    source_ip: str
    presented_ja4: str
    bound_ja4: str
    jkt_match: bool
    dpop_valid: bool
    ip_delta: bool
    risk_score: int
    outcome: Outcome
    reason: str


def evaluate(
    binding: Binding,
    presented_ja4: str,
    dpop: DpopResult,
    source_ip: str,
    ja4h: str | None,
) -> Decision:
    """Fails closed (doc 04 SS5): any unexpected exception evaluating
    signals returns BLOCK rather than propagating."""
    try:
        return _evaluate_inner(binding, presented_ja4, dpop, source_ip, ja4h)
    except Exception:
        return Decision(
            ts=int(time.time()),
            source_ip=source_ip,
            presented_ja4=presented_ja4,
            bound_ja4=getattr(binding, "ja4", ""),
            jkt_match=False,
            dpop_valid=False,
            ip_delta=True,
            risk_score=0,
            outcome="BLOCK",
            reason="internal engine error",
        )


def _evaluate_inner(
    binding: Binding,
    presented_ja4: str,
    dpop: DpopResult,
    source_ip: str,
    ja4h: str | None,
) -> Decision:
    now = int(time.time())
    jkt_match = dpop.jkt == binding.jkt
    ja4_match = presented_ja4 == binding.ja4
    ip_delta = source_ip != binding.source_ip
    ja4h_delta = bool(ja4h and binding.ja4h and ja4h != binding.ja4h)

    risk = 0
    if ip_delta:
        risk += POLICY.soft_signal_weights["ip_delta"]
    if ja4h_delta:
        risk += POLICY.soft_signal_weights["ja4h_delta"]

    def decision(outcome: Outcome, reason: str) -> Decision:
        return Decision(
            ts=now,
            source_ip=source_ip,
            presented_ja4=presented_ja4,
            bound_ja4=binding.ja4,
            jkt_match=jkt_match,
            dpop_valid=dpop.valid,
            ip_delta=ip_delta,
            risk_score=risk,
            outcome=outcome,
            reason=reason,
        )

    # Hard signals: any failure is an immediate block, checked before risk
    # score even matters. Revocation (7C.1) checked first -- an explicit
    # administrative action should always be the reported reason, not
    # whatever else might incidentally also be true about the request.
    if binding.revoked:
        return decision("BLOCK", "token revoked")
    if not dpop.valid:
        return decision("BLOCK", f"DPoP invalid: {dpop.reason}")
    if not ja4_match:
        return decision("BLOCK", "JA4 mismatch")
    if not jkt_match:
        return decision("BLOCK", "DPoP jkt mismatch")

    if risk >= POLICY.risk_threshold:
        return decision("BLOCK", "risk threshold exceeded")

    return decision("PASS", "ok")
