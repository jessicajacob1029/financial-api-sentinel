"""Attacker sophistication scoring (Phase 7C.7).

Standalone, like ja4_registry.py / rate_limiter.py / audit_log.py -- reads
the hard-signal fields proxy/engine.py's Decision already exposes on every
outcome (PASS or BLOCK; jkt_match and dpop_valid are computed before the
hard-signal checks short-circuit, so they're populated either way) and
turns them into a single number. Doesn't touch engine.py or change what it
decides -- purely a presentation-layer read of an already-public contract.

Build Spec's example (doc 07 SS7C.7): Script B (bearer token only, no
private key, different TLS stack) matches 0/3 hard signals -- low
sophistication. A hypothetical stronger attacker matching JA4 + jkt but
not IP would score higher, since IP is a soft signal, not one of these
three. The three hard signals scored here are exactly the three that are
attacker-*defeatable* by getting closer to a real client (spoofing DPoP,
matching the TLS stack, stealing the private key) -- token revocation
isn't included because it's an administrative state, not something an
attacker's request characteristics can "match" their way into.
"""

from dataclasses import dataclass

from proxy.engine import Decision

TOTAL_SIGNALS = 3

_LABELS = {
    0: "trivial",
    1: "low",
    2: "moderate",
    3: "high",
}


@dataclass(frozen=True)
class SophisticationScore:
    matched_signals: tuple[str, ...]
    score: int
    total: int
    label: str


def compute_sophistication(decision: Decision) -> SophisticationScore:
    matched = []
    if decision.dpop_valid:
        matched.append("dpop_valid")
    if decision.presented_ja4 == decision.bound_ja4:
        matched.append("ja4_match")
    if decision.jkt_match:
        matched.append("jkt_match")

    score = len(matched)
    return SophisticationScore(
        matched_signals=tuple(matched), score=score, total=TOTAL_SIGNALS, label=_LABELS[score]
    )
