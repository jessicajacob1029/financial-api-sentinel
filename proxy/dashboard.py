"""Live terminal dashboard (FR-9) and decision log (FR-10), built with Rich.

Presentation only -- no fingerprinting, DPoP, binding, or decision logic
lives here (doc 04 SS8). The addon feeds it typed events; it renders them.

Table rows are one-to-one with proxy/engine.py Decision objects, matching
Build Spec SS6's exact column spec. Requests blocked *before* a Decision
exists (missing/invalid/replayed DPoP proof, no binding found for the
presented token) still get a table row via record_raw_block, with "-"
placeholders for the fields a Decision would have had -- FR-9 promises
"blocked entries visually distinct" for every request, not only the ones
that made it as far as the engine.
"""

import collections
import datetime
from typing import Callable

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from proxy.engine import Decision
from proxy.policy import POLICY
from proxy.sophistication import SophisticationScore

MAX_ROWS = 15
MAX_LOG_LINES = 8


def _fmt_ts(epoch: int) -> str:
    return datetime.datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def _short_ja4(ja4: str | None) -> str:
    # Full JA4 stays in the decision log below the table; the table itself
    # truncates so rows stay one line regardless of terminal width -- a
    # real JA4 is unique enough in its first ~20 chars for a demo reviewer
    # to visually diff two rows at a glance.
    if not ja4:
        return "-"
    return ja4 if len(ja4) <= 22 else ja4[:19] + "..."


def _format_diff_line(diff: dict) -> str:
    # Scalar fields get their before/after inline; ciphers/extensions are
    # potentially long tuples of hex codes, so those just get a count of
    # how many entries differ -- the full lists go to the web dashboard's
    # per-row expansion (proxy/webdash.py), which has room for a table.
    parts = []
    for field, (bound_val, presented_val) in diff.items():
        if isinstance(bound_val, tuple):
            bound_set, presented_set = set(bound_val), set(presented_val)
            parts.append(f"{field}: {len(bound_set ^ presented_set)} entries differ")
        else:
            parts.append(f"{field}: {bound_val}->{presented_val}")
    return "JA4 diff (" + ", ".join(parts) + ")"


class Dashboard:
    def __init__(self) -> None:
        self._rows: collections.deque = collections.deque(maxlen=MAX_ROWS)
        self._log_lines: collections.deque = collections.deque(maxlen=MAX_LOG_LINES)
        # 7B.7: issuance events, kept separately from _rows since they're
        # not PASS/BLOCK decisions -- just enough history for a
        # newly-connected (or reloaded) web client's kill-chain timeline.
        self._issuances: collections.deque = collections.deque(maxlen=MAX_ROWS)
        self._total = 0
        self._passed = 0
        self._blocked = 0
        # 7C.3: tracked separately from _blocked -- throttling isn't a
        # fingerprint-based PASS/BLOCK decision, it's a distinct control
        # (doc SS7C.3: "logged distinctly from the engine's PASS/BLOCK
        # decisions... visible as its own event type").
        self._rate_limited = 0
        # 7C.2: requests held for step-up (neither auto-passed nor
        # auto-blocked), tracked distinctly from all of the above.
        self._challenges_issued = 0
        self._live = Live(self._render(), refresh_per_second=8, transient=False)
        # Optional fan-out to other sinks (e.g. the web dashboard's
        # WebSocket broadcaster). Presentation-only, same as the rest of
        # this module -- Dashboard doesn't know or care who's listening.
        self._listeners: list[Callable[[dict], None]] = []

    def add_listener(self, listener: Callable[[dict], None]) -> None:
        self._listeners.append(listener)

    def snapshot(self) -> dict:
        """Current full state, for a newly-connected listener to catch up on."""
        return {
            "type": "snapshot",
            "rows": list(self._rows),
            "log_lines": list(self._log_lines),
            "total": self._total,
            "passed": self._passed,
            "blocked": self._blocked,
            # 7B.6: the *actual* configured threshold, so the web
            # dashboard's interactive slider starts where the real engine
            # actually is, not a guessed default.
            "risk_threshold": POLICY.risk_threshold,
            "issuances": list(self._issuances),  # 7B.7
            "rate_limited": self._rate_limited,  # 7C.3
            "challenges_issued": self._challenges_issued,  # 7C.2
        }

    def start(self) -> None:
        self._live.start()

    def stop(self) -> None:
        self._live.stop()

    def record_decision(
        self,
        decision: Decision,
        ja4_diff: dict | None = None,
        handshake: dict | None = None,
        story_id: str | None = None,
        sophistication: SophisticationScore | None = None,
    ) -> None:
        """`ja4_diff` (7B.3): the field-by-field breakdown of what
        diverged, when `decision.reason == "JA4 mismatch"` -- as returned
        by proxy.ja4.diff_ja4(). None whenever a diff isn't applicable
        (PASS, or a block for any other reason). `handshake` (7A.2): the
        negotiated TLS version/cipher/ALPN/key-share-group for this
        connection, attached to every row so any connection -- not just
        blocked ones -- can be drilled into. `story_id` (7B.7): the
        token's jti, linking this event to its issuance and any other
        request that presented the same token, for the kill-chain view.
        `sophistication` (7C.7): how many of the three attacker-defeatable
        hard signals this request matched -- None only for the synthetic
        error-path Decision engine.py returns on an internal failure."""
        self._count(decision.outcome)
        row = {
            "ts": _fmt_ts(decision.ts),
            "source_ip": decision.source_ip,
            "presented_ja4": _short_ja4(decision.presented_ja4),
            "bound_ja4": _short_ja4(decision.bound_ja4),
            "jkt_ok": "yes" if decision.jkt_match else "no",
            "risk": str(decision.risk_score),
            "outcome": decision.outcome,
            "reason": decision.reason,  # 7B.4: shown on the topology animation's reject label
            "ja4_diff": ja4_diff,
            "handshake": handshake,
            "story_id": story_id,
            "sophistication_score": sophistication.score if sophistication else None,
            "sophistication_total": sophistication.total if sophistication else None,
            "sophistication_label": sophistication.label if sophistication else None,
        }
        self._rows.append(row)
        self._notify({"type": "row", "row": row})
        self.log(f"{_fmt_ts(decision.ts)} {decision.source_ip} {decision.outcome}: {decision.reason}")
        if ja4_diff:
            self.log(_format_diff_line(ja4_diff))

    def record_raw_block(
        self,
        ts: int,
        source_ip: str,
        presented_ja4: str | None,
        reason: str,
        handshake: dict | None = None,
        story_id: str | None = None,
    ) -> None:
        """A block that happened before a binding/Decision existed to compare against."""
        self._count("BLOCK")
        row = {
            "ts": _fmt_ts(ts),
            "source_ip": source_ip,
            "presented_ja4": _short_ja4(presented_ja4),
            "bound_ja4": "-",
            "jkt_ok": "-",
            "risk": "-",
            "outcome": "BLOCK",
            "reason": reason,
            "ja4_diff": None,
            "handshake": handshake,
            "story_id": story_id,
            "sophistication_score": None,
            "sophistication_total": None,
            "sophistication_label": None,
        }
        self._rows.append(row)
        self._notify({"type": "row", "row": row})
        self.log(f"{_fmt_ts(ts)} {source_ip} BLOCK: {reason}")

    def record_issuance(self, ts: int, jti: str, jkt: str, ja4: str, source_ip: str) -> None:
        """7B.7: the first link in a token's kill chain -- not a PASS/BLOCK
        decision, so it doesn't touch the table's row model or the
        total/passed/blocked counters, just notifies listeners (the web
        dashboard's timeline) directly."""
        event = {
            "type": "issuance",
            "ts": _fmt_ts(ts),
            "story_id": jti,
            "jkt": jkt,
            "ja4": _short_ja4(ja4),
            "source_ip": source_ip,
        }
        self._issuances.append(event)
        self._notify(event)

    def record_rate_limited(self, ts: int, key: str, attempts_in_window: int, limit: int) -> None:
        """7C.3: distinct from record_raw_block -- this is throttling
        (too many issuance attempts from one JA4 in the window), not a
        fingerprint-based PASS/BLOCK decision."""
        self._rate_limited += 1
        self._notify(
            {
                "type": "rate_limited",
                "ts": _fmt_ts(ts),
                "key": key,
                "attempts_in_window": attempts_in_window,
                "limit": limit,
                "rate_limited_total": self._rate_limited,
            }
        )
        self.log(f"{_fmt_ts(ts)} RATE LIMITED key={key} ({attempts_in_window}/{limit} in window)")

    def record_challenge_issued(self, ts: int, story_id: str, risk_score: int) -> None:
        """7C.2: a request landed in the challenge band -- neither
        auto-passed nor auto-blocked, distinct from both."""
        self._challenges_issued += 1
        self._notify(
            {
                "type": "challenge_issued",
                "ts": _fmt_ts(ts),
                "story_id": story_id,
                "risk_score": risk_score,
                "challenges_issued_total": self._challenges_issued,
            }
        )
        self.log(f"{_fmt_ts(ts)} CHALLENGE issued jti={story_id} (risk={risk_score}, step-up required)")

    def record_challenge_passed(self, ts: int, story_id: str) -> None:
        self.log(f"{_fmt_ts(ts)} CHALLENGE passed jti={story_id} -- fresh proof signed the nonce, forwarding")

    def log(self, line: str) -> None:
        self._log_lines.append(line)
        self._notify({"type": "log", "line": line})
        self._refresh()

    def _count(self, outcome: str) -> None:
        self._total += 1
        if outcome == "PASS":
            self._passed += 1
        else:
            self._blocked += 1
        self._notify({"type": "counts", "total": self._total, "passed": self._passed, "blocked": self._blocked})

    def _notify(self, event: dict) -> None:
        for listener in self._listeners:
            try:
                listener(event)
            except Exception:
                pass  # a broken web client must never take down the proxy's own dashboard

    def _refresh(self) -> None:
        self._live.update(self._render())

    def _render(self) -> Group:
        table = Table(title="Financial API Sentinel -- live decisions", expand=True)
        table.add_column("time")
        table.add_column("src_ip")
        table.add_column("presented_ja4", overflow="fold")
        table.add_column("bound_ja4", overflow="fold")
        table.add_column("jkt_ok")
        table.add_column("risk")
        table.add_column("sophistication")  # 7C.7
        table.add_column("DECISION")

        for row in self._rows:
            style = "bold green" if row["outcome"] == "PASS" else "bold red"
            outcome_label = row["outcome"] + (" *" if row.get("ja4_diff") else "")
            score = row.get("sophistication_score")
            sophistication_label = (
                f"{score}/{row['sophistication_total']} ({row['sophistication_label']})" if score is not None else "-"
            )
            table.add_row(
                row["ts"],
                row["source_ip"],
                row["presented_ja4"],
                row["bound_ja4"],
                row["jkt_ok"],
                row["risk"],
                sophistication_label,
                outcome_label,
                style=style,
            )

        rate_limited_part = f"  rate_limited={self._rate_limited}" if self._rate_limited else ""
        challenge_part = f"  challenged={self._challenges_issued}" if self._challenges_issued else ""
        footer = Text(
            f"total={self._total}  passed={self._passed}  blocked={self._blocked}{rate_limited_part}{challenge_part}"
            "   (* = JA4 diff below; full breakdown also at the web dashboard)"
        )
        log_panel = Panel("\n".join(self._log_lines) or "(no requests yet)", title="decision log")

        return Group(table, footer, log_panel)
