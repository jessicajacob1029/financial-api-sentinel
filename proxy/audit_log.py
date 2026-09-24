"""Hash-chained, tamper-evident audit log (Phase 7C.6).

Standalone, like rate_limiter.py / ja4_registry.py / challenge_store.py --
not a change to engine.py's Decision contract (Decision stays exactly
what Phases 0-6 defined; 7C.1 and 7C.5 are the only pre-approved touches
to that module). Instead this is a separate, append-only log the addon
feeds every event into (decisions, issuances, revocations, rate limits,
challenges) alongside its existing dashboard calls.

Same idea Certificate Transparency logs use: each entry commits to a hash
of the previous entry, so the entries form a chain. Editing any historical
entry changes its own hash, which no longer matches what the *next*
entry's prev_hash says it should be -- verify_chain() walks the whole
list and reports exactly where that first breaks.
"""

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: float
    event_type: str
    payload: dict
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class ChainVerificationResult:
    intact: bool
    entries_checked: int
    broken_at_seq: int | None
    reason: str | None


def _canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _compute_entry_hash(seq: int, ts: float, event_type: str, payload: dict, prev_hash: str) -> str:
    canonical = _canonical_json(
        {"seq": seq, "ts": ts, "event_type": event_type, "payload": payload, "prev_hash": prev_hash}
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """In-memory, append-only (same posture as the other in-memory stores
    in this codebase). Optionally also mirrors each entry as a JSON line
    to `persist_path`, so the log is independently inspectable -- via
    scripts/verify_audit_log.py -- rather than only living inside the
    running proxy process, which is the actual point of an audit log."""

    def __init__(self, persist_path=None) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._persist_path = persist_path
        if self._persist_path is not None:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            self._persist_path.write_text("")  # fresh log each process start, same posture as the binding cache

    def append(self, event_type: str, payload: dict, now: float | None = None) -> AuditEntry:
        now = time.time() if now is None else now
        with self._lock:
            seq = len(self._entries)
            prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            entry_hash = _compute_entry_hash(seq, now, event_type, payload, prev_hash)
            entry = AuditEntry(
                seq=seq, ts=now, event_type=event_type, payload=payload, prev_hash=prev_hash, entry_hash=entry_hash
            )
            self._entries.append(entry)
            if self._persist_path is not None:
                with self._persist_path.open("a") as f:
                    f.write(_canonical_json(entry_to_dict(entry)) + "\n")
            return entry

    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)


def verify_chain(entries: list[AuditEntry]) -> ChainVerificationResult:
    """Recomputes each entry's hash from its own recorded fields and
    checks it against both what that entry claims (tamper-with-the-hash-
    too doesn't help) and what the next entry's prev_hash says it should
    be (tamper-with-just-the-payload breaks the link forward)."""
    expected_prev = GENESIS_HASH
    for entry in entries:
        recomputed = _compute_entry_hash(entry.seq, entry.ts, entry.event_type, entry.payload, entry.prev_hash)
        if entry.prev_hash != expected_prev:
            return ChainVerificationResult(
                intact=False,
                entries_checked=entry.seq + 1,
                broken_at_seq=entry.seq,
                reason=f"entry {entry.seq}: prev_hash does not match the actual hash of entry {entry.seq - 1}",
            )
        if recomputed != entry.entry_hash:
            return ChainVerificationResult(
                intact=False,
                entries_checked=entry.seq + 1,
                broken_at_seq=entry.seq,
                reason=f"entry {entry.seq}: recomputed hash does not match stored entry_hash -- payload was altered",
            )
        expected_prev = entry.entry_hash

    return ChainVerificationResult(intact=True, entries_checked=len(entries), broken_at_seq=None, reason=None)


def entry_to_dict(entry: AuditEntry) -> dict:
    return asdict(entry)


def entry_from_dict(data: dict) -> AuditEntry:
    return AuditEntry(**data)
