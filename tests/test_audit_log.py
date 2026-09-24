"""Unit tests for proxy/audit_log.py (Phase 7C.6).

Acceptance (doc SS7C.6): a verify_chain() run over an untouched log
passes; manually editing one historical entry and re-running
verify_chain() detects the break at the correct point.
"""

import dataclasses

from proxy.audit_log import AuditLog, GENESIS_HASH, verify_chain


def test_empty_log_verifies_as_intact():
    result = verify_chain([])

    assert result.intact is True
    assert result.entries_checked == 0


def test_untouched_log_verifies_as_intact():
    log = AuditLog()
    log.append("decision", {"outcome": "PASS"}, now=1000.0)
    log.append("decision", {"outcome": "BLOCK", "reason": "JA4 mismatch"}, now=1001.0)
    log.append("issuance", {"jti": "tok-1"}, now=1002.0)

    result = verify_chain(log.entries())

    assert result.intact is True
    assert result.entries_checked == 3
    assert result.broken_at_seq is None


def test_first_entry_chains_from_genesis():
    log = AuditLog()
    entry = log.append("decision", {"outcome": "PASS"}, now=1000.0)

    assert entry.seq == 0
    assert entry.prev_hash == GENESIS_HASH


def test_each_entry_chains_to_the_previous_hash():
    log = AuditLog()
    first = log.append("decision", {"outcome": "PASS"}, now=1000.0)
    second = log.append("decision", {"outcome": "BLOCK"}, now=1001.0)

    assert second.prev_hash == first.entry_hash
    assert second.seq == first.seq + 1


def test_tampering_with_a_historical_payload_is_detected_at_the_right_entry():
    """The core acceptance criterion: edit one historical entry, confirm
    verify_chain() catches it, at that entry's own seq -- not the next
    one, not silently passing."""
    log = AuditLog()
    log.append("decision", {"outcome": "PASS"}, now=1000.0)
    log.append("decision", {"outcome": "BLOCK", "reason": "JA4 mismatch"}, now=1001.0)
    log.append("issuance", {"jti": "tok-1"}, now=1002.0)

    entries = log.entries()
    # Tamper with entry 1's payload -- an attacker rewriting history to
    # hide that a replay was ever blocked, say.
    tampered_entry_1 = dataclasses.replace(entries[1], payload={"outcome": "PASS", "reason": "ok"})
    tampered_entries = [entries[0], tampered_entry_1, entries[2]]

    result = verify_chain(tampered_entries)

    assert result.intact is False
    assert result.broken_at_seq == 1
    assert "entry 1" in result.reason


def test_forging_an_entry_hash_is_detected_at_that_same_entry():
    """A forged entry_hash that doesn't match its own recomputed hash is
    caught immediately at that entry -- verify_chain doesn't need to wait
    for the next entry's prev_hash to reveal the tamper."""
    log = AuditLog()
    log.append("decision", {"outcome": "PASS"}, now=1000.0)
    log.append("decision", {"outcome": "BLOCK"}, now=1001.0)

    entries = log.entries()
    forged = dataclasses.replace(entries[0], payload={"outcome": "BLOCK"}, entry_hash="a" * 64)
    tampered_entries = [forged, entries[1]]

    result = verify_chain(tampered_entries)

    assert result.intact is False
    assert result.broken_at_seq == 0
    assert "entry 0" in result.reason


def test_swapping_two_entries_breaks_the_chain():
    log = AuditLog()
    log.append("decision", {"outcome": "PASS"}, now=1000.0)
    log.append("decision", {"outcome": "BLOCK"}, now=1001.0)
    log.append("issuance", {"jti": "tok-1"}, now=1002.0)

    entries = log.entries()
    reordered = [entries[0], entries[2], entries[1]]

    result = verify_chain(reordered)

    assert result.intact is False


def test_sequence_numbers_increment_correctly_across_many_entries():
    log = AuditLog()
    for i in range(10):
        log.append("decision", {"i": i}, now=1000.0 + i)

    entries = log.entries()

    assert [e.seq for e in entries] == list(range(10))
    assert verify_chain(entries).intact is True
