"""verify-audit-log: independent integrity check for the hash-chained
audit trail (Phase 7C.6).

Loads demo_state/audit_log.jsonl -- written by proxy/addon.py's AuditLog
as it runs -- and walks the chain with proxy/audit_log.py's verify_chain(),
completely independent of the running proxy process. That independence is
the actual point of an audit log: you shouldn't have to trust the same
process that wrote the entries to also grade its own homework.

Usage:
    python scripts/verify_audit_log.py
    python scripts/verify_audit_log.py --path demo_state/audit_log.jsonl
"""

import argparse
import json
import pathlib
import sys

from config import AUDIT_LOG_PATH
from proxy.audit_log import entry_from_dict, verify_chain


def _load_entries(path):
    if not path.exists():
        print(f"[verify-audit-log] no log at {path} -- run a live demo first (make backend / make proxy / an attack-* target)", file=sys.stderr)
        sys.exit(2)

    entries = []
    with path.open() as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(entry_from_dict(json.loads(line)))
            except (json.JSONDecodeError, TypeError) as exc:
                print(f"[verify-audit-log] FAIL: line {lineno} is not a valid audit entry ({exc})")
                sys.exit(1)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the hash chain of a Sentinel audit log.")
    parser.add_argument("--path", type=str, default=None, help=f"defaults to {AUDIT_LOG_PATH}")
    args = parser.parse_args()

    path = pathlib.Path(args.path) if args.path else AUDIT_LOG_PATH
    entries = _load_entries(path)

    result = verify_chain(entries)

    print(f"[verify-audit-log] {path}")
    print(f"[verify-audit-log] entries checked: {result.entries_checked}")
    if result.intact:
        print("[verify-audit-log] PASS: chain is intact -- no tampering detected")
        sys.exit(0)
    else:
        print(f"[verify-audit-log] FAIL: chain broken at seq={result.broken_at_seq}")
        print(f"[verify-audit-log] reason: {result.reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
