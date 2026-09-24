"""Script F: adaptive step-up authentication (Phase 7C.2).

Demonstrates the three-tier decision model: a request landing in
[CHALLENGE_THRESHOLD, RISK_THRESHOLD) risk is neither auto-passed nor
auto-blocked -- it gets a one-time nonce (428), and only a fresh DPoP
proof signing that nonce (RFC 9449 SS4.3) lets it through.

With the real configured RISK_THRESHOLD=2, the only signal combination
that lands in that band is IP change alone (+1) -- JA4H change alone is
already +2, which meets the block threshold outright. So this script
needs the same loopback alias as script_a_legit.py's IP-roam step
(`sudo ifconfig lo0 alias 127.0.0.2 up`) to trigger it for real, and
degrades the same way when that alias isn't present: explains why,
rather than faking success. The full mechanism -- 428 issued, then a
nonce-signed retry accepted, then the same nonce rejected a second time
-- was verified live during development with RISK_THRESHOLD temporarily
widened to reach the band via JA4H instead (see the Phase 7C.2 report);
this script exercises the real, permanently-configured path.
"""

import json
import sys

import httpx

from client.dpop_client import build_dpop_proof
from client.keys import load_private_key
from config import BACKEND_BASE_URL, CA_CERT_PATH, PROXY_BASE_URL, SESSION_KEY_PATH, STOLEN_TOKEN_PATH

ROAMED_SOURCE_IP = "127.0.0.2"


def main() -> None:
    if not (STOLEN_TOKEN_PATH.exists() and SESSION_KEY_PATH.exists()):
        print(
            f"[script_f] missing {STOLEN_TOKEN_PATH} or {SESSION_KEY_PATH} -- run script_a_legit.py first",
            file=sys.stderr,
        )
        raise SystemExit(1)

    session = json.loads(STOLEN_TOKEN_PATH.read_text())
    access_token = session["access_token"]
    private_key = load_private_key(SESSION_KEY_PATH.read_bytes())
    accounts_url = f"{BACKEND_BASE_URL}/api/v1/accounts"

    transport = httpx.HTTPTransport(local_address=ROAMED_SOURCE_IP)
    client = httpx.Client(base_url=PROXY_BASE_URL, verify=str(CA_CERT_PATH), transport=transport, timeout=5.0)

    proof = build_dpop_proof(private_key, "GET", accounts_url)
    try:
        resp = client.get("/api/v1/accounts", headers={"Authorization": f"DPoP {access_token}", "DPoP": proof})
    except httpx.ConnectError as exc:
        print(
            f"[script_f] can't source a connection from {ROAMED_SOURCE_IP} ({exc}). "
            f"On macOS this needs a one-time alias: `sudo ifconfig lo0 alias {ROAMED_SOURCE_IP} up` "
            f"(remove later with `sudo ifconfig lo0 -alias {ROAMED_SOURCE_IP}`). "
            "The step-up mechanism itself (428 -> nonce-signed retry -> single-use enforcement) is "
            "covered by tests/test_challenge_store.py and was verified live during development -- "
            "see the Phase 7C.2 report for that run.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print(f"[script_f] request from a roamed IP -> HTTP {resp.status_code}")
    if resp.status_code != 428:
        print(f"[script_f] FAIL: expected 428 (step-up required), got {resp.status_code}: {resp.text}", file=sys.stderr)
        raise SystemExit(1)

    nonce = resp.json()["nonce"]
    print(f"[script_f] got challenge nonce: {nonce}")

    proof2 = build_dpop_proof(private_key, "GET", accounts_url, nonce=nonce)
    resp2 = client.get("/api/v1/accounts", headers={"Authorization": f"DPoP {access_token}", "DPoP": proof2})
    print(f"[script_f] retry with nonce-signed proof -> HTTP {resp2.status_code}")

    if resp2.status_code == 200:
        print("[script_f] PASS: held for step-up, then let through only after a fresh nonce-signed proof")
    else:
        print(f"[script_f] FAIL: expected 200 after signing the nonce, got {resp2.status_code}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
