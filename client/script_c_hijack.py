"""Script C: route hijacker (stretch, Build Spec SS5 / SS7 Phase 6).

A deliberately *stronger* attacker than Script B: this one has the DPoP
private key too (demo_state/session_key.pem), not just the bearer token
-- e.g. a compromised endpoint or a malicious intermediary that captured
the whole session, not merely a leaked log line. From the *same* TLS
stack as Script A (httpx), so the hard JA4 signal matches, and with the
*same* key, so the hard jkt signal matches too. What differs is the
network path: a spoofed X-Forwarded-For header (the engine ignores this
for its real IP-delta check -- source_ip comes from the TCP connection,
never a client-controlled header, precisely so this kind of spoofing
doesn't work) and a different header shape (shifts JA4H), plus a genuine
IP change when the loopback alias is available (see script_a_legit.py's
docstring for the sudo prerequisite; degrades gracefully without it).

Expected: BLOCK via the *soft* risk-threshold path ("risk threshold
exceeded"), not the hard "JA4 mismatch" path Script B hits -- this
contrast is the most instructive part of the demo (TRD SS5 Script C spec).
Check the proxy dashboard/log to see the distinct reason; the HTTP
response itself is the same generic 401 either way (doc 04 SS7).
"""

import json
import sys

import httpx

from client.dpop_client import build_dpop_proof
from client.keys import load_private_key
from config import BACKEND_BASE_URL, CA_CERT_PATH, PROXY_BASE_URL, SESSION_KEY_PATH, STOLEN_TOKEN_PATH

ROAMED_SOURCE_IP = "127.0.0.2"
SPOOFED_XFF = "203.0.113.9"  # attacker's naive attempt; the engine doesn't trust this header for source_ip


def main() -> None:
    if not (STOLEN_TOKEN_PATH.exists() and SESSION_KEY_PATH.exists()):
        print(
            f"[script_c] missing {STOLEN_TOKEN_PATH} or {SESSION_KEY_PATH} -- run script_a_legit.py first",
            file=sys.stderr,
        )
        raise SystemExit(1)

    stolen = json.loads(STOLEN_TOKEN_PATH.read_text())
    access_token = stolen["access_token"]
    private_key = load_private_key(SESSION_KEY_PATH.read_bytes())
    print(f"[script_c] using hijacked session (jti={stolen['jti']}) -- token AND DPoP key, from script_a")

    hijack_headers = {
        "User-Agent": "RouteHijacker/1.0 (not the original client)",
        "X-Forwarded-For": SPOOFED_XFF,  # ignored by the engine -- see module docstring
    }

    transport = httpx.HTTPTransport(local_address=ROAMED_SOURCE_IP)
    client = httpx.Client(base_url=PROXY_BASE_URL, verify=str(CA_CERT_PATH), transport=transport, timeout=5.0)

    transfer_url = f"{BACKEND_BASE_URL}/api/v1/transfer"
    proof = build_dpop_proof(private_key, "POST", transfer_url)

    try:
        resp = client.post(
            "/api/v1/transfer",
            json={"from": "acc-checking-001", "to": "acc-external-001", "amount": 2500.0},
            headers={"Authorization": f"DPoP {access_token}", "DPoP": proof, **hijack_headers},
        )
    except httpx.ConnectError:
        # loopback alias not configured -- retry from the normal source IP.
        # JA4H alone (different header shape) is already +2 risk, at
        # RISK_THRESHOLD -- the IP change is a bonus, not a requirement,
        # for this script to demonstrate the soft-block path.
        print(f"[script_c] IP-roam unavailable (see script_a_legit.py docstring) -- retrying from default IP")
        client = httpx.Client(base_url=PROXY_BASE_URL, verify=str(CA_CERT_PATH), timeout=5.0)
        resp = client.post(
            "/api/v1/transfer",
            json={"from": "acc-checking-001", "to": "acc-external-001", "amount": 2500.0},
            headers={"Authorization": f"DPoP {access_token}", "DPoP": proof, **hijack_headers},
        )

    print(f"[script_c] hijacked replay -> HTTP {resp.status_code}: {resp.text}")

    if resp.status_code in (401, 403):
        print(
            "[script_c] PASS: blocked despite matching JA4 and jkt -- check the proxy dashboard for "
            "reason='risk threshold exceeded' (soft-signal path), distinct from script_b's hard "
            "'JA4 mismatch' block"
        )
    else:
        print("[script_c] FAIL: hijacked replay was NOT blocked -- expected 401/403", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
