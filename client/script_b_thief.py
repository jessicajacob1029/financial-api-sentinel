"""Script B: token thief.

Reuses a token captured from Script A (read from demo_state/stolen_token.json,
simulating exfiltration -- e.g. via XSS, a leaked log, or proxy interception)
and replays it from a *different* TLS stack (curl, a subprocess, rather
than script_a's httpx) against a different DPoP key pair (the thief does
not have Script A's private key -- only the bearer token leaked).

Expected: BLOCK with reason "JA4 mismatch" at the proxy, before the
backend ever sees the request (doc 04 SS7: the client only ever sees a
generic 401 -- the specific reason is proxy-log-only, so this script
checks the HTTP outcome, not a leaked reason string).

doc 04 SS3: shells out to curl via subprocess.run with an argument list,
never shell=True with string interpolation.
"""

import json
import subprocess
import sys

from client.dpop_client import build_dpop_proof
from client.keys import generate_dpop_keypair
from config import BACKEND_BASE_URL, CA_CERT_PATH, PROXY_BASE_URL, STOLEN_TOKEN_PATH


def main() -> None:
    if not STOLEN_TOKEN_PATH.exists():
        print(f"[script_b] no stolen token at {STOLEN_TOKEN_PATH} -- run script_a_legit.py first", file=sys.stderr)
        raise SystemExit(1)

    stolen = json.loads(STOLEN_TOKEN_PATH.read_text())
    stolen_token = stolen["access_token"]
    print(f"[script_b] using stolen token (jti={stolen['jti']}) captured from script_a")

    thief_key = generate_dpop_keypair()  # thief has the bearer token, not the DPoP private key
    transfer_url = f"{BACKEND_BASE_URL}/api/v1/transfer"
    proof = build_dpop_proof(thief_key, "POST", transfer_url)

    body = json.dumps({"from": "acc-checking-001", "to": "acc-external-001", "amount": 4000.0})

    result = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--cacert", str(CA_CERT_PATH),
            "--request", "POST",
            f"{PROXY_BASE_URL}/api/v1/transfer",
            "--header", f"Authorization: DPoP {stolen_token}",
            "--header", f"DPoP: {proof}",
            "--header", "Content-Type: application/json",
            "--data", body,
            "--write-out", "\n%{http_code}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        print(f"[script_b] curl failed: {result.stderr}", file=sys.stderr)
        raise SystemExit(1)

    *response_lines, status_code = result.stdout.strip().rsplit("\n", 1)
    response_body = "\n".join(response_lines)
    print(f"[script_b] replay via curl -> HTTP {status_code}: {response_body}")

    if status_code in ("401", "403"):
        print("[script_b] PASS: replayed token from a different TLS stack was blocked")
    else:
        print("[script_b] FAIL: replayed token was NOT blocked -- expected 401/403", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
