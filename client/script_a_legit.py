"""Script A: legitimate user.

Authenticates once, then completes a GET /accounts and a POST /transfer,
all through the Sentinel proxy, with one DPoP key pair and one consistent
HTTP stack (httpx) throughout. Every request should PASS.

After a successful session, the issued access token is written to
demo_state/stolen_token.json so script_b_thief.py can simulate having
exfiltrated it (Build Spec SS5) -- narratively, the token is "stolen"
only after legitimate use, not instead of it.

Phase 6: also demonstrates the IP-roam-doesn't-block property (Build Spec
SS7 Phase 6 done-when) with a final request sourced from a second
loopback address (127.0.0.2). Unlike Linux, macOS does not bring up the
whole 127.0.0.0/8 range by default -- it requires a one-time, reversible
alias: `sudo ifconfig lo0 alias 127.0.0.2 up` (remove later with
`sudo ifconfig lo0 -alias 127.0.0.2`). If that alias isn't present, this
script explains that plainly and skips the live network step rather than
silently pretending it ran -- the same property is still proven, without
sudo, by proxy/engine.py's own tests
(tests/test_engine.py::test_ip_change_alone_does_not_block_a_legit_session),
which drives the real evaluate() function with a genuinely different
source_ip and asserts PASS.
"""

import json
import sys

import httpx

from client.dpop_client import build_dpop_proof
from client.keys import generate_dpop_keypair, serialize_private_key
from config import (
    BACKEND_BASE_URL,
    CA_CERT_PATH,
    DEMO_STATE_DIR,
    PROXY_BASE_URL,
    SESSION_KEY_PATH,
    STOLEN_TOKEN_PATH,
)

ROAMED_SOURCE_IP = "127.0.0.2"

CLIENT_ID = "demo-client"


def _attempt_ip_roam(private_key, access_token: str) -> None:
    """Same key, same token, same session -- only the source IP changes.
    Should PASS: ip_delta alone is a soft signal (+1 risk), below
    RISK_THRESHOLD (2), so a roaming legitimate client is never blocked
    on this signal by itself.
    """
    roamed_transport = httpx.HTTPTransport(local_address=ROAMED_SOURCE_IP)
    roamed_client = httpx.Client(
        base_url=PROXY_BASE_URL, verify=str(CA_CERT_PATH), transport=roamed_transport, timeout=5.0
    )

    accounts_url = f"{BACKEND_BASE_URL}/api/v1/accounts"
    proof = build_dpop_proof(private_key, "GET", accounts_url)
    try:
        resp = roamed_client.get(
            "/api/v1/accounts", headers={"Authorization": f"DPoP {access_token}", "DPoP": proof}
        )
    except httpx.ConnectError as exc:
        print(
            f"[script_a] IP-roam step skipped: can't source a connection from {ROAMED_SOURCE_IP} "
            f"({exc}). On macOS this needs a one-time alias: "
            f"`sudo ifconfig lo0 alias {ROAMED_SOURCE_IP} up` (remove later with "
            f"`sudo ifconfig lo0 -alias {ROAMED_SOURCE_IP}`). The same property -- IP change alone "
            f"doesn't block -- is proven without sudo by "
            f"tests/test_engine.py::test_ip_change_alone_does_not_block_a_legit_session."
        )
        return

    resp.raise_for_status()
    print(f"[script_a] PASS: same token/key from a different source IP ({ROAMED_SOURCE_IP}) still passed")


def main() -> None:
    private_key = generate_dpop_keypair()
    client = httpx.Client(base_url=PROXY_BASE_URL, verify=str(CA_CERT_PATH), timeout=5.0)

    token_url = f"{BACKEND_BASE_URL}/oauth/token"
    proof = build_dpop_proof(private_key, "POST", token_url)
    resp = client.post("/oauth/token", json={"client_id": CLIENT_ID}, headers={"DPoP": proof})
    resp.raise_for_status()
    token_data = resp.json()
    access_token = token_data["access_token"]
    print(f"[script_a] obtained access token (jti={token_data['jti']}, expires_in={token_data['expires_in']}s)")

    accounts_url = f"{BACKEND_BASE_URL}/api/v1/accounts"
    proof = build_dpop_proof(private_key, "GET", accounts_url)
    resp = client.get("/api/v1/accounts", headers={"Authorization": f"DPoP {access_token}", "DPoP": proof})
    resp.raise_for_status()
    print(f"[script_a] accounts: {resp.json()}")

    transfer_url = f"{BACKEND_BASE_URL}/api/v1/transfer"
    proof = build_dpop_proof(private_key, "POST", transfer_url)
    resp = client.post(
        "/api/v1/transfer",
        json={"from": "acc-checking-001", "to": "acc-savings-001", "amount": 100.0},
        headers={"Authorization": f"DPoP {access_token}", "DPoP": proof},
    )
    resp.raise_for_status()
    print(f"[script_a] transfer result: {resp.json()}")
    print("[script_a] PASS: legitimate session completed end to end through the proxy")

    _attempt_ip_roam(private_key, access_token)

    DEMO_STATE_DIR.mkdir(parents=True, exist_ok=True)
    STOLEN_TOKEN_PATH.write_text(json.dumps({"access_token": access_token, "jti": token_data["jti"]}))
    print(f"[script_a] wrote issued token to {STOLEN_TOKEN_PATH} for script_b_thief.py to 'steal'")

    # script_c_hijack.py models a stronger attacker who compromised the
    # DPoP private key too, not just the bearer token -- see its docstring
    # for why that's a deliberately different threat model from Script B.
    SESSION_KEY_PATH.write_bytes(serialize_private_key(private_key))
    print(f"[script_a] wrote session DPoP key to {SESSION_KEY_PATH} for script_c_hijack.py")


if __name__ == "__main__":
    try:
        main()
    except httpx.HTTPStatusError as exc:
        print(f"[script_a] FAIL: {exc.response.status_code} {exc.response.text}", file=sys.stderr)
        raise SystemExit(1)
