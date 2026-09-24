"""Script E: token revocation (Phase 7C.1) -- the live-demo beat the doc
describes: a legitimate, currently-passing session gets its token revoked
mid-session, and the very next request -- same key, same token, nothing
else about the client changed -- is blocked immediately.

Reuses Script A's issued token AND session key (unlike Script B/C, this
isn't modeling an attacker at all -- it's the token's own legitimate
owner, after an operator decides to revoke it, e.g. "this session looks
compromised, kill it now" rather than waiting for TTL expiry).
"""

import json
import sys

import httpx

from client.dpop_client import build_dpop_proof
from client.keys import load_private_key
from config import BACKEND_BASE_URL, CA_CERT_PATH, PROXY_BASE_URL, SESSION_KEY_PATH, STOLEN_TOKEN_PATH


def main() -> None:
    if not (STOLEN_TOKEN_PATH.exists() and SESSION_KEY_PATH.exists()):
        print(
            f"[script_e] missing {STOLEN_TOKEN_PATH} or {SESSION_KEY_PATH} -- run script_a_legit.py first",
            file=sys.stderr,
        )
        raise SystemExit(1)

    session = json.loads(STOLEN_TOKEN_PATH.read_text())
    access_token = session["access_token"]
    jti = session["jti"]
    private_key = load_private_key(SESSION_KEY_PATH.read_bytes())

    client = httpx.Client(base_url=PROXY_BASE_URL, verify=str(CA_CERT_PATH), timeout=5.0)
    accounts_url = f"{BACKEND_BASE_URL}/api/v1/accounts"

    proof = build_dpop_proof(private_key, "GET", accounts_url)
    resp = client.get("/api/v1/accounts", headers={"Authorization": f"DPoP {access_token}", "DPoP": proof})
    print(f"[script_e] before revocation -> HTTP {resp.status_code}")
    if resp.status_code != 200:
        print("[script_e] FAIL: expected the session to still be valid before revoking anything", file=sys.stderr)
        raise SystemExit(1)

    revoke_resp = client.post("/oauth/revoke", json={"jti": jti})
    print(f"[script_e] revoke jti={jti} -> HTTP {revoke_resp.status_code}: {revoke_resp.text}")
    if revoke_resp.status_code != 200:
        print("[script_e] FAIL: revocation request itself failed", file=sys.stderr)
        raise SystemExit(1)

    proof = build_dpop_proof(private_key, "GET", accounts_url)
    resp = client.get("/api/v1/accounts", headers={"Authorization": f"DPoP {access_token}", "DPoP": proof})
    print(f"[script_e] after revocation, same key/token -> HTTP {resp.status_code}: {resp.text}")

    if resp.status_code in (401, 403):
        print(
            "[script_e] PASS: the exact same session (same DPoP key, same token, nothing else changed) "
            "is now blocked -- check the dashboard for reason='token revoked'"
        )
    else:
        print("[script_e] FAIL: revoked token was NOT blocked -- expected 401/403", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
