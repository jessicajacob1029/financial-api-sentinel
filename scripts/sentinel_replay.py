"""sentinel-replay: ad-hoc token replay CLI (Phase 7C.4).

Lets you fire a live replay during a demo or Q&A -- "what if the attacker
used requests instead of curl?" -- without editing a script file. A thin
wrapper around the exact same TLS stack choices Scripts B/C already use
(httpx, curl subprocess, and now also plain `requests`), parameterized.

Examples:
    python scripts/sentinel_replay.py --stack httpx --target /api/v1/accounts
    python scripts/sentinel_replay.py --stack curl --target /api/v1/transfer --same-key
    python scripts/sentinel_replay.py --stack requests --target /api/v1/accounts

By default generates a fresh throwaway DPoP key (Script B's threat model:
attacker has the bearer token, not the private key). Pass --same-key to
replay with the real session key instead (Script C's threat model: full
session compromise) -- needs demo_state/session_key.pem, from
script_a_legit.py.

doc 04 SS3: curl is invoked via subprocess.run with an argument list,
never shell=True with string interpolation.
"""

import argparse
import json
import subprocess
import sys

import httpx
import requests

from client.dpop_client import build_dpop_proof
from client.keys import generate_dpop_keypair, load_private_key
from config import BACKEND_BASE_URL, CA_CERT_PATH, PROXY_BASE_URL, SESSION_KEY_PATH, STOLEN_TOKEN_PATH

STACKS = ("httpx", "requests", "curl")


def _load_token() -> tuple[str, str]:
    if not STOLEN_TOKEN_PATH.exists():
        print(f"[replay] no token at {STOLEN_TOKEN_PATH} -- run script_a_legit.py first", file=sys.stderr)
        raise SystemExit(1)
    session = json.loads(STOLEN_TOKEN_PATH.read_text())
    return session["access_token"], session["jti"]


def _load_key(same_key: bool):
    if not same_key:
        print("[replay] using a fresh throwaway DPoP key (attacker has token only, not the key)")
        return generate_dpop_keypair()
    if not SESSION_KEY_PATH.exists():
        print(f"[replay] --same-key needs {SESSION_KEY_PATH} -- run script_a_legit.py first", file=sys.stderr)
        raise SystemExit(1)
    print("[replay] using the REAL session key (full session compromise)")
    return load_private_key(SESSION_KEY_PATH.read_bytes())


def _target_request(target: str) -> tuple[str, dict | None]:
    if target == "/api/v1/transfer":
        return "POST", {"from": "acc-checking-001", "to": "acc-external-001", "amount": 1234.0}
    return "GET", None


def _replay_httpx(access_token: str, key, method: str, htu: str, connect_url: str, body: dict | None) -> tuple[int, str]:
    proof = build_dpop_proof(key, method, htu)
    client = httpx.Client(verify=str(CA_CERT_PATH), timeout=5.0)
    headers = {"Authorization": f"DPoP {access_token}", "DPoP": proof}
    resp = client.request(method, connect_url, json=body, headers=headers)
    return resp.status_code, resp.text


def _replay_requests(access_token: str, key, method: str, htu: str, connect_url: str, body: dict | None) -> tuple[int, str]:
    proof = build_dpop_proof(key, method, htu)
    headers = {"Authorization": f"DPoP {access_token}", "DPoP": proof}
    resp = requests.request(method, connect_url, json=body, headers=headers, verify=str(CA_CERT_PATH), timeout=5)
    return resp.status_code, resp.text


def _replay_curl(access_token: str, key, method: str, htu: str, connect_url: str, body: dict | None) -> tuple[int, str]:
    proof = build_dpop_proof(key, method, htu)
    cmd = [
        "curl", "--silent", "--show-error",
        "--cacert", str(CA_CERT_PATH),
        "--request", method,
        connect_url,
        "--header", f"Authorization: DPoP {access_token}",
        "--header", f"DPoP: {proof}",
        "--write-out", "\n%{http_code}",
    ]
    if body is not None:
        cmd += ["--header", "Content-Type: application/json", "--data", json.dumps(body)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    if result.returncode != 0:
        return -1, result.stderr
    *body_lines, status = result.stdout.strip().rsplit("\n", 1)
    return int(status), "\n".join(body_lines)


_REPLAYERS = {"httpx": _replay_httpx, "requests": _replay_requests, "curl": _replay_curl}


def main() -> None:
    parser = argparse.ArgumentParser(description="Ad-hoc Sentinel token replay (Phase 7C.4)")
    parser.add_argument("--stack", choices=STACKS, required=True, help="TLS stack to replay from")
    parser.add_argument(
        "--target", default="/api/v1/accounts", choices=("/api/v1/accounts", "/api/v1/transfer"),
        help="backend endpoint to hit (default: /api/v1/accounts)",
    )
    parser.add_argument(
        "--same-key", action="store_true",
        help="use the real session's DPoP key instead of a fresh one (full compromise, Script C's model)",
    )
    args = parser.parse_args()

    access_token, jti = _load_token()
    key = _load_key(args.same_key)
    method, body = _target_request(args.target)

    # DPoP `htu` targets BACKEND_BASE_URL -- that's the URL the addon and
    # backend actually validate against (mitmproxy rewrites scheme/host to
    # the upstream target before either sees the request; confirmed
    # empirically in Phase 3, see config.py's comment). The physical
    # connection goes to PROXY_BASE_URL instead -- same split every other
    # client script in this repo uses.
    htu = f"{BACKEND_BASE_URL}{args.target}"
    connect_url = f"{PROXY_BASE_URL}{args.target}"

    print(f"[replay] stack={args.stack} target={args.target} jti={jti} same_key={args.same_key}")
    status, body_text = _REPLAYERS[args.stack](access_token, key, method, htu, connect_url, body)
    print(f"[replay] -> HTTP {status}: {body_text[:200]}")


if __name__ == "__main__":
    main()
