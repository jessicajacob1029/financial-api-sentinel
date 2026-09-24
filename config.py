"""Shared configuration for Financial API Sentinel.

Per doc 04 SS8 ("config over hardcoding"): risk threshold, token TTL, DPoP
freshness window, and paths live here rather than as magic numbers
scattered through backend/ and proxy/.
"""

import os
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent
CERTS_DIR = REPO_ROOT / "certs"
CA_CERT_PATH = CERTS_DIR / "ca.pem"
CA_KEY_PATH = CERTS_DIR / "ca.key"

# Phase 7A.1: mutual TLS on the proxy<->backend leg, toggled with
# `make backend MTLS=1` / `make proxy MTLS=1` (which set this env var).
# Both use the leaf certs scripts/generate_mtls_certs.py produces.
MTLS_BACKEND_ENABLED = os.environ.get("MTLS_BACKEND_ENABLED", "false").lower() == "true"
BACKEND_SERVER_CERT_PATH = CERTS_DIR / "backend-server.pem"
BACKEND_SERVER_KEY_PATH = CERTS_DIR / "backend-server.key"
PROXY_CLIENT_CERT_PATH = CERTS_DIR / "proxy-client.pem"

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000
# Scheme must track MTLS_BACKEND_ENABLED: mitmproxy's reverse mode
# rewrites flow.request's scheme to match the upstream target *before*
# either the addon or the backend see it (confirmed empirically in Phase
# 3), so if the upstream leg switches to https, every DPoP proof's `htu`
# must be built against https too, or validation breaks for every
# request. Reading this one config value keeps client scripts, the
# addon, and the backend automatically in agreement.
BACKEND_SCHEME = "https" if MTLS_BACKEND_ENABLED else "http"
BACKEND_BASE_URL = f"{BACKEND_SCHEME}://{BACKEND_HOST}:{BACKEND_PORT}"

# The proxy's public listen address -- what client scripts physically
# connect to from Phase 4 onward. Distinct from BACKEND_BASE_URL: DPoP
# proofs still target BACKEND_BASE_URL, since mitmproxy's reverse mode
# rewrites flow.request's scheme/host to the upstream target before either
# the addon or the backend see it (confirmed empirically in Phase 3) -- so
# that's the URL both of them actually validate `htu` against.
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
PROXY_BASE_URL = f"https://{PROXY_HOST}:{PROXY_PORT}"

# Where Script A writes the issued token so Script B can "steal" it,
# simulating exfiltration (Build Spec SS5). Runtime demo state, never
# committed -- see .gitignore.
DEMO_STATE_DIR = REPO_ROOT / "demo_state"
STOLEN_TOKEN_PATH = DEMO_STATE_DIR / "stolen_token.json"

# Script C (Phase 6) models a different, stronger attacker than Script B:
# one who compromised the whole session -- token *and* DPoP private key --
# but connects over a different network path. That's a deliberately
# distinct threat model from Script B (bearer token only, no key), so it
# gets its own file rather than reusing STOLEN_TOKEN_PATH -- keeps it
# visually obvious in demo_state/ which script needs which capability.
SESSION_KEY_PATH = DEMO_STATE_DIR / "session_key.pem"

# Phase 7C.6: hash-chained audit log, mirrored to disk so it's inspectable
# independent of the running proxy process (scripts/verify_audit_log.py).
AUDIT_LOG_PATH = DEMO_STATE_DIR / "audit_log.jsonl"

# PRD SS5 success metrics: short-lived access tokens.
TOKEN_TTL_SECONDS = 300

# TD-3 / doc 04 SS3: DPoP proof `iat` must be within this window of "now"
# to be considered fresh. Not specified exactly by the TRD; 60s is a
# reasonable default for a demo (generous enough to avoid clock-skew false
# positives, tight enough that a captured proof can't be replayed later).
DPOP_FRESHNESS_WINDOW_SECONDS = 60

# doc 04 SS2: DPoP signatures must be verified against an allow-listed
# algorithm. Never derive the algorithm from attacker-controlled input.
DPOP_ALLOWED_ALGORITHMS = ["ES256"]

# Build Spec SS4 decision engine rules. As of Phase 7C.5, the risk
# threshold, step-up challenge threshold, and soft-signal weights moved
# out of this file into policy.yaml (loaded + strictly validated by
# proxy/policy.py's POLICY singleton) -- config.py no longer defines
# RISK_THRESHOLD or CHALLENGE_THRESHOLD; see policy.yaml.

# Phase 7C.3: token-issuance rate limiting. Keyed by JA4 (not source_ip --
# consistent with this project's fingerprint-centric design; IP is the
# fragile soft signal per doc 04 SS5, not something to hard-limit on).
# Not policy.yaml material -- this is a rate-limiting knob, not a
# decision-engine risk weight/threshold.
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 30

# Phase 7C.2: how long a step-up challenge nonce stays valid. A timing
# knob, not a decision-policy weight, so it stays here rather than in
# policy.yaml.
CHALLENGE_TTL_SECONDS = 30
