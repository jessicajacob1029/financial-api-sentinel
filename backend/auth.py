"""Access token issuance, sender-constrained to a DPoP key (RFC 9449 SS4.3).

Token validation order matters (doc 04 SS4): the DPoP proof presented at
issuance is verified before any of its claims (the jkt that gets bound
into the token) are trusted.
"""

import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from config import TOKEN_TTL_SECONDS
from proxy.dpop import validate_dpop

# Demo-only: an ephemeral signing key generated fresh each process start,
# held in memory only. Restarting the backend invalidates all outstanding
# tokens, which is acceptable at this scope (300s TTL) and avoids a second
# secret file to manage/gitignore alongside the TLS CA key (doc 04 SS1).
_SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())
_SIGNING_ALG = "ES256"


class TokenIssuanceError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class TokenValidationError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def issue_token(client_id: str, dpop_proof: str, request_url: str) -> dict:
    now = int(time.time())
    dpop_result = validate_dpop(dpop_proof, "POST", request_url, now)
    if not dpop_result.valid:
        raise TokenIssuanceError(f"DPoP proof invalid: {dpop_result.reason}")

    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": client_id,
        "jti": jti,
        "cnf": {"jkt": dpop_result.jkt},
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    access_token = jwt.encode(payload, _SIGNING_KEY, algorithm=_SIGNING_ALG)
    return {
        "access_token": access_token,
        "token_type": "DPoP",
        "expires_in": TOKEN_TTL_SECONDS,
        "jti": jti,
    }


def verify_access_token(access_token: str) -> dict:
    try:
        return jwt.decode(access_token, _SIGNING_KEY.public_key(), algorithms=[_SIGNING_ALG])
    except jwt.PyJWTError as exc:
        raise TokenValidationError(str(exc)) from exc
