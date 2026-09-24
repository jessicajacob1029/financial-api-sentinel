"""Build a signed DPoP proof JWT (RFC 9449), shared by all client scripts."""

import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from client.keys import public_jwk


def build_dpop_proof(
    private_key: EllipticCurvePrivateKey, method: str, url: str, nonce: str | None = None
) -> str:
    """`nonce` (Phase 7C.2): RFC 9449 SS4.3's own server-provided-nonce
    claim, not something invented for this project -- proxy/dpop.py
    doesn't require or even look at it (an extra claim is simply ignored
    by jwt.decode's "require" check), so this stays fully backward
    compatible with every existing caller that omits it."""
    headers = {"typ": "dpop+jwt", "jwk": public_jwk(private_key)}
    payload = {
        "jti": secrets.token_urlsafe(16),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }
    if nonce is not None:
        payload["nonce"] = nonce
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
