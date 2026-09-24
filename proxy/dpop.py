"""DPoP proof validation (RFC 9449).

Pure and stateless -- no mitmproxy dependency, despite living under proxy/.
Called directly by backend/auth.py in Phase 1 (no proxy in the path yet)
and later by the mitmproxy addon on every proxied request (Phase 2+). One
validator, reused everywhere it's needed, per doc 04 SS8.
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import jwt
from jwt import PyJWTError
from jwt.algorithms import ECAlgorithm

from config import DPOP_ALLOWED_ALGORITHMS, DPOP_FRESHNESS_WINDOW_SECONDS

DPOP_TYP = "dpop+jwt"
_REQUIRED_CLAIMS = ["jti", "htm", "htu", "iat"]


@dataclass
class DpopResult:
    valid: bool
    jkt: str | None
    jti: str | None
    reason: str


def _normalize_url(url: str) -> str:
    # RFC 9449 SS4.2: htu excludes query and fragment.
    parts = urlsplit(url)
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _jwk_thumbprint(jwk: dict) -> str:
    # RFC 7638: canonical JSON over the required members only, sorted keys,
    # no whitespace, SHA-256, base64url without padding.
    canonical = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical_json).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_dpop(proof_jwt: str, method: str, url: str, now: int) -> DpopResult:
    """Validate a DPoP proof JWT per RFC 9449.

    Fails closed (doc 04 SS5): any unexpected exception results in
    valid=False rather than propagating, so a crash in this function can
    never be mistaken for a passing check by a caller.
    """
    try:
        return _validate_dpop_inner(proof_jwt, method, url, now)
    except Exception:
        return DpopResult(valid=False, jkt=None, jti=None, reason="internal validation error")


def _validate_dpop_inner(proof_jwt: str, method: str, url: str, now: int) -> DpopResult:
    # Header fields (typ, alg, jwk) are read before signature verification
    # only to select how to verify -- no claim about the request itself is
    # trusted yet (doc 04 SS3, SS4).
    try:
        header = jwt.get_unverified_header(proof_jwt)
    except PyJWTError:
        return DpopResult(valid=False, jkt=None, jti=None, reason="malformed proof header")

    if header.get("typ") != DPOP_TYP:
        return DpopResult(valid=False, jkt=None, jti=None, reason="invalid typ header")

    alg = header.get("alg")
    if alg not in DPOP_ALLOWED_ALGORITHMS:
        return DpopResult(valid=False, jkt=None, jti=None, reason=f"algorithm not allow-listed: {alg!r}")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return DpopResult(valid=False, jkt=None, jti=None, reason="missing or unsupported jwk in header")

    try:
        public_key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(json.dumps(jwk))
    except (PyJWTError, ValueError, KeyError, TypeError):
        return DpopResult(valid=False, jkt=None, jti=None, reason="invalid jwk")

    # Signature and required-claim presence are verified together: a
    # failed decode here never surfaces claim values, so nothing about the
    # request is trusted before the signature checks out.
    try:
        claims = jwt.decode(
            proof_jwt,
            key=public_key,
            algorithms=DPOP_ALLOWED_ALGORITHMS,
            options={"require": _REQUIRED_CLAIMS},
        )
    except PyJWTError:
        return DpopResult(valid=False, jkt=None, jti=None, reason="signature verification failed")

    if str(claims["htm"]).upper() != method.upper():
        return DpopResult(valid=False, jkt=None, jti=None, reason="htm mismatch")

    if _normalize_url(str(claims["htu"])) != _normalize_url(url):
        return DpopResult(valid=False, jkt=None, jti=None, reason="htu mismatch")

    iat = claims["iat"]
    if not isinstance(iat, (int, float)) or abs(now - iat) > DPOP_FRESHNESS_WINDOW_SECONDS:
        return DpopResult(valid=False, jkt=None, jti=None, reason="proof not fresh (iat outside window)")

    return DpopResult(valid=True, jkt=_jwk_thumbprint(jwk), jti=str(claims["jti"]), reason="ok")
