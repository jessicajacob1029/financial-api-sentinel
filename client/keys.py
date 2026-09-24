"""DPoP keypair generation and JWK thumbprint helpers, for client scripts."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


def generate_dpop_keypair() -> EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def serialize_private_key(private_key: EllipticCurvePrivateKey) -> bytes:
    """PEM bytes, for demo scripts to hand a key to a later, separate
    script process (e.g. script_a -> script_c). A real attacker exfiltrating
    a DPoP private key would do so via a different, harder-won channel than
    a bearer token leak -- see script_c_hijack.py's docstring for the
    threat-model distinction this exists to model."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem_bytes: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=None)


def public_jwk(private_key: EllipticCurvePrivateKey) -> dict:
    numbers = private_key.public_key().public_numbers()
    size = (private_key.curve.key_size + 7) // 8
    x = numbers.x.to_bytes(size, "big")
    y = numbers.y.to_bytes(size, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x).rstrip(b"=").decode("ascii"),
        "y": base64.urlsafe_b64encode(y).rstrip(b"=").decode("ascii"),
    }


def jwk_thumbprint(jwk: dict) -> str:
    # RFC 7638. Duplicated (in miniature) from proxy/dpop.py deliberately:
    # a real client and the proxy that validates it are different actors
    # that would never share a codebase, so this stays self-contained here.
    canonical = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical_json).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
