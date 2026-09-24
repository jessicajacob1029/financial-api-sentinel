"""Unit tests for proxy/dpop.py (Build Spec SS8, doc 04 SS9).

Covers the happy path plus a negative test per rejection reason, and a
fail-closed regression test for doc 04 SS5 (an exception inside validation
must produce BLOCK, never PASS).
"""

import time

import jwt

from client.dpop_client import build_dpop_proof
from client.keys import generate_dpop_keypair, jwk_thumbprint, public_jwk
from proxy import dpop as dpop_module
from proxy.dpop import validate_dpop

METHOD = "POST"
URL = "http://127.0.0.1:8000/oauth/token"


def _now() -> int:
    return int(time.time())


def test_valid_proof_passes():
    key = generate_dpop_keypair()
    proof = build_dpop_proof(key, METHOD, URL)

    result = validate_dpop(proof, METHOD, URL, now=_now())

    assert result.valid
    assert result.reason == "ok"
    assert result.jkt == jwk_thumbprint(public_jwk(key))
    assert result.jti


def test_wrong_htm_fails():
    key = generate_dpop_keypair()
    proof = build_dpop_proof(key, "POST", URL)

    result = validate_dpop(proof, "GET", URL, now=_now())

    assert not result.valid
    assert "htm" in result.reason


def test_wrong_htu_fails():
    key = generate_dpop_keypair()
    proof = build_dpop_proof(key, METHOD, URL)

    result = validate_dpop(proof, METHOD, "http://127.0.0.1:8000/api/v1/transfer", now=_now())

    assert not result.valid
    assert "htu" in result.reason


def test_expired_proof_fails():
    key = generate_dpop_keypair()
    proof = build_dpop_proof(key, METHOD, URL)

    result = validate_dpop(proof, METHOD, URL, now=_now() + 10_000)

    assert not result.valid
    assert "fresh" in result.reason


def test_tampered_signature_fails():
    key = generate_dpop_keypair()
    proof = build_dpop_proof(key, METHOD, URL)
    header_b64, payload_b64, sig_b64 = proof.split(".")
    flipped_char = "B" if sig_b64[0] == "A" else "A"
    tampered = f"{header_b64}.{payload_b64}.{flipped_char}{sig_b64[1:]}"

    result = validate_dpop(tampered, METHOD, URL, now=_now())

    assert not result.valid
    assert result.reason == "signature verification failed"


def test_signed_by_key_other_than_embedded_jwk_fails():
    embedded_key = generate_dpop_keypair()
    actual_signing_key = generate_dpop_keypair()
    headers = {"typ": "dpop+jwt", "jwk": public_jwk(embedded_key)}
    payload = {"jti": "x", "htm": METHOD, "htu": URL, "iat": _now()}
    forged = jwt.encode(payload, actual_signing_key, algorithm="ES256", headers=headers)

    result = validate_dpop(forged, METHOD, URL, now=_now())

    assert not result.valid
    assert result.reason == "signature verification failed"


def test_alg_none_rejected():
    key = generate_dpop_keypair()
    headers = {"typ": "dpop+jwt", "alg": "none", "jwk": public_jwk(key)}
    payload = {"jti": "x", "htm": METHOD, "htu": URL, "iat": _now()}
    forged = jwt.encode(payload, key="", algorithm="none", headers=headers)

    result = validate_dpop(forged, METHOD, URL, now=_now())

    assert not result.valid
    assert "algorithm not allow-listed" in result.reason


def test_missing_typ_header_rejected():
    key = generate_dpop_keypair()
    headers = {"jwk": public_jwk(key)}  # no typ: "dpop+jwt"
    payload = {"jti": "x", "htm": METHOD, "htu": URL, "iat": _now()}
    proof = jwt.encode(payload, key, algorithm="ES256", headers=headers)

    result = validate_dpop(proof, METHOD, URL, now=_now())

    assert not result.valid
    assert result.reason == "invalid typ header"


def test_missing_required_claim_rejected():
    key = generate_dpop_keypair()
    headers = {"typ": "dpop+jwt", "jwk": public_jwk(key)}
    payload = {"htm": METHOD, "htu": URL, "iat": _now()}  # no jti
    proof = jwt.encode(payload, key, algorithm="ES256", headers=headers)

    result = validate_dpop(proof, METHOD, URL, now=_now())

    assert not result.valid


def test_malformed_proof_rejected():
    result = validate_dpop("not-a-jwt", METHOD, URL, now=_now())

    assert not result.valid
    assert result.reason == "malformed proof header"


def test_fail_closed_on_internal_exception(monkeypatch):
    """doc 04 SS5: an exception in validation must yield BLOCK, never PASS."""

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(dpop_module, "_validate_dpop_inner", _boom)

    result = validate_dpop("irrelevant", METHOD, URL, now=_now())

    assert not result.valid
    assert result.reason == "internal validation error"
