"""JA3 TLS client fingerprint (Phase 7A.4) -- the legacy predecessor to
JA4, computed alongside it purely for side-by-side comparison, never used
in any decision logic. MD5 here is not a security control (same as JA4's
truncated SHA-256): both are fingerprint hashes for bucketing similar
clients, not integrity or authentication guarantees, so MD5's known
cryptographic weaknesses (collision resistance) are irrelevant to this
use -- it's what the published JA3 spec actually uses, and reproducing a
different hash wouldn't be JA3 anymore.

JA3 fields, per the original Salesforce/Trustwave spec:
  TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
each a raw (UN-sorted, order exactly as sent), GREASE-filtered, comma-
within-field list of decimal values, joined with "-"; the five fields
joined with ",", then MD5'd. Two things JA3 does differently from JA4,
both deliberate, both why JA4 superseded it:
  1. JA3 does NOT sort before hashing -- it hashes ciphers/extensions in
     the exact order the client sent them.
  2. JA3 uses the ClientHello's legacy `version` field, not the
     negotiated max from supported_versions (which JA4 prefers).
Point (1) is the whole story: Chrome (and other modern browsers) now
deliberately randomizes TLS extension order per connection specifically
to prevent fingerprinting. That breaks JA3 -- the same browser produces a
different JA3 on every connection -- but not JA4, which sorts first.
proxy/ja3_ja4_demo.py builds exactly this contrast from two synthetic
ClientHellos with identical extension sets in different order.
"""

import hashlib

from mitmproxy.tls import ClientHello

from proxy.ja4 import GREASE_VALUES  # a TLS protocol constant (RFC 8701), not decision logic -- sharing it is correct, unlike e.g. client/keys.py's deliberate duplication of jwk_thumbprint across actors that would never share a codebase

_SUPPORTED_GROUPS_EXTENSION = 0x000A
_EC_POINT_FORMATS_EXTENSION = 0x000B


def _parse_u16_list(body: bytes, length_bytes: int) -> list[int]:
    if len(body) < length_bytes:
        return []
    if length_bytes == 2:
        list_len = int.from_bytes(body[0:2], "big")
        offset = 2
    else:
        list_len = body[0]
        offset = 1
    values = []
    step = 2 if length_bytes == 2 else 1
    for i in range(offset, offset + list_len, step):
        if i + step <= len(body):
            values.append(int.from_bytes(body[i : i + step], "big") if step == 2 else body[i])
    return values


def compute_ja3(client_hello: ClientHello) -> str:
    # Legacy version field, NOT the supported_versions extension's
    # negotiated max -- this is JA3's own behavior, unlike JA4's.
    raw_version = client_hello._client_hello.version
    version = (raw_version.major << 8) | raw_version.minor

    ciphers = [c for c in client_hello.cipher_suites if c not in GREASE_VALUES]  # raw order, not sorted

    curves: list[int] = []
    point_formats: list[int] = []
    ext_types: list[int] = []
    for ext_type, body in client_hello.extensions:
        if ext_type in GREASE_VALUES:
            continue
        ext_types.append(ext_type)  # raw order, not sorted -- this is what breaks under extension randomization
        if ext_type == _SUPPORTED_GROUPS_EXTENSION:
            curves = [g for g in _parse_u16_list(body, 2) if g not in GREASE_VALUES]
        elif ext_type == _EC_POINT_FORMATS_EXTENSION:
            point_formats = _parse_u16_list(body, 1)

    ja3_string = ",".join(
        [
            str(version),
            "-".join(str(c) for c in ciphers),
            "-".join(str(t) for t in ext_types),
            "-".join(str(g) for g in curves),
            "-".join(str(p) for p in point_formats),
        ]
    )
    return hashlib.md5(ja3_string.encode("ascii")).hexdigest()
