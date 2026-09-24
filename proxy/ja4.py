"""JA4 TLS client fingerprint computation (TD-2).

Scoped to the fields TD-2 specifies: TLS version, SNI presence, cipher
suite count, extension count, first ALPN, then a truncated SHA-256 over
the sorted cipher and extension lists. This intentionally does not
reproduce every corner of the full FoxIO JA4 spec (e.g. it omits the
signature-algorithms hash suffix some reference implementations append)
-- noted here rather than silently overclaiming byte-for-byte parity. The
core property the demo depends on -- same stack -> same JA4, different
stack -> different JA4 -- holds under this implementation.

Phase 7B.3: compute_ja4() now derives from compute_ja4_components(),
which exposes the pre-hash structured fields (not just the final hash)
so the dashboard can render a field-by-field diff on a JA4 mismatch,
rather than just two unequal strings. compute_ja4()'s signature and
return value are unchanged -- this is a behavior-preserving refactor of
its internals, not a contract change.
"""

import hashlib
from dataclasses import dataclass

from mitmproxy.tls import ClientHello

# The 16 reserved GREASE code points (RFC 8701). Chrome and other modern
# clients inject one at a random position in both the cipher and extension
# lists on every connection; left in, they'd make JA4 non-deterministic
# for an otherwise-identical client.
GREASE_VALUES = frozenset(
    {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }
)

_SNI_EXTENSION = 0x0000
_ALPN_EXTENSION = 0x0010
_SUPPORTED_VERSIONS_EXTENSION = 0x002B

_VERSION_CODES = {
    (3, 4): "13",
    (3, 3): "12",
    (3, 2): "11",
    (3, 1): "10",
    (3, 0): "s3",
}


@dataclass(frozen=True)
class Ja4Components:
    """The pre-hash structured fields behind a JA4 string, for the diff
    view (7B.3). `ciphers`/`extensions` are already GREASE-filtered and
    sorted, as hex strings, exactly as they go into ja4_b/ja4_c."""

    ja4: str
    version_code: str
    sni_char: str
    cipher_count: int
    ext_count: int
    alpn_code: str
    ciphers: tuple[str, ...]
    extensions: tuple[str, ...]


def _tls_version_code(client_hello: ClientHello) -> str:
    """Highest TLS version the client advertised, as a 2-char JA4 code."""
    best: tuple[int, int] | None = None
    for ext_type, body in client_hello.extensions:
        if ext_type == _SUPPORTED_VERSIONS_EXTENSION and len(body) >= 1:
            count = body[0]
            versions = body[1 : 1 + count]
            for i in range(0, len(versions) - 1, 2):
                major, minor = versions[i], versions[i + 1]
                if (major << 8 | minor) in GREASE_VALUES:
                    continue
                if best is None or (major, minor) > best:
                    best = (major, minor)
    if best is not None:
        return _VERSION_CODES.get(best, "00")

    # No supported_versions extension (pre-TLS1.3 client) -- fall back to
    # the legacy version field. mitmproxy's public ClientHello API doesn't
    # expose it (see tls.py), so this reaches into the parsed kaitai
    # struct directly. Stable for the mitmproxy version this project pins
    # in requirements.txt; re-verify if that pin ever changes.
    raw_version = client_hello._client_hello.version
    return _VERSION_CODES.get((raw_version.major, raw_version.minor), "00")


def _hash12(values: tuple[str, ...]) -> str:
    joined = ",".join(values)
    return hashlib.sha256(joined.encode("ascii")).hexdigest()[:12]


def compute_ja4_components(client_hello: ClientHello) -> Ja4Components:
    proto = "t"  # this project inspects TCP+TLS only, never QUIC

    version_code = _tls_version_code(client_hello)
    sni_char = "d" if client_hello.sni else "i"

    ciphers = [c for c in client_hello.cipher_suites if c not in GREASE_VALUES]
    cipher_count = min(len(ciphers), 99)

    extensions = [(t, b) for t, b in client_hello.extensions if t not in GREASE_VALUES]
    ext_count = min(len(extensions), 99)

    alpn_protocols = client_hello.alpn_protocols
    if alpn_protocols:
        first = alpn_protocols[0].decode("ascii", errors="replace")
        alpn_code = (first[:1] + first[-1:]) if first else "00"
    else:
        alpn_code = "00"

    ja4_a = f"{proto}{version_code}{sni_char}{cipher_count:02d}{ext_count:02d}{alpn_code}"

    sorted_ciphers = tuple(sorted(f"{c:04x}" for c in ciphers))
    ja4_b = _hash12(sorted_ciphers)

    # SNI and ALPN are already represented in ja4_a; excluded here so they
    # don't double-count, per the reference format.
    sorted_extensions = tuple(
        sorted(f"{t:04x}" for t, _ in extensions if t not in (_SNI_EXTENSION, _ALPN_EXTENSION))
    )
    ja4_c = _hash12(sorted_extensions)

    return Ja4Components(
        ja4=f"{ja4_a}_{ja4_b}_{ja4_c}",
        version_code=version_code,
        sni_char=sni_char,
        cipher_count=cipher_count,
        ext_count=ext_count,
        alpn_code=alpn_code,
        ciphers=sorted_ciphers,
        extensions=sorted_extensions,
    )


def compute_ja4(client_hello: ClientHello) -> str:
    """Compute a JA4 fingerprint string from a parsed TLS ClientHello.

    Example shape: "t13d1516h2_8daaf6152771_b186095e22b6"
    (proto+version+sni / cipher_count+ext_count+alpn) _ cipher_hash _ ext_hash
    """
    return compute_ja4_components(client_hello).ja4


def diff_ja4(a: Ja4Components, b: Ja4Components) -> dict[str, tuple[object, object]]:
    """Which structured fields differ between two JA4 components, for the
    dashboard's JA4-mismatch diff view (7B.3 acceptance criterion). Returns
    only the fields that actually differ, as {field: (value_a, value_b)}.
    """
    diff: dict[str, tuple[object, object]] = {}
    for field in ("version_code", "sni_char", "cipher_count", "ext_count", "alpn_code", "ciphers", "extensions"):
        va, vb = getattr(a, field), getattr(b, field)
        if va != vb:
            diff[field] = (va, vb)
    return diff
