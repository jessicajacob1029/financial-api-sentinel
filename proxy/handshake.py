"""TLS handshake breakdown (Phase 7A.2): the individual negotiated
parameters behind a connection -- version, cipher, ALPN, offered
key-exchange group -- captured per connection alongside JA4, not just
the final fingerprint hash.

Honesty note on the key-exchange group: pyOpenSSL (the library mitmproxy
uses for its TLS state) does not expose the server-negotiated group --
checked its Connection API directly, there is no get_negotiated_group()
or equivalent. What IS available, and what this module reports, is the
*client's offered* group from the ClientHello's key_share extension (its
first entry, which is what a client sends as its actual preference, not
merely something it supports) -- accurate framing, not the same claim.
For this project's connections (client and mitmproxy both defaulting to
modern groups), the negotiated group in practice matches the client's
first offer, but this module doesn't overclaim that as directly observed.
"""

import hashlib
from dataclasses import dataclass

from mitmproxy import connection
from mitmproxy.tls import ClientHello

_KEY_SHARE_EXTENSION = 0x0033

_GROUP_NAMES = {
    0x0017: "secp256r1 (P-256)",
    0x0018: "secp384r1 (P-384)",
    0x0019: "secp521r1 (P-521)",
    0x001D: "X25519",
    0x001E: "X448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    # Post-quantum hybrid KEMs (classical ECDH + NIST FIPS 203 ML-KEM),
    # now offered by default on OpenSSL 3.5+/recent BoringSSL builds.
    # Confirmed live on this machine: Python's `ssl` module (OpenSSL 3.6.0)
    # offers 0x11EC as its *first* key_share entry, ahead of classical
    # X25519 -- i.e. this stack already prefers post-quantum by default.
    0x11EC: "X25519MLKEM768 (post-quantum hybrid)",  # empirically confirmed live, see above
    0x11EB: "SecP256r1MLKEM768 (post-quantum hybrid)",  # not independently confirmed, lower confidence
    0x11ED: "SecP384r1MLKEM1024 (post-quantum hybrid)",  # not independently confirmed, lower confidence
}


@dataclass(frozen=True)
class HandshakeInfo:
    tls_version: str | None
    cipher: str | None
    alpn: str | None
    offered_key_share_group: str | None
    offered_key_share_fingerprint: str | None
    clienthello_to_first_request_ms: float | None


# Phase 7A.5 (Perfect Forward Secrecy): a one-line explanation shown
# alongside the per-connection ephemeral key fingerprint, since the
# fingerprint alone doesn't explain why it matters.
PFS_EXPLANATION = (
    "Each connection generates a fresh ephemeral (EC)DHE key pair -- note the "
    "fingerprint differs below even across connections from the same client with "
    "the same DPoP key. If this session's derived traffic key were somehow "
    "exposed later, it would reveal nothing about any other session's past "
    "traffic, including earlier or later ones from this exact client."
)


def _first_key_share_entry(client_hello: ClientHello) -> tuple[int, bytes] | None:
    """(group_id, key_exchange_bytes) from the first KeyShareEntry, or
    None if the extension is absent/malformed."""
    for ext_type, body in client_hello.extensions:
        if ext_type == _KEY_SHARE_EXTENSION and len(body) >= 4:
            list_len = int.from_bytes(body[0:2], "big")
            if list_len < 4:
                return None
            group_id = int.from_bytes(body[2:4], "big")
            key_len = int.from_bytes(body[4:6], "big")
            key_bytes = body[6 : 6 + key_len]
            return group_id, key_bytes
    return None


def offered_key_share_group(client_hello: ClientHello) -> str | None:
    """The group in the first KeyShareEntry of the ClientHello's key_share
    extension (RFC 8446 SS4.2.8) -- the client's actual preference, not
    merely something it claims to support (that's supported_groups)."""
    entry = _first_key_share_entry(client_hello)
    if entry is None:
        return None
    group_id, _ = entry
    return _GROUP_NAMES.get(group_id, f"0x{group_id:04x}")


def offered_key_share_fingerprint(client_hello: ClientHello) -> str | None:
    """A short fingerprint of the client's ephemeral public key bytes from
    key_share -- not the key material itself (doc 04-style hygiene: no
    reason to echo raw key bytes into logs even though, unlike a private
    key, this is the *public* half and was already sent in the clear as
    the whole point of the handshake). Proves a fresh key per connection
    (PFS) without dumping the key itself. A short hash, not the JA4-style
    12-char truncation, since collision risk here is irrelevant -- this
    is a demo aid, not a security identifier."""
    entry = _first_key_share_entry(client_hello)
    if entry is None or not entry[1]:
        return None
    _, key_bytes = entry
    return hashlib.sha256(key_bytes).hexdigest()[:16]


def describe_connection(client_conn: connection.Client) -> dict:
    """Post-handshake fields, read directly off the mitmproxy Connection
    object -- only meaningful once TLS is established, i.e. from inside
    the `request` hook onward, never from `tls_clienthello`."""
    alpn = client_conn.alpn.decode("ascii", errors="replace") if client_conn.alpn else None
    return {
        "tls_version": client_conn.tls_version,
        "cipher": client_conn.cipher,
        "alpn": alpn,
    }
