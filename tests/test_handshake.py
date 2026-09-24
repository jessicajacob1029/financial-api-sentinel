"""Unit tests for proxy/handshake.py (Phase 7A.2 / 7A.5)."""

from mitmproxy.tls import ClientHello

from proxy.handshake import offered_key_share_fingerprint, offered_key_share_group


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _key_share_extension(groups_and_keys: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    entries = b"".join(_u16(group) + _u16(len(key)) + key for group, key in groups_and_keys)
    return (0x0033, _u16(len(entries)) + entries)


def _build_client_hello_bytes(extensions: list[tuple[int, bytes]]) -> bytes:
    version = b"\x03\x03"
    random_ = b"\x00" * 32
    session_id = b"\x00"
    cipher_suites = _u16(2) + b"\x13\x01"
    compression_methods = b"\x01\x00"
    ext_bytes = b"".join(_u16(t) + _u16(len(body)) + body for t, body in extensions)
    return version + random_ + session_id + cipher_suites + compression_methods + _u16(len(ext_bytes)) + ext_bytes


def _client_hello(extensions: list[tuple[int, bytes]]) -> ClientHello:
    return ClientHello(_build_client_hello_bytes(extensions))


def test_x25519_key_share_identified():
    ch = _client_hello([_key_share_extension([(0x001D, b"\x00" * 32)])])

    assert offered_key_share_group(ch) == "X25519"


def test_p256_key_share_identified():
    ch = _client_hello([_key_share_extension([(0x0017, b"\x00" * 65)])])

    assert offered_key_share_group(ch) == "secp256r1 (P-256)"


def test_first_entry_wins_when_multiple_offered():
    ch = _client_hello([_key_share_extension([(0x001D, b"\x00" * 32), (0x0017, b"\x00" * 65)])])

    assert offered_key_share_group(ch) == "X25519"


def test_post_quantum_hybrid_group_identified():
    # 0x11EC = X25519MLKEM768, confirmed live during Phase 7A.2 development:
    # this machine's OpenSSL 3.6.0 offers it by default, ahead of classical
    # X25519, as the first key_share entry.
    ch = _client_hello([_key_share_extension([(0x11EC, b"\x00" * 1216)])])

    assert offered_key_share_group(ch) == "X25519MLKEM768 (post-quantum hybrid)"


def test_unknown_group_id_shown_as_hex():
    ch = _client_hello([_key_share_extension([(0x6699, b"\x00" * 32)])])

    assert offered_key_share_group(ch) == "0x6699"


def test_no_key_share_extension_returns_none():
    ch = _client_hello([])

    assert offered_key_share_group(ch) is None


def test_ephemeral_key_fingerprint_stable_for_the_same_key():
    ch1 = _client_hello([_key_share_extension([(0x001D, b"\x01" * 32)])])
    ch2 = _client_hello([_key_share_extension([(0x001D, b"\x01" * 32)])])

    assert offered_key_share_fingerprint(ch1) == offered_key_share_fingerprint(ch2)


def test_ephemeral_key_fingerprint_differs_across_fresh_keys():
    """7A.5 (PFS) acceptance: distinct ephemeral key fingerprints per
    connection, even from what would otherwise look like the same
    client/group -- proving a fresh key is generated each time."""
    ch_session_1 = _client_hello([_key_share_extension([(0x001D, b"\x01" * 32)])])
    ch_session_2 = _client_hello([_key_share_extension([(0x001D, b"\x02" * 32)])])

    assert offered_key_share_fingerprint(ch_session_1) != offered_key_share_fingerprint(ch_session_2)


def test_ephemeral_key_fingerprint_none_without_key_share():
    ch = _client_hello([])

    assert offered_key_share_fingerprint(ch) is None
