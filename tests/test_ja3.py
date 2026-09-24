"""Unit tests for proxy/ja3.py (Phase 7A.4).

Reuses test_ja4.py's synthetic ClientHello builder so both fingerprints
are computed from literally the same wire bytes.
"""

from proxy.ja3 import compute_ja3
from proxy.ja4 import compute_ja4
from tests.test_ja4 import (
    STACK_A_CIPHERS,
    STACK_A_EXTENSIONS,
    _alpn_extension,
    _client_hello,
    _sni_extension,
    _supported_versions_extension,
)


def test_stable_for_a_fixed_client_hello():
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    assert compute_ja3(ch) == compute_ja3(ch)


def test_different_stacks_yield_different_ja3():
    from tests.test_ja4 import STACK_B_CIPHERS, STACK_B_EXTENSIONS

    ch_a = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)
    ch_b = _client_hello(STACK_B_CIPHERS, STACK_B_EXTENSIONS)

    assert compute_ja3(ch_a) != compute_ja3(ch_b)


def test_ja3_diverges_but_ja4_stable_under_extension_reordering():
    """The doc's own acceptance criterion (Build Spec 7A.4): two
    connections from the *same* client, differing only in the order
    extensions were sent (Chrome deliberately randomizes this per
    connection since ~2020, specifically to defeat JA3-style
    fingerprinting) -- JA3 must diverge, JA4 must not. This is the single
    clearest demonstration of why JA4 superseded JA3."""
    same_extensions_forward_order = [
        _supported_versions_extension([(3, 4)]),
        _sni_extension(b"example.com"),
        _alpn_extension([b"h2", b"http/1.1"]),
    ]
    same_extensions_shuffled_order = [
        _alpn_extension([b"h2", b"http/1.1"]),
        _supported_versions_extension([(3, 4)]),
        _sni_extension(b"example.com"),
    ]

    ch_forward = _client_hello(STACK_A_CIPHERS, same_extensions_forward_order)
    ch_shuffled = _client_hello(STACK_A_CIPHERS, same_extensions_shuffled_order)

    ja3_forward, ja3_shuffled = compute_ja3(ch_forward), compute_ja3(ch_shuffled)
    ja4_forward, ja4_shuffled = compute_ja4(ch_forward), compute_ja4(ch_shuffled)

    assert ja3_forward != ja3_shuffled, "JA3 should diverge when extension order changes (it doesn't sort)"
    assert ja4_forward == ja4_shuffled, "JA4 should stay stable when extension order changes (it sorts first)"


def test_grease_excluded_from_ja3():
    ch_clean = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)
    ch_with_grease = _client_hello(
        [0x0A0A, *STACK_A_CIPHERS, 0x1A1A],
        [(0x2A2A, b"\x00"), *STACK_A_EXTENSIONS],
    )

    assert compute_ja3(ch_clean) == compute_ja3(ch_with_grease)


def test_ja3_is_32_char_md5_hex():
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    ja3 = compute_ja3(ch)

    assert len(ja3) == 32
    assert all(c in "0123456789abcdef" for c in ja3)
