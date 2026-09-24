"""Unit tests for proxy/ja4.py (Build Spec SS8).

Uses hand-built synthetic TLS ClientHello byte fixtures (per the TLS 1.3
ClientHello wire format mitmproxy's kaitai parser expects) rather than a
live capture, so these run fully offline and deterministically -- no
socket, no real TLS handshake. Phase 2's live acceptance check (a real
httpx handshake vs. a real curl handshake producing different JA4
strings against a running mitmproxy addon) was already run manually; see
the phase report.
"""

from mitmproxy.tls import ClientHello

from proxy.ja4 import compute_ja4, compute_ja4_components, diff_ja4


def _u8(n: int) -> bytes:
    return bytes([n])


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _sni_extension(hostname: bytes) -> tuple[int, bytes]:
    server_name = _u8(0) + _u16(len(hostname)) + hostname  # name_type=0 (host_name)
    return (0x0000, _u16(len(server_name)) + server_name)


def _alpn_extension(protocols: list[bytes]) -> tuple[int, bytes]:
    protos = b"".join(_u8(len(p)) + p for p in protocols)
    return (0x0010, _u16(len(protos)) + protos)


def _supported_versions_extension(versions: list[tuple[int, int]]) -> tuple[int, bytes]:
    vbytes = b"".join(bytes([major, minor]) for major, minor in versions)
    return (0x002B, _u8(len(vbytes)) + vbytes)


def _build_client_hello_bytes(
    cipher_suites: list[int],
    extensions: list[tuple[int, bytes]],
    legacy_version: tuple[int, int] = (3, 3),
) -> bytes:
    version = bytes(legacy_version)
    random_ = b"\x00" * 32
    session_id = _u8(0)
    cs_bytes = b"".join(_u16(c) for c in cipher_suites)
    cipher_suites_field = _u16(len(cs_bytes)) + cs_bytes
    compression_methods = _u8(1) + b"\x00"
    ext_bytes = b"".join(_u16(t) + _u16(len(body)) + body for t, body in extensions)
    extensions_field = _u16(len(ext_bytes)) + ext_bytes
    return version + random_ + session_id + cipher_suites_field + compression_methods + extensions_field


def _client_hello(cipher_suites, extensions, legacy_version=(3, 3)) -> ClientHello:
    raw = _build_client_hello_bytes(cipher_suites, extensions, legacy_version)
    return ClientHello(raw)


STACK_A_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C]
STACK_A_EXTENSIONS = [
    _supported_versions_extension([(3, 4)]),
    _sni_extension(b"example.com"),
    _alpn_extension([b"h2", b"http/1.1"]),
]

STACK_B_CIPHERS = [0x1301, 0x1302, 0xC030, 0xC02F, 0xC028, 0xC027, 0x009F]
STACK_B_EXTENSIONS = [
    _supported_versions_extension([(3, 4)]),
    _alpn_extension([b"http/1.1"]),
]


def test_stable_for_a_fixed_client_hello():
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    first = compute_ja4(ch)
    second = compute_ja4(ch)

    assert first == second
    assert first == "t13d0503h2_" + first.split("_", 1)[1]  # ja4_a is exact and deterministic


def test_ja4_a_fields_match_the_client_hello():
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    ja4 = compute_ja4(ch)
    ja4_a = ja4.split("_")[0]

    assert ja4_a == "t13d0503h2"  # tcp, TLSv1.3, sni present, 5 ciphers, 3 extensions, alpn "h2"


def test_different_stacks_yield_different_ja4():
    ch_a = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)
    ch_b = _client_hello(STACK_B_CIPHERS, STACK_B_EXTENSIONS)

    ja4_a = compute_ja4(ch_a)
    ja4_b = compute_ja4(ch_b)

    assert ja4_a != ja4_b


def test_no_sni_yields_i_not_d():
    ch = _client_hello(STACK_B_CIPHERS, STACK_B_EXTENSIONS)

    ja4 = compute_ja4(ch)

    assert ja4.split("_")[0][3] == "i"


def test_grease_values_are_excluded_from_counts_and_hash():
    ch_clean = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)
    ch_with_grease = _client_hello(
        [0x0A0A, *STACK_A_CIPHERS, 0x1A1A],
        [(0x2A2A, b"\x00"), *STACK_A_EXTENSIONS],
    )

    assert compute_ja4(ch_clean) == compute_ja4(ch_with_grease)


def test_legacy_version_fallback_when_no_supported_versions_extension():
    # A pre-TLS1.3 client hello: no supported_versions extension at all,
    # so compute_ja4 must fall back to the legacy ClientHello.version field.
    ch = _client_hello(
        [0xC02F, 0xC030],
        [_alpn_extension([b"http/1.1"])],
        legacy_version=(3, 3),
    )

    ja4_a = compute_ja4(ch).split("_")[0]

    assert ja4_a.startswith("t12")


def test_no_alpn_yields_00_code():
    ch = _client_hello(STACK_B_CIPHERS, [_supported_versions_extension([(3, 4)])])

    ja4_a = compute_ja4(ch).split("_")[0]

    assert ja4_a.endswith("00")


def test_components_ja4_matches_compute_ja4():
    """compute_ja4() must still return exactly what it always did (7B.3
    is a behavior-preserving refactor, not a contract change)."""
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    assert compute_ja4_components(ch).ja4 == compute_ja4(ch)


def test_components_stable_for_a_fixed_client_hello():
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    first = compute_ja4_components(ch)
    second = compute_ja4_components(ch)

    assert first == second  # frozen dataclass, structural equality


def test_diff_ja4_identifies_the_diverging_fields():
    ch_a = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)
    ch_b = _client_hello(STACK_B_CIPHERS, STACK_B_EXTENSIONS)

    diff = diff_ja4(compute_ja4_components(ch_a), compute_ja4_components(ch_b))

    # Stack A: SNI present, 5 ciphers, 3 extensions, ALPN "h2".
    # Stack B: no SNI, 7 ciphers, 2 extensions, ALPN "h1".
    assert diff["sni_char"] == ("d", "i")
    assert diff["cipher_count"] == (5, 7)
    assert diff["ext_count"] == (3, 2)
    assert diff["alpn_code"] == ("h2", "h1")
    assert "ciphers" in diff
    # "extensions" (the sorted non-SNI/ALPN extension list) is NOT in the
    # diff here: both fixtures reduce to the same single entry
    # (supported_versions) once SNI/ALPN are excluded per the JA4 spec --
    # ext_count still captures that A additionally sent an SNI extension.
    assert "extensions" not in diff
    assert "version_code" not in diff  # both stacks are TLS 1.3


def test_diff_ja4_covers_extensions_field_when_it_actually_diverges():
    # Two fixtures with the same cipher/SNI/ALPN shape but a genuinely
    # different *set* of other extensions (0x0033 key_share vs 0x000d
    # signature_algorithms), so "extensions" itself is what diverges here.
    ch_key_share = _client_hello(
        STACK_A_CIPHERS,
        [_supported_versions_extension([(3, 4)]), (0x0033, b"\x00")],
    )
    ch_sig_algs = _client_hello(
        STACK_A_CIPHERS,
        [_supported_versions_extension([(3, 4)]), (0x000D, b"\x00")],
    )

    diff = diff_ja4(compute_ja4_components(ch_key_share), compute_ja4_components(ch_sig_algs))

    assert "extensions" in diff
    assert diff["extensions"] == (("002b", "0033"), ("000d", "002b"))
    assert "ext_count" not in diff  # both have 2 extensions -- only *which* ones differs


def test_diff_ja4_empty_for_identical_components():
    ch = _client_hello(STACK_A_CIPHERS, STACK_A_EXTENSIONS)

    diff = diff_ja4(compute_ja4_components(ch), compute_ja4_components(ch))

    assert diff == {}
