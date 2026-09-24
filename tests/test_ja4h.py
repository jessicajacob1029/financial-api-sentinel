"""Unit tests for proxy/ja4h.py (Phase 6 stretch)."""

from mitmproxy.http import Request

from proxy.ja4h import compute_ja4h


def _request(**headers) -> Request:
    return Request.make("GET", "http://x/y", headers=headers)


def test_stable_for_identical_header_shape():
    r1 = _request(**{"User-Agent": "httpx/1.0", "Accept": "*/*", "Accept-Encoding": "gzip"})
    r2 = _request(**{"User-Agent": "httpx/1.0", "Accept": "*/*", "Accept-Encoding": "gzip"})

    assert compute_ja4h(r1) == compute_ja4h(r2)


def test_differs_for_different_header_shape():
    httpx_like = _request(**{"User-Agent": "httpx/1.0", "Accept": "*/*", "Accept-Encoding": "gzip"})
    curl_like = _request(**{"User-Agent": "curl/8.7"})

    assert compute_ja4h(httpx_like) != compute_ja4h(curl_like)


def test_volatile_headers_excluded_from_the_shape():
    with_token = Request.make(
        "POST", "http://x/y",
        headers={"User-Agent": "httpx/1.0", "Authorization": "DPoP abc", "DPoP": "proofjwt"},
    )
    without_token = Request.make("POST", "http://x/y", headers={"User-Agent": "httpx/1.0"})

    assert compute_ja4h(with_token) == compute_ja4h(without_token)


def test_same_client_different_method_and_content_type_is_stable():
    """Regression: caught live in Phase 6 -- the same session's issuance
    POST (with a JSON body, so Content-Type present) and a follow-up GET
    (no body) must fingerprint identically. Before excluding method and
    Content-Type, this pair spuriously crossed the risk threshold on
    every legitimate session, not just hijacked ones."""
    issuance_post = Request.make(
        "POST", "http://x/oauth/token",
        headers={"User-Agent": "httpx/1.0", "Accept": "*/*", "Accept-Encoding": "gzip", "Content-Type": "application/json"},
    )
    resource_get = Request.make(
        "GET", "http://x/api/v1/accounts",
        headers={"User-Agent": "httpx/1.0", "Accept": "*/*", "Accept-Encoding": "gzip"},
    )

    assert compute_ja4h(issuance_post) == compute_ja4h(resource_get)


def test_cookie_presence_reflected():
    with_cookie = _request(**{"User-Agent": "httpx/1.0", "Cookie": "session=abc"})
    without_cookie = _request(**{"User-Agent": "httpx/1.0"})

    # ja4h_a layout: "h" + version(2) + cookie_present(1) + header_count(2)
    assert compute_ja4h(with_cookie).split("_")[0][3] == "c"
    assert compute_ja4h(without_cookie).split("_")[0][3] == "n"
