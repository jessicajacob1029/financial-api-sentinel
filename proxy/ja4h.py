"""JA4H HTTP-layer fingerprint (Phase 6 stretch, per PRD SS7 / TRD architecture
diagram's "compute JA4H (opt)" box).

Scoped implementation, same honesty stance as ja4.py: this captures the
property the soft-signal demo (Script C) needs -- two different HTTP
client configurations produce different fingerprints, one consistent
client produces a stable one -- without reproducing every field of
FoxIO's full JA4H spec (no per-cookie hash, no full method/version
2-letter code table).

Deliberately excludes HTTP method from the fingerprint, unlike real JA4H:
this project's binding is created from a POST /oauth/token request and
compared against later GET/POST resource requests in the *same* session.
Including method meant a legitimate client's own token-issuance POST and
follow-up GET produced different fingerprints every single time -- a
false ja4h_delta on every normal session, not a signal of anything (this
was caught live: Script A's own first accounts request tripped the risk
threshold before this fix). Fields used instead: HTTP version, header
count, cookie presence, and a hash of the as-received header *name* order
and casing (excluding headers that legitimately vary per-request rather
than per-client: Authorization, DPoP, Content-Length, Content-Type, Host
-- Content-Type in particular is a function of "does this request have a
body", not which HTTP client library sent it).
"""

import hashlib

from mitmproxy import http

_VOLATILE_HEADERS = frozenset({b"authorization", b"dpop", b"content-length", b"content-type", b"host"})


def _hash12(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def compute_ja4h(request: http.Request) -> str:
    version = request.http_version or ""
    if "2" in version:
        version_code = "20"
    elif "1.0" in version:
        version_code = "10"
    else:
        version_code = "11"

    cookie_present = "c" if request.headers.get("cookie") else "n"

    header_names = [
        name for name, _ in request.headers.fields if name.lower() not in _VOLATILE_HEADERS
    ]
    header_count = min(len(header_names), 99)

    ja4h_a = f"h{version_code}{cookie_present}{header_count:02d}"
    ja4h_b = _hash12(",".join(n.decode("latin-1") for n in header_names))

    return f"{ja4h_a}_{ja4h_b}"
