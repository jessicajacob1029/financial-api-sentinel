# Financial API Sentinel

*(JA4 + DPoP Zero-Trust Proxy — Phases 0-6 complete (MVP + stretch), plus Phase 7 demo-grade enhancements: full track 7A (deeper crypto/protocol depth) and track 7B (dashboard visuals), all self-checked against 07_PHASE7_DEMO_ENHANCEMENTS.md's acceptance criteria — see §6 below.)*

## 1. What this is

Financial API Sentinel is an inline reverse proxy that binds OAuth2 access
tokens to the network connection they were issued on, so a bearer token
stolen via XSS, a leaked log, or proxy interception can't simply be
replayed from a different machine or HTTP client. It layers two signals:
DPoP (RFC 9449, app-layer proof-of-possession of a private key) and JA4
(network-layer TLS fingerprint of the client's handshake), and blocks a
request when either fails to match what a token was actually issued
against. **Honest limitation:** JA4 catches an attacker using a
*different* TLS stack than the victim (the common case — a stolen token
replayed from a Python script or curl); it does not catch an attacker who
clones the victim's exact TLS stack (e.g. curl-impersonate, uTLS) — that
residual risk is why DPoP is layered on top rather than relied on alone.
See §5 for the full threat model.

## 2. Architecture

```
[ Client / Attacker ]
        |  HTTPS + DPoP header + Bearer token
        v
+-----------------------------------------------------------+
|                   SENTINEL PROXY (single process)         |
|                                                           |
|  tls_clienthello hook          request hook               |
|  +----------------------+      +------------------------+  |
|  | L4 TLS inspector     |      | L7 protocol inspector  |  |
|  | - parse ClientHello  |      | - validate DPoP proof  |  |
|  | - compute JA4        |      | - extract jkt, jti     |  |
|  | - stash on connection|      | - compute JA4H (opt)   |  |
|  +----------+-----------+      +-----------+------------+  |
|             |                              |               |
|             +-------------+----------------+               |
|                           v                                |
|              +--------------------------+                  |
|              | Binding + decision engine|                  |
|              | - in-memory binding cache|                  |
|              | - hard + soft signals    |                  |
|              | - risk score -> decision |                  |
|              +------------+-------------+                   |
|                           |                                |
|          PASS ------------+------------ BLOCK              |
+-------------+-----------------------------------+----------+
              | forward                            | reject / drop
              v                                    v
   +----------------------+              +----------------------+
   | Mock banking backend |              | Dashboard + logs     |
   | (FastAPI)            |              | (terminal / web)     |
   +----------------------+              +----------------------+
```

Module map (matches the code): `proxy/ja4.py` (L4 fingerprint),
`proxy/ja4h.py` (L7 HTTP-shape fingerprint, soft signal), `proxy/dpop.py`
(L7 proof validation — also imported directly by `backend/auth.py`, since
Phase 1 had no proxy yet), `proxy/binding.py` (the cache), `proxy/engine.py`
(hard/soft signal decision), `proxy/dashboard.py` (Rich live table),
`proxy/webdash.py` (the same feed over a WebSocket, for a browser),
`proxy/addon.py` (thin — wires the above to mitmproxy's hooks, no logic
of its own).

## 3. Setup and running

```
make setup   # creates .venv (requires python3.10+), installs pinned deps, generates the local demo CA
make audit   # runs pip-audit against requirements.txt
make test    # runs the unit test suite (36 tests: JA4, JA4H, DPoP, binding, engine)
```

Note: the system `python3` on some machines may be older than 3.10, which
mitmproxy requires. `make setup` uses `python3.10` explicitly; override with
`make setup PY=/path/to/python3.x` if needed.

To run the live demo, open three terminals from the repo root:

```
# terminal 1
make backend    # mock banking API on http://127.0.0.1:8000

# terminal 2
make proxy      # Sentinel proxy on https://127.0.0.1:8080, live dashboard in this terminal,
                # and a live *web* dashboard at http://127.0.0.1:8090

# terminal 3 -- see SS4 below for what each attack does
make attack-a
make attack-b
make attack-c
```

Open **http://127.0.0.1:8090** in a browser for a web version of the same
live decision feed (a small Tornado app pushing events over a WebSocket —
`proxy/webdash.py`), if you'd rather watch it there than in terminal 2.
It shows the same rows, in the same PASS-green/BLOCK-red styling, updating
as requests arrive. Binds to `127.0.0.1` only, never `0.0.0.0` (doc 04 SS7)
— it shows token IDs, IPs, and fingerprints, so it's not meant to be
reachable from anywhere but this machine.

`make proxy` runs `mitmdump -q`, which suppresses mitmproxy's own per-flow
log lines so the live Rich table (terminal 2) is the only thing on
screen, updating in real time as requests arrive. (If you redirect its
output to a file instead of a real terminal — e.g. for scripting — Rich
detects the non-interactive output and prints one final snapshot on exit
rather than a stream of repainted frames; this is expected, not a bug.)

### Dependency audit (`make audit`, run 2026-08-05)

`pyjwt` and `cryptography` — the two libraries our own security-critical
code (DPoP proofs, CA/key generation) calls directly — are pinned to the
newest versions that resolve cleanly: `pyjwt==2.13.0` (no known
vulnerabilities) and `cryptography==44.0.1`.

`cryptography` cannot be bumped past 44.0.1 in this dependency set: 46.x+
requires `typing-extensions>=4.13.2`, but `mitmproxy==11.0.2` caps
`typing-extensions<=4.11.0`. `pip-audit` still flags `cryptography` and
several packages mitmproxy/fastapi pull in transitively that our code never
imports directly (`tornado`, `h2`, `starlette`, `flask`, `h11`, `msgpack`,
`brotli`, `pyOpenSSL`) — these are bounded by mitmproxy's own pins, not by
this project's requirements.txt. Revisit when mitmproxy raises its
typing-extensions ceiling.

### About the local demo CA

`make setup` runs `scripts/generate_ca.py`, which generates an EC P-256
certificate authority at `certs/ca.key` / `certs/ca.pem` (plus
`certs/mitmproxy-ca.pem`, the same key+cert in the combined layout
mitmproxy's own CertStore expects — `make proxy` points mitmproxy at it via
`--set confdir=./certs`, so the proxy intercepts TLS using *this* CA, not a
separately auto-generated one). This CA is:

- generated fresh on your machine, never committed to git (see `.gitignore`),
- for local demo use only — do not add it to a system or browser trust store
  you use for anything else,
- safe to delete any time (`make clean` removes it); regenerate with `make setup`.

### Optional: mutual TLS on the proxy<->backend leg (Phase 7A.1)

By default the proxy<->backend hop is plain HTTP (both on `127.0.0.1`,
decrypted-then-forwarded by mitmproxy's reverse mode). `make setup-mtls`
generates two more leaf certs, signed by the same local CA, to encrypt
and mutually authenticate that leg too:

```
make setup-mtls          # one-time: generates backend-server + proxy-client leaf certs
make backend MTLS=1      # backend now only accepts HTTPS with a valid client cert
make proxy MTLS=1        # proxy now authenticates itself to the backend with its own cert
make attack-a MTLS=1     # every attack-* / test command needs MTLS=1 too when backend/proxy are in this mode
```

`MTLS` must match across every terminal in one demo session — mixing
(e.g. `backend MTLS=1` with plain `make proxy`) will fail the connection,
not silently downgrade. Verified live (not just asserted):
- A request to the backend *without* a valid client cert gets zero bytes
  back and produces no access-log line at all — rejected at the TLS/transport
  layer, before the ASGI app ever sees it. The same request *with* the
  proxy's client cert gets a clean `200 OK`, logged normally.
- With a valid client cert, the connection negotiates real encryption:
  `TLSv1.3`, `TLS_AES_256_GCM_SHA384`.
- The exact same raw-socket, no-TLS request that returns full readable
  HTTP (headers, DPoP token, body) against the plaintext backend returns
  **zero bytes** against the mTLS backend — there's no plaintext HTTP to
  read off this port anymore, from *any* client, not just an attacker.

(Live `tcpdump -A` capture, as the Phase 7 doc suggests, needs root and
this sandbox has no interactive password prompt available — the checks
above prove the same property without it. `sudo tcpdump -i lo0` will work
fine in a real terminal if you want the packet-capture version too.)

## 4. Running the attack scripts

With the backend and proxy both running (§3):

**`make attack-a`** — the legitimate client. Generates one DPoP key pair,
authenticates once, lists accounts, and completes a transfer, all through
the proxy with one consistent TLS stack (httpx). Every request should
PASS. On success it writes the issued token to `demo_state/stolen_token.json`
(gitignored) so Script B can "steal" it.

**`make attack-b`** — the token thief. Reads the token Script A wrote,
generates its *own* DPoP key pair (it does not have Script A's private
key — only the bearer token, as if it were exfiltrated via XSS or a leaked
log), and replays a transfer request from `curl` — a different TLS stack
than Script A's httpx. Expected: `401`, with the proxy's dashboard/log
(not the HTTP response — see §5) showing `reason="JA4 mismatch"`. Check
the `make backend` terminal: it should show only Script A's three
requests, never Script B's — proof the replay was blocked *before* the
backend, not after.

**`make attack-c`** — the route hijacker: a *stronger* attacker than
Script B, who compromised the DPoP private key too (`demo_state/session_key.pem`),
not just the bearer token — e.g. a fully compromised endpoint rather than
a leaked log line. Same TLS stack as Script A (httpx, so JA4 matches) and
the same key (so jkt matches too) — both hard signals pass. What differs
is the network path: a spoofed `X-Forwarded-For` header (the engine
never trusts this for its real IP-delta check — deliberately, since a
client-controlled header is trivially spoofable and using it would let an
attacker *lower* their own risk score) and a different header shape,
which shifts JA4H. Expected: `401`, blocked via the **soft** risk-threshold
path (`reason="risk threshold exceeded"`), not the hard JA4-mismatch path
— check the dashboard: Script C's row will show `presented_ja4 == bound_ja4`
and `jkt_ok=yes`, identical to a legitimate row, yet still `BLOCK`. This
contrast with Script B is the most instructive part of the demo.

Script A's own IP-roam step (end of `make attack-a`) needs a one-time,
reversible loopback alias not enabled by default on macOS:
`sudo ifconfig lo0 alias 127.0.0.2 up` (remove later with
`sudo ifconfig lo0 -alias 127.0.0.2`). Without it, the script explains
this and skips that one step rather than silently pretending it ran; the
same property (IP change alone doesn't block a legitimate session) is
proven without sudo by `make test`
(`tests/test_engine.py::test_ip_change_alone_does_not_block_a_legit_session`,
which drives the real `evaluate()` function, not a mock).

## 5. Threat model and limitations

**In scope (defended):**
- **Cross-stack token replay.** Token stolen and replayed from Python, curl, or a different browser. Caught by the JA4 hard signal — this is exactly what `make attack-b` demonstrates.
- **DPoP proof replay.** Same proof reused. Caught by the atomic `jti` replay cache in `proxy/binding.py`.
- **Bearer token replay without a valid DPoP proof.** Caught by DPoP signature/jkt validation regardless of JA4.
- **IP change or HTTP-header-shape (JA4H) change.** Each alone contributes to a risk score (`proxy/engine.py`); IP change alone (+1) stays under `RISK_THRESHOLD` (2) so a roaming legitimate client is never blocked on that signal by itself, but IP change combined with a JA4H shift (+2), or JA4H alone, crosses it — `make attack-c` demonstrates exactly this path, distinct from Script B's hard block.

**Out of scope (documented limitations, not overclaimed):**
- **Identical-stack replay.** An attacker using the exact same TLS library and version as the victim produces the same JA4. JA4 alone will not catch this — DPoP (which needs the private key, not just the bearer token) is the backstop.
- **TLS impersonation.** Tools like curl-impersonate, uTLS, or tls-client can forge a target's JA4. Sentinel raises the cost of replay and catches the common case (an attacker on a different, ordinary stack); it is not unbreakable.
- **Compromise of both the token and the DPoP private key, plus a cloned TLS stack.** Outside this demo's scope entirely.

### Honest limitation, demonstrated (run 2026-08-05)

The claim above — "JA4 alone will not catch identical-stack replay" —
was verified live, not just asserted. After a normal Script A session
(binding recorded), a request was sent presenting Script A's stolen
bearer token, but signed with a *different* DPoP key (an attacker who
never had the private key, same as Script B), from the *same* TLS
stack/library as Script A (httpx) rather than a different one:

```
identical-stack replay -> 401 {"detail":"unauthorized"}
```

The dashboard for that request:

```
presented_ja4: t13i1711h1_ab0a1bf4...   bound_ja4: t13i1711h1_ab0a1bf4...   jkt_ok: no   DECISION: BLOCK
reason: DPoP jkt mismatch
```

`presented_ja4` exactly equals `bound_ja4` — if the decision engine
checked JA4 alone, this request would have PASSED. The only thing that
caught it was the DPoP `jkt` hard signal, because the attacker had the
bearer token but not the private key. This is the precise scenario the
threat model above warns about, and the precise reason DPoP is layered on
top of JA4 rather than JA4 being relied on by itself.

**Framing:** this is a layered, sender-constrained token architecture —
DPoP provides cryptographic proof of possession at the app layer, JA4 adds
a network-layer binding for defense in depth. JA4 raises the bar and
catches a real, common class of replay; it is not presented as a silver
bullet, and the block reason a client actually receives on the wire is
always the generic `401 {"detail":"unauthorized"}` — the specific reason
(`"JA4 mismatch"`, etc.) is deliberately proxy-log/dashboard-only, never
echoed back to a caller who could use it to fingerprint the defense.

## 6. Phase 7: demo-grade enhancements

Everything below is additive on top of Phases 0–6 (per `07_PHASE7_DEMO_ENHANCEMENTS.md` §5) — no core module contract in `engine.py` or `binding.py` changed. All of it is visible in the same `make proxy` run; most of it lives in the web dashboard (`http://127.0.0.1:8090`).

### Track 7A — protocol depth

- **7A.1 mTLS (proxy↔backend leg).** `make setup-mtls`, then `MTLS=1` on `make backend` / `make proxy` / every `attack-*` target. See §3's mTLS subsection above for the full writeup and what was verified live (rejection at the TLS layer with zero HTTP exchanged, real `TLS_AES_256_GCM_SHA384` negotiation).
- **7A.2 handshake breakdown.** Click any row in the web dashboard — negotiated TLS version, cipher, ALPN, and the client's offered key-exchange group are shown per connection, not just the JA4 hash. (Caught live during development: this machine's OpenSSL 3.6.0 offers `X25519MLKEM768`, a post-quantum hybrid KEM, by default ahead of classical X25519.)
- **7A.3 certificate validation failure demo.** `make attack-d` (add `MTLS=1` for scenario 2, needs the mTLS backend already running). Two scenarios, both real: a client that doesn't trust the proxy's CA fails at the TLS layer before any HTTP is sent; a self-signed client cert presented to the mTLS backend gets rejected server-side. Verified live that the dashboard shows `tls_clienthello` fired but zero PASS/BLOCK decisions were ever made for the rejected attempt — a genuinely different failure class than an application-level BLOCK.
- **7A.4 JA3 vs JA4.** Shown side by side in every row's connection details (web dashboard). `tests/test_ja3.py::test_ja3_diverges_but_ja4_stable_under_extension_reordering` proves the actual point: same client, extensions sent in a different order (what Chrome does deliberately) — JA3 changes, JA4 doesn't.
- **7A.5 Perfect Forward Secrecy.** Each connection's ephemeral key-share fingerprint is shown per row — verified live that two connections from the exact same client (identical JA3/JA4) produce two different fingerprints every time.
- **7A.6 packet-level view.** `python scripts/capture_sample_flow.py` — a transparent TCP byte relay (root packet capture isn't available in this sandbox; see the script's docstring) that shows a real ClientHello, real ServerHello, and then genuinely opaque encrypted records for everything after, for one live flow.

### Track 7B — dashboard visuals

All in the web dashboard, driven by the same WebSocket feed the table already uses — no separate data path:

- **7B.1 / 7B.4 live topology + attack replay animation.** A packet animates Client → Proxy → Backend on PASS; on BLOCK it visibly stops at the proxy with the reason labeled, never continuing to the backend. Verified precisely (not just by screenshot) via direct DOM/timing inspection of both paths.
- **7B.2 handshake sequence diagram.** Click a row → the standard TLS 1.3 message flow, annotated with that connection's real negotiated values (not a generic diagram — see the module docstring in `proxy/webdash.py` for the honesty note on what's literally captured vs. structurally known).
- **7B.5 simulated geo/IP map.** Clearly labeled "simulated — not real geolocation" (everything here is actually 127.0.0.1); each distinct JA4 deterministically maps to a fixed demo location, so a legit client and a replaying attacker land at different, stable points.
- **7B.6 interactive risk-threshold slider.** Drag it and watch historical rows flip PASS/BLOCK live — verified specifically that a hard-signal block (`JA4 mismatch`) never flips regardless of threshold, while a genuine `risk threshold exceeded` block does, matching `engine.py`'s actual hard-before-soft evaluation order.
- **7B.7 kill-chain timeline.** Groups events by the token's `jti` (Script A issues it, Scripts B/C explicitly reuse it, so the jti already is the natural story id) into one connected sequence: token issued → legitimate use → replay attempt → block, instead of scattered table rows.

### Track 7C — new features

- **7C.1 token revocation.** `POST /oauth/revoke {"jti": "..."}` (intercepted at the proxy, never reaches the backend) immediately marks a binding revoked; the very next request presenting that token is blocked with `reason="token revoked"`, checked first in `engine.py`, ahead of every other hard signal. `make attack-e` demonstrates it end to end.
- **7C.2 adaptive step-up authentication.** A `PASS` whose risk score lands in `[challenge_threshold, risk_threshold)` — neither clean nor bad enough to auto-block — gets a `428` with a single-use nonce instead of being forwarded; a fresh DPoP proof signing that nonce (RFC 9449 §4.3's own `nonce` claim) lets the request through. `make attack-f` demonstrates the full challenge/response round trip.
- **7C.3 token-issuance rate limiting.** A sliding window (5 attempts / 30s, keyed by JA4 — not source IP, consistent with IP being a documented soft/fragile signal) throttles `/oauth/token` with `429`, logged and counted distinctly from PASS/BLOCK decisions.
- **7C.4 `scripts/sentinel_replay.py`.** An ad-hoc CLI replay tool for live Q&A — `--stack {httpx,requests,curl}`, `--target`, `--same-key` — without needing to edit a script file mid-demo.
- **7C.5 config-driven policy engine.** `policy.yaml` externalizes the risk threshold, challenge threshold, and soft-signal weights (loaded once at proxy startup by `proxy/policy.py`, strict validation — unknown/missing keys or a `challenge_threshold >= risk_threshold` invariant violation fails startup loudly, no silent fallback). Hard signals themselves are deliberately **not** policy-configurable — see the file's header comment.
- **7C.6 hash-chained tamper-evident audit log.** Every significant event (issuance, decision, revocation, rate limit, challenge issued/passed) is appended to a Certificate-Transparency-style hash chain, mirrored to `demo_state/audit_log.jsonl`. `python scripts/verify_audit_log.py` independently re-walks the chain. Verified live: an untouched log passes; manually editing one historical entry's payload is caught immediately, at that exact entry, with a clear reason.
- **7C.7 attacker sophistication scoring.** Each decision is scored 0–3 on how many of the three attacker-defeatable hard signals (DPoP validity, JA4 match, jkt match) it matched, shown as a labeled badge (`trivial`/`low`/`moderate`/`high`) next to every row in both dashboards. Verified live: Script B (bearer-token theft, different TLS stack) scores `1/3 low` and is caught by a hard `JA4 mismatch` block; Script C (full session compromise, same stack and key) scores `3/3 high` and is only caught via soft-signal risk scoring (`risk threshold exceeded`), never a hard block — visually demonstrating that a more sophisticated attacker is harder to catch.
