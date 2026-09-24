# PRD: Financial API Sentinel

**Product name:** Financial API Sentinel (JA4 + DPoP Zero-Trust Proxy)
**Doc type:** Product Requirements Document
**Owner:** Lagai
**Status:** Draft v1 (for build in Claude Code)

---

## 1. Overview

Standard OAuth 2.0 access tokens are bearer tokens: anyone who holds a valid token can use it. If an attacker steals a JWT through XSS, a leaked log, or proxy interception, they can replay that token from a completely different machine (a Python script, cURL, a different browser) and the backend has no way to tell the request is not coming from the legitimate client.

Financial API Sentinel is an inline reverse proxy that closes this gap. It binds application-layer tokens to network-layer identity. On the app layer it validates DPoP proofs (sender-constrained tokens, RFC 9449). On the network layer it computes a JA4 TLS fingerprint from the client's TLS ClientHello and binds the token to that fingerprint. When the same token arrives over a TLS handshake that does not match the one it was issued to, the proxy scores the request as anomalous and can drop the connection before it reaches the backend.

The deliverable is a working demo: a mock Open Banking API, the Sentinel proxy in front of it, three attack scripts, and a live terminal dashboard that shows fingerprints, bindings, and blocked replays in real time.

---

## 2. Goals and non-goals

### Goals
1. Demonstrate that a stolen bearer or DPoP token replayed from a different TLS stack is detected and blocked.
2. Show layered token binding: application layer (DPoP key thumbprint) plus network layer (JA4 fingerprint).
3. Produce a clear, watchable demo where a reviewer can see a legitimate request pass and a replayed token get blocked, side by side.
4. Keep the whole thing runnable on a single laptop with no external services.

### Non-goals
1. This is not a production WAF. It will not handle high throughput, clustering, or persistence beyond an in-memory cache.
2. It will not defend against an attacker who perfectly clones the victim's TLS stack (for example curl-impersonate or a uTLS-based client on the same network). That limitation is documented, not hidden. See the threat model in the TRD.
3. No real bank integration. The backend is a mock.
4. No production key management or HSM. Keys are generated locally for the demo.

---

## 3. Users and personas

Since this is a demo and portfolio project, the "users" are really the actors in the simulation plus the person evaluating it.

1. **Legitimate client (Script A).** A well-behaved mobile or web client that authenticates, receives a token bound to its JA4 and DPoP key, and completes transfers cleanly.
2. **Token thief (Script B).** An attacker who has exfiltrated a valid token and replays it from a different TLS stack (Python urllib3 or cURL instead of a browser).
3. **Route hijacker (Script C).** An attacker who replays the token with a spoofed IP or User-Agent to test the soft network signals.
4. **Security analyst / reviewer.** The person watching the dashboard. They need to instantly see why a request passed or failed.

---

## 4. User stories

1. As a legitimate client, I can authenticate once and have my token silently bound to my TLS fingerprint and DPoP key, so that later transfers succeed without extra friction.
2. As a security analyst, I can watch a live feed of connections showing the JA4 fingerprint, the bound fingerprint, the DPoP thumbprint, and the pass/block decision, so I can understand each decision at a glance.
3. As a security analyst, when a token is replayed from a different stack, I can see the mismatch highlighted and the connection terminated, so I can confirm the control works.
4. As a developer, I can run one command to start the backend, proxy, and dashboard, and separate commands to fire each attack, so the demo is repeatable.
5. As a reviewer, I can read a short decision log that explains, per request, which signals matched and which did not, so the block is explainable rather than a black box.

---

## 5. Functional requirements

**FR-1. Mock financial backend.** A FastAPI service exposing at least `GET /api/v1/accounts` and `POST /api/v1/transfer`, requiring an `Authorization: Bearer` token and a DPoP proof header. It runs behind the proxy and never receives direct external traffic in the demo.

**FR-2. Token issuance with binding.** An auth endpoint that issues a short-lived access token. On issuance, the proxy records the binding: token ID (jti), DPoP public key thumbprint (jkt), the client's JA4 fingerprint, and source IP.

**FR-3. TLS fingerprint capture.** The proxy captures the client's TLS ClientHello on connection and computes a JA4 fingerprint before the HTTP request is processed.

**FR-4. DPoP validation.** The proxy validates the DPoP proof JWT on each request: signature against the embedded JWK, `htm`/`htu` binding to the method and URL, freshness (`iat` within a window), and replay protection on the `jti`.

**FR-5. Binding evaluation.** On each authenticated request, the proxy compares the presented token against its stored binding and produces a decision from a set of signals (see FR-6).

**FR-6. Decision signals.** The engine evaluates:
- Hard signals: JA4 fingerprint match, DPoP jkt match, DPoP proof validity.
- Soft signals: source IP delta, JA4H (HTTP-layer) fingerprint, User-Agent consistency.
A request with any failed hard signal is blocked. Soft signals raise a risk score and can escalate to block above a threshold. This avoids false-positive blocks on legitimate mobile clients that roam networks.

**FR-7. Connection termination.** On a block decision, the proxy terminates the connection and returns a 401/403 (or drops the TCP connection in strict mode). The backend never sees the request.

**FR-8. Attack simulation scripts.** Three scripts (A legitimate, B token thief, C route hijack) that exercise the pass and block paths.

**FR-9. Live dashboard.** A terminal or web dashboard showing, per connection: timestamp, source IP, JA4, bound JA4, jkt, risk score, and decision, with blocked entries visually distinct.

**FR-10. Decision log.** A structured, human-readable log line per request explaining the outcome (which signals matched).

---

## 6. Success metrics

Because this is a demo, "success" is about demonstrability and correctness, not scale.

1. **Detection rate:** 100% of Script B and Script C replays that use a different TLS stack are blocked.
2. **False-positive rate:** 0% of legitimate Script A requests are blocked across a normal session, including one simulated network change (IP roam) that should only affect a soft signal.
3. **Explainability:** every block produces a log line naming the failed signal.
4. **Latency budget:** added proxy latency under a target (for example, under 50 ms per request on localhost). Nice to have, not blocking.
5. **Setup time:** a new user can run the full demo from the README in under 10 minutes.

---

## 7. Scope

### MVP (must build)
- FR-1, FR-2, FR-3 (JA4), FR-4 (DPoP), FR-5, FR-6 (hard signals at minimum), FR-7, FR-8 (Scripts A and B), FR-9 (terminal dashboard), FR-10.

### Stretch (build if time allows)
- Soft signals and full risk scoring (the soft half of FR-6), Script C, JA4H, a web dashboard, and a short "attacker with impersonated TLS" demo that shows the honest limitation.

---

## 8. Risks and open questions

1. **TLS termination vs fingerprint capture.** The proxy must both read decrypted HTTP (to see the DPoP header) and capture the raw ClientHello (for JA4). The chosen approach (mitmproxy `tls_clienthello` hook) captures the ClientHello at handshake time in the same process that later inspects HTTP, so this is solved, but it is the highest-risk integration point and should be validated first.
2. **JA4 collisions.** Two clients using the same TLS library and version produce the same JA4. So JA4 binding catches cross-stack replay but not an attacker on an identical stack. This is why DPoP (which binds to a key the attacker also has to steal) is layered on top. Document this clearly rather than overclaiming.
3. **TLS impersonation.** A determined attacker can spoof the victim's JA4 using curl-impersonate or uTLS. Sentinel raises the bar; it does not make replay impossible. State this in the writeup.
4. **Certificate trust in the demo.** Clients must trust the proxy's certificate for TLS interception to work. Handle with a locally generated CA that the client scripts trust explicitly.
5. **IP binding is fragile.** Real mobile clients roam. IP must be a soft signal only, never a hard block, or the demo will produce false positives.

---

## 9. High-level milestones

1. Mock backend plus a valid DPoP client that can complete a transfer with no proxy in the path.
2. Proxy in the path, capturing and printing JA4 per connection.
3. Binding cache plus the hard-signal decision engine (JA4 and jkt).
4. Attack scripts A and B, end to end, with blocks working.
5. Dashboard and decision log.
6. Stretch: soft signals, risk scoring, Script C, honest-limitation demo.

Detailed acceptance criteria for each milestone are in the build spec.
