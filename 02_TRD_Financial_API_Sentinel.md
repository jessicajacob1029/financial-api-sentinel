# TRD: Financial API Sentinel

**Doc type:** Technical Requirements Document
**Companion to:** 01_PRD_Financial_API_Sentinel.md
**Status:** Draft v1

---

## 1. Purpose

This document describes how Financial API Sentinel is built: the architecture, the key technical decisions and their rationale, the data flows, the data model, and the security and threat model. It is written to be handed to Claude Code as build context.

---

## 2. System architecture

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

The critical design point: JA4 capture and DPoP inspection happen in the **same process**. The proxy captures the ClientHello at handshake time, computes the JA4, and attaches it to the connection context. When the decrypted HTTP request arrives, the request handler reads that stashed JA4 alongside the DPoP header. No separate packet-capture sidecar is needed.

---

## 3. Key technical decisions

### TD-1: Use mitmproxy as the proxy runtime (Python)
**Decision:** Build the proxy as a mitmproxy addon.
**Rationale:** mitmproxy exposes a `tls_clienthello` event hook that hands you the fully parsed ClientHello, and `request` / `response` hooks that hand you the decrypted HTTP. Both fire in the same Python process, so binding L4 fingerprint to L7 token is straightforward. It terminates TLS 1.2 and 1.3, handles ALPN, and needs no fork. This is the fastest path to a working demo and pairs well with an iterative build in Claude Code.
**Alternative considered:** A Go reverse proxy on `crypto/tls` plus `gopacket` (the fingerproxy pattern) gives cleaner fingerprints and better performance but is more code and slower to iterate. Keep it as a possible v2.

### TD-2: JA4 as the primary hard network signal
**Decision:** Compute JA4 (not just JA3) from the ClientHello and treat a JA4 mismatch as a hard block.
**Rationale:** JA4 normalizes and sorts cipher suites and extensions before hashing, so it resists the extension-order randomization that Chrome and others now do, which JA3 does not. JA4 is a 36-character string with a readable prefix plus a truncated SHA-256 hash, so it is partly interpretable in logs without a lookup table. It is the current industry standard (adopted by major CDNs and cloud WAFs).
**Note:** compute JA4 yourself from the parsed ClientHello fields (TLS version, SNI present, cipher suite count, extension count, first ALPN, sorted cipher and extension lists) rather than depending on a heavy external service. A small pure-Python function over the mitmproxy ClientHello object is enough. Cross-check output against the FoxIO reference format.

### TD-3: DPoP for application-layer proof of possession
**Decision:** Require and validate DPoP proofs (RFC 9449) per request.
**Rationale:** DPoP binds the access token to a key pair the client holds. A stolen access token alone is useless without the DPoP private key, so DPoP is the app-layer half of the binding. JA4 is the network-layer half. Together they are defense in depth: the attacker would need to steal both the token and the DPoP key **and** clone the TLS stack.
**Validation checklist per request:** signature verifies against embedded JWK; `htm` matches the HTTP method; `htu` matches the request URL; `iat` is within the freshness window; `jti` has not been seen before (replay cache); the token's bound thumbprint (jkt) equals the SHA-256 thumbprint of the DPoP JWK.

### TD-4: Hard signals block, soft signals score
**Decision:** Split signals into hard (binary block) and soft (risk score).
**Rationale:** Binding on IP or TCP window as a hard block would false-positive constantly, because legitimate mobile clients roam networks. So JA4 match, jkt match, and DPoP validity are hard. IP delta, JA4H, and User-Agent consistency are soft: they add to a risk score that only blocks above a threshold. This is both more realistic and what makes the demo credible.

### TD-5: In-memory binding cache
**Decision:** Store bindings in an in-memory dict keyed by token jti (or jkt).
**Rationale:** Demo scope. No persistence needed. Keep an interface (a small class) so it could later be swapped for Redis without touching the engine.

---

## 4. Data flows

### 4.1 Authentication / binding flow
1. Client generates a DPoP key pair.
2. Client calls the auth endpoint with a DPoP proof.
3. Proxy captures the ClientHello, computes JA4, stashes it on the connection.
4. Auth issues a short-lived access token with jti.
5. Proxy records a binding: `{ jti, jkt, ja4, source_ip, issued_at }`.
6. Token returned to client.

### 4.2 Resource request flow
1. Client sends `POST /api/v1/transfer` with Bearer token and a fresh DPoP proof.
2. Proxy computes the connection's JA4 (from this connection's ClientHello).
3. Request handler validates the DPoP proof (TD-3 checklist).
4. Engine looks up the binding by jti and evaluates:
   - JA4 == bound JA4  (hard)
   - jkt == bound jkt   (hard)
   - DPoP valid          (hard)
   - IP delta, JA4H, UA  (soft, contribute to score)
5. Decision: pass, or block. On pass, forward to backend. On block, reject and log.

### 4.3 Attack flow (Script B)
Same as 4.2, but the token was issued to Script A's connection. Script B's JA4 differs (different TLS stack), so the hard JA4 signal fails and the request is blocked before reaching the backend.

---

## 5. Data model

**Binding record (in-memory):**
```
Binding {
  jti:        str      # token ID
  jkt:        str      # DPoP public key SHA-256 thumbprint
  ja4:        str      # bound TLS fingerprint
  source_ip:  str      # for soft IP-delta signal
  issued_at:  int      # epoch seconds
  ja4h:       str|None # optional bound HTTP fingerprint
}
```

**Decision record (logged per request):**
```
Decision {
  ts:           int
  source_ip:    str
  presented_ja4:str
  bound_ja4:    str
  jkt_match:    bool
  dpop_valid:   bool
  ip_delta:     bool
  risk_score:   int
  outcome:      "PASS" | "BLOCK"
  reason:       str    # e.g. "JA4 mismatch"
}
```

**DPoP replay cache:** a set (or TTL cache) of seen `jti` values from DPoP proofs, to reject replayed proofs.

---

## 6. Security and threat model

### In scope (defended)
- **Cross-stack token replay.** Token stolen and replayed from Python, cURL, or a different browser. Caught by JA4 hard signal.
- **DPoP proof replay.** Same proof reused. Caught by the jti replay cache and freshness window.
- **Bearer token replay without DPoP.** If a legacy bearer path exists, JA4 binding still catches cross-stack replay.
- **IP or UA spoofing (Script C).** Contributes to risk score; blocks above threshold when combined with other anomalies.

### Out of scope (documented limitations, do not overclaim)
- **Identical-stack replay.** An attacker using the exact same TLS library and version as the victim produces the same JA4. JA4 alone will not catch this; DPoP (needing the private key) is the backstop. State this.
- **TLS impersonation.** curl-impersonate, uTLS, and tls-client can forge a target JA4. Sentinel raises cost and catches unsophisticated replay; it is not unbreakable.
- **Compromise of both token and DPoP key plus a cloned stack.** Outside demo scope.

### Honesty note for the writeup
The strongest and most defensible framing is: this is a **layered, sender-constrained token architecture** where DPoP provides cryptographic proof of possession at the app layer and JA4 adds a network-layer binding for defense in depth. Present JA4 as raising the bar and catching a real, common class of replay (stolen bearer token used from a script), not as a silver bullet. That framing is both accurate and more impressive to a security reviewer than an overclaim.

---

## 7. Tech stack

| Concern | Choice | Notes |
|---|---|---|
| Proxy runtime | mitmproxy (addon) | `tls_clienthello` + `request` hooks |
| Backend | FastAPI + uvicorn | mock Open Banking endpoints |
| JWT / DPoP | PyJWT + cryptography | key gen, sign, verify, thumbprint |
| JA4 | small in-repo function over mitmproxy ClientHello | validate vs FoxIO reference format |
| Binding cache | in-memory dict behind a small interface | Redis-swappable later |
| Dashboard | Rich (terminal) for MVP; Streamlit or WebSocket for stretch | live table of decisions |
| Client scripts | requests / httpx (legit + thief), cURL (thief variant) | different stacks drive the JA4 mismatch |
| Local TLS | self-generated CA + cert | clients trust it explicitly |

---

## 8. Non-functional requirements

1. **Runs on one laptop, no external services.**
2. **One-command startup** for backend + proxy + dashboard (a Makefile or a small runner script).
3. **Deterministic demo:** each attack script produces the same outcome every run.
4. **Explainable:** every block emits a reason string.
5. **Added latency** target under ~50 ms per request on localhost (soft target).
6. **Readable code:** the JA4 function and the decision engine are the two files a reviewer will read, so keep them clean and commented.

---

## 9. Build-order recommendation (de-risk first)

Build in this order so the riskiest integration is proven early:
1. Backend + DPoP client with **no proxy** (prove DPoP works).
2. Insert the proxy and print JA4 per connection (prove L4 capture works).
3. Only then add the binding cache and decision engine.
4. Then attack scripts, then dashboard, then soft signals.

Rationale: step 2 is the highest-risk unknown. If ClientHello capture and JA4 computation work end to end, the rest is standard application code.
