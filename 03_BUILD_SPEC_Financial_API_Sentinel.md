# Build Spec: Financial API Sentinel

**Doc type:** Implementation / Build Spec (for Claude Code)
**Companion to:** 01_PRD and 02_TRD
**Status:** Draft v1

This is the concrete blueprint: repo layout, per-module contracts, API definitions, the decision engine rules, attack-script behavior, and phased milestones with acceptance criteria. Feed this to Claude Code and build phase by phase.

---

## 1. Repository structure

```
financial-api-sentinel/
├── README.md
├── Makefile                  # or run.py: one-command startup + attack runners
├── requirements.txt
├── certs/
│   ├── ca.pem                # locally generated CA (git-ignored)
│   └── ca.key
├── backend/
│   ├── main.py               # FastAPI app
│   ├── auth.py               # token issuance
│   ├── models.py             # request/response schemas
│   └── mock_data.py          # fake accounts, balances
├── proxy/
│   ├── addon.py              # mitmproxy addon: hooks + wiring
│   ├── ja4.py                # JA4 computation from ClientHello
│   ├── dpop.py               # DPoP proof validation
│   ├── binding.py            # binding cache (interface + in-memory impl)
│   ├── engine.py             # decision engine: signals -> decision
│   └── dashboard.py          # live terminal dashboard (Rich)
├── client/
│   ├── keys.py               # DPoP keypair gen + thumbprint
│   ├── dpop_client.py        # shared: build signed DPoP proof
│   ├── script_a_legit.py     # legitimate user
│   ├── script_b_thief.py     # token thief, different TLS stack
│   └── script_c_hijack.py    # spoofed IP / UA (stretch)
└── tests/
    ├── test_ja4.py
    ├── test_dpop.py
    └── test_engine.py
```

---

## 2. Module contracts

### 2.1 `proxy/ja4.py`
```
def compute_ja4(client_hello) -> str
    # input: mitmproxy parsed ClientHello object
    # output: JA4 string, e.g. "t13d1516h2_8daaf6152771_b186095e22b6"
    # derive: TLS version, SNI present (d/i), cipher count, extension count,
    #         first ALPN, then truncated SHA-256 over sorted ciphers and
    #         sorted extensions. Follow the FoxIO JA4 format.
```
Acceptance: given a fixed ClientHello, returns a stable string; a Python-requests handshake and a browser handshake yield different strings.

### 2.2 `proxy/dpop.py`
```
def validate_dpop(proof_jwt: str, method: str, url: str, now: int) -> DpopResult
    # verify signature against embedded JWK
    # check htm == method, htu == url, iat within window
    # return jkt (SHA-256 JWK thumbprint), jti, and validity + reason
```
Acceptance: a correctly signed fresh proof validates; a wrong-method, expired, or tampered proof fails with a reason.

### 2.3 `proxy/binding.py`
```
class BindingStore:
    def bind(self, jti, jkt, ja4, source_ip, issued_at) -> None
    def get(self, jti) -> Binding | None
    def seen_dpop_jti(self, jti) -> bool     # replay cache
    def mark_dpop_jti(self, jti) -> None
```
Acceptance: bind then get round-trips; replay cache rejects a repeated jti.

### 2.4 `proxy/engine.py`
```
def evaluate(binding: Binding, presented_ja4: str, dpop: DpopResult,
             source_ip: str, ja4h: str|None) -> Decision
    # hard signals (any fail -> BLOCK):
    #   dpop.valid, presented_ja4 == binding.ja4, dpop.jkt == binding.jkt
    # soft signals (add to risk score):
    #   source_ip != binding.source_ip   -> +score
    #   ja4h != binding.ja4h              -> +score
    # BLOCK if any hard fails OR risk_score >= THRESHOLD
    # return Decision with outcome + reason + risk_score
```
Acceptance: matching everything passes; a single flipped JA4 blocks with reason "JA4 mismatch"; an IP change alone (soft) does not block a legit session.

### 2.5 `proxy/addon.py`
```
class SentinelAddon:
    def tls_clienthello(self, data):   # compute JA4, stash on connection
    def request(self, flow):           # validate DPoP, bind or evaluate,
                                       # forward or kill; push to dashboard
```
Acceptance: JA4 computed at handshake is available in `request`; block path returns 401/403 and the backend does not receive the request.

### 2.6 `backend/main.py`
Endpoints in section 3. The backend trusts that anything reaching it has passed the proxy, but still checks the Bearer token so it is not naked.

---

## 3. API specification (mock backend)

### `POST /oauth/token`
Issues a short-lived access token. Requires a DPoP proof.
- Request: DPoP header (proof JWT), minimal client credentials for the demo.
- Response: `{ "access_token": "...", "token_type": "DPoP", "expires_in": 300, "jti": "..." }`
- Side effect (at proxy): create the binding record.

### `GET /api/v1/accounts`
- Headers: `Authorization: DPoP <token>`, `DPoP: <proof>`.
- Response: list of mock accounts with balances.

### `POST /api/v1/transfer`
- Headers: `Authorization: DPoP <token>`, `DPoP: <proof>`.
- Body: `{ "from": "...", "to": "...", "amount": 100.0 }`.
- Response on success: `{ "status": "ok", "reference": "..." }`.
- This is the endpoint the attack scripts target.

### Proxy-injected header (optional, for debugging)
The proxy may inject `X-JA4-Fingerprint` and `X-Sentinel-Decision` so the backend and dashboard can display them. Do not rely on client-supplied values for these.

---

## 4. Decision engine rules (reference)

```
THRESHOLD = 2   # tune during build

hard_fail = (not dpop.valid)
         or (presented_ja4 != binding.ja4)
         or (dpop.jkt != binding.jkt)

risk = 0
if source_ip != binding.source_ip: risk += 1
if ja4h and binding.ja4h and ja4h != binding.ja4h: risk += 2

if hard_fail:            outcome = BLOCK, reason = first failed hard signal
elif risk >= THRESHOLD:  outcome = BLOCK, reason = "risk threshold"
else:                    outcome = PASS
```
Keep the reason string specific so blocks are explainable in the demo.

---

## 5. Attack scripts

### Script A: legitimate user (`script_a_legit.py`)
- Generate DPoP key pair, get a token, do `GET /accounts` and `POST /transfer`.
- Uses one TLS stack consistently (for example httpx). All requests should PASS.
- Include one variant that changes source IP mid-session to prove the soft IP signal does not block a legit user.

### Script B: token thief (`script_b_thief.py`)
- Reuse a token captured from Script A (read it from a shared file or env var to simulate exfiltration).
- Send `POST /transfer` from a **different** TLS stack (plain `requests`/urllib3 or `curl` subprocess).
- Expected: BLOCK with reason "JA4 mismatch" (and jkt mismatch, since the thief lacks the DPoP private key).

### Script C: route hijack (`script_c_hijack.py`, stretch)
- Replay the token with a spoofed `X-Forwarded-For` / User-Agent but, to isolate the soft signals, from a stack that could match JA4.
- Expected: risk score rises from IP/UA anomalies; blocks above threshold. Demonstrates the soft-signal path distinct from the hard JA4 block.

The contrast between B (hard block) and C (soft-score block) is the most instructive part of the demo. Make sure the dashboard shows the different reasons.

---

## 6. Dashboard spec

MVP: a Rich live table, one row per request, columns:
`time | src_ip | presented_ja4 | bound_ja4 | jkt_ok | risk | DECISION`
- PASS rows green, BLOCK rows red.
- A footer counter: total, passed, blocked.
- Below the table, the last few decision-log reason strings.

Stretch: Streamlit or a WebSocket page with the same data plus a fingerprint-diff view that highlights exactly which JA4 field diverged.

---

## 7. Phased milestones and acceptance criteria

### Phase 0: scaffold
Repo structure, requirements, local CA generation script, README skeleton.
**Done when:** `make setup` produces a working venv and certs.

### Phase 1: backend + DPoP client, no proxy
FastAPI endpoints, token issuance, DPoP client, one clean transfer.
**Done when:** `script_a_legit.py` completes a transfer directly against the backend.

### Phase 2: proxy in path + JA4 capture (highest risk, do early)
mitmproxy addon captures ClientHello, computes JA4, prints it per connection; traffic still flows to the backend.
**Done when:** every request logs a JA4 string, and a browser vs `requests` client show different JA4s.

### Phase 3: binding + hard-signal engine
Binding cache, DPoP validation wired in, engine with hard signals, block path.
**Done when:** a token replayed from a different stack is blocked before the backend, with a reason.

### Phase 4: attack scripts A + B end to end
**Done when:** A passes fully; B is blocked with "JA4 mismatch"; backend logs confirm B never arrived.

### Phase 5: dashboard + decision log
**Done when:** the live table shows pass/block rows in real time with reasons.

### Phase 6 (stretch): soft signals, Script C, risk scoring, honest-limitation demo
**Done when:** an IP roam on a legit session does not block; Script C blocks via risk threshold; and a short note/demo shows what a TLS-impersonating attacker could do.

---

## 8. Test plan

- `test_ja4.py`: fixed ClientHello fixtures -> expected JA4; different stacks -> different JA4.
- `test_dpop.py`: valid proof passes; expired, wrong-method, tampered, and replayed proofs fail with correct reasons.
- `test_engine.py`: truth table over hard and soft signals -> expected outcomes and reasons.

Aim for these three unit test files at minimum; they cover the security-critical logic and make the demo trustworthy.

---

## 9. README must cover
1. What the project does, in three sentences, including the honest limitation.
2. Architecture diagram (from the TRD).
3. Setup and one-command run.
4. How to run each attack and what to expect.
5. A short "threat model and limitations" section, copied from the TRD, so a reviewer sees you understand the boundaries.
