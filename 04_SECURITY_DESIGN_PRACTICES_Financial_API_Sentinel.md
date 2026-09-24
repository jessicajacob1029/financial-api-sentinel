# Security & Design Practices Addendum: Financial API Sentinel

**Doc type:** Engineering standards checklist
**Companion to:** PRD, TRD, Build Spec
**Purpose:** The other docs cover what the proxy defends against. This one covers how to build the proxy *itself* so it isn't the vulnerability. A security demo with sloppy secret handling or an injectable log line undercuts the whole point.

Treat every unchecked box below as a code review blocker before a phase is marked done.

---

## 1. Secrets and key management

- [ ] No private keys, CA keys, or tokens committed to git. `certs/*.key`, `.env`, and any generated JWKs go in `.gitignore` from commit one.
- [ ] The demo CA private key and DPoP signing keys are generated locally by a setup script, never checked in, never hardcoded in source.
- [ ] No secrets in code comments, log lines, or the README (use placeholders in examples).
- [ ] If you use any API key or credential (even a placeholder), load it from environment variables via `.env` + `python-dotenv`, not literals.
- [ ] Add a pre-commit hook or CI step (`gitleaks` or `trufflehog`) that scans for accidentally committed secrets. This is a cheap, high-signal addition to a security portfolio project.

## 2. Cryptography

- [ ] Use vetted libraries only (`cryptography`, `PyJWT`) — never hand-roll signing, hashing, or random generation.
- [ ] DPoP proofs must be verified with an **allow-listed** signature algorithm (e.g. ES256). Never accept `alg: none` and never let the algorithm be attacker-chosen without a server-side allow-list — this is the classic JWT vulnerability class.
- [ ] Access tokens and DPoP proof `jti` values use a cryptographically secure random generator (`secrets` module), not `random` or UUID1 (time-based).
- [ ] TLS for the demo CA: generate with modern key sizes (EC P-256 or RSA-2048+), not defaults that might be weak.
- [ ] Token expiry (`exp`) is short (the PRD says 300s) and is actually enforced server-side, not just advisory in the payload.

## 3. Input validation and injection

- [ ] All FastAPI request bodies use Pydantic models with explicit types and constraints (e.g. `amount: float = Field(gt=0)`), not raw dict parsing. Reject malformed input at the boundary.
- [ ] DPoP proof JWTs are parsed with strict validation: reject before verifying signature if `typ` header isn't `dpop+jwt`, if required claims are missing, or if the JWK in the header doesn't match the expected key type. Don't trust any claim before the signature is verified.
- [ ] Never interpolate user-controlled input (source IP, User-Agent, headers) directly into log format strings or shell commands. Log via structured logging (pass as fields, not f-string concatenation) to avoid log injection.
- [ ] The mock `/transfer` endpoint validates account IDs against the mock dataset server-side — never trust a client-supplied "from" account without checking it belongs to the authenticated token.
- [ ] If any attack script shells out to `curl`, use `subprocess.run` with an argument list, never `shell=True` with string interpolation.

## 4. Authentication and session logic

- [ ] Token validation order matters: verify DPoP proof signature and freshness **before** trusting any claim inside it (jkt, jti). Never branch decision logic on unverified data.
- [ ] The binding cache must invalidate or expire bindings when the token expires — don't let a stale binding accept a request from an expired token.
- [ ] The DPoP replay cache (`jti` seen-before check) must be checked and updated atomically to avoid a race where two nearly-simultaneous replays both pass. A simple lock around the check-and-set is enough at this scale.
- [ ] Never log full tokens or DPoP private key material, even at debug level. Log token IDs (jti) and fingerprints, not the bearer token itself.
- [ ] Constant-time comparison for any secret-equality check (e.g. `hmac.compare_digest`) if you ever compare raw secret values; not strictly needed for jkt/JA4 string compares since those aren't secrets, but be deliberate about which comparisons touch secret material.

## 5. Proxy and network hardening

- [ ] The proxy's own listening port should bind to localhost/demo network only — don't expose it on `0.0.0.0` in a way that makes your dev machine an open MITM proxy on the network.
- [ ] Certificate validation for the proxy-to-backend leg (if TLS is used there too) should not blanket-disable verification; if you must trust the demo backend's self-signed cert, pin it explicitly rather than disabling verification globally.
- [ ] Fail closed: if JA4 computation throws (malformed ClientHello) or DPoP validation throws, the decision engine's default must be BLOCK, not PASS. An exception in a security check should never fail open.
- [ ] Rate-limit the token issuance endpoint even in the demo, so a script bug or the reviewer double-clicking doesn't spam the binding cache indefinitely.

## 6. Dependency and supply-chain hygiene

- [ ] Pin dependency versions in `requirements.txt` (`==`, not bare names) so the demo is reproducible and doesn't silently pull a compromised newer release.
- [ ] Run `pip-audit` (or `safety`) against `requirements.txt` before calling any phase done, and note the result in the README.
- [ ] Keep the dependency list minimal — every extra library is attack surface and audit burden. Don't add a package for something a 10-line function can do.

## 7. Error handling and information disclosure

- [ ] Block responses to the client should be generic (`401 Unauthorized` / `403 Forbidden`) and must not leak *why* internally (don't tell an attacker "JA4 mismatch, expected t13d..." in the HTTP response body — that detail belongs only in your own dashboard/log, not in the wire response).
- [ ] Don't return stack traces or internal exception messages in API responses; catch and return a clean error, log the detail server-side.
- [ ] The dashboard and logs are for the operator only — if you ever add a web dashboard (stretch), it must not be exposed without auth, since it will show token IDs, IPs, and fingerprints.

## 8. Code design practices (so the codebase itself reads well)

- [ ] **Separation of concerns**, matching the module contracts in the build spec: JA4 computation, DPoP validation, binding storage, and decision logic are separate modules with no cross-imports of internals — only the addon wires them together. This is what lets you unit test the decision engine without spinning up TLS.
- [ ] **Single responsibility per function**: `compute_ja4`, `validate_dpop`, and `evaluate` should each do one thing and return a typed result object, not booleans or tuples, so callers don't need to remember positional meaning.
- [ ] **Explicit typed data structures** (dataclasses or Pydantic models) for `Binding`, `DpopResult`, and `Decision` rather than passing dicts around — this also makes the security-critical logic self-documenting for a reviewer reading your repo.
- [ ] **Dependency inversion on the binding store**: code against a `BindingStore` interface, not a concrete dict, even though you'll only implement the in-memory version. This shows you're not just gluing scripts together.
- [ ] **Config over hardcoding**: risk threshold, token TTL, DPoP freshness window, and cert paths live in one config module or `.env`, not scattered as magic numbers.
- [ ] **No God object**: the mitmproxy addon class should be thin — it wires hooks to the other modules, it should not itself contain fingerprinting or crypto logic.

## 9. Testing discipline

- [ ] Security-critical logic (JA4, DPoP, engine) has unit tests as specified in the build spec's test plan — treat these as required, not optional, given the project's premise.
- [ ] Add at least one negative test per hard signal: tampered DPoP signature, wrong `htm`, expired proof, replayed `jti`, mismatched JA4, mismatched jkt. Each should block with the correct reason string.
- [ ] Add a fail-open regression test: deliberately raise an exception inside JA4 computation or DPoP validation in a test and assert the engine still returns BLOCK.

## 10. Documentation as a security practice

- [ ] The README's "threat model and limitations" section (already specced) doubles as your responsible-disclosure-style honesty about what this does and doesn't defend against — this is itself a security best practice (don't overclaim guarantees).
- [ ] Document the demo CA setup clearly enough that anyone cloning the repo understands they're installing a local trust anchor for demo purposes only, and how to remove it afterward.

---

## How to use this doc

Fold the relevant checklist items into each phase's "done when" criteria from the build spec. For example, Phase 3 (binding + engine) isn't done until the fail-closed and negative-test items above are green, not just the happy path. Treat this doc as a standing code-review checklist you re-run at the end of every phase, not a one-time pass.
