# Phase 7: Demo-Grade Enhancements

**Doc type:** Extension to the Build Spec (03_BUILD_SPEC_Financial_API_Sentinel.md)
**Purpose:** Phases 0–6 produce a working, correct demo. Phase 7 makes it a *convincing, protocol-literate, visually compelling* demo for a networks security audience — deeper crypto, better dashboard, and a few new system capabilities. Build this after Phase 6 is solid; don't let it distract from getting the core detection logic right first.

This phase is organized in three tracks that can be built in parallel or sequence: **7A (protocol depth)**, **7B (dashboard/visual)**, **7C (new software features)**. Pick a subset if time is short — priority order is given in Section 4.

---

## 7A. Deeper crypto and protocol depth

### 7A.1 Mutual TLS (mTLS) on the proxy ↔ backend leg
**What:** Replace the current plaintext proxy→backend hop with mutual TLS — both the proxy and the backend present and verify certificates.
**Why:** Turns the TRD's documented limitation ("this leg is unencrypted, fine on localhost") into a demonstrated fix. Live toggle-able for a strong demo moment.
**Build:**
- Generate a second cert/key pair for the backend, signed by the same local CA.
- Backend's uvicorn server runs with `ssl_certfile`/`ssl_keyfile` and `ssl_ca_certs`, requiring client certs (`ssl_cert_reqs=CERT_REQUIRED`).
- Proxy's outbound leg presents its own client cert when forwarding.
- Add a config flag (`MTLS_BACKEND_ENABLED=true/false`) so it can be toggled without code changes.
- Demo: run `tcpdump`/Wireshark on loopback with mTLS off — show the transfer request in cleartext. Turn it on — show it encrypted. Show a connection attempt without a valid client cert getting rejected at the TLS layer.
**Acceptance:** with the flag on, a `tcpdump -A` capture of the proxy→backend leg shows no readable HTTP; a backend request without a valid client cert fails the TLS handshake before any HTTP is exchanged.

### 7A.2 TLS 1.3 handshake breakdown / capture
**What:** Capture and expose the individual handshake messages (ClientHello, ServerHello, key exchange, Finished) per connection, not just the final JA4 hash.
**Why:** Bridges the app-layer project into core networking-course material — shows you understand what's happening at each step, not just that you called a library.
**Build:**
- From the mitmproxy `tls_clienthello` and `tls_established_client` hooks, extract: negotiated TLS version, negotiated cipher suite, selected key-exchange group (e.g. X25519 vs P-256 ECDHE), ALPN result, and handshake timing.
- Store this alongside the JA4 record so it can be displayed per connection.
- Optional: a `--pcap` mode that also writes a raw packet capture per demo session for offline inspection in Wireshark.
**Acceptance:** for any connection in the dashboard, you can drill in and see the negotiated cipher suite and key exchange group, not just the JA4 hash.

### 7A.3 Certificate validation failure demo
**What:** A scripted scenario where a client attempts to connect without trusting the CA, or with a tampered/expired cert, and the TLS handshake itself fails — before any application logic runs.
**Why:** Shows a real MITM-attempt failing at the transport layer, which is a classic, very legible networking demo.
**Build:** a `client/script_d_untrusted.py` that deliberately does not pass `verify=certs/ca.pem`, or presents a self-signed cert, and the connection is refused. Capture and display the TLS alert type (e.g. `unknown_ca`).
**Acceptance:** the untrusted-client script fails with a clear TLS alert, and the dashboard/log shows it as a handshake-level rejection, distinct from an application-level BLOCK.

### 7A.4 JA3 vs JA4 side-by-side comparison
**What:** Compute both JA3 (legacy) and JA4 (current) for every connection and display them together.
**Why:** Demonstrates you understand *why* JA4 superseded JA3 — specifically, JA4 sorts cipher suites and extensions before hashing, so it resists the extension-order randomization modern browsers (Chrome) now do deliberately, which breaks JA3 uniqueness.
**Build:** add `proxy/ja3.py` alongside the existing `proxy/ja4.py`; log both. Include one demo case where two connections from the *same* browser produce *different* JA3s (due to randomized extension order) but the *same* JA4 — this is the single clearest "here's why the newer standard matters" moment available to you.
**Acceptance:** at least one captured pair of connections shows JA3 diverging while JA4 stays stable for the same client.

### 7A.5 Perfect Forward Secrecy (PFS) demonstration
**What:** Show that each session negotiates a fresh ephemeral key (ECDHE), so compromising one session's key material doesn't expose other sessions' past traffic.
**Why:** Core TLS 1.3 property, straightforward to demonstrate, and a common exam-level topic in networking courses.
**Build:** log the ephemeral key exchange output (not the actual key — just proof that a *new* one is generated per session, e.g. by hashing/fingerprinting the ephemeral public key per connection and showing they're all different even between requests from the same client). Frame this as: "if this session's derived key were somehow exposed, it would tell you nothing about this other session here."
**Acceptance:** dashboard or log shows distinct ephemeral key fingerprints per connection from the same client, with a one-line explanation of why that matters.

### 7A.6 Packet-level view (stretch)
**What:** A raw TCP/TLS record-layer view for at least one sample flow — show the TCP handshake (SYN/SYN-ACK/ACK), then the TLS record layer starting, then where encryption begins.
**Why:** Explicitly ties the project back to the OSI model / TCP fundamentals a networks course covers, not just the application-layer security story.
**Build:** use Scapy or a saved pcap opened with pyshark/tshark to extract and display this for one recorded flow. Doesn't need to be live — a captured-and-replayed example is fine.
**Acceptance:** you can show, in order, the TCP handshake packets, the TLS ClientHello/ServerHello, and the first encrypted application-data record for one flow.

---

## 7B. Dashboard visuals and interactions

### 7B.1 Live network topology animation
**What:** Replace/augment the flat table with an animated diagram: client → proxy → backend, with a packet visibly traveling between nodes, changing visual state (e.g. color/lock icon) at the TLS termination point and again at the mTLS boundary if 7A.1 is built.
**Build:** an HTML/JS panel (Canvas or SVG) driven by a WebSocket feed from the proxy's decision events. Each new request animates a dot/packet along the path; BLOCK events stop the packet at the proxy node with a visible "reject" effect instead of continuing to the backend.
**Acceptance:** a legitimate request animates all the way to the backend; a blocked request visibly stops at the proxy.

### 7B.2 TLS handshake sequence diagram (real-time)
**What:** For the currently selected connection, render the actual ClientHello → ServerHello → Finished exchange as an animated sequence diagram, using the data captured in 7A.2.
**Build:** a simple sequence-diagram renderer (arrows between "Client" and "Proxy" lanes, labeled with each message type and key params like cipher suite).
**Acceptance:** clicking a connection in the dashboard shows its actual handshake sequence, not just a summary hash.

### 7B.3 JA4 diff view
**What:** When a JA4 mismatch causes a block, show a side-by-side breakdown of *which specific component* diverged — TLS version, cipher suite list, extension list, ALPN — rather than just two different hash strings.
**Why:** This is probably the single highest-value dashboard addition. Right now a viewer sees two unequal hashes and has to trust you that they're different; this shows *why*, which is both more convincing and more educational.
**Build:** since JA4 is computed from structured fields (see TRD 3.6), store the pre-hash components alongside the final hash, and render a diff (e.g. highlight the cipher-suite-count field in red if that's what changed).
**Acceptance:** every BLOCK row with reason "JA4 mismatch" can be expanded to show exactly which underlying field(s) differed.

### 7B.4 Attack replay animation
**What:** When an attack script fires, animate the stolen token as an object moving from the legitimate client's location to a new "attacker" location/icon (different fingerprint), then hitting a visible wall/rejection at the proxy with the specific block reason called out.
**Build:** reuse the topology animation (7B.1) infrastructure; attacker events get a distinct visual style (e.g. red pulse) versus normal traffic.
**Acceptance:** running Script B produces a visually distinct animation from a normal Script A request, ending in a visible block.

### 7B.5 Simulated geo/IP map panel
**What:** A world-map or simple location panel showing where the "legitimate" traffic originates versus where "attack" traffic claims to originate (even if simulated/fake coordinates for the demo).
**Why:** Cosmetic but recognizable — resembles real SOC tooling (Splunk, Grafana, CrowdStrike-style dashboards), which helps a reviewer read this as "security tooling" at a glance.
**Build:** map arbitrary demo IPs to fixed lat/long pairs; render on a simple map (e.g. a static world SVG with plotted points) rather than depending on a live geolocation API.
**Acceptance:** legit and attack traffic appear as distinctly colored points/markers on a map panel.

### 7B.6 Interactive risk-threshold slider
**What:** A live slider on the dashboard for the risk-score `THRESHOLD` value. Moving it re-evaluates the session's historical decision log against the new threshold and shows which rows would flip from PASS to BLOCK or vice versa.
**Why:** Turns a static demo into something the professor can interact with directly — very effective for a live Q&A setting.
**Build:** requires the decision log to retain each request's raw risk score (not just the final PASS/BLOCK), so re-evaluation is just a threshold comparison, no re-computation needed.
**Acceptance:** dragging the slider visibly changes which historical rows are marked BLOCK, live, without re-running any requests.

### 7B.7 Kill-chain timeline view
**What:** A narrative timeline grouping related events into a story: token issued → legitimate use → token exfiltrated (simulated) → replay attempt → block. Instead of flat chronological rows, cluster by "session" or "storyline."
**Build:** tag events with a shared `story_id` when scripted together (e.g. Script A and the Script B that steals its token share a story), and render as a connected timeline/flowchart rather than a table.
**Acceptance:** the demo can show one complete "attack story" as a single connected visual, not scattered rows the viewer has to mentally reassemble.

---

## 7C. New software features

### 7C.1 Token revocation endpoint
**What:** `POST /oauth/revoke` (admin/demo-only) that immediately invalidates a token's binding.
**Why:** Demonstrates understanding of full session lifecycle management, not just binding-at-issuance. Good live-demo beat: revoke a token mid-session, show the very next request instantly blocked with reason "token revoked."
**Build:** add a `revoked: bool` field to the binding record; check it as an additional hard signal in the engine.
**Acceptance:** a valid, otherwise-passing request is blocked immediately after its token is revoked, with a distinct reason string.

### 7C.2 Adaptive / step-up authentication
**What:** When risk score is borderline (above a "warn" threshold but below the hard "block" threshold), instead of a binary pass/fail, require a fresh DPoP proof plus a short-lived challenge/nonce before allowing the request through.
**Why:** This is a real production pattern (step-up auth) — shows awareness that binary pass/fail isn't always the right UX/security tradeoff, and demonstrates a three-tier decision model instead of two.
**Build:** add a `CHALLENGE_THRESHOLD < THRESHOLD` band; requests in that band get a 428-style "challenge required" response with a nonce; a follow-up request presenting a fresh DPoP proof signing that nonce is allowed through.
**Acceptance:** a request landing in the challenge band is neither auto-passed nor auto-blocked; it only proceeds after a valid challenge-response.

### 7C.3 Rate limiting and brute-force detection on token issuance
**What:** Track and cap token-issuance attempts per source (IP or JA4) in a time window; flag/alert on bursts.
**Why:** A very standard, currently-missing network security control — easy to build, clearly expected by a networks security reviewer.
**Build:** a simple sliding-window counter in the binding store; issuance requests beyond the limit get a 429, logged distinctly from the engine's PASS/BLOCK decisions (this is throttling, not fingerprint-based detection).
**Acceptance:** a scripted burst of issuance requests beyond the configured limit gets rate-limited, visible as its own event type on the dashboard.

### 7C.4 Replay/attack CLI tool
**What:** A small CLI (`sentinel-replay --token <captured> --stack <requests|curl|httpx> --target /api/v1/transfer`) that lets you fire an ad-hoc replay live during a demo/Q&A, rather than relying only on pre-scripted attack files.
**Why:** Lets you respond to "what if you tried X" questions live and convincingly, instead of "let me go edit a script."
**Build:** thin wrapper around the existing client stack choices already used by Scripts B/C; parameterize the TLS library and target endpoint.
**Acceptance:** you can, live, replay a captured token through at least two different TLS stacks and show the differing outcomes without editing code.

### 7C.5 Config-driven policy engine
**What:** Move the risk weights, hard/soft signal classification, and thresholds out of hardcoded constants into a YAML/JSON policy file loaded at startup (and hot-reloadable if time allows).
**Why:** Shows the decision logic is a tunable *policy*, not a fixed rule — a more realistic and more impressive architecture, and makes 7B.6's slider demo consistent with how the engine is actually configured.
**Build:** `config/policy.yaml` with signal weights and thresholds; `proxy/engine.py` loads it instead of using constants; validate the schema on load (fail loudly on a malformed policy file, don't silently fall back to unsafe defaults — this ties back to the fail-closed principle in the security doc).
**Acceptance:** changing `policy.yaml` and restarting changes engine behavior with no code edits; a malformed policy file causes a startup failure, not a silent default.

### 7C.6 Hash-chained, tamper-evident audit log
**What:** Each decision record includes a hash of the previous record, so the log forms a chain (similar in spirit to a blockchain / Merkle log). Any edit to a past entry breaks the chain and is detectable.
**Why:** Ties the crypto theme (hashing, integrity) into the operational/logging side of the system, and demonstrates a real technique used in tamper-evident audit logging (e.g. Certificate Transparency logs use a similar idea).
**Build:** each `Decision` record stores `prev_hash` = SHA-256 of the previous record's canonical JSON; a `verify_chain()` utility walks the log and confirms no entry was altered.
**Acceptance:** a `verify_chain()` run over an untouched log passes; manually editing one historical entry and re-running `verify_chain()` detects the break at the correct point.

### 7C.7 Attacker sophistication scoring
**What:** Assign each attack script a numeric "sophistication score" based on how many signals it correctly matches (e.g. Script B matches 0/3 hard signals = low sophistication; a hypothetical Script E matching JA4 + jkt but not IP = high sophistication), and show this scaling on the dashboard as you add stronger attacker scripts.
**Why:** Directly visualizes the "layered defense" argument from the TRD — the more signals an attacker defeats, the harder they are to catch, and you can show the curve.
**Build:** a scoring function over which signals a given request satisfies; display alongside each attack run. Pairs naturally with 7C.4 (the live replay CLI) to demonstrate several sophistication levels in one sitting.
**Acceptance:** running Scripts B and C (and any additional attacker variants you build) produces visibly different sophistication scores, and the one matching more signals is demonstrably harder to catch (fewer hard blocks, more reliance on soft-signal scoring).

---

## 4. Suggested build priority

If time is limited before the demo, build in this order — each item is chosen for the ratio of "how convincing it is to a networks audience" versus "how much work it is":

1. **7B.3 JA4 diff view** — small build, makes the core mechanism instantly legible.
2. **7A.1 mTLS toggle** — the strongest "real networking, not just app logic" demo moment; directly resolves a documented limitation.
3. **7A.2 handshake breakdown** — needed as a data source for 7B.2, and valuable on its own.
4. **7B.1 topology animation + 7B.4 attack replay animation** — build together, big visual payoff, shares infrastructure.
5. **7C.1 token revocation** — cheap, adds a real lifecycle feature, easy live-demo beat.
6. **7C.3 rate limiting** — cheap, closes an obviously-missing control.
7. **7A.4 JA3 vs JA4 comparison** — strong "I understand why the standard evolved" moment, moderate effort.
8. Everything else, time permitting — 7A.5, 7A.6, 7B.2, 7B.5–7B.7, 7C.2, 7C.4–7C.7.

---

## 5. Notes for Claude Code

- Treat this phase as **additive**, not a rewrite — nothing in 7A/7B/7C should require changing the module contracts or decision logic from Phases 0–6 (except 7C.1/7C.5, which extend the engine's inputs and are meant to).
- The security and design practices checklist (doc 04) still applies to every new module here — in particular, the config-driven policy engine (7C.5) must fail closed on a malformed config, and the audit log chain (7C.6) is exactly the kind of integrity control that doc rewards.
- Follow the same phase-gated, self-check process from the kickoff prompt (doc 05) for each 7A/7B/7C item you build: confirm acceptance criteria explicitly, don't just claim done.
