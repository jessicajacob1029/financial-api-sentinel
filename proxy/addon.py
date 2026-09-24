"""Sentinel mitmproxy addon: wires TLS fingerprint capture, DPoP
validation, the binding cache, the decision engine, and the dashboard to
HTTP request handling. Thin by design (doc 04 SS8) -- no fingerprinting,
crypto, or decision logic lives here; it all lives in ja4.py / dpop.py /
binding.py / engine.py / dashboard.py, and this class only calls into them
and reacts to the result.

Flow per TRD SS4:
  tls_clienthello -> compute + stash JA4 for this connection.
  request:
    - always: validate the presented DPoP proof, reject its replay.
    - POST /oauth/token: no binding exists yet -- this is what creates
      one, once the backend issues a token. Stash what's needed and let
      the request through; `response` does the actual bind() once the
      issued jti is known.
    - resource endpoints: look up the binding by the access token's jti,
      run the decision engine, forward on PASS or block on BLOCK.

Run with `mitmdump -q` (Build Spec SS6 / FR-9): -q suppresses mitmdump's
own per-flow log lines so the Rich live table is the only thing on screen.

Phase 7C.2 (step-up auth) is layered here deliberately, not in
engine.py: the engine's contract (PASS or BLOCK, nothing else) stays
exactly as Phase 0-6 defined it. This addon reads the already-exposed
`decision.risk_score` off an ordinary PASS decision and, for scores in
the challenge band, holds the request for a fresh nonce-signed proof
before actually forwarding it -- a real risk engine returning a score
and a separate orchestration layer deciding what to do with a borderline
one is a legitimate production pattern in its own right, not just a way
to avoid touching engine.py's contract (though it also does that).
"""

import json
import time

import jwt
from mitmproxy import http
from mitmproxy.tls import ClientHelloData

from config import AUDIT_LOG_PATH, CHALLENGE_TTL_SECONDS, RATE_LIMIT_MAX_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS
from proxy.audit_log import AuditLog
from proxy.binding import InMemoryBindingStore
from proxy.challenge_store import ChallengeStore
from proxy.dashboard import Dashboard
from proxy.dpop import validate_dpop
from proxy.engine import evaluate
from proxy.handshake import describe_connection, offered_key_share_fingerprint, offered_key_share_group
from proxy.ja3 import compute_ja3
from proxy.ja4 import compute_ja4_components, diff_ja4
from proxy.ja4_registry import Ja4Registry
from proxy.ja4h import compute_ja4h
from proxy.policy import POLICY
from proxy.rate_limiter import SlidingWindowRateLimiter
from proxy.sophistication import compute_sophistication
from proxy.webdash import WebDashboard

TOKEN_PATH = "/oauth/token"
# 7C.1: admin/demo-only, intercepted entirely at the proxy -- the backend
# never sees it and never needs to, since bindings are a proxy-only
# concept (the backend doesn't track JA4/jkt at all). Deliberately does
# NOT require a DPoP proof: revocation is an operator action against the
# proxy's own binding cache, not a customer-facing resource request, and
# in a real deployment would carry its own separate strong auth (e.g. an
# admin mTLS cert) rather than reusing the DPoP flow of the thing it's
# revoking. Fine as-is for this localhost-only demo (doc 04 SS5: the
# proxy itself never binds beyond 127.0.0.1).
REVOKE_PATH = "/oauth/revoke"


class SentinelAddon:
    def __init__(self) -> None:
        # Per-connection JA4, keyed by the mitmproxy connection id (a UUID
        # stable for the lifetime of one TCP connection).
        self._ja4_by_connection: dict[str, str | None] = {}
        self._bindings = InMemoryBindingStore()
        self._dashboard = Dashboard()
        self._web_dashboard = WebDashboard(self._dashboard)
        # 7B.3: remembers the structured fields behind each JA4 string
        # seen this session, purely so a JA4-mismatch block can be shown
        # as a field-by-field diff instead of two unequal hashes.
        self._ja4_registry = Ja4Registry()
        # 7A.2: handshake breakdown, captured in two stages -- the
        # offered key-exchange group + a timestamp at tls_clienthello
        # (pre-handshake), then merged with cipher/version/ALPN (only
        # available post-handshake) the first time a request arrives on
        # that connection.
        self._key_share_by_connection: dict[str, str | None] = {}
        # 7A.5 (PFS): fingerprint of the client's ephemeral public key
        # (not the group -- the actual per-connection key), to make the
        # "fresh key every connection" property visible per session.
        self._key_share_fingerprint_by_connection: dict[str, str | None] = {}
        self._clienthello_ts_by_connection: dict[str, float] = {}
        self._handshake_by_connection: dict[str, dict] = {}
        # 7A.4: JA3 (legacy) computed alongside JA4 purely for
        # side-by-side comparison -- never used in any decision, only
        # displayed, to show why JA4 superseded it (see proxy/ja3.py).
        self._ja3_by_connection: dict[str, str | None] = {}
        # 7C.3: keyed by JA4, not source_ip (consistent with this
        # project's fingerprint-centric design; IP is documented as a
        # fragile soft signal, not something to hard-limit on).
        self._issuance_rate_limiter = SlidingWindowRateLimiter(
            max_attempts=RATE_LIMIT_MAX_ATTEMPTS, window_seconds=RATE_LIMIT_WINDOW_SECONDS
        )
        # 7C.2: step-up challenges, keyed by the token's jti.
        self._challenges = ChallengeStore(ttl_seconds=CHALLENGE_TTL_SECONDS)
        # 7C.6: hash-chained audit trail of every significant event, also
        # mirrored to disk for scripts/verify_audit_log.py.
        self._audit_log = AuditLog(persist_path=AUDIT_LOG_PATH)

    def running(self) -> None:
        self._dashboard.start()
        self._web_dashboard.start()

    def done(self) -> None:
        self._dashboard.stop()
        self._web_dashboard.stop()

    def tls_clienthello(self, data: ClientHelloData) -> None:
        try:
            components = compute_ja4_components(data.client_hello)
            ja4 = components.ja4
            self._ja4_registry.record(components)
        except Exception as exc:
            # Fail closed (doc 04 SS5): an unparseable ClientHello must
            # never silently pass through as "no fingerprint".
            ja4 = None
            self._dashboard.log(f"JA4 computation failed: {exc!r}")

        connection_id = data.context.client.id
        self._ja4_by_connection[connection_id] = ja4

        try:
            ja3 = compute_ja3(data.client_hello)
        except Exception as exc:
            ja3 = None
            self._dashboard.log(f"JA3 computation failed: {exc!r}")
        self._ja3_by_connection[connection_id] = ja3

        # 7A.2: only the client's *offer* is available at this point
        # (pre-handshake); cipher/version/ALPN come later, once
        # negotiated -- see request() below.
        try:
            self._key_share_by_connection[connection_id] = offered_key_share_group(data.client_hello)
            self._key_share_fingerprint_by_connection[connection_id] = offered_key_share_fingerprint(
                data.client_hello
            )
        except Exception:
            self._key_share_by_connection[connection_id] = None
            self._key_share_fingerprint_by_connection[connection_id] = None
        self._clienthello_ts_by_connection[connection_id] = time.time()

        self._dashboard.log(f"tls_clienthello connection={connection_id[:8]} ja4={ja4} ja3={ja3}")

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.path == REVOKE_PATH:
            self._handle_revoke(flow)
            return

        connection_id = flow.client_conn.id
        presented_ja4 = self._ja4_by_connection.get(connection_id)
        source_ip = flow.client_conn.peername[0]
        now = int(time.time())
        handshake = self._handshake_info(connection_id, flow)
        # 7B.7 (kill-chain timeline): the token's jti is the natural
        # story_id -- Script A issues it, Scripts B/C explicitly reuse it,
        # so every event carrying the same jti already belongs to the same
        # story. Extracted early so even early rejections (invalid/missing
        # DPoP) still link back to the token in play, when there is one.
        story_id = self._unverified_token_jti(flow.request.headers.get("authorization", ""))

        if flow.request.path == TOKEN_PATH:
            # 7C.3: throttle before doing any DPoP validation work -- a
            # burst gets rate-limited regardless of whether the proofs it
            # carries would otherwise be valid.
            rate_result = self._issuance_rate_limiter.check_and_record(presented_ja4 or "unknown")
            if not rate_result.allowed:
                self._dashboard.record_rate_limited(
                    now, presented_ja4 or "unknown", rate_result.attempts_in_window, rate_result.limit
                )
                self._audit_log.append(
                    "rate_limited",
                    {"key": presented_ja4 or "unknown", "attempts_in_window": rate_result.attempts_in_window},
                    now=now,
                )
                flow.response = http.Response.make(
                    429, b'{"detail":"too many token requests"}', {"Content-Type": "application/json"}
                )
                return

        try:
            presented_ja4h = compute_ja4h(flow.request)
        except Exception as exc:
            # Fail closed on the soft signal too (doc 04 SS5): a computation
            # failure yields "no fingerprint", never a fabricated one that
            # could accidentally match and suppress a real risk signal.
            presented_ja4h = None
            self._dashboard.log(f"JA4H computation failed: {exc!r}")

        dpop_header = flow.request.headers.get("dpop")
        if dpop_header is None:
            self._block(flow, now, source_ip, presented_ja4, "missing DPoP proof", handshake, story_id)
            return

        dpop_result = validate_dpop(dpop_header, flow.request.method, flow.request.pretty_url, now)
        if not dpop_result.valid:
            self._block(
                flow, now, source_ip, presented_ja4, f"DPoP invalid: {dpop_result.reason}", handshake, story_id
            )
            return

        if not self._bindings.check_and_mark_dpop_jti(dpop_result.jti):
            self._block(flow, now, source_ip, presented_ja4, "DPoP proof replayed", handshake, story_id)
            return

        if flow.request.path == TOKEN_PATH:
            # Binding doesn't exist yet -- created in `response` once the
            # backend issues a jti. Stash what that needs.
            flow.metadata["sentinel_jkt"] = dpop_result.jkt
            flow.metadata["sentinel_ja4"] = presented_ja4
            flow.metadata["sentinel_ja4h"] = presented_ja4h
            flow.metadata["sentinel_source_ip"] = source_ip
            return

        binding = self._bindings.get(story_id) if story_id else None
        if binding is None:
            self._block(flow, now, source_ip, presented_ja4, "no binding found for presented token", handshake, story_id)
            return

        decision = evaluate(binding, presented_ja4, dpop_result, source_ip, ja4h=presented_ja4h)
        # 7C.7: how many of the three attacker-defeatable hard signals this
        # request matched -- shown alongside the decision so a demo can
        # visually contrast a low-sophistication attacker (Script B) against
        # a high-sophistication one (Script C) on the same table.
        sophistication = compute_sophistication(decision)

        ja4_diff = None
        if decision.outcome == "BLOCK" and decision.reason == "JA4 mismatch":
            presented_components = self._ja4_registry.get(decision.presented_ja4)
            bound_components = self._ja4_registry.get(decision.bound_ja4)
            if presented_components and bound_components:
                ja4_diff = diff_ja4(bound_components, presented_components)

        # 7C.2: a PASS landing in the challenge band is held for step-up,
        # unless this proof already carries a valid, matching nonce (i.e.
        # this request IS the response to a challenge issued moments ago).
        if (
            decision.outcome == "PASS"
            and story_id
            and POLICY.challenge_threshold <= decision.risk_score < POLICY.risk_threshold
        ):
            presented_nonce = self._peek_dpop_nonce(dpop_header)
            if presented_nonce and self._challenges.verify_and_consume(story_id, presented_nonce):
                self._dashboard.record_challenge_passed(now, story_id)
                self._audit_log.append("challenge_passed", {"story_id": story_id}, now=now)
            else:
                nonce = self._challenges.issue(story_id)
                self._dashboard.record_challenge_issued(now, story_id, decision.risk_score)
                self._audit_log.append(
                    "challenge_issued", {"story_id": story_id, "risk_score": decision.risk_score}, now=now
                )
                flow.response = http.Response.make(
                    428,
                    json.dumps({"detail": "step-up required", "nonce": nonce}).encode(),
                    {"Content-Type": "application/json"},
                )
                return

        self._dashboard.record_decision(
            decision, ja4_diff=ja4_diff, handshake=handshake, story_id=story_id, sophistication=sophistication
        )
        self._audit_log.append(
            "decision",
            {
                "outcome": decision.outcome,
                "reason": decision.reason,
                "risk_score": decision.risk_score,
                "story_id": story_id,
                "source_ip": source_ip,
                "ja4": presented_ja4,
                "sophistication_score": sophistication.score,
                "sophistication_label": sophistication.label,
            },
            now=now,
        )
        if decision.outcome == "BLOCK":
            self._respond_unauthorized(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.path != TOKEN_PATH or flow.response is None or flow.response.status_code != 200:
            return

        try:
            body = json.loads(flow.response.content)
            token_jti = body["jti"]
        except (ValueError, KeyError, TypeError):
            return

        jkt = flow.metadata.get("sentinel_jkt")
        ja4 = flow.metadata.get("sentinel_ja4")
        ja4h = flow.metadata.get("sentinel_ja4h")
        source_ip = flow.metadata.get("sentinel_source_ip")
        if not (jkt and ja4 and source_ip):
            return

        issued_at = int(time.time())
        self._bindings.bind(token_jti, jkt, ja4, source_ip, issued_at=issued_at, ja4h=ja4h)
        self._dashboard.log(
            f"ISSUED jti={token_jti} jkt={jkt[:12]}... ja4={ja4} ja4h={ja4h} source_ip={source_ip}"
        )
        # 7B.7: the first link in this token's kill chain.
        self._dashboard.record_issuance(issued_at, token_jti, jkt, ja4, source_ip)
        self._audit_log.append(
            "issuance", {"jti": token_jti, "jkt": jkt, "ja4": ja4, "source_ip": source_ip}, now=issued_at
        )

    @staticmethod
    def _unverified_token_jti(authorization_header: str) -> str | None:
        # Used only as a binding-cache lookup key -- the actual
        # authorization decision is the hard-signal comparison against the
        # binding record in evaluate(), not this unverified read. That
        # record was only ever populated from proxy-validated data at
        # issuance time (see response() above), so a forged jti here just
        # fails to find a binding (or finds someone else's, which then
        # fails the JA4/jkt hard-signal check) -- it grants nothing on its
        # own.
        if not authorization_header.startswith("DPoP "):
            return None
        token = authorization_header.removeprefix("DPoP ")
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return None
        jti = claims.get("jti")
        return jti if isinstance(jti, str) else None

    @staticmethod
    def _peek_dpop_nonce(proof_jwt: str) -> str | None:
        # 7C.2: safe to decode without re-verifying signature here -- by
        # the time this is called, proxy/dpop.py's validate_dpop() has
        # already cryptographically verified this exact proof string
        # moments earlier in the same request; this just reads one more
        # already-authentic claim it doesn't itself look at.
        try:
            claims = jwt.decode(proof_jwt, options={"verify_signature": False})
        except jwt.PyJWTError:
            return None
        nonce = claims.get("nonce")
        return nonce if isinstance(nonce, str) else None

    def _block(
        self,
        flow: http.HTTPFlow,
        ts: int,
        source_ip: str,
        presented_ja4: str | None,
        reason: str,
        handshake: dict | None = None,
        story_id: str | None = None,
    ) -> None:
        self._dashboard.record_raw_block(ts, source_ip, presented_ja4, reason, handshake=handshake, story_id=story_id)
        self._audit_log.append(
            "block",
            {"source_ip": source_ip, "ja4": presented_ja4, "reason": reason, "story_id": story_id},
            now=ts,
        )
        self._respond_unauthorized(flow)

    def _handshake_info(self, connection_id: str, flow: http.HTTPFlow) -> dict:
        """7A.2: merge the pre-handshake key-share offer with the
        post-handshake cipher/version/ALPN (only available once TLS is
        established, which it is by the time `request` fires). Computed
        once per connection and cached -- a keep-alive connection's later
        requests reuse the same handshake, they don't renegotiate one."""
        cached = self._handshake_by_connection.get(connection_id)
        if cached is not None:
            return cached

        post_handshake = describe_connection(flow.client_conn)
        clienthello_ts = self._clienthello_ts_by_connection.get(connection_id)
        latency_ms = (time.time() - clienthello_ts) * 1000 if clienthello_ts is not None else None

        info = {
            **post_handshake,
            "offered_key_share_group": self._key_share_by_connection.get(connection_id),
            # 7A.5 (PFS): differs per connection even from the same
            # client/key -- proof of a fresh ephemeral key each time.
            "ephemeral_key_fingerprint": self._key_share_fingerprint_by_connection.get(connection_id),
            "clienthello_to_first_request_ms": round(latency_ms, 2) if latency_ms is not None else None,
            "ja3": self._ja3_by_connection.get(connection_id),  # 7A.4: legacy fingerprint, comparison only
        }
        self._handshake_by_connection[connection_id] = info
        return info

    @staticmethod
    def _respond_unauthorized(flow: http.HTTPFlow) -> None:
        # doc 04 SS7: the wire response must stay generic -- the detailed
        # reason is for our own logs/dashboard only, never echoed to the
        # client.
        flow.response = http.Response.make(
            401, b'{"detail":"unauthorized"}', {"Content-Type": "application/json"}
        )

    def _handle_revoke(self, flow: http.HTTPFlow) -> None:
        """7C.1: POST /oauth/revoke {"jti": "..."} -- immediately
        invalidates a token's binding, checked as a hard signal on the
        very next request presenting it (proxy/engine.py)."""
        try:
            body = json.loads(flow.request.content or b"{}")
            jti = body.get("jti")
        except (ValueError, TypeError):
            jti = None

        if not jti or not isinstance(jti, str):
            flow.response = http.Response.make(
                400, b'{"detail":"missing or invalid jti"}', {"Content-Type": "application/json"}
            )
            return

        found = self._bindings.revoke(jti)
        if found:
            self._dashboard.log(f"REVOKED jti={jti}")
            self._audit_log.append("revocation", {"jti": jti})
            flow.response = http.Response.make(
                200, b'{"status":"revoked"}', {"Content-Type": "application/json"}
            )
        else:
            flow.response = http.Response.make(
                404, b'{"detail":"unknown token"}', {"Content-Type": "application/json"}
            )


addons = [SentinelAddon()]
