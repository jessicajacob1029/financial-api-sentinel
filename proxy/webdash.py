"""Web dashboard (TRD SS7 stretch): mirrors the terminal dashboard
(proxy/dashboard.py) over a WebSocket so the live decision feed is also
viewable in a browser. Runs in-process with the mitmproxy addon, on
mitmproxy's own asyncio event loop -- Tornado 6.x is asyncio-native, so no
separate thread or loop is needed. Presentation only, same as
dashboard.py: this module has no fingerprinting/DPoP/binding/decision
logic, it only renders events proxy/dashboard.py's Dashboard hands it via
add_listener().

doc 04 SS7: a web dashboard must not be exposed without auth, since it
shows token IDs (truncated), IPs, and fingerprints. This binds to
127.0.0.1 only, never 0.0.0.0 -- for this single-laptop demo (PRD non-goal
#1: not a production WAF), loopback-only binding is the proportionate
control; a genuinely multi-user or non-localhost deployment would need
real authentication on top, which is out of scope here.
"""

import json

import tornado.ioloop
import tornado.web
import tornado.websocket

from proxy.dashboard import Dashboard

_INDEX_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Financial API Sentinel -- live dashboard</title>
<style>
  body { background: #0d1117; color: #c9d1d9; font-family: ui-monospace, "SF Mono", Menlo, monospace;
         margin: 0; padding: 24px; }
  h1 { font-size: 16px; font-weight: 600; color: #e6edf3; margin: 0 0 4px; }
  .sub { color: #8b949e; font-size: 12px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: #8b949e; font-weight: 500; padding: 6px 10px; border-bottom: 1px solid #30363d; }
  td { padding: 6px 10px; border-bottom: 1px solid #21262d; white-space: nowrap; }
  tr.pass td:last-child { color: #3fb950; font-weight: 600; }
  tr.block td:last-child { color: #f85149; font-weight: 600; }
  tr.has-diff td:last-child { cursor: pointer; text-decoration: underline dotted; }
  tr.detail-row td { background: #0f1420; padding: 10px 14px; }
  tr.detail-row table { width: auto; font-size: 12px; }
  tr.detail-row th, tr.detail-row td { border: none; padding: 3px 12px 3px 0; white-space: nowrap; }
  tr.detail-row td.diff-val { color: #f85149; font-weight: 600; }
  .diff-title { color: #8b949e; margin-bottom: 6px; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  .counts { margin: 14px 0; color: #8b949e; font-size: 12px; }
  .counts b { color: #e6edf3; }
  #log { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px;
         font-size: 12px; color: #8b949e; margin-top: 16px; max-height: 220px; overflow-y: auto; }
  #log div { padding: 2px 0; }
  .status { font-size: 11px; color: #8b949e; }
  .status.live { color: #3fb950; }

  /* Phase 7B.1 / 7B.4: live topology + attack replay animation */
  .topo-title { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; margin-bottom: 8px; }
  #topology { position: relative; height: 110px; background: #0f1420; border: 1px solid #30363d;
              border-radius: 6px; margin-bottom: 8px; overflow: hidden; }
  .topo-node { position: absolute; top: 26px; width: 130px; text-align: center; }
  #node-client { left: 20px; }
  #node-proxy { left: calc(50% - 65px); }
  #node-backend { right: 20px; }
  .topo-icon { font-size: 26px; line-height: 1; }
  .topo-label { font-size: 11px; color: #c9d1d9; margin-top: 4px; }
  .topo-sub { color: #6e7681; font-size: 9px; display: block; }
  .topo-edge { position: absolute; top: 39px; height: 2px; background: #30363d; }
  .packet { position: absolute; top: 34px; width: 12px; height: 12px; border-radius: 50%;
            transition: left 0.6s ease-in-out, opacity 0.3s; z-index: 5; }
  .packet.pass { background: #3fb950; box-shadow: 0 0 10px #3fb950; }
  .packet.block { background: #f85149; box-shadow: 0 0 10px #f85149; }
  .packet.reject { animation: topo-shake 0.35s; }
  @keyframes topo-shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }
  .reject-label { position: absolute; top: 78px; width: 160px; text-align: center; font-size: 10px;
                  color: #f85149; transition: opacity 0.3s; }
  #topo-legend { font-size: 11px; color: #8b949e; margin-bottom: 20px; }
  .legend-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
  .legend-dot.pass { background: #3fb950; }
  .legend-dot.block { background: #f85149; }

  /* Phase 7B.5: simulated geo/IP panel. SIMULATED coordinates, clearly
     labeled -- every request in this localhost demo actually originates
     from 127.0.0.1, so real geolocation would show one point. Deterministic
     per distinct JA4, per doc SS7B.5 ("even if simulated/fake coordinates"). */
  #geo-panel { position: relative; height: 160px; background: #0f1420; border: 1px solid #30363d;
               border-radius: 6px; margin-bottom: 8px; overflow: hidden; }
  .geo-grid-line { position: absolute; background: #1c2129; }
  .geo-grid-line.v { width: 1px; top: 0; bottom: 0; }
  .geo-grid-line.h { height: 1px; left: 0; right: 0; }
  .geo-axis-label { position: absolute; font-size: 8px; color: #4d5561; }
  .geo-marker { position: absolute; width: 9px; height: 9px; border-radius: 50%; transform: translate(-50%, -50%);
                cursor: default; transition: background 0.3s; }
  .geo-marker.pass { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
  .geo-marker.block { background: #f85149; box-shadow: 0 0 6px #f85149; }
  .geo-marker::after { content: attr(data-label); position: absolute; top: 12px; left: 50%; transform: translateX(-50%);
                        font-size: 9px; color: #8b949e; white-space: nowrap; }
  .geo-badge { position: absolute; top: 6px; right: 8px; font-size: 9px; color: #6e7681; text-transform: uppercase;
               letter-spacing: .03em; }

  /* Phase 7B.6: interactive risk-threshold slider (what-if, doesn't touch real traffic) */
  #threshold-panel { background: #0f1420; border: 1px solid #30363d; border-radius: 6px; padding: 12px 16px;
                      margin-bottom: 16px; }
  #threshold-panel input[type=range] { width: 260px; vertical-align: middle; accent-color: #58a6ff; }
  #threshold-label { font-size: 12px; color: #e6edf3; margin-left: 10px; }
  #threshold-note { font-size: 10px; color: #6e7681; margin-top: 6px; }
  #threshold-note.dirty { color: #d29922; }
  tr.flipped td:last-child { outline: 1px dashed #d29922; outline-offset: -2px; }
  .decision-sim { font-size: 9px; color: #d29922; margin-left: 4px; }

  /* Phase 7C.7: attacker sophistication badge -- how many of the three
     attacker-defeatable hard signals (DPoP validity, JA4 match, jkt match)
     this request matched. Color scales from "trivial" (easy catch) to
     "high" (matched almost everything, only soft signals gave it away). */
  .soph-badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; white-space: nowrap; }
  .soph-trivial { background: #1a2f1a; color: #3fb950; }
  .soph-low { background: #24261a; color: #d29922; }
  .soph-moderate { background: #2d1f0f; color: #f0883e; }
  .soph-high { background: #2d1414; color: #f85149; }

  /* Phase 7B.7: kill-chain timeline -- one connected story (shared jti)
     instead of scattered rows the viewer has to mentally reassemble. */
  #killchain-panel { background: #0f1420; border: 1px solid #30363d; border-radius: 6px; padding: 14px 18px;
                      margin-bottom: 16px; }
  #killchain-empty { color: #6e7681; font-size: 11px; }
  #killchain-story-id { color: #58a6ff; font-family: inherit; }
  .kc-link { display: flex; align-items: flex-start; margin: 0; padding-left: 22px; position: relative;
             padding-bottom: 16px; opacity: 0; animation: kc-fade-in 0.3s forwards; }
  .kc-link:last-child { padding-bottom: 0; }
  .kc-link::before { content: ''; position: absolute; left: 4px; top: 4px; bottom: -4px; width: 1px; background: #30363d; }
  .kc-link:last-child::before { display: none; }
  .kc-dot { position: absolute; left: 0; top: 2px; width: 9px; height: 9px; border-radius: 50%; }
  .kc-dot.issue { background: #58a6ff; box-shadow: 0 0 6px #58a6ff; }
  .kc-dot.pass { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
  .kc-dot.block { background: #f85149; box-shadow: 0 0 6px #f85149; }
  .kc-body { font-size: 12px; }
  .kc-title { color: #e6edf3; font-weight: 600; }
  .kc-detail { color: #8b949e; font-size: 10px; margin-top: 1px; }
  .kc-ts { color: #6e7681; font-size: 10px; margin-left: 6px; }
  @keyframes kc-fade-in { from { opacity: 0; transform: translateX(-4px); } to { opacity: 1; transform: translateX(0); } }

  /* Phase 7B.2: per-connection handshake sequence diagram */
  .seq-diagram { margin-top: 10px; }
  .seq-lanes { display: flex; justify-content: space-between; font-size: 10px; color: #6e7681;
               text-transform: uppercase; letter-spacing: .03em; margin-bottom: 6px; padding: 0 4px; }
  .seq-msg { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; column-gap: 8px;
             font-size: 11px; margin: 3px 0; opacity: 0; animation: seq-fade-in 0.35s forwards; }
  .seq-msg .seq-line { height: 1px; background: #30363d; position: relative; }
  .seq-msg .seq-line.l2r::after { content: '▶'; position: absolute; right: -2px; top: -6px; color: #58a6ff; font-size: 9px; }
  .seq-msg .seq-line.r2l::before { content: '◀'; position: absolute; left: -2px; top: -6px; color: #58a6ff; font-size: 9px; }
  .seq-msg .seq-label { text-align: center; color: #c9d1d9; white-space: nowrap; }
  .seq-msg .seq-detail { display: block; color: #8b949e; font-size: 9px; }
  .seq-msg.encrypted .seq-label { color: #8b949e; font-style: italic; }
  .seq-msg.encrypted .seq-line::after, .seq-msg.encrypted .seq-line::before { color: #6e7681; }
  @keyframes seq-fade-in { from { opacity: 0; transform: translateY(-3px); } to { opacity: 1; transform: translateY(0); } }
</style>
</head>
<body>
<h1>Financial API Sentinel</h1>
<div class="sub">live decision feed &middot; <span id="status" class="status">connecting...</span></div>

<div class="topo-title">live network topology</div>
<div id="topology">
  <div class="topo-node" id="node-client"><div class="topo-icon">&#128421;</div><div class="topo-label">Client</div></div>
  <div class="topo-edge" id="edge-1"></div>
  <div class="topo-node" id="node-proxy"><div class="topo-icon" id="proxy-lock">&#128275;</div>
    <div class="topo-label">Sentinel Proxy<span class="topo-sub">TLS termination + JA4/DPoP</span></div></div>
  <div class="topo-edge" id="edge-2"></div>
  <div class="topo-node" id="node-backend"><div class="topo-icon">&#127974;</div><div class="topo-label">Backend</div></div>
</div>
<div id="topo-legend">
  <span class="legend-dot pass"></span>legit request (reaches backend)
  &nbsp;&nbsp;<span class="legend-dot block"></span>blocked (stops at the proxy, never reaches backend)
</div>

<div class="topo-title">simulated origin map (by TLS stack)</div>
<div id="geo-panel">
  <div class="geo-badge">simulated -- not real geolocation</div>
</div>
<div id="topo-legend">
  <span class="legend-dot pass"></span>legit client's simulated location
  &nbsp;&nbsp;<span class="legend-dot block"></span>attacker's simulated location (distinct TLS stack -> distinct point)
</div>

<div id="threshold-panel">
  <label for="threshold-slider" style="font-size:11px;color:#8b949e;">RISK_THRESHOLD (live what-if):</label>
  <input type="range" id="threshold-slider" min="0" max="6" step="1" value="2" disabled>
  <span id="threshold-label">2 (real value, loading...)</span>
  <div id="threshold-note">Drag to see which historical rows would flip PASS/BLOCK under a different threshold --
    this does NOT re-run any request or change the live proxy's actual RISK_THRESHOLD, it only re-evaluates
    each row's already-recorded risk score against a hypothetical one. Rows blocked by a hard signal (JA4
    mismatch, jkt mismatch, invalid DPoP, missing/replayed proof) never flip -- the real engine checks those
    before risk score ever matters, so this simulation doesn't either.</div>
</div>

<div class="topo-title">kill-chain timeline (most recently active story)</div>
<div id="killchain-panel">
  <div id="killchain-empty">No token issued yet -- run an attack script to see one story connect end to end.</div>
  <div id="killchain-links" style="display:none"></div>
</div>

<table>
  <thead>
    <tr><th>time</th><th>src_ip</th><th>presented_ja4</th><th>bound_ja4</th><th>jkt_ok</th><th>risk</th><th>sophistication</th><th>DECISION</th></tr>
  </thead>
  <tbody id="rows"></tbody>
</table>
<div class="counts">total=<b id="c-total">0</b>&nbsp;&nbsp;passed=<b id="c-passed">0</b>&nbsp;&nbsp;blocked=<b id="c-blocked">0</b>&nbsp;&nbsp;<span id="c-rate-limited-wrap" style="display:none">rate_limited=<b id="c-rate-limited" style="color:#d29922">0</b></span></div>
<div id="log"></div>
<script>
const rowsEl = document.getElementById('rows');
const logEl = document.getElementById('log');
const statusEl = document.getElementById('status');
const MAX_ROWS = 15, MAX_LOG = 8;

const FIELD_LABELS = {
  version_code: 'TLS version', sni_char: 'SNI present', cipher_count: 'cipher count',
  ext_count: 'extension count', alpn_code: 'first ALPN', ciphers: 'cipher suites (sorted)',
  extensions: 'extensions (sorted)',
};

const HANDSHAKE_LABELS = {
  tls_version: 'TLS version', cipher: 'negotiated cipher', alpn: 'ALPN',
  offered_key_share_group: 'offered key-exchange group',
  ephemeral_key_fingerprint: 'ephemeral key fingerprint (PFS)',
  clienthello_to_first_request_ms: 'ClientHello->request (ms)',
  ja3: 'JA3 (legacy, comparison only)',
};

const PFS_NOTE = 'Forward secrecy: this fingerprint is unique per connection -- even a repeat ' +
  'visit from the exact same client generates a fresh ephemeral key. Exposing one session\\'s ' +
  'derived traffic key later would reveal nothing about any other session, past or future.';

function buildDiffTable(diff) {
  let rows = '';
  for (const [field, [boundVal, presentedVal]] of Object.entries(diff)) {
    const label = FIELD_LABELS[field] || field;
    const fmt = (v) => Array.isArray(v) ? `[${v.length} entries]` : v;
    rows += `<tr><th>${label}</th><td class="diff-val">bound: ${fmt(boundVal)}</td>` +
            `<td class="diff-val">presented: ${fmt(presentedVal)}</td></tr>`;
  }
  return `<div class="diff-title">JA4 diff -- fields that diverged</div><table>${rows}</table>`;
}

function buildHandshakeTable(hs) {
  let rows = '';
  for (const [field, label] of Object.entries(HANDSHAKE_LABELS)) {
    const val = hs[field];
    rows += `<tr><th>${label}</th><td>${val === null || val === undefined ? '-' : val}</td></tr>`;
  }
  const note = hs.ephemeral_key_fingerprint ? `<div class="diff-title" style="margin-top:8px">${PFS_NOTE}</div>` : '';
  return `<div class="diff-title">TLS handshake (this connection)</div><table>${rows}</table>${note}`;
}

// Phase 7B.2: the standard TLS 1.3 message flow, annotated with THIS
// connection's real negotiated values (not a generic textbook diagram --
// see proxy/webdash.py's docstring context / scripts/capture_sample_flow.py
// for the byte-level capture this flow is drawn from). Honesty note: this
// renders the known TLS 1.3 message *structure* with real per-connection
// parameters, not literally a captured message-by-message trace of this
// specific connection -- mitmproxy terminates TLS itself and doesn't
// expose each individual post-ServerHello message to the addon. For a
// byte-accurate capture of one live flow, see scripts/capture_sample_flow.py
// (Phase 7A.6), which this same structure is empirically confirmed against.
function buildSequenceDiagram(hs) {
  if (!hs) return '';
  const latency = hs.clienthello_to_first_request_ms;
  const messages = [
    { dir: 'l2r', label: 'ClientHello', detail: `offers ${hs.offered_key_share_group || 'unknown group'}`, enc: false },
    { dir: 'r2l', label: 'ServerHello', detail: `${hs.tls_version || '?'}, ${hs.cipher || '?'}`, enc: false },
    { dir: 'r2l', label: 'EncryptedExtensions, Certificate, CertificateVerify, Finished', detail: 'opaque past this point -- TLS 1.3 hides handshake message boundaries', enc: true },
    { dir: 'l2r', label: 'Finished', detail: 'encrypted', enc: true },
    { dir: 'l2r', label: 'Application Data (HTTP request)', detail: `ALPN=${hs.alpn || '?'}${latency != null ? `, +${latency}ms since ClientHello` : ''}`, enc: true },
  ];
  const rows = messages.map((m, i) => {
    const lineClass = m.dir === 'l2r' ? 'l2r' : 'r2l';
    return `<div class="seq-msg${m.enc ? ' encrypted' : ''}" style="animation-delay:${i * 0.12}s">` +
      `<div class="seq-line ${m.dir === 'r2l' ? '' : lineClass}"></div>` +
      `<div class="seq-label">${m.label}<span class="seq-detail">${m.detail}</span></div>` +
      `<div class="seq-line ${m.dir === 'r2l' ? lineClass : ''}"></div>` +
    `</div>`;
  }).join('');
  return `<div class="diff-title" style="margin-top:8px">TLS 1.3 sequence (real params, standard flow)</div>` +
    `<div class="seq-diagram"><div class="seq-lanes"><span>Client</span><span>Sentinel Proxy</span></div>${rows}</div>`;
}

// Phase 7B.6: interactive risk-threshold slider. simulatedThreshold starts
// equal to realRiskThreshold (from the snapshot -- the engine's actual
// POLICY.risk_threshold, Phase 7C.5) and only diverges when the user
// drags the slider.
let realRiskThreshold = null;
let simulatedThreshold = null;

function simulateOutcome(row, threshold) {
  // Mirrors proxy/engine.py's actual order of operations: hard signals
  // are checked -- and can block -- before risk score is ever consulted.
  // A row only "flips" here if the real engine's decision for it was
  // genuinely threshold-dependent in the first place.
  const risk = parseInt(row.risk, 10);
  if (Number.isNaN(risk)) return row.outcome;  // no risk score recorded (e.g. a pre-decision block) -- immutable
  const wasHardBlock = row.outcome === 'BLOCK' && row.reason !== 'risk threshold exceeded';
  if (wasHardBlock) return 'BLOCK';  // hard signals don't care about threshold, neither does this simulation
  return risk >= threshold ? 'BLOCK' : 'PASS';
}

function applyThresholdToRow(tr) {
  if (simulatedThreshold === null || !tr.rowData) return;
  const row = tr.rowData;
  const simulated = simulateOutcome(row, simulatedThreshold);
  const cell = tr.querySelector('.decision-cell');
  const flipped = simulated !== row.outcome;
  tr.classList.toggle('flipped', flipped);
  const hasDiff = row.ja4_diff && Object.keys(row.ja4_diff).length > 0;
  const hasHandshake = !!row.handshake;
  const arrow = (hasDiff || hasHandshake) ? ' &#9656;' : '';
  const simTag = flipped ? `<span class="decision-sim">(was ${row.outcome})</span>` : '';
  cell.innerHTML = simulated + simTag + arrow;
  tr.className = (tr.className.includes('has-diff') ? 'has-diff ' : '') +
    (simulated === 'PASS' ? 'pass' : 'block') + (flipped ? ' flipped' : '');
}

function reevaluateAllRows() {
  document.querySelectorAll('#rows tr').forEach(tr => {
    if (tr.rowData) applyThresholdToRow(tr);
  });
}

function initThresholdSlider(threshold) {
  realRiskThreshold = threshold;
  simulatedThreshold = threshold;
  const slider = document.getElementById('threshold-slider');
  const label = document.getElementById('threshold-label');
  slider.value = threshold;
  slider.disabled = false;
  label.textContent = `${threshold} (real configured value)`;
}

document.getElementById('threshold-slider').addEventListener('input', (e) => {
  simulatedThreshold = parseInt(e.target.value, 10);
  const label = document.getElementById('threshold-label');
  const note = document.getElementById('threshold-note');
  const isReal = simulatedThreshold === realRiskThreshold;
  label.textContent = isReal ? `${simulatedThreshold} (real configured value)` : `${simulatedThreshold} (simulated -- real is ${realRiskThreshold})`;
  note.classList.toggle('dirty', !isReal);
  reevaluateAllRows();
});

function addRow(row) {
  const tr = document.createElement('tr');
  tr.rowData = row;  // 7B.6: kept for live threshold re-evaluation, original data never mutated
  tr.className = row.outcome === 'PASS' ? 'pass' : 'block';
  const hasDiff = row.ja4_diff && Object.keys(row.ja4_diff).length > 0;
  const hasHandshake = !!row.handshake;
  const expandable = hasDiff || hasHandshake;
  if (expandable) tr.className += ' has-diff';
  const outcomeLabel = expandable ? `${row.outcome} &#9656;` : row.outcome;
  const sophistication = row.sophistication_score != null
    ? `<span class="soph-badge soph-${row.sophistication_label}">${row.sophistication_score}/${row.sophistication_total} ${row.sophistication_label}</span>`
    : '-';
  tr.innerHTML = `<td>${row.ts}</td><td>${row.source_ip}</td><td>${row.presented_ja4}</td>` +
                 `<td>${row.bound_ja4}</td><td>${row.jkt_ok}</td><td>${row.risk}</td>` +
                 `<td>${sophistication}</td><td class="decision-cell">${outcomeLabel}</td>`;
  rowsEl.appendChild(tr);
  applyThresholdToRow(tr);

  if (expandable) {
    const detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.style.display = 'none';
    const td = document.createElement('td');
    td.colSpan = 8;
    td.innerHTML = (hasDiff ? buildDiffTable(row.ja4_diff) : '') +
      (hasHandshake ? buildHandshakeTable(row.handshake) + buildSequenceDiagram(row.handshake) : '');
    detailTr.appendChild(td);
    rowsEl.appendChild(detailTr);
    tr.addEventListener('click', () => {
      detailTr.style.display = detailTr.style.display === 'none' ? '' : 'none';
    });
  }

  // Trim from the front, removing a detail row along with its parent data
  // row so a diff panel never ends up orphaned under the wrong row.
  while (rowsEl.children.length > MAX_ROWS * 2) {
    const first = rowsEl.firstChild;
    rowsEl.removeChild(first);
    if (first.classList.contains('has-diff') && rowsEl.firstChild && rowsEl.firstChild.classList.contains('detail-row')) {
      rowsEl.removeChild(rowsEl.firstChild);
    }
  }
}

// Phase 7B.1 / 7B.4: live topology animation, driven by the same 'row'
// events the table already consumes -- no separate data feed.
let topoPositions = null;

function layoutTopology() {
  const topo = document.getElementById('topology');
  const rect = topo.getBoundingClientRect();
  const c = document.getElementById('node-client').getBoundingClientRect();
  const p = document.getElementById('node-proxy').getBoundingClientRect();
  const b = document.getElementById('node-backend').getBoundingClientRect();
  const cx = c.left + c.width / 2 - rect.left;
  const px = p.left + p.width / 2 - rect.left;
  const bx = b.left + b.width / 2 - rect.left;
  const e1 = document.getElementById('edge-1');
  e1.style.left = cx + 'px'; e1.style.width = (px - cx) + 'px';
  const e2 = document.getElementById('edge-2');
  e2.style.left = px + 'px'; e2.style.width = (bx - px) + 'px';
  return { cx, px, bx };
}

function spawnPacket(row) {
  if (!topoPositions) topoPositions = layoutTopology();
  const topo = document.getElementById('topology');
  const isPass = row.outcome === 'PASS';

  const packet = document.createElement('div');
  packet.className = 'packet ' + (isPass ? 'pass' : 'block');
  packet.style.left = topoPositions.cx + 'px';
  topo.appendChild(packet);

  // Leg 1, Client -> Proxy: always happens -- this is where TLS
  // terminates and JA4/DPoP get inspected, PASS or BLOCK alike.
  requestAnimationFrame(() => { packet.style.left = topoPositions.px + 'px'; });

  setTimeout(() => {
    const lock = document.getElementById('proxy-lock');
    lock.textContent = '🔒'; // locked, momentarily, on every arrival
    setTimeout(() => { lock.textContent = '🔓'; }, 400);

    if (isPass) {
      // Leg 2, Proxy -> Backend: only a PASS decision continues this far.
      packet.style.left = topoPositions.bx + 'px';
      setTimeout(() => {
        packet.style.opacity = '0';
        setTimeout(() => packet.remove(), 300);
      }, 650);
    } else {
      // Stops here. Visibly. Never reaches the backend node.
      packet.classList.add('reject');
      const label = document.createElement('div');
      label.className = 'reject-label';
      label.textContent = row.reason || 'blocked';
      label.style.left = (topoPositions.px - 80) + 'px';
      topo.appendChild(label);
      setTimeout(() => {
        packet.style.opacity = '0';
        label.style.opacity = '0';
        setTimeout(() => { packet.remove(); label.remove(); }, 300);
      }, 1000);
    }
  }, 650);
}

window.addEventListener('load', () => { topoPositions = layoutTopology(); drawGeoGrid(); });
window.addEventListener('resize', () => { topoPositions = layoutTopology(); });

// Phase 7B.5: simulated geo panel. A small fixed pool of plausible demo
// locations; which one a given JA4 maps to is a deterministic hash, not
// random -- so the same client always lands at the same simulated point,
// and a genuinely different TLS stack (an attacker's replay) reliably
// lands somewhere else. Equirectangular projection (lon,lat -> x,y).
const GEO_LOCATIONS = [
  { city: 'Frankfurt, DE', lat: 50.1, lon: 8.7 },
  { city: 'Ashburn, US', lat: 39.0, lon: -77.5 },
  { city: 'Singapore, SG', lat: 1.35, lon: 103.8 },
  { city: 'Sao Paulo, BR', lat: -23.5, lon: -46.6 },
  { city: 'Sydney, AU', lat: -33.9, lon: 151.2 },
  { city: 'Moscow, RU', lat: 55.75, lon: 37.6 },
  { city: 'Lagos, NG', lat: 6.5, lon: 3.4 },
  { city: 'Tokyo, JP', lat: 35.7, lon: 139.7 },
];
const geoMarkersByJa4 = {};

function hashToLocation(key) {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return GEO_LOCATIONS[h % GEO_LOCATIONS.length];
}

function drawGeoGrid() {
  const panel = document.getElementById('geo-panel');
  const w = panel.clientWidth, h = panel.clientHeight;
  for (let lon = -150; lon <= 150; lon += 30) {
    const x = ((lon + 180) / 360) * w;
    const line = document.createElement('div');
    line.className = 'geo-grid-line v';
    line.style.left = x + 'px';
    panel.appendChild(line);
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const y = ((90 - lat) / 180) * h;
    const line = document.createElement('div');
    line.className = 'geo-grid-line h';
    line.style.top = y + 'px';
    panel.appendChild(line);
  }
}

function plotGeoMarker(row) {
  if (!row.presented_ja4 || row.presented_ja4 === '-') return;
  const panel = document.getElementById('geo-panel');
  const w = panel.clientWidth, h = panel.clientHeight;
  const loc = hashToLocation(row.presented_ja4);
  const x = ((loc.lon + 180) / 360) * w;
  const y = ((90 - loc.lat) / 180) * h;
  const isPass = row.outcome === 'PASS';

  let marker = geoMarkersByJa4[row.presented_ja4];
  if (!marker) {
    marker = document.createElement('div');
    marker.style.left = x + 'px';
    marker.style.top = y + 'px';
    marker.setAttribute('data-label', loc.city);
    panel.appendChild(marker);
    geoMarkersByJa4[row.presented_ja4] = marker;
  }
  marker.className = 'geo-marker ' + (isPass ? 'pass' : 'block');
}

// Phase 7B.7: kill-chain timeline. Groups events by story_id (the
// token's jti) instead of leaving the viewer to mentally reassemble
// scattered table rows -- issuance, legitimate use, and any replay
// attempts against that same token render as one connected sequence.
const storiesById = {};
let activeStoryId = null;

function addStoryEvent(storyId, event) {
  if (!storyId) return;
  if (!storiesById[storyId]) storiesById[storyId] = [];
  storiesById[storyId].push(event);
  activeStoryId = storyId;  // auto-follow whichever story most recently gained a new link
  renderKillChain();
}

function renderKillChain() {
  const emptyEl = document.getElementById('killchain-empty');
  const linksEl = document.getElementById('killchain-links');
  const events = activeStoryId ? storiesById[activeStoryId] : null;
  if (!events || events.length === 0) {
    emptyEl.style.display = '';
    linksEl.style.display = 'none';
    return;
  }
  emptyEl.style.display = 'none';
  linksEl.style.display = '';

  linksEl.innerHTML = `<div style="font-size:10px;color:#8b949e;margin-bottom:10px;">` +
    `story (token jti) = <span id="killchain-story-id">${activeStoryId}</span></div>` +
    events.map((ev, i) => {
      if (ev.type === 'issuance') {
        return `<div class="kc-link" style="animation-delay:${i * 0.1}s">` +
          `<div class="kc-dot issue"></div><div class="kc-body">` +
          `<span class="kc-title">Token issued</span><span class="kc-ts">${ev.ts}</span>` +
          `<div class="kc-detail">ja4=${ev.ja4} source_ip=${ev.source_ip}</div></div></div>`;
      }
      const isPass = ev.outcome === 'PASS';
      const title = isPass ? 'Legitimate use' : `Replay attempt -- blocked`;
      const detail = isPass ? `from ${ev.source_ip}` : `${ev.reason} (from ${ev.source_ip})`;
      return `<div class="kc-link" style="animation-delay:${i * 0.1}s">` +
        `<div class="kc-dot ${isPass ? 'pass' : 'block'}"></div><div class="kc-body">` +
        `<span class="kc-title">${title}</span><span class="kc-ts">${ev.ts}</span>` +
        `<div class="kc-detail">${detail}</div></div></div>`;
    }).join('');
}

function addLog(line) {
  const div = document.createElement('div');
  div.textContent = line;
  logEl.appendChild(div);
  while (logEl.children.length > MAX_LOG) logEl.removeChild(logEl.firstChild);
  logEl.scrollTop = logEl.scrollHeight;
}

function setCounts(c) {
  document.getElementById('c-total').textContent = c.total;
  document.getElementById('c-passed').textContent = c.passed;
  document.getElementById('c-blocked').textContent = c.blocked;
}

function setRateLimited(n) {
  document.getElementById('c-rate-limited').textContent = n;
  document.getElementById('c-rate-limited-wrap').style.display = n > 0 ? '' : 'none';
}

function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => { statusEl.textContent = 'live'; statusEl.className = 'status live'; };
  ws.onclose = () => { statusEl.textContent = 'disconnected -- retrying...'; statusEl.className = 'status'; setTimeout(connect, 1000); };
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'snapshot') {
      rowsEl.innerHTML = ''; logEl.innerHTML = '';
      initThresholdSlider(msg.risk_threshold);
      (msg.issuances || []).forEach(ev => addStoryEvent(ev.story_id, ev));
      msg.rows.forEach(addRow);
      msg.rows.forEach(plotGeoMarker);  // static markers DO reflect history; the travel animation doesn't replay
      msg.rows.forEach(r => addStoryEvent(r.story_id, r));
      msg.log_lines.forEach(addLog);
      setCounts(msg);
      setRateLimited(msg.rate_limited || 0);
    } else if (msg.type === 'row') {
      addRow(msg.row);
      spawnPacket(msg.row);  // snapshot rows (page load/reconnect) don't replay animations, only live ones do
      plotGeoMarker(msg.row);
      addStoryEvent(msg.row.story_id, msg.row);
    } else if (msg.type === 'issuance') {
      addStoryEvent(msg.story_id, msg);
    } else if (msg.type === 'rate_limited') {
      setRateLimited(msg.rate_limited_total);
    } else if (msg.type === 'log') {
      addLog(msg.line);
    } else if (msg.type === 'counts') {
      setCounts(msg);
    }
  };
}
connect();
</script>
</body>
</html>
"""


class _WebSocketHandler(tornado.websocket.WebSocketHandler):
    clients: set = set()
    dashboard: Dashboard | None = None

    def open(self) -> None:
        _WebSocketHandler.clients.add(self)
        if _WebSocketHandler.dashboard is not None:
            self.write_message(json.dumps(_WebSocketHandler.dashboard.snapshot()))

    def on_close(self) -> None:
        _WebSocketHandler.clients.discard(self)

    def check_origin(self, origin: str) -> bool:
        return True  # localhost-only demo server; the bind address is the real control


class _IndexHandler(tornado.web.RequestHandler):
    def get(self) -> None:
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.write(_INDEX_HTML)


class WebDashboard:
    def __init__(self, dashboard: Dashboard, host: str = "127.0.0.1", port: int = 8090) -> None:
        self._host = host
        self._port = port
        self._server = None
        _WebSocketHandler.dashboard = dashboard
        self._app = tornado.web.Application([(r"/", _IndexHandler), (r"/ws", _WebSocketHandler)])
        dashboard.add_listener(self._broadcast)

    def start(self) -> None:
        self._server = self._app.listen(self._port, address=self._host)
        print(f"[sentinel] web dashboard: http://{self._host}:{self._port}")

    def stop(self) -> None:
        if self._server is not None:
            self._server.stop()

    @staticmethod
    def _broadcast(event: dict) -> None:
        payload = json.dumps(event)
        for client in list(_WebSocketHandler.clients):
            try:
                client.write_message(payload)
            except Exception:
                _WebSocketHandler.clients.discard(client)
