/* Quarry Workbench — frontend */
"use strict";

const MAX_EVENTS = 5000;

const state = {
  events:      [],   // all received events (capped)
  filterType:  "",
  filterPid:   0,
  filterText:  "",
  selectedPid: 0,    // from tree click
  selectedEv:  null,
};

// ── DOM refs ────────────────────────────────────────────────────────
const $eventList   = document.getElementById("event-list");
const $treeList    = document.getElementById("tree-list");
const $detail      = document.getElementById("detail-content");
const $counter     = document.getElementById("counter");
const $dot         = document.getElementById("status-dot");
const $filterType  = document.getElementById("filter-type");
const $filterPid   = document.getElementById("filter-pid");
const $filterText  = document.getElementById("filter-text");

// ── WebSocket ────────────────────────────────────────────────────────
let ws;
function connect() {
  ws = new WebSocket(`ws://${location.host}/ws/events`);
  ws.onopen    = () => $dot.classList.add("live");
  ws.onclose   = () => { $dot.classList.remove("live"); setTimeout(connect, 2000); };
  ws.onmessage = e => onEvent(JSON.parse(e.data));
}

function onEvent(ev) {
  if (ev.event_type === "ping") return;
  state.events.push(ev);
  if (state.events.length > MAX_EVENTS) state.events.shift();
  appendRow(ev);
  if (ev.event_type === "process" && ev.data?.sub_type === "create") {
    addTreeNode(ev);
  }
  $counter.textContent = `${state.events.length} events`;
}

// ── Event rows ───────────────────────────────────────────────────────
function appendRow(ev) {
  if (!matchesFilter(ev)) return;
  const row = buildRow(ev);
  $eventList.appendChild(row);
  // Auto-scroll only if already at bottom
  const el = $eventList;
  if (el.scrollHeight - el.scrollTop - el.clientHeight < 40) {
    el.scrollTop = el.scrollHeight;
  }
}

function matchesFilter(ev) {
  if (state.filterType && ev.event_type !== state.filterType) return false;
  if (state.filterPid  && ev.pid !== state.filterPid)          return false;
  if (state.selectedPid && ev.pid !== state.selectedPid)       return false;
  if (state.filterText) {
    const hay = JSON.stringify(ev).toLowerCase();
    if (!hay.includes(state.filterText.toLowerCase())) return false;
  }
  return true;
}

function buildRow(ev) {
  const d   = new Date(ev.timestamp * 1000);
  const ts  = d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0");
  const row = document.createElement("div");
  row.className = "event-row";
  row.innerHTML = `
    <span class="ts">${esc(ts)}</span>
    <span><span class="badge ${esc(ev.event_type)}">${esc(ev.event_type)}</span></span>
    <span class="pid">${ev.pid || ""}</span>
    <span class="pname">${esc(ev.process_name || "")}</span>
    <span class="detail">${esc(summarize(ev))}</span>
  `;
  row.addEventListener("click", () => showDetail(ev, row));
  return row;
}

function summarize(ev) {
  const d = ev.data || {};
  if (ev.event_type === "process") {
    if (d.sub_type === "create")     return `spawn: ${d.cmdline || d.image_path || ""}`;
    if (d.sub_type === "exit")       return `exit code ${d.exit_code ?? ""}`;
    if (d.sub_type === "image_load") return `load: ${d.image_path || ""}`;
  }
  if (ev.event_type === "file")     return `${d.op || ""}: ${d.path || ""}`;
  if (ev.event_type === "registry") return `${d.op || ""}: ${d.key || ""}`;
  if (ev.event_type === "network") {
    if (d.op === "dns_query" || d.op === "dns_response") return `${d.op}: ${d.name || ""}`;
    return `${d.op || ""} ${d.src_addr || ""}→${d.dst_addr || ""}:${d.dst_port || ""}`;
  }
  if (ev.event_type === "hook")     return `${d.hook || ""}: ${d.payload || ""}`;
  if (ev.event_type === "yara") {
    const rules = (d.matches || []).map(m => m.rule).join(", ");
    return `${rules} → ${d.path || ""}`;
  }
  return JSON.stringify(d).slice(0, 80);
}

// ── Detail panel ─────────────────────────────────────────────────────
function showDetail(ev, row) {
  if (state.selectedEv === ev) return;
  state.selectedEv = ev;
  document.querySelectorAll(".event-row.selected").forEach(r => r.classList.remove("selected"));
  row.classList.add("selected");

  const d = new Date(ev.timestamp * 1000);
  const ts = d.toISOString();
  const pairs = [
    ["type",    ev.event_type],
    ["time",    ts],
    ["pid",     ev.pid],
    ["ppid",    ev.ppid],
    ["process", ev.process_name],
    ...Object.entries(ev.data || {}),
  ];
  $detail.innerHTML = pairs
    .filter(([, v]) => v !== "" && v !== 0 && v !== null && v !== undefined)
    .map(([k, v]) => `<div class="kv"><span class="k">${esc(String(k))}</span><span class="v">${esc(String(v))}</span></div>`)
    .join("");
}

// ── Process tree ─────────────────────────────────────────────────────
const _treeNodes = {};  // pid -> DOM element

function addTreeNode(ev) {
  if (_treeNodes[ev.pid]) return;
  const name   = ev.process_name || ev.data?.image_path?.split("\\").pop() || "?";
  const indent = _depth(ev.ppid) * 12;
  const node   = document.createElement("div");
  node.className = "tree-node";
  node.style.paddingLeft = (8 + indent) + "px";
  node.innerHTML = `<span class="name">${esc(name)}</span><span class="pid">${ev.pid}</span>`;
  node.addEventListener("click", () => {
    document.querySelectorAll(".tree-node.selected").forEach(n => n.classList.remove("selected"));
    node.classList.add("selected");
    state.selectedPid = (state.selectedPid === ev.pid) ? 0 : ev.pid;
    rebuildEventList();
  });
  _treeNodes[ev.pid] = node;
  $treeList.appendChild(node);
}

function _depth(pid, depth = 0) {
  if (!pid || depth > 8) return depth;
  const parent = Object.values(_treeNodes).find(n => parseInt(n.querySelector(".pid").textContent) === pid);
  return parent ? _depth(parseInt(parent.style.paddingLeft) || 0, depth + 1) : depth;
}

// ── Filtering ────────────────────────────────────────────────────────
function rebuildEventList() {
  $eventList.innerHTML = "";
  state.events.filter(matchesFilter).forEach(ev => $eventList.appendChild(buildRow(ev)));
  $eventList.scrollTop = $eventList.scrollHeight;
}

$filterType.addEventListener("change", () => {
  state.filterType = $filterType.value;
  rebuildEventList();
});
$filterPid.addEventListener("input", () => {
  state.filterPid = parseInt($filterPid.value) || 0;
  rebuildEventList();
});
$filterText.addEventListener("input", () => {
  state.filterText = $filterText.value;
  rebuildEventList();
});

// ── Utilities ────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ── Tab switching ─────────────────────────────────────────────────────
function showTab(el) {
  const view = el.dataset.view;
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.getElementById(`view-${view}`).classList.add("active");
  el.classList.add("active");
  if (view === "static") loadStatic();
}

// ── Static analysis ───────────────────────────────────────────────────
let _staticLoaded = false;

async function loadStatic() {
  if (_staticLoaded) return;
  const res = await fetch("/api/static");
  const data = await res.json();
  if (!data) return;
  _staticLoaded = true;
  renderStatic(data);
}

function renderStatic(d) {
  const root = document.getElementById("static-content");
  if (d.error && !d.sha256) {
    root.innerHTML = `<p style="color:var(--red);padding:16px">Error: ${esc(d.error)}</p>`;
    return;
  }

  const score = d.risk_score ?? 0;
  const scoreClass = score < 30 ? "risk-low" : score < 60 ? "risk-medium"
                   : score < 80 ? "risk-high" : "risk-crit";
  const barColor = score < 30 ? "var(--green)" : score < 60 ? "var(--yellow)"
                 : score < 80 ? "var(--orange)" : "var(--red)";

  root.innerHTML = `

    <!-- Risk gauge -->
    <div class="risk-gauge">
      <div>
        <div style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:1px">Risk Score</div>
        <div class="risk-number ${scoreClass}">${score}</div>
      </div>
      <div style="flex:1">
        <div class="risk-bar-track">
          <div class="risk-bar-fill" style="width:${score}%;background:${barColor}"></div>
        </div>
        <ul class="indicator-list" style="margin-top:8px">
          ${(d.risk_indicators ?? []).map(i => `<li>${esc(i)}</li>`).join("")}
        </ul>
      </div>
    </div>

    <!-- File identity -->
    <div class="static-section">
      <div class="static-section-header">
        <span>File Identity</span>
        <span style="color:var(--text)">${esc(d.path ?? "")}</span>
      </div>
      <div class="static-section-body">
        <div class="identity-grid">
          <span class="lbl">SHA-256</span><span class="val hash">${esc(d.sha256 ?? "")}</span>
          <span class="lbl">MD5</span><span class="val hash">${esc(d.md5 ?? "")}</span>
          <span class="lbl">Size</span><span class="val">${fmtSize(d.file_size)}</span>
          <span class="lbl">Machine</span><span class="val">${esc(d.machine ?? "")}</span>
          <span class="lbl">Subsystem</span><span class="val">${esc(d.subsystem ?? "")}</span>
          <span class="lbl">Compile time</span><span class="val">${esc(d.compile_timestamp_str ?? "")}</span>
          <span class="lbl">Entry point</span><span class="val">0x${(d.entry_point ?? 0).toString(16).toUpperCase()}</span>
          <span class="lbl">Image base</span><span class="val">0x${(d.image_base ?? 0).toString(16).toUpperCase()}</span>
          <span class="lbl">Type</span><span class="val">${d.is_dll ? "DLL" : "EXE"} / ${d.is_64bit ? "64-bit" : "32-bit"}</span>
          <span class="lbl">Overall entropy</span><span class="val">${(d.overall_entropy ?? 0).toFixed(3)}</span>
        </div>
        ${d.error ? `<p style="color:var(--yellow);margin-top:8px;font-size:11px">⚠ ${esc(d.error)}</p>` : ""}
      </div>
    </div>

    <!-- Sections -->
    <div class="static-section">
      <div class="static-section-header">Sections (${(d.sections ?? []).length})</div>
      <div class="static-section-body" style="padding:0">
        <table class="sect-table">
          <tr><th>Name</th><th>VA</th><th>V.Size</th><th>Raw</th><th>Flags</th><th>Entropy</th><th>MD5</th></tr>
          ${(d.sections ?? []).map(s => {
            const ec = s.entropy > 7.5 ? "crit" : s.entropy > 7.0 ? "high"
                     : s.entropy > 5.0 ? "medium" : "low";
            return `<tr>
              <td>${esc(s.name)}</td>
              <td>0x${s.virtual_address.toString(16).toUpperCase()}</td>
              <td>${fmtSize(s.virtual_size)}</td>
              <td>${fmtSize(s.raw_size)}</td>
              <td style="color:var(--dim)">${esc(s.characteristics)}</td>
              <td>
                <span class="ent-bar-track">
                  <span class="ent-bar-fill ent-${ec}" style="width:${Math.min(s.entropy/8*100,100).toFixed(1)}%"></span>
                </span>
                <span style="margin-left:6px">${s.entropy.toFixed(3)}</span>
              </td>
              <td style="color:var(--dim);font-size:10px">${esc(s.md5 ?? "")}</td>
            </tr>`;
          }).join("")}
        </table>
      </div>
    </div>

    <!-- Suspicious imports -->
    ${(d.suspicious_imports ?? []).length > 0 ? `
    <div class="static-section">
      <div class="static-section-header" style="color:var(--red)">
        Suspicious Imports (${d.suspicious_imports.length})
      </div>
      <div class="static-section-body">
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${d.suspicious_imports.map(fn =>
            `<span class="badge hook">${esc(fn)}</span>`
          ).join("")}
        </div>
      </div>
    </div>` : ""}

    <!-- All imports -->
    <div class="static-section">
      <div class="static-section-header">Imports (${(d.imports ?? []).length} DLLs)</div>
      <div class="static-section-body">
        ${(d.imports ?? []).map(entry => `
          <details class="import-dll">
            <summary>
              ${esc(entry.dll)}
              <span style="color:var(--dim);font-size:10px"> — ${entry.functions.length} function(s)
              ${entry.suspicious.length > 0 ? `<span style="color:var(--red)"> · ${entry.suspicious.length} suspicious</span>` : ""}
              </span>
            </summary>
            <div class="import-fns">
              ${entry.functions.map(fn =>
                entry.suspicious.includes(fn)
                  ? `<span class="fn-susp">${esc(fn)}</span><br>`
                  : `<span>${esc(fn)}</span><br>`
              ).join("")}
            </div>
          </details>
        `).join("")}
      </div>
    </div>

    <!-- Anomalies + packer clues -->
    ${[...(d.packer_clues ?? []), ...(d.anomalies ?? [])].length > 0 ? `
    <div class="static-section">
      <div class="static-section-header" style="color:var(--yellow)">Anomalies & Packer Clues</div>
      <div class="static-section-body">
        <ul class="indicator-list">
          ${[...(d.packer_clues ?? []), ...(d.anomalies ?? [])].map(a =>
            `<li>${esc(a)}</li>`
          ).join("")}
        </ul>
      </div>
    </div>` : ""}

    <!-- Strings -->
    <div class="static-section">
      <div class="static-section-header">
        Strings
        <span style="color:var(--dim)">
          ${d.strings_ascii?.length ?? 0} ASCII · ${d.strings_unicode?.length ?? 0} Unicode
          ${d.strings_truncated ? " (truncated)" : ""}
        </span>
      </div>
      <div class="static-section-body">
        <div class="strings-tabs">
          <span class="str-tab active" onclick="switchStrings(this,'ascii')">ASCII</span>
          <span class="str-tab"       onclick="switchStrings(this,'unicode')">Unicode</span>
        </div>
        <div id="strings-ascii" class="strings-list">
          ${(d.strings_ascii ?? []).map(s => `<div>${esc(s)}</div>`).join("")}
        </div>
        <div id="strings-unicode" class="strings-list" style="display:none">
          ${(d.strings_unicode ?? []).map(s => `<div>${esc(s)}</div>`).join("")}
        </div>
      </div>
    </div>
  `;
}

function switchStrings(el, which) {
  document.querySelectorAll(".str-tab").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  ["ascii","unicode"].forEach(id => {
    const el2 = document.getElementById(`strings-${id}`);
    if (el2) el2.style.display = (id === which) ? "" : "none";
  });
}

function fmtSize(n) {
  if (!n) return "0";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

// ── Boot ─────────────────────────────────────────────────────────────
connect();
