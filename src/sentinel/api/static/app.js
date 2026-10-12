"use strict";
// Sentinel dashboard. All dynamic text is inserted with textContent (log lines are attacker-controlled).
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_VAR = { critical: "--critical", high: "--high", medium: "--medium", low: "--low", info: "--info" };
const $ = (id) => document.getElementById(id);
const state = { tab: "overview", info: null, selected: null, token: null };
try { state.token = sessionStorage.getItem("sentinel-token"); } catch (e) { /* storage blocked: stay in memory */ }

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v; else if (k.startsWith("on")) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const clear = (el, ...kids) => { el.replaceChildren(...kids.flat().filter(Boolean)); return el; };
const badge = (sev) => h("span", { class: `badge sev-${sev}` }, sev);
const empty = (msg) => h("div", { class: "empty" }, msg);
const when = (iso) => (iso ? iso.replace("T", " ").slice(0, 16) + "Z" : "");

async function api(path, opts = {}) {
  const headers = { Accept: "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (opts.body) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { ...opts, headers });
  let data = null;
  try { data = await r.json(); } catch (e) { /* non-JSON error */ }
  if (r.status === 401) { showLogin(); throw new Error("unauthorized"); }
  if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
  return data;
}

function showLogin(msg) {
  $("login").hidden = false;
  $("login-err").textContent = msg || "";
  for (const v of document.querySelectorAll(".view")) v.hidden = true;
}

// ---- tiles / rows ---------------------------------------------------------------------------
function tiles(counts) {
  return SEVS.map((s) => {
    const n = counts[s] || 0;
    const t = h("div", { class: "tile" + (n ? "" : " zero") }, h("div", { class: "n" }, n), h("div", { class: "l" }, s));
    t.style.setProperty("--c", `var(${SEV_VAR[s]})`);
    return t;
  });
}

function findingRow(f, opts = {}) {
  const where = f.window_start ? `window ${when(f.window_start)}` : f.target || "";
  const meta = opts.time ? when(f.ts || f.created_at) : where;
  return h("div", { class: "row" }, badge(f.severity),
    h("div", { class: "title" }, f.title, h("span", { class: "muted" }, `  ${f.source}/${f.check_name}`)),
    h("div", { class: "meta" }, opts.time ? [meta, where ? ` · ${where}` : ""] : meta),
    f.detail ? h("div", { class: "detail" }, f.detail) : null);
}

// ---- overview -------------------------------------------------------------------------------
async function loadOverview() {
  const s = await api("/api/summary");
  $("host").textContent = s.hostname ? "@ " + s.hostname : "";
  $("audit-when").textContent = s.latest_audit ? `run #${s.latest_audit.id}, ${when(s.latest_audit.started_at)}` : "";
  $("detect-when").textContent = s.latest_detect ? `last detection ${when(s.latest_detect.started_at)}` : "";
  clear($("audit-tiles"), s.latest_audit ? tiles(s.latest_audit_counts) : empty("No audit yet. Run `sentinel audit` or start the daemon."));
  clear($("anom-tiles"), tiles(s.anomalies_24h));
  const [timeline, top] = await Promise.all([
    api("/api/timeline?hours=48&min_severity=info&limit=2000"),
    s.latest_audit ? api(`/api/runs/${s.latest_audit.id}`) : Promise.resolve({ findings: [] }),
  ]);
  drawChart(timeline);
  const worst = top.findings.filter((f) => f.severity !== "info").slice(0, 8);
  clear($("top-findings"), worst.length ? worst.map((f) => findingRow(f)) : empty("Nothing above info severity in the latest audit."));
}

function drawChart(rows) {
  const BUCKETS = 48, now = Date.now(), hour = 3600e3;
  const grid = Array.from({ length: BUCKETS }, () => ({}));
  for (const r of rows) {
    const idx = BUCKETS - 1 - Math.floor((now - Date.parse(r.ts)) / hour);
    if (idx >= 0 && idx < BUCKETS) grid[idx][r.severity] = (grid[idx][r.severity] || 0) + 1;
  }
  const max = Math.max(1, ...grid.map((g) => Object.values(g).reduce((a, b) => a + b, 0)));
  const NS = "http://www.w3.org/2000/svg", W = 480, H = 100, bw = W / BUCKETS;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H + 12}`); svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Findings per hour, last 48 hours: ${rows.length} total`);
  grid.forEach((g, i) => {
    let y = H;
    for (const sev of [...SEVS].reverse()) {
      const n = g[sev] || 0; if (!n) continue;
      const bh = (n / max) * (H - 4);
      const rect = document.createElementNS(NS, "rect");
      rect.setAttribute("x", i * bw + 0.6); rect.setAttribute("y", y - bh); rect.setAttribute("width", bw - 1.2); rect.setAttribute("height", bh);
      rect.setAttribute("fill", `var(${SEV_VAR[sev]})`);
      const t = document.createElementNS(NS, "title");
      t.textContent = `${sev}: ${n} (${BUCKETS - 1 - i}h ago)`; rect.append(t); svg.append(rect); y -= bh;
    }
  });
  const base = document.createElementNS(NS, "line");
  base.setAttribute("x1", 0); base.setAttribute("x2", W); base.setAttribute("y1", H + .5); base.setAttribute("y2", H + .5);
  base.setAttribute("stroke", "var(--line)"); svg.append(base);
  clear($("chart"), svg);
  clear($("legend"), SEVS.map((s) => { const i = h("i"); i.style.background = `var(${SEV_VAR[s]})`; return h("span", {}, i, s); }),
    h("span", {}, rows.length ? `${rows.length} entries, 1 bar = 1 hour, oldest left` : "no activity in this window"));
}

// ---- timeline -------------------------------------------------------------------------------
async function loadTimeline() {
  const rows = await api(`/api/timeline?hours=${$("tl-hours").value}&min_severity=${$("tl-sev").value}&limit=500`);
  $("tl-count").textContent = `${rows.length} entries (UTC)`;
  clear($("timeline"), rows.length ? rows.map((r) => findingRow(r, { time: true })) : empty("No findings in this window."));
}

// ---- runs -----------------------------------------------------------------------------------
async function loadRuns() {
  const kind = $("runs-kind").value;
  const runs = await api("/api/runs?limit=60" + (kind ? `&kind=${kind}` : ""));
  clear($("runs"), runs.length ? runs.map((r) => {
    const row = h("div", { class: "row click" + (state.selected === r.id ? " sel" : ""), tabindex: "0", role: "button", onclick: () => openRun(r.id),
      onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openRun(r.id); } } },
      h("span", { class: "meta id" }, `#${r.id}`),
      h("div", { class: "title" }, `${r.kind} · ${r.total} finding${r.total === 1 ? "" : "s"} `, r.max_severity ? badge(r.max_severity) : null),
      h("div", { class: "meta" }, `${when(r.started_at)} ${r.hostname || ""}`));
    return row;
  }) : empty("No runs yet."));
}

async function openRun(id) {
  state.selected = id;
  const box = $("run-detail"); box.hidden = false;
  const [d, logs] = await Promise.all([api(`/api/runs/${id}`), api(`/api/runs/${id}/logs`)]);
  const prev = await api(`/api/runs?kind=${d.run.kind}&limit=100`).then((l) => l.find((r) => r.id < id));
  const diffBox = h("div");
  clear(box,
    h("h2", {}, `Run #${id} `, h("span", { class: "muted" }, `${d.run.kind} · ${when(d.run.started_at)} · ${d.run.hostname || ""}`)),
    prev ? h("button", { class: "ghost", onclick: async (e) => {
      e.target.disabled = true;
      try {
        const df = await api(`/api/diff?old=${prev.id}&new=${id}`);
        clear(diffBox, h("h4", {}, `New since #${prev.id} (${df.new_findings.length})`),
          df.new_findings.length ? df.new_findings.map((f) => findingRow(f)) : empty("nothing new"),
          h("h4", {}, `Resolved (${df.resolved.length})`), df.resolved.length ? df.resolved.map((f) => findingRow(f)) : empty("nothing resolved"));
      } finally { e.target.disabled = false; }
    } }, `Diff vs #${prev.id}`) : null,
    diffBox,
    h("h4", {}, `Findings (${d.findings.length})`),
    d.findings.length ? d.findings.map((f) => findingRow(f)) : empty("No findings."),
    h("h4", {}, `Log (${logs.length} lines)`),
    h("pre", { class: "out" }, logs.map((l) => `${l.ts.slice(11, 19)} ${l.level.padEnd(7)} ${l.message}`).join("\n") || "(empty)"));
  for (const r of document.querySelectorAll("#runs .row")) r.classList.toggle("sel", r.firstChild.textContent === `#${id}`);
}

// ---- actions --------------------------------------------------------------------------------
function wireActions() {
  for (const b of document.querySelectorAll("[data-action]")) b.addEventListener("click", async () => {
    const out = $("action-out"); out.hidden = false; out.textContent = "running...";
    const all = document.querySelectorAll("[data-action]"); all.forEach((x) => (x.disabled = true));
    try { out.textContent = JSON.stringify(await api(`/api/actions/${b.dataset.action}`, { method: "POST", body: "{}" }), null, 2); refresh(); }
    catch (e) { out.textContent = "error: " + e.message; }
    finally { all.forEach((x) => (x.disabled = false)); }
  });
}

// ---- shell ----------------------------------------------------------------------------------
const LOADERS = { overview: loadOverview, timeline: loadTimeline, runs: loadRuns, actions: async () => {} };

async function refresh() {
  $("error").textContent = "";
  try {
    $("login").hidden = true;
    for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== "view-" + state.tab;
    await LOADERS[state.tab]();
    $("dot").className = "dot ok"; $("updated").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (e) {
    if (e.message !== "unauthorized") { $("dot").className = "dot bad"; $("error").textContent = "Could not load data: " + e.message; }
  }
}

function setTab(tab) {
  state.tab = tab;
  for (const b of document.querySelectorAll("#tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
  refresh();
}

async function init() {
  const sel = $("tl-sev");
  for (const s of [...SEVS].reverse()) sel.append(h("option", { value: s, ...(s === "low" ? { selected: "" } : {}) }, s));
  for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => setTab(b.dataset.tab));
  for (const id of ["tl-hours", "tl-sev", "runs-kind"]) $(id).addEventListener("change", refresh);
  $("refresh").addEventListener("click", refresh);
  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault(); state.token = $("token").value.trim();
    try { await api("/api/summary"); try { sessionStorage.setItem("sentinel-token", state.token); } catch (x) { /* ignore */ } $("token").value = ""; refresh(); }
    catch (err) { state.token = null; showLogin(err.message === "unauthorized" ? "Wrong token." : err.message); }
  });
  wireActions();
  try { state.info = await api("/api/info"); } catch (e) { $("error").textContent = "Server unreachable."; $("dot").className = "dot bad"; return; }
  $("tab-actions").hidden = !state.info.actions_enabled;
  if (state.info.auth_required && !state.token) { showLogin(); return; }
  refresh();
  setInterval(() => { if (!document.hidden && $("login").hidden && state.tab !== "actions") refresh(); }, 30000);
}
init();
