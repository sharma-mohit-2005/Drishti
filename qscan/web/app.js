/* Q-Scan dashboard. Vanilla JS, no external libraries, works offline. */
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const app = $("#app");
  const BANDS = ["critical", "high", "medium", "low"];
  const BAND_COLOR = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)" };
  const BAND_FILL = { critical: "var(--crit-fill)", high: "var(--high-fill)", medium: "var(--med-fill)", low: "var(--low-fill)" };
  const BAND_SOFT = { critical: "var(--crit-soft)", high: "var(--high-soft)", medium: "var(--med-soft)", low: "var(--low-soft)" };
  const STATUS_FILL = { broken: "var(--crit-fill)", "quantum-vulnerable": "var(--high-fill)", weak: "var(--med-fill)", "quantum-weakened": "var(--med-fill)",
    safe: "var(--low-fill)", info: "var(--low-fill)", pqc: "var(--pqc-fill)", unknown: "var(--line-2)" };
  const HEAT_COLS = ["Exposed now", "< 3 yrs margin", "3–6 yrs", "> 6 yrs", "Not exposed"];
  const HEAT_BASE = ["var(--crit-fill)", "var(--high-fill)", "var(--med-fill)", "var(--low-fill)", "var(--pqc-fill)"];
  const KIND_LABEL = { algorithm: "Algorithm", protocol: "Protocol", suite: "Cipher suite", certificate: "Certificate", key: "Key", library: "Library" };
  const SURFACE_LABEL = { source: "Source code", config: "Config", certificate: "Certificates", key: "Keys", dependency: "Dependencies", binary: "Binaries", endpoint: "Live TLS", container: "Containers" };
  const TABS = [
    ["overview", "Overview", "grid", "Quantum readiness, where the risk sits, and what to look at first."],
    ["inventory", "Inventory", "list", "Every cryptographic asset found, ranked by Quantum Risk Score."],
    ["roadmap", "Migration roadmap", "flag", "Assets grouped into migration waves, with the readiness gain from each."],
    ["lab", "PQC lab", "zap", "Real timings and size costs of post-quantum algorithms on this machine."],
    ["export", "Export & CI", "download", "Download the CBOM and reports, compare scans, and gate pull requests."],
  ];

  // Lucide-style stroke icons (inline, so the dashboard stays offline)
  const ICONS = {
    grid: '<rect width="7" height="9" x="3" y="3" rx="1.5"/><rect width="7" height="5" x="14" y="3" rx="1.5"/><rect width="7" height="9" x="14" y="12" rx="1.5"/><rect width="7" height="5" x="3" y="16" rx="1.5"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
    zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    chevron: '<path d="m9 18 6-6-6-6"/>',
    play: '<circle cx="12" cy="12" r="9"/><path d="m10 8.5 5 3.5-5 3.5z"/>',
    folder: '<path d="M20 19a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9l-.8-1.2A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2z"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
    box: '<path d="M21 8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4a2 2 0 0 0 1-1.7z"/><path d="M3.3 7 12 12l8.7-5"/><path d="M12 22V12"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 3.5 9A14 14 0 0 1 12 21a14 14 0 0 1-3.5-9A14 14 0 0 1 12 3z"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    shield: '<path d="M20 13c0 5-3.5 7.5-7.7 9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    alert: '<path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3z"/><path d="M12 9v4M12 17h.01"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    code: '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
    calendar: '<rect width="18" height="18" x="3" y="4" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
    layers: '<path d="m12 2 10 5-10 5L2 7z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
    compare: '<path d="M8 3 4 7l4 4"/><path d="M4 7h16"/><path d="m16 21 4-4-4-4"/><path d="M20 17H4"/>',
    terminal: '<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>',
    table: '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M3 9h18M3 15h18M9 3v18"/>',
    arrow: '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
    wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9z"/>',
  };
  const icon = (name, cls = "") => `<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;

  const state = { public: false, sources: null, scans: [], scan: null, sim: null, tab: "overview", filter: { q: "", band: "", kind: "", surface: "" }, bench: null, diff: null };

  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  async function api(path, opts = {}) {
    const res = await fetch(path, opts);
    if (!res.ok) {
      let msg = res.statusText;
      try { msg = (await res.json()).detail || msg; } catch (_) {}
      throw new Error(msg);
    }
    return res.json();
  }
  const riskOf = (a) => (state.sim ? state.sim.risks[a.id] : a.risk) || null;
  const summary = () => (state.sim ? state.sim.summary : state.scan.summary);
  const pill = (cls, text) => `<span class="pill ${cls}">${esc(text)}</span>`;
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const STATUS_LABEL = { pqc: "PQC", "quantum-vulnerable": "Quantum-vulnerable", "quantum-weakened": "Quantum-weakened" };
  const bandPill = (b) => (b ? pill("b-" + b, cap(b)) : "");
  const statusPill = (s) => pill("s-" + s, STATUS_LABEL[s] || cap(s.replace("-", " ")));
  const fmtDate = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  const errorBox = (msg) => `<div class="error" role="alert">${icon("alert", "sm")}<span>${esc(msg)}</span></div>`;
  const cardHead = (title, hint = "") => `<div class="card-head"><h2>${title}</h2>${hint ? `<span class="hint">${hint}</span>` : ""}</div>`;

  // ---------- sidebar ----------
  function renderNav() {
    const nav = $("#nav");
    if (!state.scan) {
      nav.innerHTML = `<div class="nav-empty">Open or run a scan to see its results here.</div>`;
      return;
    }
    nav.innerHTML = `<div class="nav-label">Results</div>` + TABS.map(([k, l, ic]) => `
      <button class="nav-item" data-tab="${k}" ${state.tab === k ? 'aria-current="page"' : ""}>${icon(ic)}<span>${l}</span>${k === "inventory" ? `<span class="count">${state.scan.assets.length}</span>` : ""}</button>`).join("");
    nav.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; render(); app.focus({ preventScroll: true }); window.scrollTo({ top: 0 }); }));
  }

  // ---------- scans list ----------
  async function refreshScans(selectId) {
    state.scans = await api("/api/scans");
    const picker = $("#scanPicker");
    picker.innerHTML = `<option value="">${state.scans.length ? "Select a scan…" : "No scans yet"}</option>` +
      state.scans.map((s) => `<option value="${esc(s.id)}">${esc(s.name)} · QRI ${s.qri}</option>`).join("");
    if (selectId) picker.value = selectId;
  }

  async function openScan(id) {
    state.scan = await api(`/api/scans/${encodeURIComponent(id)}`);
    state.sim = null; state.diff = null;
    state.filter = { q: "", band: "", kind: "", surface: "" };
    $("#scanPicker").value = id;
    try { localStorage.setItem("qd:last", id); } catch (_) {}
    render();
  }

  // ---------- new scan ----------
  let formTab = "demo";
  const FORM_TABS = [["demo", "Demo repo", "play"], ["path", "Folder", "folder"], ["upload", "Upload .zip", "upload"], ["image", "Container", "box"], ["hosts", "TLS hosts", "globe"]];
  const formTabs = () => FORM_TABS.filter(([k]) => !state.sources || state.sources.includes(k));
  const COVERAGE = ["Source code (7 languages)", "Dependencies", "Binaries & JARs", "Certificates & keys", "TLS / SSH configs", "Container images", "Live TLS endpoints", "CBOM · SARIF · CSV"];

  function renderHome(message) {
    state.scan = null;
    renderNav();
    const recent = state.scans.slice(0, 6);
    app.innerHTML = `
      <div class="fade-in">
        <header class="home-head">
          <div class="home-brand"><img src="logo.png" alt="Q-Scan logo" width="56" height="56"><span class="eyebrow">Cryptographic discovery</span></div>
          <h1>Find every cryptographic lock before a quantum computer can.</h1>
          <p class="lead">Q-Scan builds a CycloneDX CBOM of your crypto, scores each asset's quantum risk with a probabilistic Mosca model, and recommends the NIST post-quantum replacement.</p>
        </header>
        <div class="grid g-main">
          <section class="card" id="scanForm" aria-labelledby="nsTitle">
            ${cardHead('<span id="nsTitle">Start a new scan</span>', "Choose a source")}
            <div class="seg" role="tablist" aria-label="Scan source">
              ${formTabs().map(([k, l, ic]) => `<button role="tab" data-ftab="${k}" aria-selected="${formTab === k}">${icon(ic)}<span>${l}</span></button>`).join("")}
            </div>
            <div class="form-body" id="formBody" role="tabpanel">${formBody()}</div>
            ${state.public ? `<p class="help">Public demo: only the bundled demo repo or an uploaded .zip can be scanned here. Uploaded scans are not listed for other visitors. Run Q-Scan locally to scan folders, container images or live TLS hosts fully offline.</p>` : ""}
            <div class="form-foot">
              <div class="field"><label for="crqc">Expected quantum computer (median year)</label>
                <input id="crqc" type="number" min="2027" max="2060" step="1" value="2034" inputmode="numeric"></div>
              <button id="startScan" class="btn primary">${icon("play", "sm")}Start scan</button>
            </div>
            <div id="jobStatus" class="job" aria-live="polite">${message ? errorBox(message) : ""}</div>
          </section>
          <div class="stack">
            ${recent.length ? `<section class="card">${cardHead("Recent scans", `${state.scans.length} total`)}
              <ul class="recent">${recent.map((s) => `
                <li><button data-open="${esc(s.id)}"><span class="nm">${esc(s.name)}</span><span class="dt">${s.assets} assets · ${esc(fmtDate(s.created))}</span><span class="q">QRI ${s.qri}</span></button></li>`).join("")}</ul></section>` : ""}
            <section class="card">${cardHead("What gets scanned")}
              <ul class="coverage">${COVERAGE.map((s) => `<li>${icon("check", "sm")}${esc(s)}</li>`).join("")}</ul></section>
          </div>
        </div>
      </div>`;
    app.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => openScan(b.dataset.open)));
    app.querySelectorAll("[data-ftab]").forEach((b) => b.addEventListener("click", () => {
      formTab = b.dataset.ftab;
      app.querySelectorAll("[data-ftab]").forEach((x) => x.setAttribute("aria-selected", x === b));
      $("#formBody").innerHTML = formBody();
    }));
    $("#startScan").addEventListener("click", startScan);
  }

  function formBody() {
    switch (formTab) {
      case "demo": return `<p>Scans the bundled <b>Bharat FinServe</b> demo monorepo (fictional): a Java payments service, Python KYC service, Node notifications, Go reports, a C card gateway, nginx, sshd, OpenSSL config, a Dockerfile, certificates and keys.</p>`;
      case "path": return `<div class="field"><label for="fPath">Folder or file on this machine</label><input id="fPath" placeholder="D:\\code\\my-repo" autocomplete="off"></div>`;
      case "upload": return `<div class="field"><label for="fZip">Repository as a .zip</label><input id="fZip" type="file" accept=".zip"></div>`;
      case "image": return `<div class="field"><label for="fImage">Local container image</label><input id="fImage" placeholder="nginx:1.25"><span class="help">Needs Docker. The image must already be pulled.</span></div>`;
      case "hosts": return `<div class="field"><label for="fHosts">Hosts (host:port, one per line)</label><textarea id="fHosts" rows="4" placeholder="127.0.0.1:8443"></textarea><span class="help">Probes TLS 1.0–1.3 support, the negotiated cipher and the certificate. Only scan systems you are authorised to test.</span></div>`;
    }
    return "";
  }

  async function startScan() {
    const btn = $("#startScan");
    const status = $("#jobStatus");
    const crqc = parseFloat($("#crqc").value) || 2034;
    btn.disabled = true;
    try {
      let job;
      if (formTab === "demo") job = await api("/api/scans/demo", { method: "POST" });
      else if (formTab === "upload") {
        const f = $("#fZip").files[0];
        if (!f) throw new Error("Choose a .zip file first.");
        const fd = new FormData(); fd.append("file", f);
        job = await api("/api/scans/upload", { method: "POST", body: fd });
      } else {
        const body = { crqc_year: crqc };
        if (formTab === "path") body.path = $("#fPath").value.trim();
        if (formTab === "image") body.image = $("#fImage").value.trim();
        if (formTab === "hosts") body.hosts = $("#fHosts").value.split(/\s+/).filter(Boolean);
        job = await api("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      }
      await poll(job.job_id, status);
    } catch (e) {
      status.innerHTML = errorBox(e.message);
      btn.disabled = false;
    }
  }

  async function poll(jobId, status) {
    for (;;) {
      const j = await api(`/api/jobs/${jobId}`);
      status.innerHTML = `<div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(j.progress * 100)}"><span style="width:${Math.round(j.progress * 100)}%"></span></div><p class="muted small">${esc(j.message)}</p>`;
      if (j.status === "done") { await refreshScans(j.scan_id); state.tab = "overview"; await openScan(j.scan_id); return; }
      if (j.status === "error") throw new Error(j.error || "Scan failed");
      await new Promise((r) => setTimeout(r, 400));
    }
  }

  // ---------- scan view ----------
  function render() {
    if (!state.scan) return renderHome();
    renderNav();
    const r = state.scan, st = r.stats;
    const [, title, , desc] = TABS.find((t) => t[0] === state.tab);
    const targets = r.targets.map((t) => `${t.type}: ${t.value}`).join(" · ");
    app.innerHTML = `
      <header class="pagehead">
        <div>
          <div class="crumb"><span>Scans</span>${icon("chevron", "sm")}<b>${esc(r.name)}</b></div>
          <h1>${title}</h1>
          <p class="desc">${desc}</p>
        </div>
        <div class="head-actions">
          <a class="btn soft" href="/api/scans/${esc(r.id)}/export/cbom" download>${icon("download", "sm")}CBOM</a>
        </div>
      </header>
      <div class="metabar">
        <span class="meta-chip">${icon("calendar")}${esc(fmtDate(r.created))}</span>
        <span class="meta-chip">${icon("file")}${st.files_scanned} files</span>
        <span class="meta-chip">${icon("code")}${st.source_files} source · ${st.loc.toLocaleString()} LOC</span>
        <span class="meta-chip">${icon("clock")}${st.duration_s}s</span>
        <span class="meta-chip" title="${esc(targets)}">${icon("target")}<span class="trunc">${esc(targets)}</span></span>
      </div>
      <div id="view" class="fade-in"></div>
      ${r.errors && r.errors.length ? `<p class="notes">Notes: ${r.errors.map(esc).join(" · ")}</p>` : ""}`;
    ({ overview: renderOverview, inventory: renderInventory, roadmap: renderRoadmap, lab: renderLab, export: renderExport })[state.tab]();
  }

  function gauge(v) {
    const r = 46, c = Math.PI * r, pct = Math.max(0, Math.min(100, v)) / 100;
    const color = v >= 70 ? "var(--low-fill)" : v >= 40 ? "var(--med-fill)" : "var(--crit-fill)";
    return `<svg width="128" height="78" viewBox="0 0 120 72" role="img" aria-label="Quantum Readiness Index ${v} out of 100">
      <path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="var(--sky-100)" stroke-width="10" stroke-linecap="round"/>
      <path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${c * pct} ${c}"/>
      <text x="60" y="58" text-anchor="middle" font-size="26" font-weight="750" fill="var(--ink)" font-family="inherit">${v}</text>
      <text x="60" y="71" text-anchor="middle" font-size="9" fill="var(--muted)" font-family="inherit">of 100</text></svg>`;
  }
  const verdict = (v) => (v >= 70 ? "Largely quantum-ready" : v >= 40 ? "Partially exposed" : "High quantum exposure");

  function renderOverview() {
    const s = summary(), r = state.scan;
    const year = state.sim ? state.sim.risk_config.crqc_median_year : r.risk_config.crqc_median_year;
    const kinds = Object.entries(s.by_kind).sort((a, b) => b[1] - a[1]);
    const surf = Object.entries(s.by_surface).sort((a, b) => b[1] - a[1]);
    const status = Object.entries(s.by_status).sort((a, b) => b[1] - a[1]);
    const maxK = Math.max(1, ...kinds.map((k) => k[1])), maxS = Math.max(1, ...surf.map((k) => k[1]));
    const heatMax = Math.max(1, ...s.heatmap.flat());
    const heatPct = (n) => 18 + Math.round(72 * n / heatMax);
    const heatStyle = (col, n) => {
      if (!n) return "background:var(--surface-2)";
      const p = heatPct(n);
      return `background:color-mix(in srgb, ${HEAT_BASE[col]} ${p}%, #fff);color:${p > 60 ? "#fff" : "var(--ink)"}`;
    };
    const barList = (entries, max, label, fill, cls = "") => `<div class="bars ${cls}">${entries.map(([k, n]) => `
      <div class="bar"><span>${label(k)}</span><div class="track"><div class="fill" style="width:${100 * n / max}%;background:${fill(k)}"></div></div><span class="n">${n}</span></div>`).join("")}</div>`;

    $("#view").innerHTML = `
      <div class="hero-row">
        <section class="card qri-card" aria-label="Quantum Readiness Index">
          <div class="qri-top">${gauge(s.qri)}
            <div><div class="label">Quantum Readiness Index</div><div class="verdict">${verdict(s.qri)}</div>
              <div class="sub">100 = fully quantum-safe. Weighted by app criticality.</div></div></div>
          <div class="whatif">
            <label for="crqcSlider">Scenario: quantum computer arrives in</label>
            <span class="year" id="crqcYear">${Math.round(year)}</span>
            <input id="crqcSlider" type="range" min="2028" max="2045" step="1" value="${year}">
            <div class="scale" aria-hidden="true"><span>2028 · sooner</span><span>2045 · later</span></div>
            <span class="hint">Median year for a cryptographically relevant quantum computer (CRQC). Risk uses P(X + Y &gt; Z), with Z sampled from a lognormal distribution.</span>
          </div>
        </section>
        <div class="stats">
          ${BANDS.map((b) => `<div class="stat"><div class="label"><span class="swatch" style="background:${BAND_FILL[b]}"></span>${cap(b)} risk</div><div class="value">${s.bands[b]}</div><div class="sub">assets</div></div>`).join("")}
          <div class="stat"><div class="label">${icon("clock", "sm")}Harvest now, decrypt later</div><div class="value">${s.hndl}</div><div class="sub">confidential data exposed</div></div>
          <div class="stat"><div class="label">${icon("alert", "sm")}Broken today</div><div class="value">${s.classical}</div><div class="sub">classically weak or broken</div></div>
        </div>
      </div>

      <div class="grid g-main">
        <section class="card">${cardHead("Top risks", "Click an asset for details")}
          <div class="toplist">${s.top.map((t) => `
            <button data-asset="${esc(t.id)}"><span class="score" style="color:${BAND_COLOR[t.band]};background:${BAND_SOFT[t.band]}">${t.qrs}</span><span class="nm">${esc(t.name)}</span>${bandPill(t.band)}${icon("chevron", "sm")}</button>`).join("")}</div>
        </section>
        <section class="card">${cardHead("Risk heatmap", "Criticality × time margin")}
          <div class="heat" role="table" aria-label="Assets by criticality and time margin">
            <div></div>${HEAT_COLS.map((h) => `<div class="h" role="columnheader">${h}</div>`).join("")}
            ${s.heatmap.map((row, i) => `<div class="r" role="rowheader">Crit. ${5 - i}</div>${row.map((n, j) => `<div class="cell" role="cell" style="${heatStyle(j, n)}" title="${n} assets · ${HEAT_COLS[j]}">${n || ""}</div>`).join("")}`).join("")}
          </div>
          <p class="muted small" style="margin-top:12px">Margin = CRQC median − (data shelf life + migration time).</p>
        </section>
      </div>

      <div class="grid g-3 mt">
        <section class="card">${cardHead("Assets by type")}${barList(kinds, maxK, (k) => esc(KIND_LABEL[k] || k), () => "var(--sky-500)")}</section>
        <section class="card">${cardHead("Where we found them")}${barList(surf, maxS, (k) => esc(SURFACE_LABEL[k] || k), () => "var(--sky-300)")}</section>
        <section class="card">${cardHead("Status mix")}${barList(status, Math.max(1, r.assets.length), (k) => statusPill(k), (k) => STATUS_FILL[k] || "var(--line-2)", "wide")}</section>
      </div>

      <section class="card mt">${cardHead("Applications", `${r.apps.length} in scope`)}
        <div class="tablewrap"><table><thead><tr><th>Application</th><th class="num">Criticality</th><th>Data class</th><th>Exposure</th><th>Worst band</th></tr></thead><tbody>
          ${r.apps.map((ap) => `<tr><td><b>${esc(ap.name)}</b></td><td class="num">${ap.criticality}</td><td>${esc(ap.data_class)}</td><td>${esc(ap.exposure)}</td><td>${bandPill(worstFor(ap.name)) || '<span class="muted">—</span>'}</td></tr>`).join("")}
        </tbody></table></div>
      </section>`;
    wireAssetButtons();
    const slider = $("#crqcSlider");
    let t;
    slider.addEventListener("input", () => {
      $("#crqcYear").textContent = slider.value;
      clearTimeout(t);
      t = setTimeout(() => simulate(parseFloat(slider.value)), 220);
    });
  }

  function worstFor(appName) {
    let best = null;
    for (const a of state.scan.assets) {
      const rk = riskOf(a);
      if (!rk || !rk.per_app) continue;
      const p = rk.per_app.find((x) => x.app === appName);
      if (p && (!best || BANDS.indexOf(p.band) < BANDS.indexOf(best))) best = p.band;
    }
    return best;
  }

  async function simulate(year) {
    const orig = state.scan.risk_config.crqc_median_year;
    if (Math.round(year) === Math.round(orig)) { state.sim = null; }
    else state.sim = await api(`/api/scans/${state.scan.id}/simulate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ crqc_year: year }) });
    const active = document.activeElement && document.activeElement.id;
    renderOverview();
    if (active === "crqcSlider") $("#crqcSlider").focus();
  }

  function wireAssetButtons() {
    app.querySelectorAll("[data-asset]").forEach((el) => {
      el.addEventListener("click", () => openAsset(el.dataset.asset));
      if (el.tagName === "TR") el.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openAsset(el.dataset.asset); } });
    });
  }

  // ---------- inventory ----------
  function renderInventory() {
    const f = state.filter;
    const surfaces = [...new Set(state.scan.occurrences.map((o) => o.surface))];
    $("#view").innerHTML = `
      <section class="card">
        <div class="toolbar" style="margin-bottom:16px">
          <div class="search">${icon("search")}<label class="sr" for="q">Search</label><input id="q" type="text" placeholder="Search assets, files, apps…" value="${esc(f.q)}" autocomplete="off"></div>
          <label class="sr" for="fb">Band</label><select id="fb"><option value="">All bands</option>${BANDS.map((b) => `<option value="${b}" ${f.band === b ? "selected" : ""}>${b[0].toUpperCase() + b.slice(1)}</option>`).join("")}</select>
          <label class="sr" for="fk">Type</label><select id="fk"><option value="">All types</option>${Object.keys(KIND_LABEL).map((k) => `<option value="${k}" ${f.kind === k ? "selected" : ""}>${KIND_LABEL[k]}</option>`).join("")}</select>
          <label class="sr" for="fs">Surface</label><select id="fs"><option value="">All surfaces</option>${surfaces.map((k) => `<option value="${k}" ${f.surface === k ? "selected" : ""}>${esc(SURFACE_LABEL[k] || k)}</option>`).join("")}</select>
          <span class="count" id="count" aria-live="polite"></span>
        </div>
        <div class="tablewrap"><table><thead><tr><th>Risk</th><th>Asset</th><th>Type</th><th>Status</th><th>Apps</th><th>Found in</th><th class="num">Seen</th><th>Recommended</th></tr></thead><tbody id="rows"></tbody></table></div>
      </section>`;
    const draw = () => {
      const occ = new Map(state.scan.occurrences.map((o) => [o.id, o]));
      const q = f.q.toLowerCase();
      const rows = state.scan.assets.filter((a) => {
        const rk = riskOf(a);
        if (f.band && (!rk || rk.band !== f.band)) return false;
        if (f.kind && a.kind !== f.kind) return false;
        if (f.surface && !a.surfaces.includes(f.surface)) return false;
        if (q) {
          const hay = [a.name, a.status, a.apps.join(" "), ...a.occurrences.map((id) => occ.get(id).path)].join(" ").toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      }).sort((x, y) => ((riskOf(y) || {}).qrs || 0) - ((riskOf(x) || {}).qrs || 0) || x.name.localeCompare(y.name));
      $("#count").textContent = `${rows.length} of ${state.scan.assets.length} assets`;
      $("#rows").innerHTML = rows.map((a) => {
        const rk = riskOf(a) || { qrs: 0, band: "low" };
        const rec = a.recommendations[0];
        return `<tr class="row" tabindex="0" data-asset="${esc(a.id)}">
          <td><span class="qrs"><b>${rk.qrs}</b><span class="mini"><span style="width:${rk.qrs}%;background:${BAND_FILL[rk.band]}"></span></span>${bandPill(rk.band)}</span></td>
          <td class="name">${esc(a.name)}</td><td>${esc(KIND_LABEL[a.kind] || a.kind)}</td><td>${statusPill(a.status)}</td>
          <td>${esc(a.apps.join(", "))}</td><td class="muted">${esc(a.surfaces.map((s) => SURFACE_LABEL[s] || s).join(", "))}</td>
          <td class="num">${a.occurrences.length}</td><td>${rec ? `<span class="target">${esc(rec.target)}</span>` : '<span class="muted">No action</span>'}</td></tr>`;
      }).join("") || `<tr><td colspan="8" class="empty">No assets match these filters.</td></tr>`;
      wireAssetButtons();
    };
    $("#q").addEventListener("input", (e) => { f.q = e.target.value; draw(); });
    $("#fb").addEventListener("change", (e) => { f.band = e.target.value; draw(); });
    $("#fk").addEventListener("change", (e) => { f.kind = e.target.value; draw(); });
    $("#fs").addEventListener("change", (e) => { f.surface = e.target.value; draw(); });
    draw();
  }

  // ---------- asset drawer ----------
  let lastFocus = null;
  function mosca(rk, year) {
    const today = state.scan.risk_config.today;
    const median = Math.max(0.5, year - today), sigma = (state.sim ? state.sim.risk_config.sigma : state.scan.risk_config.sigma) || 0.45;
    const lo = median * Math.exp(-1.2816 * sigma), hi = median * Math.exp(1.2816 * sigma);
    const maxY = Math.max(30, rk.x_years + rk.y_years + 2, hi + 2);
    const W = 560, x = (v) => 20 + (W - 40) * v / maxY;
    const ticks = [0, 5, 10, 15, 20, 25, 30, 35, 40].filter((t) => t <= maxY);
    return `<svg viewBox="0 0 ${W} 96" width="100%" role="img" aria-label="Mosca timeline: data shelf life ${rk.x_years} years plus migration ${rk.y_years} years against a quantum computer expected in ${median.toFixed(0)} years">
      <rect x="${x(lo)}" y="8" width="${x(hi) - x(lo)}" height="54" rx="4" fill="var(--crit-soft)"/>
      <line x1="${x(median)}" x2="${x(median)}" y1="4" y2="66" stroke="var(--crit)" stroke-width="1.5" stroke-dasharray="4 3"/>
      <rect x="${x(0)}" y="24" width="${x(rk.x_years) - x(0)}" height="12" rx="6" fill="var(--primary)"/>
      <rect x="${x(rk.x_years)}" y="24" width="${Math.max(2, x(rk.x_years + rk.y_years) - x(rk.x_years))}" height="12" rx="6" fill="var(--sky-300)"/>
      <line x1="20" x2="${W - 20}" y1="66" y2="66" stroke="var(--line-2)"/>
      ${ticks.map((t) => `<line x1="${x(t)}" x2="${x(t)}" y1="66" y2="70" stroke="var(--muted)"/><text x="${x(t)}" y="84" font-size="11" text-anchor="middle" fill="var(--muted)">${t}y</text>`).join("")}
      <text x="${x(median) + 5}" y="18" font-size="11" fill="var(--crit)">CRQC median ${Math.round(year)}</text>
    </svg>
    <div class="meta" style="margin-top:6px"><span><b style="color:var(--primary)">■</b> X · data shelf life ${rk.x_years} y</span><span><b style="color:var(--sky-400)">■</b> Y · migration ${rk.y_years} y</span><span>Shaded: 80% of CRQC arrival scenarios</span><span>P(exposure) ${(rk.p_exposure * 100).toFixed(0)}%</span></div>`;
  }

  function openAsset(id) {
    const a = state.scan.assets.find((x) => x.id === id);
    if (!a) return;
    if ($("#drawer").hidden) lastFocus = document.activeElement;
    const rk = riskOf(a);
    const occ = new Map(state.scan.occurrences.map((o) => [o.id, o]));
    const year = state.sim ? state.sim.risk_config.crqc_median_year : state.scan.risk_config.crqc_median_year;
    const byId = new Map(state.scan.assets.map((x) => [x.id, x]));
    const parents = state.scan.assets.filter((x) => x.links.includes(a.id));
    const ex = a.extra || {};
    const details = [];
    if (a.classical_bits) details.push(`Classical security ${a.classical_bits} bits`);
    if (a.nist_level !== null && a.nist_level !== undefined) details.push(`NIST quantum level ${a.nist_level}`);
    if (a.oid) details.push(`OID ${a.oid}`);
    if (ex.not_after) details.push(`Valid until ${ex.not_after.slice(0, 10)}${ex.expired ? " (expired)" : ""}`);
    if (ex.is_ca) details.push("CA certificate");
    if (ex.pqc) details.push(`PQC support: ${ex.pqc}`);
    $("#drawerBody").innerHTML = `
      <div><div class="dtitle">${esc(a.name)}</div>
        <div class="dpills">${rk ? bandPill(rk.band) : ""}${statusPill(a.status)}${pill("s-unknown plain", KIND_LABEL[a.kind] || a.kind)}${rk && rk.hndl ? pill("b-high", "Harvest-now-decrypt-later") : ""}</div>
        ${details.length ? `<div class="meta" style="margin-top:10px">${details.map((d) => `<span>${esc(d)}</span>`).join("")}</div>` : ""}
        ${a.note ? `<p style="margin-top:10px;color:var(--ink-2)">${esc(a.note)}</p>` : ""}</div>
      ${rk ? `<div><div class="section-title">Quantum Risk Score</div>
        <div class="score-row"><span class="big" style="color:${BAND_COLOR[rk.band]}">${rk.qrs}</span><span class="muted">/ 100 · scored for <b style="color:var(--ink)">${esc(rk.app)}</b></span></div>
        <div class="factors">${[["Q", rk.factors.Q, "quantum"], ["H", rk.factors.H, "HNDL"], ["P", rk.factors.P, "P(exp.)"], ["C", rk.factors.C, "criticality"], ["S", rk.factors.S, "sensitivity"], ["E", rk.factors.E, "exposure"]]
          .map(([k, v, l]) => `<div class="factor"><b>${v}</b><span>${k} · ${l}</span></div>`).join("")}</div>
        <p class="muted small" style="margin-top:8px">QRS = 100 × Q × H × P × (0.40·C/5 + 0.35·S + 0.25·E)${rk.classical ? "; floor applied because it is classically weak or broken today" : ""}.</p></div>
        ${rk.factors.Q ? `<div><div class="section-title">Mosca timeline</div>${mosca(rk, year)}</div>` : ""}` : ""}
      ${a.recommendations.length ? `<div><div class="section-title">Recommended fix</div>${a.recommendations.map((r) => `
        <div class="reco"><span class="t">${icon("wrench", "sm")}${esc(r.target)}</span><span>${esc(r.why)}</span><span class="c">${esc(r.change)}</span><span class="meta">${esc(r.standard)}</span></div>`).join("")}</div>` : ""}
      ${a.links.length ? `<div><div class="section-title">Made of</div><div class="chips">${a.links.map((l) => byId.get(l)).filter(Boolean).map((c) => `<button class="chip" data-asset="${esc(c.id)}">${esc(c.name)}</button>`).join("")}</div></div>` : ""}
      ${parents.length ? `<div><div class="section-title">Used by</div><div class="chips">${parents.slice(0, 20).map((c) => `<button class="chip" data-asset="${esc(c.id)}">${esc(c.name)}</button>`).join("")}</div></div>` : ""}
      <div><div class="section-title">Evidence (${a.occurrences.length})</div>${a.occurrences.slice(0, 60).map((oid) => { const o = occ.get(oid); return `
        <div class="occ"><span class="loc">${esc(o.path)}${o.line ? ":" + o.line : ""}</span>
          <span class="meta"><span>${esc(o.app)}</span><span>${esc(SURFACE_LABEL[o.surface] || o.surface)}</span><span>${esc(o.usage)}</span><span>${esc(o.agility)}</span><span>confidence ${Math.round(o.confidence * 100)}%</span><span>${esc(o.rule_id)}</span></span>
          ${o.snippet ? `<pre>${esc(o.snippet)}</pre>` : ""}</div>`; }).join("")}</div>`;
    $("#drawer").hidden = false; $("#scrim").hidden = false;
    $("#drawer").scrollTop = 0;
    $("#drawerBody").querySelectorAll("[data-asset]").forEach((el) => el.addEventListener("click", () => openAsset(el.dataset.asset)));
    $("#drawerClose").focus();
  }
  function closeDrawer() {
    if ($("#drawer").hidden) return;
    $("#drawer").hidden = true; $("#scrim").hidden = true;
    if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
  }

  // ---------- roadmap ----------
  function renderRoadmap() {
    const assets = state.scan.assets.filter((a) => riskOf(a));
    const qriAfter = (fixedBands) => {
      let num = 0, den = 0;
      for (const a of assets) { const rk = riskOf(a); const q = fixedBands.includes(rk.band) ? 0 : rk.qrs; num += q * rk.factors.C; den += rk.factors.C; }
      return den ? Math.round(100 - num / den) : 100;
    };
    const steps = [["Today", summary().qri], ["After wave 1", qriAfter(["critical"])], ["After wave 2", qriAfter(["critical", "high"])], ["After wave 3", qriAfter(["critical", "high", "medium"])]];
    const waves = [["critical", "Wave 1", "Now", "Broken today or data already exposed"], ["high", "Wave 2", "Next 12 months", "Start with hybrid mode"], ["medium", "Wave 3", "Next tech refresh", "Plan and budget"]];
    $("#view").innerHTML = `
      <div class="grid g-main">
        <section class="card">${cardHead("Readiness after each wave", "Quantum Readiness Index")}
          <div class="projection">${steps.map(([l, v], i) => `<div class="col"><span class="v">${v}</span><div class="colbar ${i ? "after" : ""}" style="height:${Math.max(4, v)}%"></div><span class="l">${l}</span></div>`).join("")}</div></section>
        <section class="card">${cardHead("How waves are built")}
          <div class="explain">
            <div class="item"><span class="ic">${icon("layers")}</span><div><b>Ordered by risk</b><p>Wave 1 holds everything critical: classically broken crypto and quantum-vulnerable crypto protecting long-lived, sensitive data.</p></div></div>
            <div class="item"><span class="ic">${icon("clock")}</span><div><b>Migration effort (Y)</b><p>Comes from where the crypto lives (config 0.25 y, library 0.5 y, source 1 y, PKI 2 y), how hard-coded it is, and how many places use it.</p></div></div>
            <div class="item"><span class="ic">${icon("wrench")}</span><div><b>One fix per asset</b><p>Each asset shows its first recommended fix. Open it for the exact change.</p></div></div>
          </div></section>
      </div>
      <div class="waves">${waves.map(([band, step, when, sub]) => {
        const items = assets.filter((a) => riskOf(a).band === band).sort((x, y) => riskOf(y).qrs - riskOf(x).qrs);
        return `<section class="card wave"><div class="wave-head" style="border-top-color:${BAND_FILL[band]}">
            <div class="top"><span class="step">${step}</span>${bandPill(band)}</div>
            <h2>${when}</h2><p>${sub} · ${items.length} assets</p></div>
          ${items.length ? `<ul>${items.map((a) => `
            <li><button data-asset="${esc(a.id)}"><b style="color:${BAND_COLOR[band]}">${riskOf(a).qrs}</b><span><span class="nm">${esc(a.name)}</span><span class="muted small">${esc(a.recommendations[0] ? a.recommendations[0].target : "Review")} · ${esc(a.apps.join(", "))}</span></span></button></li>`).join("")}</ul>` : `<p class="none">Nothing in this wave.</p>`}
        </section>`;
      }).join("")}</div>`;
    wireAssetButtons();
  }

  // ---------- PQC lab ----------
  function renderLab() {
    const b = state.bench;
    const rows = b ? [...b.classical, ...b.pqc] : [];
    $("#view").innerHTML = `
      <div class="grid g-2">
        <section class="card">
          <div class="card-head"><h2>Benchmark on this machine</h2><button id="runBench" class="btn primary">${icon("zap", "sm")}${b ? "Run again" : "Run benchmark"}</button></div>
          <p class="muted">Measures real timings here instead of quoting papers. Classical algorithms use pyca/cryptography; PQC timings need <code>liboqs-python</code>.</p>
          ${b ? `<p class="muted small" style="margin:12px 0 16px">${esc(b.machine)} · median of ${b.iterations} runs${b.note ? " · " + esc(b.note) : ""}</p>
          <div class="tablewrap"><table><thead><tr><th>Algorithm</th><th>Operation</th><th class="num">Median</th><th class="num">Public key</th><th class="num">CT / sig</th></tr></thead><tbody>
          ${rows.map((x) => `<tr><td><b>${esc(x.algorithm)}</b></td><td>${esc(x.operation)}</td><td class="num">${x.median_ms.toFixed(3)} ms</td><td class="num">${x.public_key ?? ""} B</td><td class="num">${x.ciphertext ?? x.signature ?? ""} B</td></tr>`).join("")}
          </tbody></table></div>` : `<div class="empty">${icon("zap", "lg")}<p style="margin-top:8px">No results yet. Run the benchmark to measure this machine.</p></div>`}
        </section>
        <section class="card">${cardHead("Size cost of post-quantum", "FIPS 203 · 204 · 205")}
          <div class="tablewrap"><table><thead><tr><th>Algorithm</th><th class="num">Public key</th><th class="num">CT / signature</th><th class="num">Level</th></tr></thead><tbody>
          ${Object.entries(sizes()).map(([k, v]) => `<tr><td><b>${esc(k)}</b></td><td class="num">${v.public_key.toLocaleString()} B</td><td class="num">${(v.ciphertext ?? v.signature).toLocaleString()} B</td><td class="num">${v.level ?? "–"}</td></tr>`).join("")}
          </tbody></table></div>
          <div class="callout"><span class="ic">${icon("globe")}</span><div><b>Hybrid TLS handshake overhead</b><br>
            ML-KEM-768 adds 1,184 + 1,088 = <b>2,272 bytes</b> per handshake. At 10 Mbps that is 2,272 × 8 ÷ 10,000,000 s ≈ <b>1.8 ms</b> of transfer time.</div></div>
        </section>
      </div>`;
    $("#runBench").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true; btn.textContent = "Running…";
      try { state.bench = await api("/api/bench?iterations=40"); renderLab(); } catch (err) { renderLab(); alertInline(err.message); }
    });
  }
  const sizes = () => ({
    "ML-KEM-512": { public_key: 800, ciphertext: 768, level: 1 }, "ML-KEM-768": { public_key: 1184, ciphertext: 1088, level: 3 },
    "ML-KEM-1024": { public_key: 1568, ciphertext: 1568, level: 5 }, "ML-DSA-44": { public_key: 1312, signature: 2420, level: 2 },
    "ML-DSA-65": { public_key: 1952, signature: 3309, level: 3 }, "ML-DSA-87": { public_key: 2592, signature: 4627, level: 5 },
    "SLH-DSA-SHA2-128s": { public_key: 32, signature: 7856, level: 1 }, "X25519 (classical)": { public_key: 32, ciphertext: 32 },
  });
  function alertInline(msg) { $("#view").insertAdjacentHTML("afterbegin", errorBox(msg)); }

  // ---------- export ----------
  function renderExport() {
    const id = state.scan.id;
    const others = state.scans.filter((s) => s.id !== id);
    const d = state.diff;
    const dl = (path, ic, name, desc) => `<a class="dl" href="/api/scans/${esc(id)}/export/${path}" download><span class="ic">${icon(ic)}</span><span><b>${name}</b><small>${desc}</small></span>${icon("download", "sm")}</a>`;
    const delta = d ? d.qri_after - d.qri_before : 0;
    $("#view").innerHTML = `
      <div class="grid g-2">
        <div class="stack">
          <section class="card">${cardHead("Download")}
            <div class="downloads">
              ${dl("cbom", "layers", "CBOM", "CycloneDX 1.6 · every algorithm, protocol, cert, key and library with evidence")}
              ${dl("sarif", "shield", "SARIF 2.1.0", "Findings for GitHub code scanning and IDEs")}
              ${dl("csv", "table", "Inventory CSV", "Flat asset list for spreadsheets")}
              ${dl("json", "code", "Full result JSON", "Raw scan output including risk properties")}
            </div>
          </section>
          <section class="card">${cardHead("Compare with an earlier scan")}
            ${others.length ? `<div class="toolbar"><label class="sr" for="cmp">Earlier scan</label><select id="cmp" style="flex:1;min-width:0">${others.map((s) => `<option value="${esc(s.id)}">${esc(s.name)} · QRI ${s.qri} · ${esc(fmtDate(s.created))}</option>`).join("")}</select><button id="cmpBtn" class="btn">${icon("compare", "sm")}Compare</button></div>` : `<p class="muted">Run another scan to compare.</p>`}
            ${d ? `<div class="diff">
                <div class="stat"><div class="label">QRI change</div><div class="value">${d.qri_before} → ${d.qri_after}</div><div class="sub ${delta >= 0 ? "up" : "down"}">${delta >= 0 ? "+" : ""}${delta} points</div></div>
                <div class="stat"><div class="label">Risky assets fixed</div><div class="value">${d.fixed_risky.length}</div><div class="sub">new assets: ${d.added.length}</div></div>
              </div>
              <p class="muted small" style="margin-top:12px"><b>Fixed:</b> ${d.fixed_risky.length ? d.fixed_risky.map(esc).join(", ") : "none"}</p>
              <p class="muted small" style="margin-top:4px"><b>Added:</b> ${d.added.length ? d.added.map(esc).join(", ") : "none"}</p>` : ""}
          </section>
        </div>
        <section class="card">${cardHead("CI crypto gate", "Block new risky crypto in PRs")}
          <p class="muted">Fail a pull request when it adds new quantum-vulnerable or classically broken crypto. Findings already in the baseline are ignored.</p>
          <div class="codeblock"><span class="c"># once, on main</span>
qscan scan . --out baseline

<span class="c"># on every pull request</span>
qscan gate . --baseline baseline/qscan-result.json \\
  --fail-on critical,classical --sarif q.sarif</div>
          <ol class="steps">
            <li><span>Commit a baseline scan from your main branch.</span></li>
            <li><span>Run the gate in CI on each pull request.</span></li>
            <li><span>Upload <code>q.sarif</code> with <code>github/codeql-action/upload-sarif</code> so findings appear on the PR.</span></li>
          </ol>
        </section>
      </div>`;
    const btn = $("#cmpBtn");
    if (btn) btn.addEventListener("click", async () => {
      btn.disabled = true;
      try { state.diff = await api(`/api/scans/${$("#cmp").value}/diff/${id}`); renderExport(); }
      catch (err) { btn.disabled = false; alertInline(err.message); }
    });
  }

  // ---------- boot ----------
  $("#newScanBtn").addEventListener("click", () => { closeDrawer(); renderHome(); $("#scanPicker").value = ""; });
  $("#scanPicker").addEventListener("change", (e) => { if (e.target.value) openScan(e.target.value); else renderHome(); });
  $("#drawerClose").addEventListener("click", closeDrawer);
  $("#scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  (async () => {
    try {
      try {
        const h = await api("/api/health");
        state.public = !!h.public; state.sources = h.sources || null;
        if (state.sources && !state.sources.includes(formTab)) formTab = state.sources[0];
      } catch (_) {}
      await refreshScans();
      let last = null;
      try { last = localStorage.getItem("qd:last"); } catch (_) {}
      if (last && state.scans.some((s) => s.id === last)) await openScan(last);
      else if (last && state.public) { try { await openScan(last); } catch (_) { state.scans.length ? await openScan(state.scans[0].id) : renderHome(); } }
      else if (state.scans.length) await openScan(state.scans[0].id);
      else renderHome();
    } catch (e) { renderHome(e.message); }
  })();
})();
