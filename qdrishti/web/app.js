/* Q-Drishti dashboard. Vanilla JS, no external libraries, works offline. */
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const app = $("#app");
  const BANDS = ["critical", "high", "medium", "low"];
  const BAND_COLOR = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)" };
  const HEAT_COLS = ["Exposed now", "< 3 yrs margin", "3–6 yrs", "> 6 yrs", "Not quantum-exposed"];
  const KIND_LABEL = { algorithm: "Algorithm", protocol: "Protocol", suite: "Cipher suite", certificate: "Certificate", key: "Key", library: "Library" };
  const SURFACE_LABEL = { source: "Source code", config: "Config", certificate: "Certificates", key: "Keys", dependency: "Dependencies", binary: "Binaries", endpoint: "Live TLS", container: "Containers" };

  const state = { scans: [], scan: null, sim: null, tab: "overview", filter: { q: "", band: "", kind: "", surface: "" }, bench: null, diff: null };

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
  const bandPill = (b) => (b ? pill("b-" + b, b) : "");
  const statusPill = (s) => pill("s-" + s, s.replace("-", " "));
  const fmtDate = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

  // ---------- scans list ----------
  async function refreshScans(selectId) {
    state.scans = await api("/api/scans");
    const picker = $("#scanPicker");
    picker.innerHTML = `<option value="">${state.scans.length ? "Open a scan…" : "No scans yet"}</option>` +
      state.scans.map((s) => `<option value="${esc(s.id)}">${esc(s.name)} · QRI ${s.qri} · ${esc(fmtDate(s.created))}</option>`).join("");
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
  function renderHome(message) {
    state.scan = null;
    const recent = state.scans.slice(0, 6);
    app.innerHTML = `
      <section class="hero">
        <div class="panel">
          <h1>Find every cryptographic lock before a quantum computer can.</h1>
          <p class="lead">Q-Drishti scans source code, dependencies, binaries, certificates, configs, container images and live TLS endpoints. It builds a CycloneDX CBOM, scores each asset's quantum risk with a probabilistic Mosca model, and recommends the NIST post-quantum replacement.</p>
          <div class="surfaces">${["Source code (7 languages)", "Dependencies", "Binaries & JARs", "Certificates & keys", "TLS / SSH configs", "Container images", "Live TLS endpoints", "CBOM · SARIF · CSV"].map((s) => `<div>${esc(s)}</div>`).join("")}</div>
          ${recent.length ? `<h2 style="margin-top:18px">Recent scans</h2><div class="recent"><ul>${recent.map((s) => `
            <li data-open="${esc(s.id)}"><span>${esc(s.name)}</span><span class="muted">QRI ${s.qri} · ${s.assets} assets · ${esc(fmtDate(s.created))}</span></li>`).join("")}</ul></div>` : ""}
        </div>
        <div class="panel" id="scanForm">
          <h2>New scan</h2>
          <div class="formtabs" role="tablist">
            ${[["demo", "Demo repo"], ["path", "Folder"], ["upload", "Upload .zip"], ["image", "Container image"], ["hosts", "TLS hosts"]]
              .map(([k, l]) => `<button role="tab" data-ftab="${k}" aria-selected="${formTab === k}">${l}</button>`).join("")}
          </div>
          <div id="formBody">${formBody()}</div>
          <div class="field" style="margin-top:6px"><label for="crqc">Expected CRQC year (median)</label>
            <input id="crqc" type="number" min="2027" max="2060" step="1" value="2034"></div>
          <button id="startScan" class="btn accent">Start scan</button>
          <div id="jobStatus" style="margin-top:14px">${message ? `<p class="error">${esc(message)}</p>` : ""}</div>
        </div>
      </section>`;
    app.querySelectorAll("[data-open]").forEach((li) => li.addEventListener("click", () => openScan(li.dataset.open)));
    app.querySelectorAll("[data-ftab]").forEach((b) => b.addEventListener("click", () => { formTab = b.dataset.ftab; renderHome(); }));
    $("#startScan").addEventListener("click", startScan);
  }

  function formBody() {
    switch (formTab) {
      case "demo": return `<p class="muted">Scans the bundled <b>Bharat FinServe</b> demo monorepo (fictional): a Java payments service, Python KYC service, Node notifications, Go reports, a C card gateway, nginx, sshd, OpenSSL config, a Dockerfile, certificates and keys.</p>`;
      case "path": return `<div class="field"><label for="fPath">Folder or file on this machine</label><input id="fPath" placeholder="D:\\code\\my-repo" autocomplete="off"></div>`;
      case "upload": return `<div class="field"><label for="fZip">Repository as a .zip</label><input id="fZip" type="file" accept=".zip"></div>`;
      case "image": return `<div class="field"><label for="fImage">Local container image</label><input id="fImage" placeholder="nginx:1.25"></div><p class="muted">Needs Docker. The image must already be pulled.</p>`;
      case "hosts": return `<div class="field"><label for="fHosts">host:port, one per line</label><textarea id="fHosts" rows="4" placeholder="127.0.0.1:8443"></textarea></div><p class="muted">Probes TLS 1.0–1.3 support, the negotiated cipher and the certificate. Only scan systems you are authorised to test.</p>`;
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
      status.innerHTML = `<p class="error">${esc(e.message)}</p>`;
      btn.disabled = false;
    }
  }

  async function poll(jobId, status) {
    for (;;) {
      const j = await api(`/api/jobs/${jobId}`);
      status.innerHTML = `<div class="progress"><span style="width:${Math.round(j.progress * 100)}%"></span></div><p class="muted">${esc(j.message)}</p>`;
      if (j.status === "done") { await refreshScans(j.scan_id); await openScan(j.scan_id); return; }
      if (j.status === "error") throw new Error(j.error || "Scan failed");
      await new Promise((r) => setTimeout(r, 400));
    }
  }

  // ---------- scan view ----------
  function render() {
    if (!state.scan) return renderHome();
    const r = state.scan, st = r.stats;
    const targets = r.targets.map((t) => `${t.type}: ${t.value}`).join(" · ");
    app.innerHTML = `
      <div class="scanhead">
        <div><h1>${esc(r.name)}</h1>
          <div class="scanmeta">${esc(fmtDate(r.created))} · ${st.files_scanned} files · ${st.source_files} source files · ${st.loc.toLocaleString()} lines of code · scanned in ${st.duration_s}s · ${esc(targets)}</div></div>
      </div>
      <div class="tabs" role="tablist">
        ${[["overview", "Overview"], ["inventory", `Inventory (${r.assets.length})`], ["roadmap", "Migration roadmap"], ["lab", "PQC lab"], ["export", "Export & CI"]]
          .map(([k, l]) => `<button class="tab" role="tab" data-tab="${k}" aria-selected="${state.tab === k}">${l}</button>`).join("")}
      </div>
      <div id="view"></div>
      ${r.errors && r.errors.length ? `<p class="muted">Notes: ${r.errors.map(esc).join(" · ")}</p>` : ""}`;
    app.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; render(); }));
    ({ overview: renderOverview, inventory: renderInventory, roadmap: renderRoadmap, lab: renderLab, export: renderExport })[state.tab]();
  }

  function gauge(v) {
    const r = 46, c = Math.PI * r, pct = Math.max(0, Math.min(100, v)) / 100;
    const color = v >= 70 ? "var(--low)" : v >= 40 ? "var(--accent-2)" : "#FF8C82";
    return `<svg width="120" height="72" viewBox="0 0 120 72" role="img" aria-label="Quantum Readiness Index ${v} out of 100">
      <path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="#2B3A66" stroke-width="12" stroke-linecap="round"/>
      <path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${c * pct} ${c}"/>
      <text x="60" y="60" text-anchor="middle" font-size="26" font-weight="800" fill="#EEF1F7">${v}</text></svg>`;
  }

  function renderOverview() {
    const s = summary(), r = state.scan;
    const year = state.sim ? state.sim.risk_config.crqc_median_year : r.risk_config.crqc_median_year;
    const kinds = Object.entries(s.by_kind).sort((a, b) => b[1] - a[1]);
    const surf = Object.entries(s.by_surface).sort((a, b) => b[1] - a[1]);
    const maxK = Math.max(1, ...kinds.map((k) => k[1])), maxS = Math.max(1, ...surf.map((k) => k[1]));
    const heatMax = Math.max(1, ...s.heatmap.flat());
    const heatColor = (col, n) => {
      if (!n) return "var(--surface-2)";
      const base = ["var(--crit)", "var(--high)", "var(--med)", "var(--low)", "var(--pqc)"][col];
      return `color-mix(in srgb, ${base} ${20 + Math.round(70 * n / heatMax)}%, var(--surface))`;
    };
    $("#view").innerHTML = `
      <div class="kpis">
        <div class="kpi gauge-card">${gauge(s.qri)}<div><div class="label">Quantum Readiness Index</div><div class="sub">100 = fully quantum-safe. Criticality-weighted.</div></div></div>
        ${BANDS.map((b) => `<div class="kpi ${b === "medium" ? "med" : b === "critical" ? "crit" : b}"><div class="label">${b}</div><div class="value">${s.bands[b]}</div><div class="sub">assets</div></div>`).join("")}
        <div class="kpi"><div class="label">Harvest-now, decrypt-later</div><div class="value">${s.hndl}</div><div class="sub">confidentiality assets exposed</div></div>
        <div class="kpi"><div class="label">Broken today</div><div class="value">${s.classical}</div><div class="sub">classically weak or broken</div></div>
      </div>
      <div class="whatif">
        <label for="crqcSlider">What if a quantum computer arrives in</label>
        <input id="crqcSlider" type="range" min="2028" max="2045" step="1" value="${year}">
        <span class="year" id="crqcYear">${Math.round(year)}</span>
        <span class="hint">Median year for a cryptographically relevant quantum computer. Risk uses P(X + Y &gt; Z) with Z sampled from a lognormal distribution.</span>
      </div>
      <div class="grid g-3">
        <div class="panel"><h2>Risk heatmap</h2>
          <div class="heat">
            <div></div>${HEAT_COLS.map((h) => `<div class="h">${h}</div>`).join("")}
            ${s.heatmap.map((row, i) => `<div class="r">Criticality ${5 - i}</div>${row.map((n, j) => `<div class="cell" style="background:${heatColor(j, n)}" title="${n} assets">${n || ""}</div>`).join("")}`).join("")}
          </div>
          <p class="muted" style="margin:10px 0 0;font-size:12px">Margin = CRQC median − (data shelf life + migration time).</p>
        </div>
        <div class="panel"><h2>Assets by type</h2><div class="bars">${kinds.map(([k, n]) => `<div class="bar"><span>${esc(KIND_LABEL[k] || k)}</span><div class="track"><div class="fill" style="width:${100 * n / maxK}%"></div></div><span class="n">${n}</span></div>`).join("")}</div>
          <h2 style="margin-top:16px">Where we found them</h2><div class="bars">${surf.map(([k, n]) => `<div class="bar"><span>${esc(SURFACE_LABEL[k] || k)}</span><div class="track"><div class="fill" style="width:${100 * n / maxS}%;background:var(--accent)"></div></div><span class="n">${n}</span></div>`).join("")}</div>
        </div>
        <div class="panel"><h2>Top risks</h2><div class="toplist">${s.top.map((t) => `
          <button data-asset="${esc(t.id)}"><span class="score" style="color:${BAND_COLOR[t.band]}">${t.qrs}</span><span>${esc(t.name)}</span>${bandPill(t.band)}</button>`).join("")}</div></div>
      </div>
      <div class="grid g-2" style="margin-top:14px">
        <div class="panel"><h2>Status mix</h2><div class="bars">${Object.entries(s.by_status).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<div class="bar"><span>${statusPill(k)}</span><div class="track"><div class="fill" style="width:${100 * n / state.scan.assets.length}%"></div></div><span class="n">${n}</span></div>`).join("")}</div></div>
        <div class="panel"><h2>Applications</h2><div class="tablewrap" style="border:0"><table><thead><tr><th>App</th><th>Criticality</th><th>Data</th><th>Exposure</th><th>Worst</th></tr></thead><tbody>
          ${r.apps.map((ap) => { const worst = worstFor(ap.name); return `<tr><td>${esc(ap.name)}</td><td class="num">${ap.criticality}</td><td>${esc(ap.data_class)}</td><td>${esc(ap.exposure)}</td><td>${bandPill(worst)}</td></tr>`; }).join("")}
        </tbody></table></div></div>
      </div>`;
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
      if (el.tagName === "TR") el.addEventListener("keydown", (e) => { if (e.key === "Enter") openAsset(el.dataset.asset); });
    });
  }

  // ---------- inventory ----------
  function renderInventory() {
    const f = state.filter;
    const surfaces = [...new Set(state.scan.occurrences.map((o) => o.surface))];
    $("#view").innerHTML = `
      <div class="toolbar">
        <label class="sr" for="q">Search</label><input id="q" placeholder="Search assets, files, apps…" value="${esc(f.q)}">
        <label class="sr" for="fb">Band</label><select id="fb"><option value="">All bands</option>${BANDS.map((b) => `<option ${f.band === b ? "selected" : ""}>${b}</option>`).join("")}</select>
        <label class="sr" for="fk">Type</label><select id="fk"><option value="">All types</option>${Object.keys(KIND_LABEL).map((k) => `<option value="${k}" ${f.kind === k ? "selected" : ""}>${KIND_LABEL[k]}</option>`).join("")}</select>
        <label class="sr" for="fs">Surface</label><select id="fs"><option value="">All surfaces</option>${surfaces.map((k) => `<option value="${k}" ${f.surface === k ? "selected" : ""}>${esc(SURFACE_LABEL[k] || k)}</option>`).join("")}</select>
        <span class="muted" id="count"></span>
      </div>
      <div class="tablewrap"><table><thead><tr><th>Risk</th><th>Asset</th><th>Type</th><th>Status</th><th>Apps</th><th>Found in</th><th>Seen</th><th>Recommended</th></tr></thead><tbody id="rows"></tbody></table></div>`;
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
      $("#count").textContent = `${rows.length} of ${state.scan.assets.length}`;
      $("#rows").innerHTML = rows.map((a) => {
        const rk = riskOf(a) || { qrs: 0, band: "low" };
        const rec = a.recommendations[0];
        return `<tr class="row" tabindex="0" data-asset="${esc(a.id)}">
          <td><span class="qrs"><b style="min-width:26px;text-align:right;display:inline-block">${rk.qrs}</b><span class="mini"><span style="width:${rk.qrs}%;background:${BAND_COLOR[rk.band]}"></span></span>${bandPill(rk.band)}</span></td>
          <td><b>${esc(a.name)}</b></td><td>${esc(KIND_LABEL[a.kind] || a.kind)}</td><td>${statusPill(a.status)}</td>
          <td>${esc(a.apps.join(", "))}</td><td>${esc(a.surfaces.map((s) => SURFACE_LABEL[s] || s).join(", "))}</td>
          <td class="num">${a.occurrences.length}</td><td>${rec ? esc(rec.target) : '<span class="muted">No action</span>'}</td></tr>`;
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
  function mosca(rk, year) {
    const today = state.scan.risk_config.today;
    const median = Math.max(0.5, year - today), sigma = (state.sim ? state.sim.risk_config.sigma : state.scan.risk_config.sigma) || 0.45;
    const lo = median * Math.exp(-1.2816 * sigma), hi = median * Math.exp(1.2816 * sigma);
    const maxY = Math.max(30, rk.x_years + rk.y_years + 2, hi + 2);
    const W = 560, x = (v) => 20 + (W - 40) * v / maxY;
    const ticks = [0, 5, 10, 15, 20, 25, 30, 35, 40].filter((t) => t <= maxY);
    return `<svg viewBox="0 0 ${W} 96" width="100%" role="img" aria-label="Mosca timeline: data shelf life ${rk.x_years} years plus migration ${rk.y_years} years against a quantum computer expected in ${median.toFixed(0)} years">
      <rect x="${x(lo)}" y="8" width="${x(hi) - x(lo)}" height="54" fill="var(--crit-soft)"/>
      <line x1="${x(median)}" x2="${x(median)}" y1="4" y2="66" stroke="var(--crit)" stroke-width="2" stroke-dasharray="4 3"/>
      <rect x="${x(0)}" y="22" width="${x(rk.x_years) - x(0)}" height="12" rx="3" fill="var(--navy)"/>
      <rect x="${x(rk.x_years)}" y="22" width="${Math.max(2, x(rk.x_years + rk.y_years) - x(rk.x_years))}" height="12" rx="3" fill="var(--accent)"/>
      <line x1="20" x2="${W - 20}" y1="66" y2="66" stroke="var(--line)"/>
      ${ticks.map((t) => `<line x1="${x(t)}" x2="${x(t)}" y1="66" y2="70" stroke="var(--muted)"/><text x="${x(t)}" y="84" font-size="11" text-anchor="middle" fill="var(--muted)">${t}y</text>`).join("")}
      <text x="${x(median) + 4}" y="16" font-size="11" fill="var(--crit)">CRQC median ${Math.round(year)}</text>
    </svg>
    <div class="meta"><span><b style="color:var(--ink)">X</b> data shelf life ${rk.x_years} y</span><span><b style="color:var(--accent)">Y</b> migration ${rk.y_years} y</span><span>shaded: 80% of CRQC arrival scenarios</span><span>P(exposure) ${(rk.p_exposure * 100).toFixed(0)}%</span></div>`;
  }

  function openAsset(id) {
    const a = state.scan.assets.find((x) => x.id === id);
    if (!a) return;
    const rk = riskOf(a);
    const occ = new Map(state.scan.occurrences.map((o) => [o.id, o]));
    const year = state.sim ? state.sim.risk_config.crqc_median_year : state.scan.risk_config.crqc_median_year;
    const byId = new Map(state.scan.assets.map((x) => [x.id, x]));
    const parents = state.scan.assets.filter((x) => x.links.includes(a.id));
    const ex = a.extra || {};
    const details = [];
    if (a.classical_bits) details.push(`classical security ${a.classical_bits} bits`);
    if (a.nist_level !== null && a.nist_level !== undefined) details.push(`NIST quantum level ${a.nist_level}`);
    if (a.oid) details.push(`OID ${a.oid}`);
    if (ex.not_after) details.push(`valid until ${ex.not_after.slice(0, 10)}${ex.expired ? " (expired)" : ""}`);
    if (ex.is_ca) details.push("CA certificate");
    if (ex.pqc) details.push(`PQC support: ${ex.pqc}`);
    $("#drawerBody").innerHTML = `
      <div><div class="dtitle">${esc(a.name)}</div>
        <div class="dpills">${rk ? bandPill(rk.band) : ""}${statusPill(a.status)}${pill("s-unknown", KIND_LABEL[a.kind] || a.kind)}${rk && rk.hndl ? pill("b-high", "harvest-now-decrypt-later") : ""}</div>
        ${details.length ? `<div class="meta" style="margin-top:8px">${details.map(esc).join(" · ")}</div>` : ""}
        ${a.note ? `<p style="margin:8px 0 0">${esc(a.note)}</p>` : ""}</div>
      ${rk ? `<div><h3>Quantum Risk Score: <span style="color:${BAND_COLOR[rk.band]}">${rk.qrs}</span>/100</h3>
        <div class="factors">${[["Q", rk.factors.Q, "quantum"], ["H", rk.factors.H, "HNDL"], ["P", rk.factors.P, "P(exposure)"], ["C", rk.factors.C, "criticality"], ["S", rk.factors.S, "sensitivity"], ["E", rk.factors.E, "exposure"]]
          .map(([k, v, l]) => `<div class="factor"><b>${v}</b><span>${k} · ${l}</span></div>`).join("")}</div>
        <p class="muted" style="font-size:12px;margin:6px 0 0">QRS = 100 × Q × H × P × (0.40·C/5 + 0.35·S + 0.25·E)${rk.classical ? "; floor applied because it is classically weak or broken today" : ""}. Scored for app <b>${esc(rk.app)}</b>.</p></div>
        ${rk.factors.Q ? `<div><h3>Mosca timeline</h3>${mosca(rk, year)}</div>` : ""}` : ""}
      ${a.recommendations.length ? `<div><h3>Recommended fix</h3>${a.recommendations.map((r) => `
        <div class="reco"><span class="t">${esc(r.target)}</span><span>${esc(r.why)}</span><span class="c">${esc(r.change)}</span><span class="meta">${esc(r.standard)}</span></div>`).join("")}</div>` : ""}
      ${a.links.length ? `<div><h3>Made of</h3><div class="chips">${a.links.map((l) => byId.get(l)).filter(Boolean).map((c) => `<button class="chip" data-asset="${esc(c.id)}">${esc(c.name)}</button>`).join("")}</div></div>` : ""}
      ${parents.length ? `<div><h3>Used by</h3><div class="chips">${parents.slice(0, 20).map((c) => `<button class="chip" data-asset="${esc(c.id)}">${esc(c.name)}</button>`).join("")}</div></div>` : ""}
      <div><h3>Evidence (${a.occurrences.length})</h3>${a.occurrences.slice(0, 60).map((oid) => { const o = occ.get(oid); return `
        <div class="occ"><span class="loc">${esc(o.path)}${o.line ? ":" + o.line : ""}</span>
          <span class="meta"><span>${esc(o.app)}</span><span>${esc(SURFACE_LABEL[o.surface] || o.surface)}</span><span>${esc(o.usage)}</span><span>${esc(o.agility)}</span><span>confidence ${Math.round(o.confidence * 100)}%</span><span>${esc(o.rule_id)}</span></span>
          ${o.snippet ? `<pre>${esc(o.snippet)}</pre>` : ""}</div>`; }).join("")}</div>`;
    $("#drawer").hidden = false; $("#scrim").hidden = false;
    $("#drawerBody").querySelectorAll("[data-asset]").forEach((el) => el.addEventListener("click", () => openAsset(el.dataset.asset)));
    $("#drawerClose").focus();
  }
  function closeDrawer() { $("#drawer").hidden = true; $("#scrim").hidden = true; }

  // ---------- roadmap ----------
  function renderRoadmap() {
    const assets = state.scan.assets.filter((a) => riskOf(a));
    const qriAfter = (fixedBands) => {
      let num = 0, den = 0;
      for (const a of assets) { const rk = riskOf(a); const q = fixedBands.includes(rk.band) ? 0 : rk.qrs; num += q * rk.factors.C; den += rk.factors.C; }
      return den ? Math.round(100 - num / den) : 100;
    };
    const steps = [["Today", summary().qri], ["After wave 1", qriAfter(["critical"])], ["After wave 2", qriAfter(["critical", "high"])], ["After wave 3", qriAfter(["critical", "high", "medium"])]];
    const waves = [["critical", "Wave 1 · now", "Broken today or data already exposed"], ["high", "Wave 2 · next 12 months", "Start with hybrid mode"], ["medium", "Wave 3 · next tech refresh", "Plan and budget"]];
    $("#view").innerHTML = `
      <div class="grid g-2">
        <div class="panel"><h2>Quantum Readiness Index after each wave</h2>
          <div class="projection">${steps.map(([l, v], i) => `<div class="col"><span class="v">${v}</span><div class="colbar ${i ? "after" : ""}" style="height:${Math.max(4, v)}%"></div><span class="l">${l}</span></div>`).join("")}</div></div>
        <div class="panel"><h2>How waves are built</h2><p class="muted">Assets are ordered by Quantum Risk Score. Wave 1 holds everything critical: classically broken crypto and quantum-vulnerable crypto protecting long-lived, sensitive data. Each asset shows its first recommended fix; open it for the exact change.</p>
          <p class="muted">Migration effort (Y) per asset comes from where the crypto lives (config 0.25 y, library 0.5 y, source 1 y, PKI 2 y), how hard-coded it is, and how many places use it.</p></div>
      </div>
      <div class="waves" style="margin-top:14px">${waves.map(([band, title, sub]) => {
        const items = assets.filter((a) => riskOf(a).band === band).sort((x, y) => riskOf(y).qrs - riskOf(x).qrs);
        return `<div class="panel wave"><h3><span>${title}</span>${bandPill(band)}</h3><p class="muted" style="margin:0 0 6px">${sub} · ${items.length} assets</p><ul>${items.map((a) => `
          <li data-asset="${esc(a.id)}"><b>${riskOf(a).qrs}</b> · ${esc(a.name)}<br><span class="muted">${esc(a.recommendations[0] ? a.recommendations[0].target : "review")} · ${esc(a.apps.join(", "))}</span></li>`).join("")}</ul></div>`;
      }).join("")}</div>`;
    wireAssetButtons();
  }

  // ---------- PQC lab ----------
  function renderLab() {
    const b = state.bench;
    const rows = b ? [...b.classical, ...b.pqc] : [];
    $("#view").innerHTML = `
      <div class="grid g-2">
        <div class="panel"><h2>Benchmark on this machine</h2>
          <p class="muted">Measures real timings here instead of quoting papers. Classical algorithms use pyca/cryptography; PQC timings need <code>liboqs-python</code>.</p>
          <button id="runBench" class="btn accent">${b ? "Run again" : "Run benchmark"}</button>
          ${b ? `<p class="muted" style="margin-top:10px">${esc(b.machine)} · median of ${b.iterations} runs${b.note ? " · " + esc(b.note) : ""}</p>
          <div class="tablewrap"><table><thead><tr><th>Algorithm</th><th>Operation</th><th>Median</th><th>Public key</th><th>Ciphertext / signature</th></tr></thead><tbody>
          ${rows.map((x) => `<tr><td><b>${esc(x.algorithm)}</b></td><td>${esc(x.operation)}</td><td class="num">${x.median_ms.toFixed(3)} ms</td><td class="num">${x.public_key ?? ""} B</td><td class="num">${x.ciphertext ?? x.signature ?? ""} B</td></tr>`).join("")}
          </tbody></table></div>` : ""}
        </div>
        <div class="panel"><h2>Size cost of post-quantum (FIPS 203 / 204 / 205)</h2>
          <div class="tablewrap"><table><thead><tr><th>Algorithm</th><th>Public key</th><th>Ciphertext / signature</th><th>Level</th></tr></thead><tbody>
          ${Object.entries(sizes()).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="num">${v.public_key} B</td><td class="num">${v.ciphertext ?? v.signature} B</td><td class="num">${v.level ?? "–"}</td></tr>`).join("")}
          </tbody></table></div>
          <div class="panel" style="margin-top:12px;background:var(--accent-soft);border:0"><b>Hybrid TLS handshake overhead</b><br>
            ML-KEM-768 adds 1,184 + 1,088 = <b>2,272 bytes</b> per handshake. At 10 Mbps that is 2,272 × 8 ÷ 10,000,000 s ≈ <b>1.8 ms</b> of transfer time.</div>
        </div>
      </div>`;
    $("#runBench").addEventListener("click", async (e) => {
      e.target.disabled = true; e.target.textContent = "Running…";
      try { state.bench = await api("/api/bench?iterations=40"); } catch (err) { alertInline(err.message); }
      renderLab();
    });
  }
  const sizes = () => ({
    "ML-KEM-512": { public_key: 800, ciphertext: 768, level: 1 }, "ML-KEM-768": { public_key: 1184, ciphertext: 1088, level: 3 },
    "ML-KEM-1024": { public_key: 1568, ciphertext: 1568, level: 5 }, "ML-DSA-44": { public_key: 1312, signature: 2420, level: 2 },
    "ML-DSA-65": { public_key: 1952, signature: 3309, level: 3 }, "ML-DSA-87": { public_key: 2592, signature: 4627, level: 5 },
    "SLH-DSA-SHA2-128s": { public_key: 32, signature: 7856, level: 1 }, "X25519 (classical)": { public_key: 32, ciphertext: 32 },
  });
  function alertInline(msg) { const p = document.createElement("p"); p.className = "error"; p.textContent = msg; $("#view").prepend(p); }

  // ---------- export ----------
  function renderExport() {
    const id = state.scan.id;
    const others = state.scans.filter((s) => s.id !== id);
    const d = state.diff;
    $("#view").innerHTML = `
      <div class="grid g-2">
        <div class="panel"><h2>Download</h2>
          <div class="toolbar">
            <a class="btn accent" href="/api/scans/${id}/export/cbom" download>CBOM (CycloneDX 1.6)</a>
            <a class="btn" href="/api/scans/${id}/export/sarif" download>SARIF 2.1.0</a>
            <a class="btn" href="/api/scans/${id}/export/csv" download>Inventory CSV</a>
            <a class="btn" href="/api/scans/${id}/export/json" download>Full result JSON</a>
          </div>
          <p class="muted">The CBOM lists every algorithm, protocol, certificate, key and library with evidence locations, plus Q-Drishti risk properties.</p>
          <h2 style="margin-top:16px">Compare with an earlier scan</h2>
          ${others.length ? `<div class="toolbar"><label class="sr" for="cmp">Earlier scan</label><select id="cmp">${others.map((s) => `<option value="${esc(s.id)}">${esc(s.name)} · QRI ${s.qri} · ${esc(fmtDate(s.created))}</option>`).join("")}</select><button id="cmpBtn" class="btn">Compare</button></div>` : `<p class="muted">Run another scan to compare.</p>`}
          ${d ? `<p><b>QRI ${d.qri_before} → ${d.qri_after}</b> (${d.qri_after - d.qri_before >= 0 ? "+" : ""}${d.qri_after - d.qri_before})</p>
            <p class="muted">Fixed risky assets: ${d.fixed_risky.length ? d.fixed_risky.map(esc).join(", ") : "none"}</p>
            <p class="muted">New assets: ${d.added.length ? d.added.map(esc).join(", ") : "none"}</p>` : ""}
        </div>
        <div class="panel"><h2>CI crypto gate</h2>
          <p class="muted">Fail a pull request when it adds new quantum-vulnerable or classically broken crypto. Findings already in the baseline are ignored.</p>
          <div class="codeblock">qdrishti scan . --out baseline      # once, on main
qdrishti gate . --baseline baseline/qdrishti-result.json \\
  --fail-on critical,classical --sarif q.sarif</div>
          <p class="muted" style="margin-top:10px">GitHub Actions: run the gate, then upload <code>q.sarif</code> with <code>github/codeql-action/upload-sarif</code> so findings appear on the PR.</p>
        </div>
      </div>`;
    const btn = $("#cmpBtn");
    if (btn) btn.addEventListener("click", async () => { state.diff = await api(`/api/scans/${$("#cmp").value}/diff/${id}`); renderExport(); });
  }

  // ---------- boot ----------
  $("#newScanBtn").addEventListener("click", () => { closeDrawer(); renderHome(); $("#scanPicker").value = ""; });
  $("#scanPicker").addEventListener("change", (e) => { if (e.target.value) openScan(e.target.value); else renderHome(); });
  $("#drawerClose").addEventListener("click", closeDrawer);
  $("#scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  (async () => {
    try {
      await refreshScans();
      let last = null;
      try { last = localStorage.getItem("qd:last"); } catch (_) {}
      if (last && state.scans.some((s) => s.id === last)) await openScan(last);
      else if (state.scans.length) await openScan(state.scans[0].id);
      else renderHome();
    } catch (e) { renderHome(e.message); }
  })();
})();
