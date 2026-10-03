/* RedTeam Console dashboard (v0.22.0) — vanilla JS, talks to the UI API. */
"use strict";

const $ = (sel, el) => (el || document).querySelector(sel);
const $$ = (sel, el) => Array.from((el || document).querySelectorAll(sel));
const app = $("#app");

const api = {
  async call(path, opts = {}) {
    const res = await fetch(path, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    if (res.status === 401) {
      location.href = "/?login=1";
      throw new Error("unauthorized");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
  get: (p) => api.call(p),
  post: (p, body) => api.call(p, { method: "POST", body: JSON.stringify(body || {}) }),
};

function esc(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function time(iso) {
  try { return new Date(iso).toLocaleString(); } catch { return iso || ""; }
}
function statusBadge(s) {
  return `<span class="badge ${esc(s)}">${esc(s)}</span>`;
}
function sevBadge(s) {
  return `<span class="sev ${esc(s)}">${esc(s)}</span>`;
}

/* ---------- modal ---------- */
function confirmModal(title, bodyHtml, confirmLabel, danger) {
  return new Promise((resolve) => {
    const root = $("#modal-root");
    root.innerHTML = `<div class="modal-back"><div class="modal">
      <h3 style="margin-top:0">${esc(title)}</h3><div>${bodyHtml}</div>
      <div class="actions"><button class="ghost" id="m-cancel">Cancel</button>
      <button class="${danger ? "danger" : ""}" id="m-ok">${esc(confirmLabel)}</button></div></div></div>`;
    $("#m-cancel").onclick = () => { root.innerHTML = ""; resolve(false); };
    $("#m-ok").onclick = () => { root.innerHTML = ""; resolve(true); };
    $(".modal-back", root).onclick = (e) => { if (e.target.classList.contains("modal-back")) { root.innerHTML = ""; resolve(false); } };
  });
}

/* ---------- engagements list ---------- */
async function viewList() {
  app.innerHTML = `<div class="card"><h3>Engagements</h3><div id="list"><p class="muted">Loading…</p></div></div>`;
  try {
    const list = await api.get("/api/engagements");
    if (!list.length) {
      $("#list").innerHTML = `<p class="muted">No engagements yet. <a href="#/launch">Launch one</a>.</p>`;
      return;
    }
    $("#list").innerHTML = `<table><thead><tr><th>ID</th><th>Target</th><th>Mode</th><th>Status</th><th>Findings</th><th>Updated</th></tr></thead><tbody>` +
      list.map((e) => `<tr class="clickable" data-id="${esc(e.id)}">
        <td><code>${esc(e.id)}</code>${e.live ? ' <span class="badge running">live</span>' : ""}</td>
        <td>${esc(e.target)}</td><td>${esc(e.mode)}</td><td>${statusBadge(e.status)}</td>
        <td>${e.findings}</td><td class="muted small">${esc(time(e.updatedAt))}</td></tr>`).join("") +
      `</tbody></table>`;
    $$("#list tr.clickable").forEach((tr) => {
      tr.onclick = () => location.hash = `#/e/${encodeURIComponent(tr.dataset.id)}`;
    });
  } catch (err) {
    $("#list").innerHTML = `<p style="color:var(--red)">${esc(err.message)}</p>`;
  }
}

/* ---------- launcher ---------- */
function launchForm() {
  return `<div class="card"><h3>Launch engagement</h3>
  <form id="launch-form">
  <div class="grid2">
    <label><span>Target (domain or URL)</span><input name="target" required placeholder="secscan.us"></label>
    <label><span>Mode</span><select name="mode"><option value="red">red — broad adversary emulation</option><option value="black">black — covert, stealth-first</option></select></label>
  </div>
  <label><span>Objective</span><input name="objective" required placeholder="assess the external attack surface"></label>
  <label><span>Scope — exact hosts, one per line</span><textarea name="scope" rows="3" required placeholder="secscan.us"></textarea></label>
  <div class="grid2">
    <label><span>Client (optional)</span><input name="client"></label>
    <label><span>Operator name</span><input name="operatorName" placeholder="required for production"></label>
  </div>
  <div class="grid2">
    <label><span>Environment</span><select name="environment"><option value="staging">staging</option><option value="production">production</option></select></label>
    <label><span>Autonomy tier</span><select name="tier"><option value="1">1 — validate (single-step)</option><option value="0">0 — observe (read-only)</option><option value="2">2 — chain (multi-step)</option></select></label>
  </div>
  <label><span>Battery targets</span><div class="chips" id="tchips">
    ${["secscan", "seclayer", "windows", "linux"].map((t) => `<span class="chip active" data-t="${t}">${t}</span>`).join("")}
  </div></label>
  <label><span>Excluded techniques (comma-separated, optional)</span><input name="excludedTechniques" placeholder="T1110"></label>
  <div class="row" style="margin-bottom:12px">
    <label style="margin:0"><input type="checkbox" name="fullBattery" checked style="width:auto"> full battery</label>
    <label style="margin:0"><input type="checkbox" name="confirmProduction" style="width:auto"> confirm production</label>
    <label style="margin:0"><input type="checkbox" name="confirmTier2Production" style="width:auto"> confirm tier-2 on prod</label>
    <label style="margin:0"><input type="checkbox" name="dryRun" style="width:auto"> dry run (no agents)</label>
  </div>
  <button type="submit">Review & launch</button>
  </form></div>`;
}

async function viewLaunch() {
  app.innerHTML = launchForm();
  $$("#tchips .chip").forEach((c) => c.onclick = () => c.classList.toggle("active"));
  $("#launch-form").onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = {
      target: fd.get("target").trim(),
      mode: fd.get("mode"),
      objective: fd.get("objective").trim(),
      scope: String(fd.get("scope")).split("\n").map((s) => s.trim()).filter(Boolean),
      client: fd.get("client").trim() || undefined,
      operatorName: fd.get("operatorName").trim() || undefined,
      fullBattery: fd.get("fullBattery") === "on",
      targets: $$("#tchips .chip.active").map((c) => c.dataset.t),
      environment: fd.get("environment"),
      confirmProduction: fd.get("confirmProduction") === "on",
      confirmTier2Production: fd.get("confirmTier2Production") === "on",
      tier: Number(fd.get("tier")),
      excludedTechniques: String(fd.get("excludedTechniques")).split(",").map((s) => s.trim()).filter(Boolean),
      dryRun: fd.get("dryRun") === "on",
    };
    const ok = await confirmModal("Launch engagement?",
      `<p>Target <strong>${esc(body.target)}</strong> · mode <strong>${esc(body.mode)}</strong> · env <strong>${esc(body.environment)}</strong> · tier <strong>${esc(body.tier)}</strong></p>
       <p class="muted small">Scope: ${body.scope.map(esc).join(", ")}<br>Targets: ${body.targets.map(esc).join(", ") || "(all)"}${body.dryRun ? "<br><strong>Dry run — no agents, no traffic.</strong>" : ""}</p>
       <p class="muted small">Authorization gates run first and fail closed. The kill switch is available on the live view.</p>`,
      "Launch", false);
    if (!ok) return;
    try {
      const { id } = await api.post("/api/engagements", body);
      location.hash = `#/e/${encodeURIComponent(id)}`;
    } catch (err) {
      confirmModal("Launch failed", `<p style="color:var(--red)">${esc(err.message)}</p>`, "Close", false);
    }
  };
}

/* ---------- engagement detail ---------- */
let feedSource = null;
function stopFeed() {
  if (feedSource) { feedSource.close(); feedSource = null; }
  $("#conn").classList.remove("live");
}

async function viewDetail(id) {
  stopFeed();
  app.innerHTML = `<div id="detail"><p class="muted">Loading…</p></div>`;
  let detail;
  try {
    detail = await api.get(`/api/engagements/${encodeURIComponent(id)}`);
  } catch (err) {
    app.innerHTML = `<div class="card"><p style="color:var(--red)">${esc(err.message)}</p></div>`;
    return;
  }
  const st = detail.state;
  $("#app").innerHTML = `
  <div class="card"><div class="row" style="justify-content:space-between">
    <div><h3 style="margin:0 0 4px"><code>${esc(id)}</code></h3>
    <div class="muted small">${esc(st.target)} · ${esc(st.mode)} · ${esc(time(st.startedAt))}</div></div>
    <div class="row">${statusBadge(st.status)}${detail.live ? '<span class="badge running">live</span>' : ""}</div>
  </div></div>
  <div class="tabs" id="dtabs">
    <button data-tab="live" class="active">Live feed</button>
    <button data-tab="findings">Findings (${st.findings.length})</button>
    <button data-tab="coverage">Coverage</button>
    <button data-tab="compliance">Compliance</button>
  </div>
  <div id="tab-body"></div>
  ${detail.live ? `<div class="killbar"><strong>Kill switch</strong><span class="muted small">aborts in-flight work immediately</span><button class="danger" id="kill" style="margin-left:auto">Abort engagement</button></div>` : ""}
  ${detail.live ? `<div class="killbar"><strong>Autonomy tier</strong><span class="muted small">change mid-run — recorded operator approval</span><button id="escalate" style="margin-left:auto">Change tier</button></div>` : ""}`;

  const setTab = (tab) => {
    $$("#dtabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    stopFeed();
    if (tab === "live") tabLive(id);
    else if (tab === "findings") tabFindings(id);
    else if (tab === "coverage") tabCoverage(id);
    else if (tab === "compliance") tabCompliance(id);
  };
  $$("#dtabs button").forEach((b) => b.onclick = () => setTab(b.dataset.tab));
  const kill = $("#kill");
  if (kill) kill.onclick = async () => {
    const reason = prompt("Abort reason (recorded in the audit log):", "operator abort from UI");
    if (reason === null) return;
    const ok = await confirmModal("Abort engagement?", "<p>This terminates in-flight executions immediately. The engagement unwinds to <strong>halted</strong>.</p>", "Abort now", true);
    if (!ok) return;
    try {
      await api.post(`/api/engagements/${encodeURIComponent(id)}/abort`, { reason });
      setTab("live");
    } catch (err) {
      confirmModal("Abort failed", `<p style="color:var(--red)">${esc(err.message)}</p>`, "Close", false);
    }
  };
  const escalateBtn = $("#escalate");
  if (escalateBtn) escalateBtn.onclick = async () => {
    const tier = prompt("New autonomy tier (0 observe · 1 validate · 2 chain):", "2");
    if (tier === null) return;
    if (!["0", "1", "2"].includes(tier.trim())) {
      confirmModal("Bad tier", "<p>Want 0, 1, or 2.</p>", "Close", false);
      return;
    }
    const operator = prompt("Operator name (recorded in the approval log):", "");
    if (operator === null) return;
    if (!operator.trim()) {
      confirmModal("Operator required", "<p>A named operator is required — someone must own the tier change.</p>", "Close", false);
      return;
    }
    const reason = prompt("Reason (required when RAISING the tier):", "");
    if (reason === null) return;
    const ok = await confirmModal("Change tier?",
      `<p>Set autonomy to <strong>Tier ${esc(tier.trim())}</strong> by <strong>${esc(operator.trim())}</strong>.</p>` +
      (tier.trim() === "2" ? `<p>On <strong>production</strong> this also counts as your explicit Tier-2 approval.</p>` : "") +
      `<p class="muted small">The running dispatcher picks it up on its next tool call — no restart. The approval lands in approvals.jsonl and the audit log.</p>`,
      "Change tier", true);
    if (!ok) return;
    try {
      const r = await api.post(`/api/engagements/${encodeURIComponent(id)}/escalate`, {
        tier: tier.trim(), operator: operator.trim(), reason: reason.trim(),
        confirmTier2Production: tier.trim() === "2",
      });
      confirmModal("Tier changed", `<p>${esc(r.message || `Tier ${r.fromTier} → ${r.toTier}`)}</p>`, "Close", false);
      setTab("live");
    } catch (err) {
      confirmModal("Tier change failed", `<p style="color:var(--red)">${esc(err.message)}</p>`, "Close", false);
    }
  };
  setTab("live");
}

function feedRow(ev) {
  return `<div class="ev"><span class="ts">${esc(ev.ts.slice(11, 19))}</span><span class="ph">${esc(ev.phase)}</span><span class="ac">${esc(ev.actor)}:${esc(ev.action)}</span><span class="rs">${esc(ev.result).slice(0, 400)}</span></div>`;
}

function tabLive(id) {
  $("#tab-body").innerHTML = `<div class="feed" id="feed"></div>`;
  const feed = $("#feed");
  let lastSeq = 0;
  feedSource = new EventSource(`/api/engagements/${encodeURIComponent(id)}/events`);
  $("#conn").classList.add("live");
  feedSource.addEventListener("event", (e) => {
    const ev = JSON.parse(e.data);
    lastSeq = ev.seq;
    feed.insertAdjacentHTML("beforeend", feedRow(ev));
    feed.scrollTop = feed.scrollHeight;
  });
  feedSource.addEventListener("state", (e) => {
    const st = JSON.parse(e.data);
    $$("#dtabs .badge").forEach(() => {});
  });
  feedSource.addEventListener("done", () => {
    stopFeed();
    feed.insertAdjacentHTML("beforeend", `<div class="ev"><span class="rs muted">— stream ended —</span></div>`);
  });
  feedSource.onerror = () => { /* dashboard reconnects via reload; SSE auto-retries */ };
}

async function tabFindings(id) {
  const body = $("#tab-body");
  body.innerHTML = `<p class="muted">Loading findings…</p>`;
  try {
    const findings = await api.get(`/api/engagements/${encodeURIComponent(id)}/findings`);
    if (!findings.length) { body.innerHTML = `<p class="muted">No findings recorded.</p>`; return; }
    const sevs = ["critical", "high", "medium", "low", "info"];
    body.innerHTML = `<div class="chips" id="fchips"><span class="chip active" data-s="">all</span>${sevs.map((s) => `<span class="chip" data-s="${s}">${s}</span>`).join("")}</div><div id="flist"></div><div id="fdetail"></div>`;
    const render = (filter) => {
      const rows = findings.filter((f) => !filter || f.severity === filter);
      $("#flist").innerHTML = `<table><thead><tr><th></th><th>ID</th><th>Title</th><th>ATT&CK</th><th>Proof</th></tr></thead><tbody>` +
        rows.map((f) => `<tr class="clickable" data-fid="${esc(f.id)}"><td>${sevBadge(f.severity)}</td><td><code>${esc(f.id)}</code></td><td>${esc(f.title)}</td><td class="muted small">${esc((f.attackIds || []).join(", "))}</td><td>${f.hasProof ? "✓ bundle" : '<span class="muted">—</span>'}</td></tr>`).join("") +
        `</tbody></table>`;
      $$("#flist tr.clickable").forEach((tr) => tr.onclick = () => showFinding(id, tr.dataset.fid));
    };
    $$("#fchips .chip").forEach((c) => c.onclick = () => {
      $$("#fchips .chip").forEach((x) => x.classList.remove("active"));
      c.classList.add("active");
      render(c.dataset.s);
    });
    render("");
  } catch (err) {
    body.innerHTML = `<p style="color:var(--red)">${esc(err.message)}</p>`;
  }
}

async function showFinding(id, fid) {
  const d = $("#fdetail");
  d.innerHTML = `<p class="muted">Loading proof bundle…</p>`;
  try {
    const b = await api.get(`/api/engagements/${encodeURIComponent(id)}/proof/${encodeURIComponent(fid)}`);
    d.innerHTML = `<div class="card"><h3>${esc(b.title)} <span class="muted small">${esc(b.validationTier)} validation</span></h3>
    <p><strong>Proves:</strong> ${esc(b.proves)}</p>
    <p><strong>Does not prove:</strong> ${esc(b.doesNotProve)}</p>
    ${b.markerObserved ? `<p class="small">Canary marker observed: <code>${esc(b.markerObserved)}</code></p>` : ""}
    <table><thead><tr><th>Seq</th><th>Tool</th><th>Target</th><th>Command</th></tr></thead><tbody>
    ${(b.steps || []).map((s) => `<tr><td>${s.seq}</td><td><code>${esc(s.tool)}</code></td><td class="small">${esc(s.target || "")}</td><td class="small"><code>${esc((s.command || "").slice(0, 160))}</code></td></tr>`).join("")}
    </tbody></table>
    <p class="muted small">Re-verify: <code>${esc(b.reverifyCommand || "")}</code></p></div>`;
    d.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (err) {
    d.innerHTML = `<p class="muted">No proof bundle for this finding (${esc(err.message)}).</p>`;
  }
}

async function tabCoverage(id) {
  const body = $("#tab-body");
  body.innerHTML = `<p class="muted">Loading coverage…</p>`;
  try {
    const cov = await api.get(`/api/engagements/${encodeURIComponent(id)}/coverage`);
    const total = cov.total || 1;
    const colors = { confirmed: "var(--green)", "executed-clean": "var(--accent)", killed: "var(--purple)", blocked: "var(--yellow)", na: "var(--muted)", pending: "var(--red)" };
    const rows = Object.entries(cov.byDisposition || {}).map(([k, v]) => {
      const pct = Math.round((v / total) * 100);
      return `<div><div class="row" style="justify-content:space-between"><span>${esc(k)}</span><span class="muted">${v} (${pct}%)</span></div><div class="bar"><div style="width:${pct}%;background:${colors[k] || "var(--muted)"}"></div></div></div>`;
    }).join("");
    body.innerHTML = `<div class="card"><h3>Per-item verdicts (${cov.total} items)</h3>${rows || '<p class="muted">No verdicts yet.</p>'}
    ${cov.pendingTotal ? `<h3>Pending (${cov.pendingTotal})</h3><pre class="dump">${esc((cov.pending || []).join("\n"))}</pre>` : ""}</div>
    ${cov.cells ? `<div class="card"><h3>Cell coverage</h3><pre class="dump">${esc(JSON.stringify(cov.cells, null, 2))}</pre></div>` : ""}`;
  } catch (err) {
    body.innerHTML = `<p style="color:var(--red)">${esc(err.message)}</p>`;
  }
}

async function tabCompliance(id) {
  const body = $("#tab-body");
  body.innerHTML = `<p class="muted">Loading compliance pack…</p>`;
  try {
    const c = await api.get(`/api/engagements/${encodeURIComponent(id)}/compliance`);
    const tabs = [["pack", "Evidence pack", c.packHtml], ["attestation", "Attestation", c.attestationHtml], ["safety", "Safety manifest", c.safetyHtml], ["report", "Report", c.reportHtml]];
    body.innerHTML = `<div class="tabs" id="ctabs">${tabs.map(([k, l], i) => `<button data-k="${k}" class="${i === 0 ? "active" : ""}">${l}</button>`).join("")}</div><div class="card doc" id="cbody"></div>`;
    const show = (k) => {
      const t = tabs.find((x) => x[0] === k);
      $("#cbody").innerHTML = t[2] || `<p class="muted">Not generated for this engagement.</p>`;
      $$("#ctabs button").forEach((b) => b.classList.toggle("active", b.dataset.k === k));
    };
    $$("#ctabs button").forEach((b) => b.onclick = () => show(b.dataset.k));
    show(tabs.find((t) => t[2])[0] || "pack");
  } catch (err) {
    body.innerHTML = `<p style="color:var(--red)">${esc(err.message)}</p>`;
  }
}

/* ---------- watch ---------- */
async function viewWatch() {
  app.innerHTML = `<div class="card"><h3>Continuous watch</h3>
  <label><span>Profiles directory</span><div class="row"><input id="wdir" style="flex:1" placeholder="/path/to/profiles"><button class="ghost" id="wlist">List</button></div></label>
  <div id="wprofiles"></div></div>
  <div class="card"><h3>Trigger a cycle</h3>
  <label><span>Profile path</span><input id="wpath" placeholder="/path/to/profile.json"></label>
  <label><span>Change reference (optional — CI/CD hook)</span><input id="wtrigger" placeholder="deploy abc123"></label>
  <button id="wgo">Trigger one cycle</button> <span id="wstatus" class="muted small"></span></div>`;
  const list = async () => {
    const dir = $("#wdir").value.trim() || ".";
    try {
      const profiles = await api.get(`/api/watch/profiles?dir=${encodeURIComponent(dir)}`);
      $("#wprofiles").innerHTML = profiles.length
        ? `<table><thead><tr><th>Profile</th><th>Target</th><th>Cadence</th><th></th></tr></thead><tbody>` +
          profiles.map((p) => `<tr><td class="small"><code>${esc(p.path)}</code></td><td>${esc(p.target || "")}</td><td class="muted">${p.intervalHours ? p.intervalHours + "h" : ""}</td><td><button class="ghost" data-p="${esc(p.path)}">Trigger</button></td></tr>`).join("") + `</tbody></table>`
        : `<p class="muted">No watch profiles in ${esc(dir)}.</p>`;
      $$("#wprofiles button[data-p]").forEach((b) => b.onclick = () => { $("#wpath").value = b.dataset.p; $("#wgo").click(); });
    } catch (err) {
      $("#wprofiles").innerHTML = `<p style="color:var(--red)">${esc(err.message)}</p>`;
    }
  };
  $("#wlist").onclick = list;
  $("#wgo").onclick = async () => {
    const profilePath = $("#wpath").value.trim();
    if (!profilePath) return;
    const ok = await confirmModal("Trigger watch cycle?", `<p>Runs one full cycle of <code>${esc(profilePath)}</code> now — engagement, drift detection, alerts.</p>`, "Trigger", false);
    if (!ok) return;
    $("#wstatus").textContent = "triggered…";
    try {
      const { jobId } = await api.post("/api/watch/trigger", { profilePath, trigger: $("#wtrigger").value.trim() || undefined });
      pollJob(jobId, $("#wstatus"));
    } catch (err) {
      $("#wstatus").textContent = err.message;
    }
  };
  list();
}

async function pollJob(jobId, el) {
  const tick = async () => {
    try {
      const job = await api.get(`/api/jobs/${encodeURIComponent(jobId)}`);
      if (job.status === "running") {
        el.textContent = "running…";
        setTimeout(tick, 2000);
      } else if (job.status === "done") {
        el.textContent = "done: " + JSON.stringify(job.result).slice(0, 300);
      } else {
        el.textContent = "failed: " + (job.error || "unknown");
      }
    } catch (err) {
      el.textContent = err.message;
    }
  };
  tick();
}

/* ---------- reverify ---------- */
async function viewReverify() {
  app.innerHTML = `<div class="card"><h3>Reverify a proof bundle</h3>
  <p class="muted small">Re-executes a PoC bundle's steps with a fresh canary marker. Plan mode shows the replay plan with zero traffic.</p>
  <label><span>Bundle path</span><input id="rbundle" placeholder="/path/to/engagements/live/eng-.../poc/F-1.json"></label>
  <label><span>Scope — exact hosts, one per line (required for execute)</span><textarea id="rscope" rows="2"></textarea></label>
  <label style="margin-bottom:12px"><input type="checkbox" id="rexec" style="width:auto"> execute (otherwise plan only)</label>
  <div><button id="rgo">Run</button> <span id="rstatus" class="muted small"></span></div>
  <div id="rout"></div></div>`;
  $("#rgo").onclick = async () => {
    const bundlePath = $("#rbundle").value.trim();
    const scope = $("#rscope").value.split("\n").map((s) => s.trim()).filter(Boolean);
    const execute = $("#rexec").checked;
    if (!bundlePath) return;
    if (execute) {
      const ok = await confirmModal("Execute reverify?", `<p>This sends real traffic to: ${scope.map(esc).join(", ") || "(no scope!)"}.</p>`, "Execute", true);
      if (!ok) return;
    }
    $("#rstatus").textContent = "working…";
    try {
      const res = await api.post("/api/reverify", { bundlePath, scope, execute });
      if (res.plan) {
        $("#rstatus").textContent = `plan: ${res.steps.length} steps, no traffic sent`;
        $("#rout").innerHTML = `<table><thead><tr><th>Seq</th><th>Tool</th><th>Target</th><th>Command</th><th>Replayable</th></tr></thead><tbody>` +
          res.steps.map((s) => `<tr><td>${s.seq}</td><td><code>${esc(s.tool)}</code></td><td class="small">${esc(s.target || "")}</td><td class="small"><code>${esc(s.command)}</code></td><td>${s.replayable ? "yes" : "no"}</td></tr>`).join("") + `</tbody></table>`;
      } else {
        pollJob(res.jobId, $("#rstatus"));
      }
    } catch (err) {
      $("#rstatus").textContent = err.message;
    }
  };
}

/* ---------- router ---------- */
function nav() {
  $$("[data-nav]").forEach((a) => {
    const h = a.getAttribute("href");
    a.classList.toggle("active", location.hash === h || (h === "#/" && (location.hash === "" || location.hash === "#/")));
  });
}

async function router() {
  nav();
  stopFeed();
  const h = location.hash || "#/";
  const m = h.match(/^#\/e\/([^/]+)$/);
  if (h === "#/" || h === "") await viewList();
  else if (h === "#/launch") await viewLaunch();
  else if (h === "#/watch") await viewWatch();
  else if (h === "#/reverify") await viewReverify();
  else if (m) await viewDetail(decodeURIComponent(m[1]));
  else app.innerHTML = `<div class="card"><p>Unknown view.</p></div>`;
}

window.addEventListener("hashchange", router);
router();
