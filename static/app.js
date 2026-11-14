// honeypot-net HUD. Every value from the API may contain attacker-controlled text, so all
// output goes through hud.esc (renderTable escapes plain columns itself).
(() => {
const { api, toast, renderTable, severityTag, heatmap, fmtTime, esc, every, initTabs } = window.hud;

const sim = () => (document.getElementById("incSim").checked ? 1 : 0);
const q = (path) => `${path}${path.includes("?") ? "&" : "?"}sim=${sim()}`;
const list = (v) => esc((v || []).join(", "));
const code = (v) => `<code>${esc(v)}</code>`;
const tag = (cls, text) => `<span class="tag ${cls}">${esc(text)}</span>`;

function summary(ev) {
  const d = ev.data || {};
  switch (ev.event_type) {
    case "auth": return `${ev.username ?? ""} / ${ev.password ?? ""} ${ev.success ? "(accepted)" : ""} ${d.key_fingerprint || ""}`;
    case "command": return ev.command;
    case "http_request": return `${ev.method} ${ev.path}  [${ev.category}${ev.cves ? " " + ev.cves : ""}]`;
    case "client_version": return `${d.client_version || ""} hassh=${d.hassh || ""}`;
    case "download_attempt": return `URL (not fetched): ${d.url}`;
    case "banner": return `${d.profile}: ${d.preview || ""}`;
    case "session_end": return `duration ${d.duration ?? ""}s, commands ${d.commands ?? ""}`;
    default: return "";
  }
}

// ---- Live ---------------------------------------------------------------
async function refreshLive() {
  const [ov, events, nodes, rate] = await Promise.all([
    api(q("/api/overview")), api(q("/api/events?limit=80")), api("/api/nodes"), api(q("/api/rate?minutes=10")),
  ]);
  const now = Date.now() / 1000;
  const recent = (mins) => rate.filter((r) => r.m >= now - mins * 60).reduce((a, r) => a + r.n, 0);
  const rows = [["events", ov.events], ["of which simulated", ov.simulated_events], ["unique source IPs", ov.unique_ips],
    ["auth attempts", ov.auth_attempts], ["shell commands", ov.commands], ["exploit attempts", ov.exploit_attempts],
    ["sessions", ov.sessions], ["received last 1 min", recent(1)], ["received last 10 min", recent(10)]];
  document.getElementById("overview").innerHTML =
    `<table class="kv">${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table>`;
  renderTable("#nodes", nodes, [
    { key: "node_id", label: "node" }, { key: "region", label: "region" },
    { key: "status", label: "status", render: (v) => tag(v === "ok" ? "ok" : v === "simulated" ? "info" : "warn", v) },
    { key: "heartbeat_age", label: "last heartbeat", render: (v) => (v == null ? "-" : esc(`${v}s ago`)) },
    { key: "events", label: "events" }, { key: "spool_backlog", label: "spool backlog" },
    { key: "sensors", label: "sensors", render: list },
  ], { empty: "No node has checked in yet. Start sensors with ./run.sh" });
  renderTable("#feed", events, [
    { key: "ts", label: "time", render: (v) => esc(fmtTime(v)) }, { key: "node_id", label: "node" },
    { key: "sensor", label: "sensor" }, { key: "event_type", label: "type" }, { key: "src_ip", label: "source" },
    { key: "event_id", label: "detail", render: (_, r) => code(summary(r)) },
    { key: "simulated", label: "sim", render: (v) => (v ? "yes" : "") },
  ], { empty: "No events yet. Use the Simulate tab." });
}

// ---- Analysis -----------------------------------------------------------
async function runAnalysis() {
  const note = document.getElementById("analysisNote");
  note.textContent = "running...";
  const [bf, cr, ca, ex, inf, geo, tm] = await Promise.all([
    api(q("/api/bruteforce")), api(q("/api/credentials")), api(q("/api/campaigns")), api(q("/api/exploits")),
    api(q("/api/infrastructure")), api(q("/api/geo")), api(q("/api/temporal")),
  ]);
  note.textContent = `${bf.total_attempts} auth attempts from ${bf.source_ips} IPs, ${bf.flagged} flagged as brute force, ` +
    `${bf.low_and_slow} low-and-slow; geo lookups: ${JSON.stringify(geo.lookup_sources)}`;

  renderTable("#bf", bf.ips.slice(0, 40), [
    { key: "ip", label: "ip", render: ipLink }, { key: "attempts", label: "attempts" },
    { key: "peak_per_window", label: "peak/min" }, { key: "distinct_users", label: "users" },
    { key: "distinct_passwords", label: "passwords" }, { key: "successes", label: "accepted" },
    { key: "shape", label: "pattern" },
    { key: "brute_force", label: "flag", render: (v, r) => (v ? tag("crit", "brute force") : r.low_and_slow ? tag("warn", "low and slow") : "") },
    { key: "sensors", label: "protocols", render: list },
  ]);
  renderTable("#pairs", cr.top_pairs, [{ key: "username", label: "user" }, { key: "password", label: "password" },
    { key: "count", label: "count" }, { key: "family", label: "family" }]);
  renderTable("#families", cr.families, [{ key: "family", label: "family" }, { key: "attempts", label: "attempts" }, { key: "ips", label: "IPs" }]);
  renderTable("#campaigns", ca.campaigns, [
    { key: "id", label: "id" }, { key: "label", label: "pattern" }, { key: "size", label: "IPs" },
    { key: "prefixes", label: "/24s" }, { key: "attempts", label: "attempts" }, { key: "nodes", label: "nodes", render: list },
    { key: "shared_creds", label: "shared credentials", render: (v) => code((v || []).join("  ")) },
    { key: "shared_commands", label: "shared commands", render: (v) => code((v || []).join("\n")) },
  ], { empty: "No campaigns: need at least two IPs with similar behaviour." });
  renderTable("#excat", ex.by_category, [{ key: "label", label: "category" }, { key: "value", label: "count" }]);
  renderTable("#excve", ex.by_cve, [{ key: "cve", label: "CVE" }, { key: "count", label: "requests" }, { key: "ips", label: "IPs" }]);
  renderTable("#scanners", ex.scanners, [{ key: "scanner", label: "scanner" }, { key: "kind", label: "kind" }, { key: "count", label: "requests" }]);
  renderTable("#samples", ex.samples, [
    { key: "src_ip", label: "source", render: ipLink }, { key: "severity", label: "sev", render: severityTag },
    { key: "category", label: "category" }, { key: "cves", label: "CVE" },
    { key: "path", label: "request", render: (v, r) => code(`${r.method} ${v}\nUA: ${r.user_agent}${r.body ? "\n\n" + r.body : ""}`) },
  ]);
  renderTable("#ips", inf.top_ips.slice(0, 40), [
    { key: "ip", label: "ip", render: ipLink }, { key: "events", label: "events" }, { key: "country", label: "cc" },
    { key: "asn", label: "ASN" }, { key: "sensors", label: "protocols", render: list }, { key: "nodes", label: "nodes", render: list },
  ]);
  renderTable("#asns", inf.asns, [{ key: "asn", label: "ASN" }, { key: "as_name", label: "name" }, { key: "country", label: "cc" }, { key: "ips", label: "IPs" }]);
  renderTable("#prefixes", inf.prefixes, [{ key: "prefix", label: "prefix" }, { key: "ips", label: "IPs" }]);
  renderTable("#fps", inf.fingerprints, [{ key: "kind", label: "kind" }, { key: "value", label: "value", render: code }, { key: "ips", label: "IPs" }]);
  renderTable("#countries", geo.countries, [{ key: "country", label: "country" }, { key: "events", label: "events" }, { key: "ips", label: "IPs" }]);
  heatmap("#heat", tm.heatmap, tm.weekdays, [...Array(24).keys()].map(String));
  renderTable("#pernode", tm.per_node, [{ key: "node_id", label: "node" }, { key: "events", label: "events" },
    { key: "by_sensor", label: "by sensor", render: (v) => esc(Object.entries(v).map(([k, n]) => `${k} ${n}`).join(", ")) },
    { key: "peak_bucket", label: "peak / bucket" }]);
  const kinds = Object.entries(inf.session_kind_counts).map(([k, n]) => `<span class="tag info">${esc(k)}: ${esc(n)}</span>`).join(" ");
  document.getElementById("bursts").innerHTML = `<p>Interactive sessions by command timing: ${kinds || "none"}</p>` +
    `<p class="muted">Peak hour ${esc(tm.peak_hour_utc)}:00 UTC, peak weekday ${esc(tm.peak_weekday)}. Bucket ${esc(tm.bucket_seconds)} s.</p><div id="burstTable"></div>`;
  renderTable("#burstTable", tm.bursts, [{ key: "ts", label: "bucket start", render: (v) => esc(fmtTime(v)) },
    { key: "ips", label: "source IPs" }, { key: "events", label: "events" }, { key: "limit", label: "limit" }], { empty: "No bursts detected." });
}

function ipLink(ip) {
  return `<span class="clickable" data-ip="${esc(ip)}">${esc(ip)}</span>`;
}

async function showProfile(ip) {
  const p = await api(q(`/api/ip/${encodeURIComponent(ip)}`));
  const el = document.getElementById("profile");
  if (!p.found) { el.innerHTML = `<p class="muted">No events for ${esc(ip)}.</p>`; return; }
  const kv = [["ip", p.ip], ["prefix", p.prefix], ["country / ASN", `${p.geo.country} / AS${p.geo.asn ?? "?"} ${p.geo.as_name ?? ""} (${p.geo.source})`],
    ["first seen", fmtTime(p.first_seen)], ["last seen", fmtTime(p.last_seen)], ["events", p.events],
    ["nodes", p.nodes.join(", ")], ["protocols", p.protocols.join(", ")], ["event types", JSON.stringify(p.event_types)],
    ["client versions", p.client_versions.join(", ")], ["fingerprints", p.fingerprints.join(", ")],
    ["session timing", [...new Set(p.sessions.map((s) => s.timing))].join(", ")], ["simulated", p.simulated ? "yes" : "no"]];
  el.innerHTML = `<table class="kv">${kv.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table>` +
    `<h2 style="margin-top:10px">credentials</h2><div id="pCreds"></div><h2>commands</h2><div id="pCmds"></div><h2>HTTP</h2><div id="pHttp"></div>`;
  renderTable("#pCreds", p.credentials.slice(0, 30), [{ key: "username", label: "user" }, { key: "password", label: "password" }, { key: "count", label: "n" }]);
  renderTable("#pCmds", p.commands.slice(0, 40), [{ key: "ts", label: "time", render: (v) => esc(fmtTime(v)) }, { key: "command", label: "command", render: code }]);
  renderTable("#pHttp", p.exploits.slice(0, 30), [{ key: "method", label: "m" }, { key: "path", label: "path", render: code }, { key: "category", label: "category" }, { key: "cves", label: "CVE" }]);
}

// ---- Simulate & export ---------------------------------------------------
let simPoll = null;
function renderSim(st) {
  const el = document.getElementById("simStatus");
  const job = st.current;
  if (!job) return;
  const results = job.result ? (job.result.results || [job.result]) : [];
  let html = `<p>${esc(job.name)}: ${tag(job.state === "done" ? "ok" : job.state === "failed" ? "crit" : "info", job.state)}</p>`;
  for (const r of results) {
    if (r.error) html += `<pre>${esc(r.error)}</pre>`;
    if (r.verification) {
      const v = r.verification;
      html += `<p><b>${esc(r.scenario)}</b> against ${esc(r.target)}: ${esc(v.passed)}/${esc(v.total)} checks passed; events landed ${esc(JSON.stringify(v.events_landed))}</p>`;
      html += `<table><tr><th>check</th><th>got</th><th>result</th></tr>${v.checks.map((c) =>
        `<tr><td>${esc(c.check)}</td><td>${esc(c.got)}</td><td>${c.pass ? tag("ok", "pass") : tag("crit", "fail")}</td></tr>`).join("")}</table>`;
    }
    if (r.log) html += `<pre>${esc(r.log.join("\n"))}</pre>`;
    if (r.inserted !== undefined) html += `<pre>${esc(JSON.stringify(r, null, 2))}</pre>`;
  }
  el.innerHTML = html;
  if (job.state !== "running" && simPoll) { clearInterval(simPoll); simPoll = null; toast(`${job.name} ${job.state}`); refreshLive(); }
}

async function startSim(path) {
  try {
    await api(path, { method: "POST" });
    if (simPoll) clearInterval(simPoll);
    simPoll = every(1500, async () => renderSim(await api("/api/simulate/status")));
  } catch (e) { toast(e.message); }
}

function wire() {
  document.querySelectorAll("[data-live]").forEach((b) => b.addEventListener("click", () => startSim(`/api/simulate/live/${b.dataset.live}`)));
  document.getElementById("inject").addEventListener("click", () =>
    startSim(`/api/simulate/inject?days=${document.getElementById("days").value}&scale=${document.getElementById("scale").value}`));
  document.getElementById("purge").addEventListener("click", async () => {
    if (!confirm("Delete all simulated events, sessions and nodes?")) return;
    const r = await api("/api/simulate/purge", { method: "POST" });
    toast(`purged ${r.events} events, ${r.sessions} sessions, ${r.nodes} nodes`);
    refreshLive();
  });
  document.getElementById("enrich").addEventListener("click", async () => {
    const r = await api(q("/api/enrich"), { method: "POST" });
    document.getElementById("exportOut").innerHTML = `<pre>${esc(JSON.stringify(r, null, 2))}</pre>`;
  });
  document.getElementById("runAnalysis").addEventListener("click", () => runAnalysis().catch((e) => toast(e.message)));
  document.getElementById("incSim").addEventListener("change", () => {
    document.getElementById("csv").href = q("/api/export/csv");
    document.getElementById("stix").href = q("/api/export/stix");
    refreshLive();
  });
  document.body.addEventListener("click", (e) => {
    const t = e.target.closest("[data-ip]");
    if (t) showProfile(t.dataset.ip).catch((err) => toast(err.message));
  });
  document.getElementById("csv").href = q("/api/export/csv");
  document.getElementById("stix").href = q("/api/export/stix");
}

wire();
initTabs((view) => { if (view === "analysis") runAnalysis().catch((e) => toast(e.message)); });
every(5000, () => refreshLive().catch(() => {}));
api("/api/simulate/status").then(renderSim).catch(() => {});
})();
