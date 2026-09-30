/* CyberShield SOC dashboard: polls /api/dashboard + /api/metrics/timeline */
"use strict";

const fmtInt = n => (n ?? 0).toLocaleString();
const fmtKB = b => b >= 1048576 ? (b / 1048576).toFixed(1) + " MB"
                 : b >= 1024 ? (b / 1024).toFixed(1) + " KB" : fmtInt(b || 0);

const SEV_COLORS = { CRITICAL: "#cf4a45", HIGH: "#dd8a3c", MEDIUM: "#e0a639", LOW: "#6C8480" };
const PALETTE = ["#7B9669", "#6C8480", "#cf4a45", "#dd8a3c", "#8a917f", "#e0a639"];

let chartTraffic = null, chartSeverity = null, chartAlertsTime = null;
let currentHours = 24;

/* ---------------- charts ---------------- */
function initCharts() {
  const grid = { color: "#eef1ea" };
  const smallTicks = { maxTicksLimit: 10, maxRotation: 0, font: { size: 10 } };

  chartTraffic = new Chart(document.getElementById("chart-traffic"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "Packets", data: [], borderColor: "#7B9669",
          backgroundColor: "rgba(123,150,105,.12)", fill: true,
          tension: .35, pointRadius: 0, borderWidth: 2, yAxisID: "y" },
        { label: "Volume (KB)", data: [], borderColor: "#6C8480",
          backgroundColor: "transparent", fill: false,
          tension: .35, pointRadius: 0, borderWidth: 1.5,
          borderDash: [5, 3], yAxisID: "y1" },
      ],
    },
    options: {
      maintainAspectRatio: false,
      responsive: true,
      layout: { padding: { top: 6, right: 8 } },
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: smallTicks },
        y: { beginAtZero: true, grid, ticks: { precision: 0, font: { size: 10 } },
             title: { display: true, text: "Packets", font: { size: 10 } } },
        y1: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false },
              ticks: { callback: v => fmtKB(v * 1024), font: { size: 10 } },
              title: { display: true, text: "Volume", font: { size: 10 } } },
      },
    },
  });

  chartSeverity = new Chart(document.getElementById("chart-severity"), {
    type: "doughnut",
    data: {
      labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
      datasets: [{ data: [0, 0, 0, 0], backgroundColor: Object.values(SEV_COLORS),
                   borderWidth: 2, borderColor: "#ffffff" }],
    },
    options: {
      maintainAspectRatio: false,
      responsive: true,
      cutout: "62%",
      layout: { padding: 4 },
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 10, boxHeight: 10, font: { size: 10 } } },
        tooltip: { callbacks: { label: ctx => {
          const total = ctx.dataset.data.reduce((a, b) => a + b, 0) || 1;
          return ` ${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed / total * 100)}%)`;
        } } },
      },
    },
  });

  chartAlertsTime = new Chart(document.getElementById("chart-alerts-time"), {
    type: "line",
    data: {
      labels: [],
      datasets: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => ({
        label: sev, data: [], borderColor: SEV_COLORS[sev],
        backgroundColor: SEV_COLORS[sev] + "22", fill: true,
        tension: .35, pointRadius: 0, borderWidth: 1.6,
      })),
    },
    options: {
      maintainAspectRatio: false,
      responsive: true,
      layout: { padding: { top: 6, right: 8 } },
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, boxHeight: 10, font: { size: 10 } } } },
      scales: {
        x: { stacked: true, grid: { display: false }, ticks: smallTicks },
        y: { stacked: true, beginAtZero: true, grid,
             ticks: { precision: 0, font: { size: 10 } },
             title: { display: true, text: "Alerts", font: { size: 10 } } },
      },
    },
  });
}

function setEmpty(id, empty) {
  document.getElementById(id)?.classList.toggle("d-none", !empty);
}

function renderTraffic(metrics) {
  const rows = metrics.buckets || [];
  chartTraffic.data.labels = rows.map(r => r.label);
  chartTraffic.data.datasets[0].data = rows.map(r => r.packets);
  chartTraffic.data.datasets[1].data = rows.map(r => +(r.bytes / 1024).toFixed(2));
  chartTraffic.update("none");
  setEmpty("traffic-empty", !rows.some(r => r.packets > 0));

  const note = `packets per interval (window: ${metrics.hours >= 168 ? "7D" : metrics.hours + "H"}`
             + ` · ${metrics.interval_minutes} min buckets)`;
  document.getElementById("traffic-window-note").textContent = " — " + note;
  document.getElementById("alerts-window-note").textContent =
    ` — by severity (window: ${metrics.hours >= 168 ? "7D" : metrics.hours + "H"})`;

  const p = metrics.summary || {};
  document.getElementById("sub-packets").textContent =
    `${fmtInt(p.packets)} in window · ${fmtKB(p.bytes)} captured`;
}

function renderAlertsTime(metrics) {
  const rows = metrics.buckets || [];
  chartAlertsTime.data.labels = rows.map(r => r.label);
  const key = s => "alerts_" + s.toLowerCase();
  chartAlertsTime.data.datasets.forEach(ds => {
    ds.data = rows.map(r => r[key(ds.label)] || 0);
  });
  chartAlertsTime.update("none");
  setEmpty("alerts-empty", !(metrics.summary?.alerts > 0));
}

function renderSeverity(sevMap) {
  const sev = sevMap || {};
  chartSeverity.data.datasets[0].data =
    [sev.CRITICAL || 0, sev.HIGH || 0, sev.MEDIUM || 0, sev.LOW || 0];
  chartSeverity.update("none");
  setEmpty("severity-empty", !(sev.CRITICAL || sev.HIGH || sev.MEDIUM || sev.LOW));
}

/* ---------------- risk card ---------------- */
const RISK_TOKENS = { accent: "#7B9669", yellow: "#e0a639", orange: "#dd8a3c",
                      red: "#cf4a45", muted: "#6C8480" };

function renderRisk(c) {
  const valEl = document.getElementById("stat-risk");
  const labelEl = document.getElementById("risk-label");
  const factorsEl = document.getElementById("risk-factors");
  const ring = document.getElementById("risk-ring");
  const sourceEl = document.getElementById("risk-source");

  if (c.risk_score === null || c.risk_score === undefined) {
    valEl.textContent = "–";
    labelEl.textContent = "INSUFFICIENT DATA";
    factorsEl.textContent = "No open alerts, incidents or watchlist entries yet.";
    ring.style.setProperty("--risk", 0);
    ring.style.setProperty("--cs-accent", RISK_TOKENS.muted);
    sourceEl.textContent = "no data";
    return;
  }
  valEl.textContent = c.risk_score;
  labelEl.textContent = c.risk_label;
  ring.style.setProperty("--risk", c.risk_score);
  ring.style.setProperty("--cs-accent", RISK_TOKENS[c.risk_color] || RISK_TOKENS.accent);

  const f = c.risk_factors || {};
  const parts = [];
  if (f.open_alerts_24h) parts.push(`${f.open_alerts_24h} open alert(s)`);
  if (f.open_incidents) parts.push(`${f.open_incidents} open incident(s)`);
  if (f.watchlist_ips) parts.push(`${f.watchlist_ips} watchlisted IP(s)`);
  factorsEl.textContent = parts.length
    ? "Main factors: " + parts.join(" · ")
    : "Score trending to zero as items resolve.";
  sourceEl.textContent = c.demo_data ? "demo data" : "live data";
}

/* ---------------- metric cards ---------------- */
function renderStats(data) {
  const c = data.cards;
  document.getElementById("stat-packets").textContent = fmtInt(c.total_packets);
  document.getElementById("stat-connections").textContent = fmtInt(c.active_connections);
  document.getElementById("stat-alerts").textContent = fmtInt(c.security_alerts);
  document.getElementById("stat-suspicious").textContent = fmtInt(c.suspicious_ips);
  document.getElementById("stat-incidents").textContent = fmtInt(c.open_incidents);

  document.getElementById("sub-alerts").textContent =
    `${c.alerts_high_priority || 0} high/critical · ${c.alerts_resolved_24h || 0} resolved`;
  document.getElementById("sub-suspicious").textContent =
    (c.blocked_ips ? `${c.blocked_ips} blocked · ` : "") + "risk score ≥ 20";
  document.getElementById("sub-incidents").textContent =
    c.open_incidents ? "awaiting investigation" : "nothing open — all clear";

  renderRisk(c);

  const pill = document.getElementById("nav-unread");
  if (pill) {
    const n = c.open_alerts || 0;
    pill.style.display = n > 0 ? "inline-flex" : "none";
    pill.textContent = n > 99 ? "99+" : n;
  }

  renderSeverity(data.charts.alerts_by_severity);
  renderTopIps(data.top_suspicious || []);
  renderIncidents(data.recent_incidents || []);
  renderRecentAlerts(data.recent_alerts || []);
  document.getElementById("last-update").textContent =
    new Date().toLocaleTimeString();
}

/* ---------------- sections D / E / C ---------------- */
function renderTopIps(rows) {
  const box = document.getElementById("top-ips");
  if (!rows.length) {
    box.innerHTML = `<div class="cs-empty">
      <i class="bi bi-shield-check" style="font-size:1.5rem;display:block;margin-bottom:.35rem"></i>
      No suspicious IPs right now.<br>
      <span class="small">Demo Mode or a PCAP import will populate this watchlist.</span></div>`;
    return;
  }
  const max = rows[0].risk_score || 1;
  box.innerHTML = rows.slice(0, 6).map((r, i) => `
    <div class="cs-tt-item cs-ip-link" data-ip="${escapeHtml(r.ip)}" title="Open IP analysis">
      <div class="d-flex justify-content-between align-items-center">
        <span class="text-truncate"><span class="cs-tt-rank">${i + 1}</span><span class="cs-mono">${escapeHtml(r.ip)}</span></span>
        <span class="cs-tt-val ms-2">${r.risk_score}</span>
      </div>
      <div class="cs-tt-bar"><div style="width:${Math.max(6, Math.round(r.risk_score / max * 100))}%;background:${riskCss(r.risk_score)}"></div></div>
      <div class="small text-cs-muted">${r.alert_count} alert(s) · ${escapeHtml(r.categories || "-")}</div>
    </div>`).join("");
  box.querySelectorAll(".cs-ip-link").forEach(l => l.addEventListener("click", () =>
    window.open(`/ips?focus=${encodeURIComponent(l.dataset.ip)}`, "_self")));
}

function riskCss(score) {
  return score >= 75 ? "#cf4a45" : score >= 50 ? "#dd8a3c"
       : score >= 25 ? "#e0a639" : "#7B9669";
}

function renderIncidents(rows) {
  const box = document.getElementById("recent-incidents");
  if (!rows.length) {
    box.innerHTML = `<div class="cs-empty">
      <i class="bi bi-folder-check" style="font-size:1.5rem;display:block;margin-bottom:.35rem"></i>
      No incidents recorded.</div>`;
    return;
  }
  box.innerHTML = rows.map(i => `
    <a class="d-block border-bottom py-2 text-decoration-none" style="border-color:var(--cs-border) !important;color:inherit"
       href="/incidents/${i.id}" title="Open incident ${escapeHtml(i.ref)}">
      <div><span class="cs-mono">${escapeHtml(i.ref)}</span> ${sevBadge(i.severity)} ${statusBadge(i.status)}</div>
      <div class="small text-truncate">${escapeHtml(i.title)}</div>
      <div class="small text-cs-muted">${i.created}</div>
    </a>`).join("");
}

function renderRecentAlerts(rows) {
  const tbody = document.getElementById("recent-alerts");
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="cs-empty">No alerts yet - run Demo Mode to generate traffic.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(a => `
    <tr>
      <td class="cs-mono text-nowrap small">${a.created}</td>
      <td>${sevBadge(a.severity)}</td>
      <td class="cs-mono small">
        <a href="/ips?focus=${encodeURIComponent(a.source_ip)}" class="cs-ip-link" title="Analyze source IP">${escapeHtml(a.source_ip)}</a>
      </td>
      <td class="small">${escapeHtml(a.type)}</td>
      <td>${a.incident_id
        ? `<a href="/incidents/${a.incident_id}" class="small" title="Open linked incident"><i class="bi bi-folder2-open"></i></a>` : ""}</td>
    </tr>`).join("");
}

/* ---------------- monitoring strip (Section F) ---------------- */
function renderCaptureBadge(status) {
  const el = document.getElementById("capture-badge");
  const detail = document.getElementById("monitor-detail");
  if (status.live_running) {
    el.className = "badge text-bg-success";
    el.innerHTML = '<span class="cs-dot cs-dot-live"></span>LIVE CAPTURE';
    detail.textContent = `Capturing on interface '${status.interface || "default"}' · ${fmtInt(status.live_captured || 0)} packets this session`;
  } else if (status.demo_running) {
    el.className = "badge text-bg-warning";
    el.innerHTML = '<span class="cs-dot cs-dot-live"></span>DEMO MODE';
    detail.textContent = "Synthetic training traffic is flowing (clearly labelled demo data).";
  } else {
    el.className = "badge text-bg-secondary";
    el.textContent = "MONITORING STOPPED";
    detail.textContent = status.live_error
      ? `Live capture unavailable (${status.live_error}). Use Demo Mode or PCAP Analysis.`
      : "No active capture - use Demo Mode, Live Capture, or PCAP Analysis.";
  }
  const btnDemo = document.getElementById("btn-demo");
  if (btnDemo) btnDemo.disabled = !!status.demo_running;
  const btnLive = document.getElementById("btn-live");
  if (btnLive) btnLive.disabled = !!status.live_running;
}

/* ---------------- data loading ---------------- */
let loadingTimeline = false;
async function loadTimeline() {
  if (loadingTimeline) return;           // prevent duplicate parallel requests
  loadingTimeline = true;
  try {
    const metrics = await csFetch(`/api/metrics/timeline?hours=${currentHours}`);
    renderTraffic(metrics);
    renderAlertsTime(metrics);
  } catch (e) {
    console.error(e);
    toast("Failed to load charts: " + e.message, "err");
  } finally {
    loadingTimeline = false;
  }
}

let refreshInFlight = false;
async function refresh() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const data = await csFetch("/api/dashboard");
    renderStats(data);
    renderCaptureBadge(data.capture_status || {});
  } catch (e) {
    console.error(e);
    toast("Dashboard refresh failed: " + e.message, "err");
  } finally {
    refreshInFlight = false;
  }
}

/* ---------------- controls ---------------- */
document.getElementById("btn-demo").addEventListener("click", async ev => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  try {
    await csPost("/api/demo/start");
    toast("Demo Mode started - synthetic traffic is flowing.", "ok");
    refresh(); loadTimeline();
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; }
});

document.getElementById("btn-live").addEventListener("click", async ev => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  try {
    const r = await csPost("/api/capture/start");
    if (r.started) toast("Live capture started.", "ok");
    else toast(r.message || "Live capture is unavailable. Use PCAP Analysis or Demo Mode.", "warn");
    refresh();
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; }
});

document.querySelectorAll(".cs-seg-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".cs-seg-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    currentHours = parseInt(btn.dataset.hours, 10);
    loadTimeline();
  });
});

const btnCsv = document.getElementById("btn-csv");
if (btnCsv) {
  btnCsv.addEventListener("click", async () => {
    btnCsv.disabled = true;
    try {
      await exportAlertsCsv();
      toast("Alerts exported to CSV.", "ok");
    } catch (e) { toast(e.message, "err"); }
    finally { btnCsv.disabled = false; }
  });
}

document.querySelectorAll(".scenario-chip").forEach(chip => {
  chip.addEventListener("click", async () => {
    chip.disabled = true;
    try {
      const r = await csPost("/api/demo/inject", { scenario: chip.dataset.scenario });
      toast(`Injected ${r.injected} packets (${chip.dataset.scenario}) - ${r.result.alerts_created || 0} new alert(s).`, "ok");
      refresh(); loadTimeline();
    } catch (e) { toast(e.message, "err"); }
    finally { chip.disabled = false; }
  });
});

initCharts();
refresh();
loadTimeline();
setInterval(refresh, 5000);
setInterval(loadTimeline, 15000);
