/* CyberShield - shared helpers */
"use strict";

/** fetch JSON with error propagation */
async function csFetch(url, options = {}) {
  const res = await fetch(url, Object.assign({ headers: { "Accept": "application/json" } }, options));
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function csPost(url, body) {
  return csFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

/** severity badge html */
function sevBadge(sev) {
  return `<span class="badge badge-sev-${sev}">${sev}</span>`;
}
function statusBadge(status) {
  return `<span class="badge badge-status-${status}">${status}</span>`;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(message, kind = "info") {
  let host = document.getElementById("cs-toast-host");
  if (!host) {
    host = document.createElement("div");
    host.id = "cs-toast-host";
    host.style.cssText = "position:fixed;top:70px;right:16px;z-index:2000;display:flex;flex-direction:column;gap:8px;";
    document.body.appendChild(host);
  }
  const el = document.createElement("div");
  const bg = { info: "#1e2a3d", ok: "#0e9384", warn: "#b45309", err: "#dc2626" }[kind] || "#1e2a3d";
  el.style.cssText = `background:${bg};color:#fff;padding:10px 14px;border-radius:8px;font-size:.9rem;max-width:340px;box-shadow:0 8px 24px rgba(30,42,61,.25);`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

/** Chart.js defaults shared by all pages */
if (window.Chart) {
  Chart.defaults.color = "#6C8480";
  Chart.defaults.borderColor = "#e3e7dd";
  Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
}

/** Download the latest alerts as a CSV file (shared by Dashboard + Alerts). */
async function exportAlertsCsv() {
  const res = await fetch("/api/alerts/export", { headers: { "Accept": "text/csv" } });
  if (!res.ok) throw new Error(`Export failed (${res.status})`);
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `cybershield_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}
