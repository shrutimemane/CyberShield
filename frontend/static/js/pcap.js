/* CyberShield PCAP analysis page */
"use strict";

const modal = new bootstrap.Modal(document.getElementById("pcapModal"));

async function uploadPcap(ev) {
  ev.preventDefault();
  const input = document.getElementById("pcap-file");
  const btn = document.getElementById("btn-upload");
  const box = document.getElementById("upload-result");
  if (!input.files.length) return;
  const fd = new FormData();
  fd.append("pcap_file", input.files[0]);
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Analyzing...';
  try {
    const res = await fetch("/api/pcap/upload", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Upload failed");
    box.innerHTML = `
      <div class="alert alert-success small mb-2">
        <b>${escapeHtml(data.filename)}</b>: ${data.packets} packets parsed,
        <b>${data.alerts_created}</b> alerts, <b>${data.incidents_created}</b> incidents created.
      </div>
      <div class="small text-cs-muted cs-mono" style="word-break:break-all">SHA-256: ${data.sha256}</div>`;
    setTimeout(() => location.reload(), 2500);
  } catch (e) {
    box.innerHTML = `<div class="alert alert-danger small mb-0">${escapeHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-upload"></i> Upload & Analyze';
  }
}

async function showDetails(id) {
  try {
    const d = await csFetch(`/api/pcap/${id}`);
    document.getElementById("pcapModalTitle").textContent = d.filename;
    document.getElementById("pcapModalBody").innerHTML = `
      <table class="table table-dark-cs">
        <tr><td class="text-cs-muted">Packets</td><td>${d.packets}</td></tr>
        <tr><td class="text-cs-muted">Size</td><td>${d.size}</td></tr>
        <tr><td class="text-cs-muted">Alerts found</td><td>${d.alerts_found}</td></tr>
        <tr><td class="text-cs-muted">Uploaded</td><td>${d.uploaded}</td></tr>
        <tr><td class="text-cs-muted">SHA-256</td><td class="cs-mono" style="word-break:break-all">${d.sha256 || "-"}</td></tr>
        <tr><td class="text-cs-muted">Protocols</td><td class="cs-mono">${escapeHtml(Object.entries(d.protocols).map(([k, v]) => `${k}: ${v}`).join(" | ") || "-")}</td></tr>
      </table>
      <div class="cs-panel-title">Top Talkers (sources)</div>
      <table class="table table-dark-cs">
        <thead><tr><th>Source IP</th><th>Packets</th></tr></thead>
        <tbody>${Object.entries(d.top_talkers).map(([ip, n]) => `<tr><td class="cs-mono">${escapeHtml(ip)}</td><td>${n}</td></tr>`).join("") || '<tr><td colspan="2" class="cs-empty">-</td></tr>'}</tbody>
      </table>`;
    modal.show();
  } catch (e) { toast(e.message, "err"); }
}

document.getElementById("pcap-form").addEventListener("submit", uploadPcap);

document.querySelectorAll(".btn-detail").forEach(b =>
  b.addEventListener("click", () => showDetails(b.dataset.id)));

document.querySelectorAll(".btn-reanalyze").forEach(b =>
  b.addEventListener("click", async () => {
    try {
      const r = await csPost(`/api/pcap/${b.dataset.id}/reanalyze`);
      toast(`Re-analysis done: ${r.result.alerts_created} new alerts.`, "ok");
      setTimeout(() => location.reload(), 1500);
    } catch (e) { toast(e.message, "err"); }
  }));

document.querySelectorAll(".btn-delete").forEach(b =>
  b.addEventListener("click", async () => {
    if (!confirm("Delete this PCAP file and its record?")) return;
    try { await csPost(`/api/pcap/${b.dataset.id}/delete`); location.reload(); }
    catch (e) { toast(e.message, "err"); }
  }));
