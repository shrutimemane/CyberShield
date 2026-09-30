/* CyberShield alerts page */
"use strict";

async function loadAlerts() {
  const status = document.getElementById("f-status").value;
  const severity = document.getElementById("f-severity").value;
  const type = document.getElementById("f-type").value;
  try {
    const data = await csFetch(`/api/alerts?status=${status}&severity=${severity}&type=${type}`);
    const body = document.getElementById("alerts-body");
    if (!data.alerts.length) {
      body.innerHTML = '<tr><td colspan="9" class="cs-empty">No alerts match the current filters.</td></tr>';
      return;
    }
    body.innerHTML = data.alerts.map(a => `
      <tr>
        <td class="cs-mono text-nowrap">${a.created}</td>
        <td>${sevBadge(a.severity)}</td>
        <td><span class="cs-mono">${escapeHtml(a.type)}</span></td>
        <td><a href="#" class="cs-ip-link cs-mono" data-ip="${escapeHtml(a.source_ip)}">${escapeHtml(a.source_ip)}</a></td>
        <td class="cs-mono">${escapeHtml(a.destination_ip || "-")}</td>
        <td class="small">${escapeHtml(a.reason)}</td>
        <td>${statusBadge(a.status)}</td>
        <td>${a.incident_id ? `<a href="/incidents/${a.incident_id}">#${a.incident_id}</a>` : "-"}</td>
        <td class="text-nowrap">
          ${a.status === "NEW" ? `<button class="btn btn-sm btn-outline-cs btn-ack" data-id="${a.id}">Ack</button>` : ""}
          ${a.status !== "RESOLVED" ? `<button class="btn btn-sm btn-outline-cs btn-resolve" data-id="${a.id}">Resolve</button>` : ""}
          <button class="btn btn-sm btn-outline-cs btn-hash" data-id="${a.id}" title="Evidence hash">SHA-256</button>
        </td>
      </tr>`).join("");

    body.querySelectorAll(".btn-ack").forEach(b => b.addEventListener("click",
      () => alertAction(`/api/alerts/${b.dataset.id}/ack`, "Alert acknowledged")));
    body.querySelectorAll(".btn-resolve").forEach(b => b.addEventListener("click",
      () => alertAction(`/api/alerts/${b.dataset.id}/resolve`, "Alert resolved")));
    body.querySelectorAll(".btn-hash").forEach(b => b.addEventListener("click", async () => {
      try {
        const r = await csFetch(`/api/alerts/${b.dataset.id}/evidence`);
        toast(`Evidence SHA-256: ${r.sha256.slice(0, 24)}...`, "info");
      } catch (e) { toast(e.message, "err"); }
    }));
    body.querySelectorAll(".cs-ip-link").forEach(l => l.addEventListener("click", ev => {
      ev.preventDefault();
      window.open(`/ips?focus=${encodeURIComponent(l.dataset.ip)}`, "_self");
    }));
  } catch (e) {
    toast(e.message, "err");
  }
}

async function alertAction(url, okMsg) {
  try { await csPost(url); toast(okMsg, "ok"); loadAlerts(); }
  catch (e) { toast(e.message, "err"); }
}

document.getElementById("btn-apply").addEventListener("click", loadAlerts);
document.getElementById("btn-refresh").addEventListener("click", loadAlerts);

const btnCsv = document.getElementById("btn-csv");
if (btnCsv) {
  btnCsv.addEventListener("click", async () => {
    btnCsv.disabled = true;
    try { await exportAlertsCsv(); toast("Alerts exported to CSV.", "ok"); }
    catch (e) { toast(e.message, "err"); }
    finally { btnCsv.disabled = false; }
  });
}

loadAlerts();
setInterval(loadAlerts, 8000);
