/* CyberShield incidents list */
"use strict";

async function loadIncidents() {
  const status = document.getElementById("f-status").value;
  try {
    const data = await csFetch(`/api/incidents?status=${status}`);
    const body = document.getElementById("incidents-body");
    if (!data.incidents.length) {
      body.innerHTML = '<tr><td colspan="9" class="cs-empty">No incidents. Open Demo Mode and inject an attack scenario to see the full detection -> alert -> incident flow.</td></tr>';
      return;
    }
    body.innerHTML = data.incidents.map(i => `
      <tr>
        <td class="cs-mono">${i.ref}</td>
        <td>${escapeHtml(i.title)}</td>
        <td>${sevBadge(i.severity)}</td>
        <td>${statusBadge(i.status)}</td>
        <td class="cs-mono">${escapeHtml(i.source_ip || "-")}</td>
        <td class="cs-mono text-nowrap">${i.created}</td>
        <td>${i.alerts}</td>
        <td>${i.events}</td>
        <td><a class="btn btn-sm btn-outline-cs" href="/incidents/${i.id}"><i class="bi bi-search"></i> Investigate</a></td>
      </tr>`).join("");
  } catch (e) { toast(e.message, "err"); }
}

document.getElementById("f-status").addEventListener("change", loadIncidents);
loadIncidents();
setInterval(loadIncidents, 10000);
