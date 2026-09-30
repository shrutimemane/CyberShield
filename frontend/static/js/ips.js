/* CyberShield IP analysis */
"use strict";

const params = new URLSearchParams(location.search);
const focusIp = params.get("focus");

async function loadIps() {
  try {
    const data = await csFetch("/api/ips");
    const body = document.getElementById("ips-body");
    if (!data.ips.length) {
      body.innerHTML = '<tr><td colspan="4" class="cs-empty">No suspicious IPs yet - run Demo Mode.</td></tr>';
      return;
    }
    body.innerHTML = data.ips.map(ip => `
      <tr class="cs-ip-row" data-ip="${escapeHtml(ip.ip)}" style="cursor:pointer">
        <td class="cs-mono">${escapeHtml(ip.ip)} ${scopeBadge(ip.scope)} ${ip.is_blocked ? '<span class="badge bg-danger">BLOCKED</span>' : ""}</td>
        <td>
          <div class="d-flex align-items-center gap-2">
            <div style="width:52px"><div class="progress" style="height:6px;background:#dfe3d9">
              <div class="progress-bar" style="width:${ip.risk_score}%;background:${riskColor(ip.risk_score)}"></div>
            </div></div>
            <span class="small">${ip.risk_score}</span>
          </div>
        </td>
        <td>${ip.alert_count}</td>
        <td class="small text-cs-muted">${escapeHtml(ip.categories || "-")}</td>
      </tr>`).join("");
    body.querySelectorAll(".cs-ip-row").forEach(row =>
      row.addEventListener("click", () => showIp(row.dataset.ip)));
    if (focusIp) showIp(focusIp);
  } catch (e) { toast(e.message, "err"); }
}

function riskColor(score) {
  return score >= 75 ? "#cf4a45" : score >= 50 ? "#dd8a3c" : score >= 25 ? "#e0a639" : "#7B9669";
}

/* Address scope: LAN hosts, documented demo ranges and real external IPs */
function scopeBadge(scope) {
  if (scope === "private") return '<span class="badge bg-secondary">LAN</span>';
  if (scope === "documentation") return '<span class="badge bg-info">DEMO RANGE</span>';
  return '<span class="badge text-bg-dark border border-secondary">EXTERNAL</span>';
}

function scopeLabel(scope) {
  if (scope === "private") return "Private/LAN address (RFC1918)";
  if (scope === "documentation") {
    return "External address in a documentation range (RFC 5737) - the safe " +
           "synthetic attacker used by Demo Mode and the sample PCAP";
  }
  return "External/public address";
}

async function showIp(ip) {
  const box = document.getElementById("ip-detail");
  box.innerHTML = '<div class="cs-empty">Loading profile...</div>';
  try {
    const d = await csFetch(`/api/ips/${encodeURIComponent(ip)}`);
    box.innerHTML = `
      <div class="d-flex justify-content-between align-items-start flex-wrap gap-2">
        <div>
          <h5 class="mb-1 cs-mono">${escapeHtml(d.ip)}</h5>
          <span class="small text-cs-muted">
            ${scopeLabel(d.scope)} &bull;
            first seen ${d.first_seen} &bull; last seen ${d.last_seen}
          </span>
        </div>
        <div class="text-center">
          <div class="cs-risk-ring" style="--risk:${d.risk_score};width:96px;height:96px">
            <span class="val" style="font-size:1.3rem">${d.risk_score}</span>
            <span class="lbl">RISK</span>
          </div>
        </div>
      </div>

      <div class="row g-2 my-3">
        <div class="col-4"><div class="cs-card py-2 text-center"><div class="h5 mb-0">${d.alert_count}</div><div class="cs-stat-label">Alerts</div></div></div>
        <div class="col-4"><div class="cs-card py-2 text-center"><div class="h5 mb-0">${d.packet_count}</div><div class="cs-stat-label">Packets</div></div></div>
        <div class="col-4"><div class="cs-card py-2 text-center"><div class="h5 mb-0">${d.unique_ports}</div><div class="cs-stat-label">Unique Ports</div></div></div>
      </div>

      <div class="row g-3">
        <div class="col-md-6">
          <div class="cs-panel-title"><i class="bi bi-tags"></i> Detection Categories</div>
          <p class="small">${escapeHtml(d.categories || "None")}</p>
          <div class="cs-panel-title"><i class="bi bi-hdd-network"></i> Protocols</div>
          <p class="small cs-mono">${escapeHtml(Object.entries(d.protocols).map(([k, v]) => `${k}:${v}`).join("  ") || "-")}</p>
          <div class="cs-panel-title"><i class="bi bi-bricks"></i> Firewall Simulator Verdict</div>
          <p class="small">
            ${d.firewall_decision === "DENY"
              ? '<span class="badge bg-danger">DENY - would be blocked</span>'
              : '<span class="badge bg-success">ALLOW - no rule matches</span>'}
            <button class="btn btn-sm btn-outline-cs ms-2" id="btn-block-ip">Add BLOCK rule</button>
            ${d.is_blocked ? '<span class="badge bg-danger ms-1">watchlist blocked</span>' : ""}
          </p>
        </div>
        <div class="col-md-6">
          <div class="cs-panel-title"><i class="bi bi-arrow-right-circle"></i> Top Destinations</div>
          <table class="table table-dark-cs">
            <thead><tr><th>Destination</th><th>Packets</th></tr></thead>
            <tbody>${d.top_destinations.map(t => `<tr><td class="cs-mono">${escapeHtml(t.ip)}</td><td>${t.count}</td></tr>`).join("") || '<tr><td colspan="2" class="cs-empty">-</td></tr>'}</tbody>
          </table>
        </div>
      </div>

      <div class="cs-panel-title"><i class="bi bi-activity"></i> Recent Packets from this IP</div>
      <div class="table-responsive cs-scroll-y" style="max-height:220px">
        <table class="table table-dark-cs">
          <thead><tr><th>Time</th><th>To</th><th>Port</th><th>Proto</th><th>Len</th><th>Flags</th><th>Status</th></tr></thead>
          <tbody>
            ${d.recent_packets.map(p => `
              <tr>
                <td class="cs-mono text-nowrap">${p.time}</td>
                <td class="cs-mono">${escapeHtml(p.dst_ip)}</td>
                <td class="cs-mono">${p.dst_port ?? "-"}</td>
                <td>${p.protocol}</td><td>${p.length}</td>
                <td class="cs-mono">${escapeHtml(p.flags || "-")}</td>
                <td>${statusBadge(p.status)}</td>
              </tr>`).join("") || '<tr><td colspan="7" class="cs-empty">No packet detail stored.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="cs-panel-title mt-3"><i class="bi bi-bell"></i> Alert History</div>
      <table class="table table-dark-cs">
        <tbody>
          ${d.alerts.slice(0, 8).map(a => `
            <tr><td class="cs-mono text-nowrap">${a.created}</td>
            <td>${sevBadge(a.severity)}</td>
            <td class="small">${escapeHtml(a.reason)}</td></tr>`).join("") ||
            '<tr><td class="cs-empty">No alerts.</td></tr>'}
        </tbody>
      </table>`;

    const blockBtn = document.getElementById("btn-block-ip");
    blockBtn.addEventListener("click", async () => {
      try {
        await csPost("/api/firewall/rules", { rule_type: "BLOCK", target: d.ip, reason: "Added from IP analysis" });
        toast(`BLOCK rule added for ${d.ip} (simulator only).`, "ok");
        showIp(d.ip);
      } catch (e) { toast(e.message, "err"); }
    });
  } catch (e) {
    box.innerHTML = `<div class="cs-empty">Failed to load profile: ${escapeHtml(e.message)}</div>`;
  }
}

loadIps();
