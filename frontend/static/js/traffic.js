/* CyberShield live traffic page */
"use strict";

let filterFlagged = false;

function renderTraffic(data) {
  // capture badge + soft fallback warning
  const badge = document.getElementById("capture-badge");
  const warn = document.getElementById("capture-warning");
  const st = data.capture_status || {};
  if (st.live_running) {
    badge.className = "badge bg-success";
    badge.innerHTML = '<span class="cs-dot cs-dot-live"></span>LIVE';
    warn.style.display = "none";
  } else if (st.demo_running) {
    badge.className = "badge bg-info";
    badge.innerHTML = '<span class="cs-dot cs-dot-live"></span>DEMO';
    warn.style.display = "none";
  } else {
    badge.className = "badge bg-secondary";
    badge.textContent = "IDLE";
    if (st.live_error) {
      warn.textContent = "Live capture is unavailable (" + st.live_error +
        "). Use PCAP Analysis or Demo Mode.";
      warn.style.display = "block";
    }
  }

  const body = document.getElementById("traffic-body");
  if (!data.packets.length) {
    body.innerHTML = '<tr><td colspan="9" class="cs-empty">No packets captured yet. Start Live Capture, Demo Mode, or import a PCAP file.</td></tr>';
    return;
  }
  body.innerHTML = data.packets.map(p => `
    <tr>
      <td class="cs-mono text-nowrap">${p.time}</td>
      <td class="cs-mono">${escapeHtml(p.src_ip)}</td>
      <td class="cs-mono">${escapeHtml(p.dst_ip)}</td>
      <td>${p.protocol}</td>
      <td class="cs-mono">${p.src_port ?? "-"}</td>
      <td class="cs-mono">${p.dst_port ?? "-"}</td>
      <td>${p.length}</td>
      <td class="cs-mono">${escapeHtml(p.tcp_flags || "-")}</td>
      <td>${statusBadge(p.status)}${p.reason ? ` <span class="small text-cs-muted">${escapeHtml(p.reason)}</span>` : ""}</td>
    </tr>`).join("");
}

async function refreshTraffic() {
  filterFlagged = document.getElementById("chk-flagged").checked;
  const limit = document.getElementById("limit").value;
  try {
    const data = await csFetch(`/api/traffic?limit=${limit}${filterFlagged ? "&flagged=1" : ""}`);
    renderTraffic(data);
  } catch (e) { console.error(e); }
}

document.getElementById("btn-start").addEventListener("click", async () => {
  try {
    const r = await csPost("/api/capture/start");
    if (!r.started) toast(r.message || "Live capture is unavailable. Use PCAP Analysis or Demo Mode.", "warn");
    else toast("Live capture started.", "ok");
  } catch (e) { toast(e.message, "err"); }
  refreshTraffic();
});

document.getElementById("btn-stop").addEventListener("click", async () => {
  try { await csPost("/api/capture/stop"); toast("Capture stopped.", "info"); }
  catch (e) { toast(e.message, "err"); }
  refreshTraffic();
});

document.getElementById("btn-demo").addEventListener("click", async () => {
  try { await csPost("/api/demo/start"); toast("Demo Mode started.", "ok"); }
  catch (e) { toast(e.message, "err"); }
  refreshTraffic();
});

document.getElementById("chk-flagged").addEventListener("change", refreshTraffic);
document.getElementById("limit").addEventListener("change", refreshTraffic);

refreshTraffic();
setInterval(refreshTraffic, 2000);
