/* CyberShield firewall simulator page */
"use strict";

const fwForm = document.getElementById("fw-form");
const fwTarget = document.getElementById("fw-target");
const fwAddBtn = document.getElementById("fw-add");

function setFieldError(input, message) {
  const feedback = input.parentElement.querySelector(".invalid-feedback") ||
                   input.nextElementSibling;
  input.classList.toggle("is-invalid", !!message);
  if (feedback && feedback.classList.contains("invalid-feedback"))
    feedback.textContent = message || "";
}

function setBtnLoading(btn, loading) {
  btn.disabled = loading;
  const spin = btn.querySelector(".spinner-border");
  if (spin) spin.classList.toggle("d-none", !loading);
}

async function loadRules() {
  const body = document.getElementById("fw-body");
  try {
    const data = await csFetch("/api/firewall/rules");
    if (!data.rules.length) {
      body.innerHTML = `
        <tr><td colspan="7">
          <div class="cs-empty">
            <i class="bi bi-shield" style="font-size:1.6rem;display:block;margin-bottom:.4rem"></i>
            No rules yet &mdash; all traffic is implicitly <b>allowed</b> (simulation).<br>
            <span class="small">Add a rule on the left to see how the firewall would decide.</span>
          </div>
        </td></tr>`;
      return;
    }
    body.innerHTML = data.rules.map((r, i) => `
      <tr>
        <td class="text-cs-muted">${i + 1}</td>
        <td>${r.type === "BLOCK"
          ? '<span class="badge badge-sev-CRITICAL">BLOCK</span>'
          : '<span class="badge badge-status-RESOLVED">ALLOW</span>'}</td>
        <td class="cs-mono">${escapeHtml(r.target)}</td>
        <td class="small">${escapeHtml(r.reason || "-")}</td>
        <td class="text-end cs-mono">${r.hits}</td>
        <td>${r.active
          ? '<span class="badge badge-status-CONTAINED"><span class="cs-dot cs-dot-live"></span>Active</span>'
          : '<span class="badge badge-status-NORMAL">Off</span>'}</td>
        <td class="text-end text-nowrap">
          <button class="btn btn-sm btn-outline-cs btn-toggle" data-id="${r.id}"
                  title="${r.active ? "Disable rule" : "Enable rule"}">${r.active ? "Disable" : "Enable"}</button>
          <button class="btn btn-sm btn-outline-danger-cs btn-del" data-id="${r.id}" title="Delete rule">Del</button>
        </td>
      </tr>`).join("");

    body.querySelectorAll(".btn-toggle").forEach(b => b.addEventListener("click", async () => {
      try {
        await csPost(`/api/firewall/rules/${b.dataset.id}/toggle`);
        toast("Rule updated.", "ok");
      } catch (e) { toast(e.message, "err"); }
      loadRules();
    }));
    body.querySelectorAll(".btn-del").forEach(b => b.addEventListener("click", async () => {
      if (!confirm("Delete this firewall rule? This cannot be undone.")) return;
      try {
        await csPost(`/api/firewall/rules/${b.dataset.id}/delete`);
        toast("Rule deleted.", "ok");
      } catch (e) { toast(e.message, "err"); }
      loadRules();
    }));
  } catch (e) {
    body.innerHTML = `<tr><td colspan="7" class="cs-empty">
      <i class="bi bi-wifi-off" style="display:block;margin-bottom:.4rem"></i>
      Failed to load rules: ${escapeHtml(e.message)}</td></tr>`;
    toast(e.message, "err");
  }
}

/* live inline validation as the analyst types */
fwTarget.addEventListener("input", () => {
  const err = csValidateFirewallTarget(fwTarget.value);
  setFieldError(fwTarget, err);
});

fwForm.addEventListener("submit", async ev => {
  ev.preventDefault();
  const err = csValidateFirewallTarget(fwTarget.value);
  setFieldError(fwTarget, err);
  if (err) { fwTarget.focus(); return; }
  setBtnLoading(fwAddBtn, true);
  try {
    await csPost("/api/firewall/rules", {
      rule_type: document.getElementById("fw-type").value,
      target: fwTarget.value.trim(),
      reason: document.getElementById("fw-reason").value.trim(),
    });
    toast("Rule added (simulator only).", "ok");
    fwTarget.value = "";
    document.getElementById("fw-reason").value = "";
    setFieldError(fwTarget, "");
    loadRules();
  } catch (e) {
    // server re-validated and rejected -> show inline + toast
    setFieldError(fwTarget, e.message);
    toast(e.message, "err");
  } finally {
    setBtnLoading(fwAddBtn, false);
  }
});

document.getElementById("sim-run").addEventListener("click", async () => {
  const srcInput = document.getElementById("sim-src");
  const portInput = document.getElementById("sim-port");
  const box = document.getElementById("sim-result");
  const btn = document.getElementById("sim-run");

  const srcErr = srcInput.value.trim().toLowerCase() === "any"
    ? null
    : (csValidIPv4(srcInput.value.trim()) ? null
       : "Enter a valid IPv4 address (or 'any').");
  setFieldError(srcInput, srcErr);
  const port = portInput.value.trim();
  const portErr = port && (!/^\d{1,5}$/.test(port) || +port < 1 || +port > 65535)
    ? "Port must be between 1 and 65535." : "";
  setFieldError(portInput, portErr);
  if (srcErr || portErr) return;

  setBtnLoading(btn, true);
  try {
    const r = await csPost("/api/firewall/simulate",
                           { src_ip: srcInput.value.trim(), dst_port: port || null });
    box.innerHTML = r.action === "DENY"
      ? `<div class="alert alert-danger small mb-0 py-2"><b>DENY</b> - matched rule <span class="cs-mono">${escapeHtml(r.matched_rule)}</span></div>`
      : `<div class="alert alert-success small mb-0 py-2"><b>ALLOW</b> - no matching rule${r.matched_rule ? ` (explicit <span class="cs-mono">${escapeHtml(r.matched_rule)}</span>)` : " (implicit allow-all)"}</div>`;
  } catch (e) {
    box.innerHTML = `<div class="alert alert-warning small mb-0 py-2">${escapeHtml(e.message)}</div>`;
  } finally {
    setBtnLoading(btn, false);
  }
});

document.getElementById("fw-refresh").addEventListener("click", loadRules);
loadRules();
