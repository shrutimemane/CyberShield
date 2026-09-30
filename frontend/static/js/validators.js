/* CyberShield - client-side validators
   ====================================
   Mirrors backend/utils/validators.py. The server ALWAYS re-validates;
   these helpers just give instant inline feedback before submit. */
"use strict";

const CS_USERNAME_RE = /^[a-zA-Z0-9_.]{3,32}$/;
const CS_EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/;
const CS_MIN_PASSWORD = 8;

/** Valid IPv4, four octets 0-255, no leading zeros. */
function csValidIPv4(ip) {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4) return false;
  return parts.every(o => {
    if (!/^\d{1,3}$/.test(o)) return false;
    if (o.length > 1 && o.startsWith("0")) return false; // 012.02.32.4 style
    const n = parseInt(o, 10);
    return n >= 0 && n <= 255;
  });
}

/**
 * Firewall target validation - mirrors validate_firewall_target().
 * Accepts: IPv4 | IPv4:port (1-65535) | 'any'.  Returns an error string or null.
 */
function csValidateFirewallTarget(raw) {
  const target = String(raw || "").trim().toLowerCase();
  if (!target) return "Target is required (IP, IP:port, or 'any').";
  if (target === "any") return null;
  if ((target.match(/:/g) || []).length > 1)
    return "Use IP, IP:port (single colon) or 'any'.";
  if (target.includes("/"))
    return "CIDR ranges are not supported by the simulator - use an exact IP or IP:port.";

  let ipPart = target, portPart = null;
  if (target.includes(":")) {
    [ipPart, portPart] = target.split(":", 1)[1] !== undefined
      ? [target.slice(0, target.indexOf(":")), target.slice(target.indexOf(":") + 1)]
      : [target, null];
    if (!/^\d{1,5}$/.test(portPart || ""))
      return "Port must be a number between 1 and 65535.";
    const port = parseInt(portPart, 10);
    if (port < 1 || port > 65535)
      return "Port must be between 1 and 65535.";
  }
  if (!csValidIPv4(ipPart))
    return "Invalid IPv4 address. Use four octets 0-255, e.g. 203.0.113.66.";
  return null;
}

/** Registration form validation - returns {field: message} of errors. */
function csValidateRegistration(f) {
  const errors = {};
  const fullName = (f.full_name || "").trim();
  const username = (f.username || "").trim();
  const email = (f.email || "").trim();
  const password = f.password || "";
  const confirm = f.confirm_password || "";

  if (fullName.length < 2 || fullName.length > 80)
    errors.full_name = "Please enter your full name (2-80 characters).";
  if (!CS_USERNAME_RE.test(username))
    errors.username = "3-32 characters; letters, numbers, dot or underscore only.";
  if (!CS_EMAIL_RE.test(email))
    errors.email = "Enter a valid email address (e.g. name@example.com).";
  if (password.length < CS_MIN_PASSWORD)
    errors.password = `At least ${CS_MIN_PASSWORD} characters.`;
  else if (!/[A-Za-z]/.test(password) || !/\d/.test(password))
    errors.password = "Must contain both letters and numbers.";
  if (confirm !== password)
    errors.confirm_password = "Passwords do not match.";
  return errors;
}

/** Render inline field errors into .invalid-feedback siblings. */
function csShowFieldErrors(form, errors) {
  form.querySelectorAll(".is-invalid").forEach(el => el.classList.remove("is-invalid"));
  Object.entries(errors).forEach(([field, msg]) => {
    const input = form.querySelector(`[name="${field}"]`);
    if (!input) return;
    input.classList.add("is-invalid");
    const feedback = input.parentElement.querySelector(".invalid-feedback") ||
                     input.nextElementSibling;
    if (feedback && feedback.classList.contains("invalid-feedback"))
      feedback.textContent = msg;
  });
}
