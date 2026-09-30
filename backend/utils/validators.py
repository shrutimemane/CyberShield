"""
CyberShield - input validators
==============================

Shared server-side validation helpers. The same rules are mirrored in the
browser (static/js/validators.js) for instant inline feedback, but the server
always re-validates: frontend validation alone is never trusted.

Firewall targets supported by the rule engine (utils/firewall_simulator.py):
  * IPv4 address          203.0.113.66
  * IPv4 address + port   203.0.113.66:80
  * wildcard              any
CIDR (192.168.1.0/24) is intentionally NOT accepted: the simulator matches on
exact string equality, so a CIDR target could never match and would silently
never fire. We reject it instead of storing a dead rule.
"""

import ipaddress
import re

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

MIN_PASSWORD_LENGTH = 8


class ValidationError(Exception):
    """Raised when user-supplied input fails validation."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def validate_registration(full_name: str, username: str, email: str,
                          password: str, confirm: str = None,
                          confirm_password: str = None) -> dict:
    """Validate the registration form; return cleaned fields or raise
    ValidationError with a human-readable message.

    ``confirm`` and ``confirm_password`` are accepted as the confirmation
    field (the template posts ``confirm_password``)."""
    full_name = (full_name or "").strip()
    username = (username or "").strip().lower()
    email = (email or "").strip().lower()
    password = password or ""
    confirm = confirm if confirm is not None else confirm_password
    confirm = confirm or ""

    if len(full_name) < 2 or len(full_name) > 80:
        raise ValidationError("Please enter your full name (2-80 characters).")
    if not USERNAME_RE.match(username):
        raise ValidationError(
            "Username must be 3-32 characters; letters, numbers, dot or underscore only.")
    if not EMAIL_RE.match(email) or len(email) > 120:
        raise ValidationError("Please enter a valid email address (e.g. name@example.com).")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValidationError("Password must contain both letters and numbers.")
    if password != confirm:
        raise ValidationError("Passwords do not match.")

    return {"full_name": full_name, "username": username,
            "email": email, "password": password}


def validate_password_strength(password: str) -> str | None:
    """Return an error message for a weak password, or None if acceptable."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"At least {MIN_PASSWORD_LENGTH} characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Letters and numbers."
    return None


def validate_firewall_target(raw: str) -> str:
    """Strict validation of firewall rule targets.

    Accepts:  IPv4  (203.0.113.66)
              IPv4:port  (203.0.113.66:80, port 1-65535)
              wildcard  'any'
    Rejects everything else (malformed IPs, out-of-range octets/ports,
    leading-zero octets like 012.02.32.0444, CIDR, hostnames, empty input).
    Returns the cleaned target string or raises ValidationError.
    """
    target = (raw or "").strip().lower()
    if not target:
        raise ValidationError("Target is required (IP, IP:port, or 'any').")
    if target == "any":
        return "any"

    # extra separators / stray ports -> reject early
    if target.count(":") > 1:
        raise ValidationError(
            "Invalid target: use IP, IP:port (single colon) or 'any'.")
    if "/" in target:
        raise ValidationError(
            "CIDR ranges are not supported by the simulator - use an exact IP or IP:port.")

    ip_part, port_part = target, None
    if ":" in target:
        ip_part, port_part = target.split(":", 1)
        if not port_part.isdigit():
            raise ValidationError("Port must be a number between 1 and 65535.")
        port = int(port_part)
        if not (1 <= port <= 65535):
            raise ValidationError("Port must be between 1 and 65535.")

    # ipaddress.ip_address rejects out-of-range octets, but accepts
    # leading-zero forms like 012.02.32.4 on some versions - reject
    # those explicitly as malformed input.
    if any(len(octet) > 1 and octet.startswith("0") for octet in ip_part.split(".")):
        raise ValidationError(
            "Invalid IPv4 address: octets cannot have leading zeros.")
    try:
        addr = ipaddress.ip_address(ip_part)
    except ValueError:
        raise ValidationError(
            "Invalid IPv4 address. Use four octets 0-255, e.g. 203.0.113.66.")
    if addr.version != 4:
        raise ValidationError("Only IPv4 addresses are supported.")

    return f"{ip_part}:{port}" if port_part else ip_part


def validate_simulate_payload(src_ip: str, dst_port) -> tuple[str, int | None]:
    """Validate the firewall simulator form: source must be a valid IPv4 or
    'any'; destination port (if given) must be 1-65535."""
    src = (src_ip or "").strip().lower()
    if src != "any":
        src = validate_firewall_target(src)
    if dst_port in ("", None):
        return src, None
    try:
        port = int(dst_port)
    except (TypeError, ValueError):
        raise ValidationError("Destination port must be a number between 1 and 65535.")
    if not (1 <= port <= 65535):
        raise ValidationError("Destination port must be between 1 and 65535.")
    return src, port


__all__ = ["ValidationError", "validate_registration", "validate_password_strength",
           "validate_firewall_target", "validate_simulate_payload",
           "USERNAME_RE", "EMAIL_RE", "MIN_PASSWORD_LENGTH"]
