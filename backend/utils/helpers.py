"""CyberShield - shared helper functions."""

import html
import ipaddress
import json
import re
from datetime import datetime, timezone


# Real LAN ranges only. Python's str.is_private also counts documentation
# ranges (203.0.113.0/24 etc.), which would label the demo attacker as "LAN".
_LAN_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
))

# RFC 5737 / RFC 3849 documentation ranges - the safe "pretend attacker" IPs
# used by the demo traffic generator.
_DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))


def ip_scope(ip: str) -> str:
    """Classify an address for the UI: private | documentation | public | invalid."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except (ValueError, TypeError):
        return "invalid"
    def _in(addr, networks):
        return any(addr.version == net.version and addr in net for net in networks)

    if _in(addr, _LAN_NETWORKS):
        return "private"
    if _in(addr, _DOC_NETWORKS):
        return "documentation"
    return "public"


def is_private_ip(ip: str) -> bool:
    """True for real LAN addresses (RFC1918 / loopback / link-local)."""
    return ip_scope(ip) == "private"


def safe_json_loads(text, default=None):
    try:
        return json.loads(text) if text else (default if default is not None else {})
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


def safe_json_dumps(obj) -> str:
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return "{}"


def escape_html(text) -> str:
    return html.escape(str(text), quote=True)


def fmt_dt(value, fmt="%Y-%m-%d %H:%M:%S"):
    if value is None:
        return "-"
    return value.strftime(fmt) if isinstance(value, datetime) else str(value)


def utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def slugify(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(text))[:80]


def human_bytes(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
