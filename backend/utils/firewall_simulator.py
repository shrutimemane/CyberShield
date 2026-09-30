"""
CyberShield - Firewall rule simulator (EDUCATIONAL ONLY)
========================================================

Simulates deny/allow decisions against a rule table so students can see how a
firewall would treat the traffic CyberShield observed. IT DOES NOT BLOCK
ANYTHING REAL - no packets are filtered; this is a policy-training aid.

Rule matching (first match wins, implicit allow-all at the end):
  * target "203.0.113.66"        -> matches source IP
  * target "203.0.113.66:80"     -> matches source IP AND destination port
  * target "any"                 -> matches any source
"""

from backend.models import FirewallRule, db


def simulate(src_ip: str, dst_ip: str, dst_port: int | None) -> dict:
    """Return {'action': 'DENY'|'ALLOW', 'rule': <matched rule or None>}."""
    for rule in FirewallRule.query.filter_by(active=True) \
            .order_by(FirewallRule.id.asc()).all():
        target = (rule.target or "").strip().lower()
        if ":" in target:
            ip_part, port_part = target.split(":", 1)
            try:
                port_match = int(port_part) == int(dst_port or -1)
            except ValueError:
                port_match = False
            ip_match = ip_part == "any" or ip_part == (src_ip or "").lower()
        else:
            ip_match = target == "any" or target == (src_ip or "").lower()
            port_match = True

        if ip_match and port_match:
            if rule.rule_type == "BLOCK":
                rule.hit_count = (rule.hit_count or 0) + 1
                db.session.commit()
            return {"action": "DENY" if rule.rule_type == "BLOCK" else "ALLOW",
                    "rule": rule}
    return {"action": "ALLOW", "rule": None}


def would_block_packets(packets) -> int:
    """How many of these packets a real firewall with these rules would drop."""
    denied = 0
    for p in packets or []:
        if simulate(p.get("src_ip"), p.get("dst_ip"), p.get("dst_port"))["action"] == "DENY":
            denied += 1
    return denied
