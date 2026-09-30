"""
CyberShield - Packet parser
===========================

Validates normalized packet dicts (from any capture source) and turns them
into PacketRecord ORM rows ready for persistence. Keeps parsing logic in one
place so capture sources stay thin.
"""

from backend.models import PacketRecord
from backend.utils.helpers import is_private_ip

ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "OTHER"}


def parse_packet(pkt: dict) -> PacketRecord | None:
    """Convert a normalized packet dict to a PacketRecord, or None if invalid."""
    try:
        if not pkt.get("src_ip") or not pkt.get("dst_ip"):
            return None
        protocol = str(pkt.get("protocol", "OTHER")).upper()
        if protocol not in ALLOWED_PROTOCOLS:
            protocol = "OTHER"
        return PacketRecord(
            capture_id=str(pkt.get("capture_id", "unknown"))[:64],
            timestamp=pkt.get("timestamp"),
            src_ip=str(pkt["src_ip"])[:45],
            dst_ip=str(pkt["dst_ip"])[:45],
            src_port=_int_or_none(pkt.get("src_port")),
            dst_port=_int_or_none(pkt.get("dst_port")),
            protocol=protocol,
            length=int(pkt.get("length") or 0),
            tcp_flags=str(pkt.get("tcp_flags") or "")[:32],
            status="NORMAL",
        )
    except (TypeError, ValueError):
        return None


def parse_many(packets) -> list[PacketRecord]:
    out = []
    for p in packets or []:
        rec = parse_packet(p)
        if rec is not None:
            out.append(rec)
    return out


def _int_or_none(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def classify_status(record: PacketRecord, flagged_sources: set[str]):
    """Mark a packet FLAGGED when its source IP currently has active alerts."""
    if record.src_ip in flagged_sources:
        record.status = "FLAGGED"
        record.alert_reason = "Source IP has active security alerts"
    return record


def is_internal(src: str) -> bool:
    return is_private_ip(src)
