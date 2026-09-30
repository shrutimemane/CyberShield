"""
CyberShield - shared packet format
==================================

Every capture source (live sniffer, PCAP reader, demo generator) emits plain
dicts in this shape so the analyzer/detection layers never care where traffic
came from:

    {
        "capture_id": str,          "live" | "demo" | "pcap:<filename>"
        "timestamp":  datetime,     naive UTC
        "src_ip":     str,
        "dst_ip":     str,
        "src_port":   int | None,
        "dst_port":   int | None,
        "protocol":   str,          "TCP" | "UDP" | "ICMP" | "OTHER"
        "length":     int,          bytes on the wire
        "tcp_flags":  str,          e.g. "SYN", "SYN,ACK", "" for non-TCP
    }
"""

from datetime import datetime, timezone


def make_packet(capture_id, src_ip, dst_ip, protocol, length,
                src_port=None, dst_port=None, tcp_flags="", timestamp=None):
    return {
        "capture_id": capture_id,
        "timestamp": timestamp or datetime.now(timezone.utc).replace(tzinfo=None),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": int(length or 0),
        "tcp_flags": tcp_flags or "",
    }
