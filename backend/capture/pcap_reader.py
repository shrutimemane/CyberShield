"""
CyberShield - PCAP reader
=========================

Reads PCAP/PCAPNG capture files with Scapy and converts them to CyberShield's
normalized packet format. Used by the PCAP Analysis page: an analyst uploads
a capture taken with Wireshark/tcpdump and CyberShield runs its own detection
engine over it - Wireshark stays the external verification tool.

Works entirely offline; no network access is required or performed.
"""

import os

from backend.utils.logger import get_logger
from backend.capture.packet_format import make_packet
from datetime import datetime, timezone

log = get_logger("cybershield.pcap")

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False


def read_pcap(path: str, capture_id: str | None = None, max_packets: int = 50000):
    """
    Parse a PCAP file into normalized packet dicts.

    Returns (packets, error_message). error_message is None on success.
    Timestamps come from the capture file so detection windows replay exactly
    as they happened in real traffic.
    """
    if not SCAPY_AVAILABLE:
        return [], "Scapy is not installed - PCAP analysis unavailable"
    if not os.path.isfile(path):
        return [], f"File not found: {path}"

    capture_id = capture_id or f"pcap:{os.path.basename(path)}"
    packets = []
    try:
        raw = rdpcap(path)
    except Exception as exc:
        return [], f"Could not parse PCAP: {exc}"

    for pkt in raw[:max_packets]:
        try:
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue
            ts = float(getattr(pkt, "time", 0) or 0)
            timestamp = (datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
                         if ts > 0 else datetime.now(timezone.utc).replace(tzinfo=None))

            protocol, src_port, dst_port, tcp_flags = "OTHER", None, None, ""
            tcp = pkt.getlayer(TCP)
            udp = pkt.getlayer(UDP)
            if tcp is not None:
                protocol = "TCP"
                src_port, dst_port = int(tcp.sport), int(tcp.dport)
                bits = int(tcp.flags)
                order = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                         (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
                tcp_flags = ",".join(n for m, n in order if bits & m)
            elif udp is not None:
                protocol = "UDP"
                src_port, dst_port = int(udp.sport), int(udp.dport)
            elif pkt.getlayer(ICMP) is not None:
                protocol = "ICMP"

            packets.append(make_packet(
                capture_id=capture_id, timestamp=timestamp,
                src_ip=str(ip_layer.src), dst_ip=str(ip_layer.dst),
                protocol=protocol, length=int(len(pkt)),
                src_port=src_port, dst_port=dst_port, tcp_flags=tcp_flags,
            ))
        except Exception as exc:  # keep parsing the rest of the file
            log.debug("PCAP packet skipped: %s", exc)
    return packets, None
