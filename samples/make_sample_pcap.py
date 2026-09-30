"""
CyberShield - sample PCAP generator
===================================

Builds a small, SAFE capture file that demonstrates PCAP forensic analysis
without touching a real network. Every packet is synthesised in memory and
written straight to disk - nothing is sent anywhere.

The capture replays the same educational timeline as Demo Mode:

    benign internal traffic -> port scan -> connection flood -> DoS-like burst

Usage (from the CyberShield folder):

    venv\\Scripts\\python samples\\make_sample_pcap.py
    venv\\Scripts\\python samples\\make_sample_pcap.py --out data\\pcaps\\my_capture.pcap

Then upload the file on the PCAP Analysis page and CyberShield runs its own
detection engine over it. Timestamps are placed in the past, exactly like a
capture you would take with Wireshark and analyse later.
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

# Make the project root importable when run as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.capture.demo_traffic import generate_demo_batch  # noqa: E402

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap
except ImportError:  # pragma: no cover
    print("Scapy is required: pip install scapy")
    raise SystemExit(1)

DEFAULT_OUT = os.path.join("samples", "demo_portscan.pcap")

_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04,
              "PSH": 0x08, "ACK": 0x10, "URG": 0x20}


def _tcp_flags(text: str) -> int:
    """\"SYN,ACK\" -> 0x12 (integer flag bitmask for Scapy)."""
    bits = 0
    for part in (text or "").split(","):
        bits |= _FLAG_BITS.get(part.strip().upper(), 0)
    return bits


def _to_scapy(pkt: dict):
    """Convert one CyberShield packet dict into a real Scapy packet."""
    length = max(int(pkt.get("length") or 54), 40)
    ip = IP(src=pkt["src_ip"], dst=pkt["dst_ip"])
    proto = (pkt.get("protocol") or "OTHER").upper()
    if proto == "TCP":
        layer = TCP(sport=pkt.get("src_port") or 0,
                    dport=pkt.get("dst_port") or 0,
                    flags=_tcp_flags(pkt.get("tcp_flags")))
        payload_len = max(length - 40, 0)
    elif proto == "UDP":
        layer = UDP(sport=pkt.get("src_port") or 0,
                    dport=pkt.get("dst_port") or 0)
        payload_len = max(length - 28, 0)
    elif proto == "ICMP":
        layer = ICMP()
        payload_len = max(length - 28, 0)
    else:
        layer = UDP(sport=pkt.get("src_port") or 0,
                    dport=pkt.get("dst_port") or 0)
        payload_len = max(length - 28, 0)

    packet = ip / layer
    if payload_len:
        packet = packet / Raw(load=b"\x00" * payload_len)

    # Timestamps deliberately in the past: this is an archived capture file.
    ts = pkt["timestamp"].replace(tzinfo=timezone.utc).timestamp()
    packet.time = ts
    return packet


def build_packets(age_minutes: int = 5, n_benign: int = 60):
    """Synthetic packets for the sample capture, shifted `age_minutes` back."""
    packets = generate_demo_batch(n_benign=n_benign, include_attacks=True)
    shift = timedelta(minutes=age_minutes)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for p in packets:
        p["timestamp"] = min(p["timestamp"] - shift, now - shift)
    return packets


def main():
    parser = argparse.ArgumentParser(description="Build a CyberShield sample PCAP")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help=f"output file (default: {DEFAULT_OUT})")
    parser.add_argument("--age-minutes", type=int, default=5,
                        help="how far in the past to stamp the capture")
    parser.add_argument("--benign", type=int, default=60,
                        help="number of benign packets to mix in")
    args = parser.parse_args()

    dicts = build_packets(age_minutes=args.age_minutes, n_benign=args.benign)
    scapy_packets = [_to_scapy(p) for p in dicts]

    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    wrpcap(out_path, scapy_packets)

    size_kb = os.path.getsize(out_path) / 1024
    print(f"Wrote {len(scapy_packets)} packets to {out_path} ({size_kb:.1f} KB)")
    print("Scenarios inside: benign traffic, port scan, connection flood, "
          "DoS-like burst (attacker 203.0.113.66 - TEST-NET-2).")
    print("Upload it on the PCAP Analysis page to run detection over it.")


if __name__ == "__main__":
    main()
