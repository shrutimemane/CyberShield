"""
CyberShield - Live packet sniffer
=================================

Thin wrapper around Scapy's sniff() that normalizes packets into the shared
dict format. Designed to fail SOFT: if the OS denies raw-capture privileges
or no interface is available, start() returns False and the UI falls back to
PCAP/Demo mode instead of crashing.

SAFETY: passively listens on the local machine only. No packets are injected
and no remote systems are contacted.
"""

import threading
import time
from datetime import datetime, timezone

from backend.utils.logger import get_logger
from backend.capture.packet_format import make_packet

log = get_logger("cybershield.capture")

try:
    from scapy.all import sniff, conf
    from scapy.arch.windows import get_windows_if_list
    SCAPY_AVAILABLE = True
except Exception:                                    # pragma: no cover
    SCAPY_AVAILABLE = False


class LiveSniffer:
    """Background thread that captures packets and appends them to a queue."""

    def __init__(self, packet_sink, interface=None, promiscuous=False):
        """
        packet_sink: callable(list[dict]) invoked per capture batch.
        interface:   Scapy interface name; None => default route interface.
        """
        self.packet_sink = packet_sink
        self.interface = interface
        self.promiscuous = promiscuous
        self._stop = threading.Event()
        self._thread = None
        self.captured_count = 0
        self.last_error = None
        self.started_at = None

    # ------------------------------------------------------------------ #
    @property
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    @staticmethod
    def available() -> bool:
        return SCAPY_AVAILABLE

    @staticmethod
    def list_interfaces():
        """Best-effort interface discovery; returns [] on failure."""
        if not SCAPY_AVAILABLE:
            return []
        try:
            ifs = get_windows_if_list()
            return [{"name": i["name"], "description": i.get("description", i["name"])}
                    for i in ifs]
        except Exception:
            try:  # pragma: no cover - non-Windows fallback
                from scapy.all import get_if_list
                return [{"name": n, "description": n} for n in get_if_list()]
            except Exception:
                return []

    # ------------------------------------------------------------------ #
    def start(self) -> bool:
        if not SCAPY_AVAILABLE:
            self.last_error = "Scapy is not installed"
            return False
        if self.is_running:
            return True
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="cs-sniffer")
        self._thread.start()
        # give the thread a moment to surface permission errors
        time.sleep(0.4)
        if self.last_error:
            return False
        log.info("Live sniffer started on interface=%r promisc=%s",
                 self.interface, self.promiscuous)
        return True

    def stop(self, timeout=3):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self._thread = None
        log.info("Live sniffer stopped after %s packets", self.captured_count)

    # ------------------------------------------------------------------ #
    def _run(self):
        try:
            kwargs = dict(
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _p: self._stop.is_set(),
                promisc=self.promiscuous,
                timeout=2,          # short cycles so stop_filter is checked often
            )
            if self.interface:
                kwargs["iface"] = self.interface
            while not self._stop.is_set():
                sniff(**kwargs)
        except PermissionError as exc:
            self.last_error = f"Capture permission denied: {exc}"
        except Exception as exc:  # pragma: no cover
            self.last_error = str(exc)
        finally:
            if self.last_error:
                log.warning("Live sniffer error: %s", self.last_error)

    def _handle_packet(self, scapy_pkt):
        """Convert a Scapy packet into CyberShield's dict format."""
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP
            ts = float(getattr(scapy_pkt, "time", time.time()))
            timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
            length = int(len(scapy_pkt))

            ip_layer = scapy_pkt.getlayer(IP) or scapy_pkt.getlayer(IPv6)
            if ip_layer is None:
                return  # ignore non-IP frames (ARP, ...)
            src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)

            protocol, src_port, dst_port, tcp_flags = "OTHER", None, None, ""
            tcp = scapy_pkt.getlayer(TCP)
            udp = scapy_pkt.getlayer(UDP)
            if tcp is not None:
                protocol = "TCP"
                src_port, dst_port = int(tcp.sport), int(tcp.dport)
                tcp_flags = self._decode_flags(tcp.flags)
            elif udp is not None:
                protocol = "UDP"
                src_port, dst_port = int(udp.sport), int(udp.dport)
            elif scapy_pkt.getlayer(ICMP) is not None:
                protocol = "ICMP"

            self.captured_count += 1
            self.packet_sink([make_packet(
                capture_id="live", timestamp=timestamp,
                src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
                length=length, src_port=src_port, dst_port=dst_port,
                tcp_flags=tcp_flags,
            )])
        except Exception as exc:  # never let one bad packet kill the thread
            log.debug("Packet parse skipped: %s", exc)

    @staticmethod
    def _decode_flags(tcp_flags) -> str:
        """TCP flag bitmask -> 'SYN,ACK' style string."""
        try:
            bits = int(tcp_flags)
        except (TypeError, ValueError):
            return str(tcp_flags)
        order = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                 (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
        return ",".join(name for mask, name in order if bits & mask)
