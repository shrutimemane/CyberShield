"""
CyberShield - Demo traffic generator
====================================

Produces SAFE synthetic packets so the whole pipeline (detection, alerting,
incidents, dashboard, reports) can be demonstrated with zero risk: nothing is
sent on the network - these packets only exist inside CyberShield's database.

The generator mixes realistic benign traffic with three scripted attack
scenarios, so every detector has something to find during a demo:

  1. Port scan        - attacker sweeps many ports on the internal gateway
  2. Connection flood - attacker opens excessive connections to a web server
  3. Volumetric burst - attacker floods high-volume traffic (DoS-like)

Timestamps matter: CyberShield analyzes a rolling window that ENDS at the
newest packet it receives, so every scenario is generated inside the last few
seconds ("now" going backwards). Packets stamped in the future would fall
outside the evaluation window and never be detected.

Demo attacker IP is documentation-reserved (TEST-NET-2: 203.0.113.0/24).
"""

import random
import threading
from datetime import datetime, timedelta, timezone

from backend.config import Config
from backend.capture.packet_format import make_packet

_rng = random.Random()

WEB_PORTS = [80, 443]
SAFE_PORTS = [53, 123, 993, 587, 8443, 3306, 3389]
# Longer than PORT_SCAN_HIGH_THRESHOLD (25) so the demo sweep is a HIGH
# severity alert instead of a borderline MEDIUM one - a real service sweep.
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 161, 389,
              443, 445, 636, 873, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080,
              8443, 9000, 9100, 9200]
TALKATIVE_SERVICES = [80, 443, 53]

# A real client keeps only a handful of connections open at a time, so
# server->client replies reuse a small pool of ephemeral ports. Randomising
# destination ports here would look exactly like a port scan to the detector
# and would raise a false positive from completely benign traffic.
_CLIENT_PORTS = [49153, 51204, 53890, 57321, 60112, 62540]

# Where each scripted scenario sits relative to "now" (seconds in the past).
# Ordered so the demo timeline reads: scan -> flood -> burst.
_SCAN_END_OFFSET = 6.0
_FLOOD_END_OFFSET = 3.2
_BURST_END_OFFSET = 0.0


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _spread(count: int, span_seconds: float, end: datetime):
    """`count` timestamps evenly spread over `span_seconds`, ending at `end`."""
    if count <= 1:
        return [end]
    gap = span_seconds / (count - 1) if span_seconds > 0 else 0.0
    return [end - timedelta(seconds=gap * (count - 1 - i)) for i in range(count)]


def _benign_packet(capture_id="demo", timestamp=None):
    """One realistic internal client <-> gateway/server exchange."""
    internal = _rng.choice(Config.DEMO_HOSTS)
    gateway = Config.DEMO_INTERNAL_VICTIM
    if _rng.random() < 0.5:
        src, dst = internal, gateway
        dport = _rng.choice(TALKATIVE_SERVICES)
        sport = _rng.choice(_CLIENT_PORTS)
        flags = _rng.choice(["SYN", "SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK"])
    else:
        src, dst = gateway, internal
        sport = _rng.choice(TALKATIVE_SERVICES)
        dport = _rng.choice(_CLIENT_PORTS)
        flags = _rng.choice(["ACK", "PSH,ACK", "SYN,ACK", "FIN,ACK"])
    length = _rng.choice([54, 60, 66, 74, 128, 218, 342, 512, 780, 1024, 1420, 1514])
    return make_packet(capture_id, src, dst, "TCP", length,
                       sport, dport, flags, timestamp or _now())


def _port_scan_packets(capture_id="demo", end=None):
    """Attacker sweeps > threshold unique ports on the gateway -> PORT_SCAN."""
    attacker = Config.DEMO_ATTACKER_IP
    victim = Config.DEMO_INTERNAL_VICTIM
    end = end or _now() - timedelta(seconds=_SCAN_END_OFFSET)
    times = _spread(len(SCAN_PORTS), 2.7, end)
    return [
        make_packet(capture_id, attacker, victim, "TCP", 54,
                    _rng.randint(40000, 60000), port, "SYN", ts)
        for port, ts in zip(SCAN_PORTS, times)
    ]


def _conn_flood_packets(capture_id="demo", end=None):
    """Attacker makes excessive SYN connection attempts to the web server."""
    attacker = Config.DEMO_ATTACKER_IP
    victim = Config.DEMO_INTERNAL_VICTIM
    end = end or _now() - timedelta(seconds=_FLOOD_END_OFFSET)
    count = Config.CONN_FLOOD_THRESHOLD + 12
    times = _spread(count, 2.5, end)
    return [
        make_packet(capture_id, attacker, victim, "TCP", 54,
                    _rng.randint(40000, 60000), 80, "SYN", ts)
        for ts in times
    ]


def _dos_burst_packets(capture_id="demo", end=None):
    """Volumetric DoS-like burst: many packets in a few seconds."""
    attacker = Config.DEMO_ATTACKER_IP
    victim = Config.DEMO_INTERNAL_VICTIM
    end = end or _now() - timedelta(seconds=_BURST_END_OFFSET)
    count = Config.TRAFFIC_ANOMALY_PPS_THRESHOLD + 40
    times = _spread(count, 6.0, end)
    return [
        make_packet(capture_id, attacker, victim,
                    _rng.choice(["UDP", "ICMP", "TCP"]),
                    _rng.choice([512, 1024, 1400, 1514]),
                    _rng.randint(40000, 60000), _rng.choice(TALKATIVE_SERVICES),
                    "" if _rng.random() < 0.4 else "SYN", ts)
        for ts in times
    ]


def generate_demo_batch(n_benign: int = 45, include_attacks: bool = True,
                        spread_seconds: float = 8.0):
    """
    Return a list of synthetic packets: benign noise + scripted attacks.

    All packets are stamped within the last `spread_seconds` so the analysis
    window that ends at the newest packet contains the whole demo timeline.
    """
    now = _now()
    pkts = [_benign_packet(timestamp=now - timedelta(
        seconds=_rng.uniform(0, spread_seconds))) for _ in range(n_benign)]
    if include_attacks:
        pkts += _port_scan_packets(end=now - timedelta(seconds=_SCAN_END_OFFSET))
        pkts += _conn_flood_packets(end=now - timedelta(seconds=_FLOOD_END_OFFSET))
        pkts += _dos_burst_packets(end=now - timedelta(seconds=_BURST_END_OFFSET))
    pkts.sort(key=lambda p: p["timestamp"])
    return pkts


ATTACK_SCENARIOS = ("port_scan", "conn_flood", "dos")


def generate_attack_only(attack: str):
    """Return one scripted attack scenario by name (port_scan|conn_flood|dos)."""
    return {"port_scan": _port_scan_packets,
            "conn_flood": _conn_flood_packets,
            "dos": _dos_burst_packets}[attack]()


def generate_demo_sequence(n_benign: int = 25):
    """
    Ordered batches for first-run seeding / guided demo:

        [benign warm-up] -> [benign + port scan] -> [benign + conn flood]
        -> [benign + DoS burst]

    Feeding the attacks one batch at a time (instead of all at once) makes the
    incident timeline read like a real investigation: the alert escalates and
    related alerts attach to the same incident as the attack develops.
    """
    batches = [generate_demo_batch(n_benign=n_benign, include_attacks=False)]
    for scenario in ATTACK_SCENARIOS:
        batch = generate_demo_batch(n_benign=n_benign, include_attacks=False)
        batch += generate_attack_only(scenario)
        batch.sort(key=lambda p: p["timestamp"])
        batches.append(batch)
    return batches


class DemoTrafficThread(threading.Thread):
    """Continuously emits mixed demo traffic while Demo Mode is active."""

    def __init__(self, packet_sink, interval=1.5):
        super().__init__(daemon=True, name="cs-demo-traffic")
        self.packet_sink = packet_sink
        self.interval = interval
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            self.packet_sink(generate_demo_batch(n_benign=25, include_attacks=True))
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
