"""
CyberShield - Feature extraction
================================

Converts streams of packets into the aggregate features the detection rules
consume (unique ports per source, connection attempt rates, packet rates,
protocol/flag distributions). Pure functions - no database access here, which
keeps the detectors unit-testable.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from backend.utils.helpers import utcnow_naive


def _as_naive_utc(ts):
    if ts is None:
        return utcnow_naive()
    if isinstance(ts, datetime) and ts.tzinfo is not None:
        return ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts


def extract_features(packets, window_seconds=10, now=None):
    """
    Aggregate packets into detection features over a sliding window.

    The window ENDS at the newest packet of the batch (or at wall-clock now
    when `now` is passed explicitly). Anchoring to the batch - instead of the
    wall clock - is what lets a PCAP captured last week still be analyzed:
    the window replays the capture's own timeline.

    Returns a dict with per-source maps:
      unique_ports[src]  = set of destination ports contacted
      port_timestamps[src][(src_port,dst_port)] = newest packet time
      conn_attempts[src][dst]  = list of packet times flagged SYN
      packet_times[src]  = list of packet times (any protocol)
      total_packets, protocol_counts, flag_syn_count
    """
    packets = list(packets or [])
    if now is None:
        newest = max((_as_naive_utc(p.get("timestamp")) for p in packets),
                     default=None)
        now = newest or utcnow_naive()
    now = _as_naive_utc(now) or utcnow_naive()
    window_start = now - timedelta(seconds=window_seconds)

    features = {
        "window_start": window_start,
        "window_end": now,
        "window_seconds": window_seconds,
        "unique_ports": defaultdict(set),
        "conn_attempts": defaultdict(lambda: defaultdict(list)),
        "packet_times": defaultdict(list),
        "total_packets": 0,
        "protocol_counts": defaultdict(int),
        "flag_syn_count": 0,
        "ports_seen": defaultdict(set),
        "last_dst": {},
    }
    for pkt in packets or []:
        ts = _as_naive_utc(pkt.get("timestamp"))
        if ts is None or ts < window_start or ts > now:
            continue  # only analyze the configured window
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        if not src or not dst:
            continue
        features["total_packets"] += 1
        features["protocol_counts"][pkt.get("protocol", "OTHER")] += 1
        features["packet_times"][src].append(ts)
        features["last_dst"][src] = dst

        dport = pkt.get("dst_port")
        if dport:
            features["unique_ports"][src].add(int(dport))
            features["ports_seen"][src].add((int(dport), ts))

        flags = str(pkt.get("tcp_flags") or "")
        if "SYN" in flags and "ACK" not in flags:
            features["flag_syn_count"] += 1
            features["conn_attempts"][src][dst].append(ts)

    return features


def sliding_windows(packets, window_seconds=10, max_windows=25):
    """
    Yield one feature set per time window across a whole packet batch.

    Traffic that spans more than one window (a long PCAP capture, or a batch
    of saved packets) is tiled end-to-end so earlier activity is analyzed too,
    instead of only the most recent `window_seconds`. The number of passes is
    bounded by `max_windows`; a capture long enough to need more is sampled at
    even intervals (documented behaviour for very large PCAP files).
    """
    packets = list(packets or [])
    if not packets:
        return
    window_seconds = max(int(window_seconds or 10), 1)
    times = [_as_naive_utc(p.get("timestamp")) for p in packets]
    times = [t for t in times if t is not None]
    if not times:
        return
    first, last = min(times), max(times)

    span = (last - first).total_seconds()
    step = max(window_seconds, span / max(int(max_windows or 1), 1))
    if span <= window_seconds:
        yield extract_features(packets, window_seconds, now=last)
        return

    end = first + timedelta(seconds=window_seconds)
    while end < last:
        yield extract_features(packets, window_seconds, now=end)
        end = end + timedelta(seconds=step)
    yield extract_features(packets, window_seconds, now=last)


def ports_contacted_in_window(features, src):
    """[(port, newest_time), ...] for a source within the current window."""
    # kept separate from extract_features so detectors share one definition
    per_port = {}
    for port, ts in features.get("ports_seen", {}).get(src, set()):
        if port not in per_port or ts > per_port[port]:
            per_port[port] = ts
    return sorted(per_port.items(), key=lambda kv: kv[1])


def packet_rate_per_source(features) -> dict:
    """packets-per-second for each source in the window."""
    w = max(features.get("window_seconds", 1), 1)
    return {src: len(times) / w for src, times in features["packet_times"].items()}
