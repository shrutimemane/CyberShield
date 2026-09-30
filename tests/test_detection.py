"""
CyberShield - detection engine unit tests
=========================================

Run from the CyberShield folder:
    venv\\Scripts\\python -m pytest tests/ -v
(offline, no Flask server required - uses the app test context)
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from backend.app import app  # initializes DB + seeds
from backend.database import reset_db
from backend.models import db, Alert, Incident
from backend.analyzer.feature_extractor import (extract_features,
                                               packet_rate_per_source,
                                               sliding_windows)
from backend.detection.detection_engine import DetectionEngine
from backend.alerts.alert_manager import AlertManager
from backend.capture.demo_traffic import generate_attack_only
from backend.utils.helpers import ip_scope, is_private_ip


def _pkt(src, dst="192.168.1.1", dport=80, flags="SYN", proto="TCP",
         minutes_ago=0.0, length=60):
    ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
    return {"capture_id": "test", "timestamp": ts, "src_ip": src, "dst_ip": dst,
            "src_port": 40000, "dst_port": dport, "protocol": proto,
            "length": length, "tcp_flags": flags}


@pytest.fixture()
def client():
    """Reset DB per test and yield a logged-in Flask test client."""
    with app.app_context():
        reset_db(app)
    with app.test_client() as c:
        yield c


# --------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------- #
def test_feature_extractor_counts_unique_ports():
    pkts = [_pkt("1.2.3.4", dport=p) for p in (22, 23, 25, 80, 443, 3306, 3389)]
    feats = extract_features(pkts, window_seconds=10)
    assert len(feats["unique_ports"]["1.2.3.4"]) == 7
    assert feats["total_packets"] == 7


def test_feature_extractor_ignores_packets_outside_the_window():
    """Only packets inside window_seconds of the window end are analyzed.

    The window ends at the newest packet of the batch, so a packet minutes
    older than its neighbours is excluded while a lone old batch (a replayed
    PCAP) is still analyzed - see test_historic_batch_is_still_analyzed.
    """
    pkts = [_pkt("1.2.3.4", minutes_ago=5), _pkt("1.2.3.4", minutes_ago=0)]
    feats = extract_features(pkts, window_seconds=10)
    assert feats["total_packets"] == 1
    assert feats["packet_times"]["1.2.3.4"] == [feats["window_end"]]


def test_packet_rate_per_source():
    pkts = [_pkt("1.2.3.4", dport=p, flags="ACK") for p in range(20)]
    feats = extract_features(pkts, window_seconds=10)
    rates = packet_rate_per_source(feats)
    assert rates["1.2.3.4"] == pytest.approx(2.0)


# --------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------- #
def test_port_scan_detected(client):
    with app.app_context():
        pkts = [_pkt("9.9.9.9", dport=p) for p in range(1, 16)]  # 15 unique ports
        feats = extract_features(pkts, window_seconds=10)
        engine, mgr = DetectionEngine(), AlertManager()
        alerts = engine.evaluate(feats, mgr)
        db.session.commit()
        scan = [a for a in alerts if a.alert_type == "PORT_SCAN"]
        assert scan, "port scan alert expected"
        assert scan[0].source_ip == "9.9.9.9"
        assert "15 unique ports" in scan[0].reason


def test_benign_traffic_not_flagged(client):
    with app.app_context():
        pkts = [_pkt("8.8.8.8", dport=443, flags="SYN") for _ in range(3)]
        pkts += [_pkt("8.8.8.8", dport=53, flags="ACK")]
        feats = extract_features(pkts, window_seconds=10)
        engine, mgr = DetectionEngine(), AlertManager()
        alerts = engine.evaluate(feats, mgr)
        db.session.commit()
        assert not [a for a in alerts if a.source_ip == "8.8.8.8" and
                    a.alert_type in ("PORT_SCAN", "TRAFFIC_ANOMALY",
                                     "EXCESSIVE_CONNECTIONS")]


def test_connection_flood_detected(client):
    with app.app_context():
        pkts = [_pkt("7.7.7.7", dport=80, flags="SYN") for _ in range(35)]
        feats = extract_features(pkts, window_seconds=10)
        engine, mgr = DetectionEngine(), AlertManager()
        alerts = engine.evaluate(feats, mgr)
        db.session.commit()
        assert any(a.alert_type == "EXCESSIVE_CONNECTIONS" for a in alerts)


def test_dos_burst_detected(client):
    with app.app_context():
        pkts = ([_pkt("6.6.6.6", dport=80, flags="SYN")] +
                [_pkt("6.6.6.6", dport=53, flags="ACK", proto="UDP") for _ in range(150)])
        feats = extract_features(pkts, window_seconds=10)
        engine, mgr = DetectionEngine(), AlertManager()
        alerts = engine.evaluate(feats, mgr)
        db.session.commit()
        anomaly = [a for a in alerts if a.alert_type == "TRAFFIC_ANOMALY"]
        assert anomaly and anomaly[0].severity in ("HIGH", "CRITICAL")


# --------------------------------------------------------------------- #
# End-to-end ingest -> alert -> incident
# --------------------------------------------------------------------- #
def test_ingest_creates_alert_and_incident(client):
    with app.app_context():
        pkts = [_pkt("5.5.5.5", dport=p) for p in range(1, 14)]   # 13 ports -> scan
        from backend.analyzer.traffic_analyzer import TrafficAnalyzer
        result = TrafficAnalyzer().ingest(pkts)
        db.session.commit()
        assert result["alerts_created"] >= 1
        assert Incident.query.count() >= 1


def test_alert_dedupe(client):
    with app.app_context():
        mgr = AlertManager()
        a1 = mgr.create_alert("PORT_SCAN", "MEDIUM", "4.4.4.4", "test reason")
        db.session.commit()
        a2 = mgr.create_alert("PORT_SCAN", "MEDIUM", "4.4.4.4", "test reason")
        assert a1.id == a2.id, "duplicate alert should be suppressed within window"


# --------------------------------------------------------------------- #
# Demo traffic generator
# --------------------------------------------------------------------- #
def test_demo_batch_contains_attacks():
    from backend.capture.demo_traffic import generate_demo_batch
    pkts = generate_demo_batch(n_benign=10, include_attacks=True)
    attackers = {p["src_ip"] for p in pkts}
    assert any(ip.startswith("203.0.113.") for ip in attackers), \
        "demo attacker (TEST-NET-2) should appear in scripted scenarios"


def test_demo_batch_is_not_timestamped_in_the_future():
    """Regression: future-stamped packets fell outside the analysis window."""
    from backend.capture.demo_traffic import generate_demo_batch
    batches = [generate_demo_batch(n_benign=10, include_attacks=True)]
    batches += [generate_attack_only(s) for s in ("port_scan", "conn_flood", "dos")]
    for pkts in batches:
        newest = max(p["timestamp"] for p in pkts)
        assert newest <= datetime.now(timezone.utc).replace(tzinfo=None)
        feats = extract_features(pkts, window_seconds=10)
        assert feats["total_packets"] == len(pkts), \
            "every generated packet must fall inside the analysis window"


def test_benign_demo_traffic_raises_no_alerts(client):
    """Regression: random benign ports used to look like a port scan."""
    from backend.analyzer.traffic_analyzer import TrafficAnalyzer
    from backend.capture.demo_traffic import generate_demo_batch
    with app.app_context():
        result = TrafficAnalyzer().ingest(
            generate_demo_batch(n_benign=120, include_attacks=False))
        assert result["alerts_created"] == 0, \
            f"benign traffic must stay quiet, got {result}"
        assert Alert.query.count() == 0


def test_demo_each_scenario_is_detected(client):
    """Each scripted scenario must produce its own alert type when ingested."""
    from backend.analyzer.traffic_analyzer import TrafficAnalyzer
    expected = {"port_scan": "PORT_SCAN",
                "conn_flood": "EXCESSIVE_CONNECTIONS",
                "dos": "TRAFFIC_ANOMALY"}
    with app.app_context():
        for scenario, alert_type in expected.items():
            result = TrafficAnalyzer().ingest(generate_attack_only(scenario))
            assert result["alerts_created"] >= 1, f"{scenario} produced no alert"
            assert Alert.query.filter_by(alert_type=alert_type).count() >= 1, \
                f"{scenario} should raise {alert_type}"
        assert Incident.query.count() >= 1


# --------------------------------------------------------------------- #
# Historic traffic (PCAP replay) - windows follow the batch, not the clock
# --------------------------------------------------------------------- #
def test_historic_batch_is_still_analyzed():
    """Regression: timestamps older than the window were dropped entirely."""
    pkts = [_pkt("3.3.3.3", dport=p, minutes_ago=24 * 60)
            for p in range(1, 16)]           # yesterday, 15 unique ports
    feats = extract_features(pkts, window_seconds=10)
    assert feats["total_packets"] == 15
    assert len(feats["unique_ports"]["3.3.3.3"]) == 15


def test_sliding_windows_cover_a_long_capture():
    """A 60s capture is tiled so activity at the start is analyzed too."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    pkts = [{"capture_id": "pcap", "timestamp": now - timedelta(seconds=60),
             "src_ip": "2.2.2.2", "dst_ip": "192.168.1.1", "src_port": 40000,
             "dst_port": p, "protocol": "TCP", "length": 60, "tcp_flags": "SYN"}
            for p in range(1, 16)]
    pkts.append({"capture_id": "pcap", "timestamp": now, "src_ip": "2.2.2.2",
                 "dst_ip": "192.168.1.1", "src_port": 40000, "dst_port": 443,
                 "protocol": "TCP", "length": 60, "tcp_flags": "ACK"})
    windows = list(sliding_windows(pkts, window_seconds=10, max_windows=25))
    assert len(windows) > 1, "a 60s capture must be split into several windows"
    assert any(len(w["unique_ports"].get("2.2.2.2", ())) > 10 for w in windows), \
        "the scan at the start of the capture must be visible"


def test_replayed_pcap_batch_raises_alerts(client):
    """End-to-end: an old capture still yields alerts after import."""
    from backend.analyzer.traffic_analyzer import TrafficAnalyzer
    with app.app_context():
        pkts = [_pkt("1.1.1.1", dport=p, minutes_ago=180) for p in range(1, 20)]
        result = TrafficAnalyzer().ingest(pkts)
        assert result["alerts_created"] >= 1
        assert Alert.query.filter_by(alert_type="PORT_SCAN").count() >= 1


# --------------------------------------------------------------------- #
# Address scope (used to label IPs in the UI)
# --------------------------------------------------------------------- #
def test_ip_scope_classification():
    assert ip_scope("192.168.1.10") == "private"
    assert ip_scope("10.0.0.5") == "private"
    assert ip_scope("127.0.0.1") == "private"
    assert ip_scope("8.8.8.8") == "public"
    assert ip_scope("203.0.113.66") == "documentation"
    assert ip_scope("not-an-ip") == "invalid"


def test_documentation_ranges_are_not_labelled_lan():
    """Regression: Python's is_private counts TEST-NET, mislabelling the
    demo attacker as a LAN host on the IP Analysis page."""
    assert is_private_ip("203.0.113.66") is False
    assert is_private_ip("192.0.2.10") is False
    assert is_private_ip("198.51.100.7") is False
    assert is_private_ip("192.168.1.10") is True


# --------------------------------------------------------------------- #
# Web flow (login protected)
# --------------------------------------------------------------------- #
def test_login_required_redirects(client):
    rv = client.get("/dashboard")
    assert rv.status_code == 302 and "/login" in rv.headers["Location"]


def test_login_and_dashboard(client):
    assert client.get("/login").status_code == 200
    rv = client.post("/login", data={"username": "admin", "password": "admin123"})
    assert rv.status_code == 302
    rv = client.get("/dashboard")
    assert rv.status_code == 200
    api = client.get("/api/dashboard")
    assert api.status_code == 200
    data = api.get_json()
    assert "cards" in data and "risk_score" in data["cards"]
