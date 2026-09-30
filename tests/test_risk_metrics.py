"""
CyberShield - risk engine & dashboard metrics tests
===================================================

Verifies the documented scoring formula end to end:
* Empty database  -> calculate_global_risk() is None ("Insufficient Data").
* A single alert does NOT pin the score at CRITICAL (factor caps work).
* Score grows with real signal and maps to the required display ranges
  0-24 LOW / 25-49 MODERATE / 50-74 HIGH / 75-100 CRITICAL.
* /api/metrics/timeline returns clamped windows and real bucket data.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from backend.app import app  # initializes DB + seeds
from backend.database import reset_db
from backend.models import db, Alert, Incident, PacketRecord, SuspiciousIP
from backend.analyzer.risk_engine import (calculate_global_risk, risk_label,
                                          risk_color, RISK_RANGES)


def _utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _mk_alert(sev="HIGH", status="NEW", minutes_ago=10):
    a = Alert(alert_type="PORT_SCAN", severity=sev, status=status,
              source_ip="203.0.113.66", destination_ip="192.168.1.1",
              reason="test", created_at=_utc() - timedelta(minutes=minutes_ago))
    db.session.add(a)
    return a


@pytest.fixture()
def ctx():
    with app.app_context():
        reset_db(app)
        yield db.session
        db.session.rollback()


@pytest.fixture()
def client(ctx):
    """Flask test client (DB already reset by the ctx fixture)."""
    with app.test_client() as c:
        yield c


# --------------------------------------------------------------------- #
# Empty database -> None (Insufficient Data), never a fake number
# --------------------------------------------------------------------- #
def test_empty_db_returns_none(ctx):
    assert calculate_global_risk() is None
    assert risk_label(None) == "INSUFFICIENT DATA"


def test_zero_risk_when_all_resolved(ctx):
    _mk_alert(status="RESOLVED")
    db.session.commit()
    assert calculate_global_risk() is None


# --------------------------------------------------------------------- #
# Single signals must not pin the meter at CRITICAL
# --------------------------------------------------------------------- #
def test_single_high_alert_is_low_or_moderate(ctx):
    _mk_alert("HIGH")
    db.session.commit()
    score = calculate_global_risk()
    assert score is not None and score < 50          # not HIGH/CRITICAL
    assert risk_label(score) in ("LOW", "MODERATE")


def test_single_critical_alert_is_not_pinned_at_100(ctx):
    _mk_alert("CRITICAL")
    db.session.commit()
    score = calculate_global_risk()
    assert score is not None
    assert score <= 60                                # caps hold it down
    assert score >= 25                                # but clearly visible


def test_alert_flood_dampening(ctx):
    for i in range(60):
        _mk_alert("MEDIUM", minutes_ago=i % 50)
    db.session.commit()
    score = calculate_global_risk()
    assert score is not None and score < 75           # flood cannot pin CRITICAL


# --------------------------------------------------------------------- #
# Score grows with real signal + range mapping
# --------------------------------------------------------------------- #
def test_more_open_alerts_raise_score(ctx):
    _mk_alert("LOW")
    db.session.commit()
    s1 = calculate_global_risk()
    for _ in range(5):
        _mk_alert("HIGH")
    db.session.commit()
    s2 = calculate_global_risk()
    assert s2 > s1


def test_resolving_alerts_lowers_score(ctx):
    a = _mk_alert("HIGH")
    db.session.commit()
    s1 = calculate_global_risk()
    a.status = "RESOLVED"
    db.session.commit()
    s2 = calculate_global_risk()
    assert s2 is None or s2 < s1


def test_open_incident_contributes(ctx):
    _mk_alert("LOW")
    db.session.add(Incident(incident_ref="INC-0001", title="t", severity="HIGH",
                            status="OPEN"))
    db.session.commit()
    score = calculate_global_risk()
    assert score is not None and score >= 20


def test_watchlist_contributes_and_caps(ctx):
    for i in range(10):
        db.session.add(SuspiciousIP(ip=f"10.0.0.{i}", risk_score=40))
    db.session.commit()
    score = calculate_global_risk()
    assert score is not None and score <= 100


# --------------------------------------------------------------------- #
# Labels / colors follow the required ranges
# --------------------------------------------------------------------- #
def test_risk_ranges_match_spec():
    assert RISK_RANGES[0] == (0, 24, "LOW", "accent")
    assert RISK_RANGES[1] == (25, 49, "MODERATE", "yellow")
    assert RISK_RANGES[2] == (50, 74, "HIGH", "orange")
    assert RISK_RANGES[3] == (75, 100, "CRITICAL", "red")


@pytest.mark.parametrize("score,label", [
    (0, "LOW"), (24, "LOW"), (25, "MODERATE"), (49, "MODERATE"),
    (50, "HIGH"), (74, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL"),
])
def test_risk_label_boundaries(score, label):
    assert risk_label(score) == label


def test_risk_color_tokens():
    assert risk_color(None) == "muted"
    assert risk_color(10) == "accent"
    assert risk_color(90) == "red"


# --------------------------------------------------------------------- #
# Dashboard API: risk fields + metrics timeline endpoint
# --------------------------------------------------------------------- #
def _login(client):
    return client.post("/login",
                       data={"username": "admin", "password": "admin123"})


def test_dashboard_cards_carry_risk_metadata(client, ctx):
    _mk_alert("HIGH")
    db.session.commit()
    _login(client)
    data = client.get("/api/dashboard").get_json()
    cards = data["cards"]
    assert cards["risk_score"] is not None
    assert cards["risk_label"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert cards["risk_color"] in ("accent", "yellow", "orange", "red")
    assert "open_alerts_24h" in cards["risk_factors"]
    assert "top_suspicious" in data


def test_dashboard_insufficient_data_is_explicit(client, ctx):
    _login(client)
    data = client.get("/api/dashboard").get_json()
    assert data["cards"]["risk_score"] is None
    assert data["cards"]["risk_label"] == "INSUFFICIENT DATA"


def test_metrics_timeline_windows_and_buckets(client, ctx):
    _login(client)
    for hours, expect_buckets in ((1, 12), (6, 72), (24, 24), (168, 28)):
        data = client.get(f"/api/metrics/timeline?hours={hours}").get_json()
        assert data["hours"] == hours
        assert len(data["buckets"]) == expect_buckets
    # invalid values clamp to the nearest allowed window (999 -> 168/7D)
    data = client.get("/api/metrics/timeline?hours=999").get_json()
    assert data["hours"] == 168 and len(data["buckets"]) == 28


def test_metrics_timeline_uses_real_packets(client, ctx):
    db.session.add(PacketRecord(capture_id="test", timestamp=_utc(),
                                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                protocol="TCP", length=512))
    db.session.commit()
    _login(client)
    data = client.get("/api/metrics/timeline?hours=1").get_json()
    assert data["summary"]["packets"] == 1
    assert data["summary"]["bytes"] == 512
    assert sum(b["packets"] for b in data["buckets"]) == 1


def test_metrics_timeline_empty_db_is_zeroed_not_fake(client, ctx):
    _login(client)
    data = client.get("/api/metrics/timeline?hours=24").get_json()
    assert data["summary"]["packets"] == 0
    assert data["summary"]["alerts"] == 0
    assert all(b["packets"] == 0 for b in data["buckets"])
