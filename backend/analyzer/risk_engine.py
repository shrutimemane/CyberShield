"""
CyberShield - Security risk engine
==================================

Computes the application-wide Security Risk Score (0-100) shown on the
dashboard from REAL data. Purely derived - nothing hardcoded, no fake numbers.

Scoring formula (documented, deterministic)
-------------------------------------------
Four factors, each individually capped so no single dimension can dominate:

1. Open alerts (last 24h, status NEW/ACKNOWLEDGED)
      alert_points  = sum(severity_weight per alert)
      capped:       alert_factor = min(40, alert_points)
      dampening:    if more than 20 open alerts, excess points count half
                    (one noisy rule cannot pin the meter at CRITICAL)
      weights:      LOW=2  MEDIUM=6  HIGH=14  CRITICAL=22

2. Open incidents (status OPEN/INVESTIGATING)
      incident_factor = min(25, sum(severity_weight per incident))
      weights:        LOW=5  MEDIUM=10  HIGH=18  CRITICAL=25

3. Suspicious IPs (watchlist entries with risk_score >= 20)
      ip_factor = min(20, 4 * n_watchlisted + 2 * n_blocked)

4. Severity pressure: the highest severity among open alerts/incidents
      adds a small tilt so a single CRITICAL alert is visible even if the
      totals stay small:  LOW+0  MEDIUM+2  HIGH+6  CRITICAL+10

risk_score = alert_factor + incident_factor + ip_factor + pressure  (0-100)

Display ranges (identical frontend/backend - see RISK_RANGES):
      0-24 LOW · 25-49 MODERATE · 50-74 HIGH · 75-100 CRITICAL

Empty database / no open alerts, incidents and watchlist entries
    -> calculate_global_risk() returns None and the UI shows
       "Insufficient Data" instead of an invented number.
"""

from datetime import timedelta

from backend.models import Alert, Incident, SuspiciousIP
from backend.utils.helpers import utcnow_naive

ALERT_WEIGHTS = {"LOW": 2, "MEDIUM": 6, "HIGH": 14, "CRITICAL": 22}
INCIDENT_WEIGHTS = {"LOW": 5, "MEDIUM": 10, "HIGH": 18, "CRITICAL": 25}
PRESSURE_WEIGHTS = {"LOW": 0, "MEDIUM": 2, "HIGH": 6, "CRITICAL": 10}

ALERT_FACTOR_CAP = 40
INCIDENT_FACTOR_CAP = 25
IP_FACTOR_CAP = 20
ALERT_DAMPEN_THRESHOLD = 20   # open alerts beyond this count half

# (min_inclusive, max_inclusive, label, css color var)
RISK_RANGES = (
    (0, 24, "LOW", "accent"),
    (25, 49, "MODERATE", "yellow"),
    (50, 74, "HIGH", "orange"),
    (75, 100, "CRITICAL", "red"),
)

# Severity rank used for the "highest open severity" pressure factor
_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def calculate_global_risk():
    """Return the risk score as int 0-100, or None when there is no signal.

    "No signal" = zero open alerts, zero open incidents and zero watchlisted
    suspicious IPs. The caller (API/report) then exposes it as
    "Insufficient Data" rather than a misleading 0 or 100.
    """
    cutoff = utcnow_naive() - timedelta(hours=24)

    open_alerts = Alert.query.filter(
        Alert.created_at >= cutoff,
        Alert.status.in_(("NEW", "ACKNOWLEDGED")),
    ).all()
    open_incidents = Incident.query.filter(
        Incident.status.in_(("OPEN", "INVESTIGATING"))
    ).all()
    watchlist = SuspiciousIP.query.filter(SuspiciousIP.risk_score >= 20).all()

    # --- insufficient data: nothing open anywhere ---------------------- #
    if not open_alerts and not open_incidents and not watchlist:
        return None

    # --- factor 1: open alerts (capped, flood-dampened) ---------------- #
    alert_points = sum(ALERT_WEIGHTS.get(a.severity, 4) for a in open_alerts)
    if len(open_alerts) > ALERT_DAMPEN_THRESHOLD:
        base = ALERT_WEIGHTS.get(
            max((a.severity for a in open_alerts),
                key=lambda s: _SEV_RANK.get(s, 0), default="LOW"), 2)
        # keep the first 20 alerts' points intact, halve the excess
        kept = sorted((ALERT_WEIGHTS.get(a.severity, 4) for a in open_alerts),
                      reverse=True)[:ALERT_DAMPEN_THRESHOLD]
        alert_factor = min(ALERT_FACTOR_CAP,
                           sum(kept) + (alert_points - sum(kept)) * 0.5)
    else:
        alert_factor = min(ALERT_FACTOR_CAP, alert_points)

    # --- factor 2: open incidents (capped) ----------------------------- #
    incident_factor = min(
        INCIDENT_FACTOR_CAP,
        sum(INCIDENT_WEIGHTS.get(i.severity, 6) for i in open_incidents))

    # --- factor 3: suspicious IP watchlist (capped) --------------------- #
    blocked = sum(1 for s in watchlist if s.is_blocked)
    ip_factor = min(IP_FACTOR_CAP, len(watchlist) * 4 + blocked * 2)

    # --- factor 4: highest open severity pressure ----------------------- #
    severities = [a.severity for a in open_alerts] + \
                 [i.severity for i in open_incidents]
    top_sev = max(severities, key=lambda s: _SEV_RANK.get(s, 0), default="LOW")
    pressure = PRESSURE_WEIGHTS.get(top_sev, 0)

    score = round(alert_factor + incident_factor + ip_factor + pressure)
    return int(max(0, min(100, score)))


def risk_factors():
    """Return the individual factor breakdown for UI explanation."""
    cutoff = utcnow_naive() - timedelta(hours=24)
    open_alerts = Alert.query.filter(
        Alert.created_at >= cutoff,
        Alert.status.in_(("NEW", "ACKNOWLEDGED")),
    ).all()
    open_incidents = Incident.query.filter(
        Incident.status.in_(("OPEN", "INVESTIGATING"))
    ).count()
    watchlist = SuspiciousIP.query.filter(SuspiciousIP.risk_score >= 20).count()
    blocked = SuspiciousIP.query.filter(
        SuspiciousIP.risk_score >= 20, SuspiciousIP.is_blocked.is_(True)).count()
    sev_counts = {}
    for a in open_alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
    return {
        "open_alerts_24h": len(open_alerts),
        "alerts_by_severity": sev_counts,
        "open_incidents": open_incidents,
        "watchlist_ips": watchlist,
        "blocked_ips": blocked,
    }


def risk_label(score):
    """Map a score (or None) to its display label using RISK_RANGES."""
    if score is None:
        return "INSUFFICIENT DATA"
    for lo, hi, label, _color in RISK_RANGES:
        if lo <= score <= hi:
            return label
    return "LOW"


def risk_color(score):
    """CSS color token name for a score (or None)."""
    if score is None:
        return "muted"
    for lo, hi, _label, color in RISK_RANGES:
        if lo <= score <= hi:
            return color
    return "accent"


__all__ = ["calculate_global_risk", "risk_label", "risk_color", "risk_factors",
           "RISK_RANGES", "ALERT_WEIGHTS", "INCIDENT_WEIGHTS"]
