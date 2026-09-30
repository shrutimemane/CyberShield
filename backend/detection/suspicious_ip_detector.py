"""
CyberShield - Suspicious IP detector
====================================

Aggregates detection activity per source IP. When an IP accumulates at least
`suspicious_ip_event_threshold` alert events (including previous ones), it is
added/updated in the suspicious_ips table with a composite risk score used by
the dashboard and the IP Analysis page.
"""

from datetime import datetime, timedelta, timezone

from backend.models import db, Alert, SuspiciousIP
from backend.utils.helpers import utcnow_naive
from backend.utils.settings import get_setting
from backend.utils.logger import get_logger

log = get_logger("cybershield.detect.susip")

SEVERITY_WEIGHTS = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 45}


class SuspiciousIPDetector:
    name = "SUSPICIOUS_IP"

    def evaluate(self, features, alert_manager):
        """Called after other detectors; refreshes IP risk profiles.

        Returns the list of SUSPICIOUS_IP alerts created (so the caller can
        escalate them into incidents like every other alert type)."""
        self._alert_mgr = alert_manager
        self.created_alerts = []
        threshold = get_setting("suspicious_ip_event_threshold", 2)
        recent_cutoff = utcnow_naive() - timedelta(minutes=30)
        sources = set(features["packet_times"].keys())

        for ip in sources | {a.source_ip for a in alert_manager.session_new_alerts}:
            self._refresh_ip(ip, threshold, recent_cutoff)
        return self.created_alerts

    def _refresh_ip(self, ip: str, threshold: int, cutoff):
        if not ip:
            return
        alerts = Alert.query.filter(
            Alert.source_ip == ip,
            Alert.created_at >= cutoff,
        ).all()
        if not alerts:
            return

        row = SuspiciousIP.query.filter_by(ip=ip).first()
        if row is None:
            row = SuspiciousIP(ip=ip)
            db.session.add(row)

        row.alert_count = len(alerts)
        row.last_seen = utcnow_naive()
        row.categories = ",".join(sorted({a.alert_type for a in alerts}))
        row.risk_score = self._risk_score(alerts)

        if row.alert_count >= threshold and row.risk_score >= 20:
            # create an aggregate alert once per dedupe window
            alert_manager = getattr(self, "_alert_mgr", None)
            if alert_manager:
                new_alert = alert_manager.create_alert(
                    alert_type=self.name,
                    severity="MEDIUM" if row.risk_score < 60 else "HIGH",
                    source_ip=ip,
                    reason=(f"IP linked to {row.alert_count} security events "
                            f"({row.categories}) - risk score {row.risk_score}/100"),
                    details={"risk_score": row.risk_score,
                             "categories": row.categories},
                )
                if new_alert not in self.created_alerts:
                    self.created_alerts.append(new_alert)

    @staticmethod
    def _risk_score(alerts) -> int:
        """0-100 composite: severity weights, capped, plus recency bonus."""
        if not alerts:
            return 0
        base = sum(SEVERITY_WEIGHTS.get(a.severity, 10) for a in alerts)
        newest = max(a.created_at for a in alerts)
        minutes_old = (utcnow_naive() - newest).total_seconds() / 60
        recency = 10 if minutes_old < 5 else 5 if minutes_old < 15 else 0
        return min(100, base + recency)
