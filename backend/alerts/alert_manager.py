"""
CyberShield - Alert manager
===========================

Creates alerts (with severity + dedupe), maintains suspicious-IP aggregates,
and escalates alert clusters into incidents for investigation. Every alert is
persisted with a human-readable explanation - the SOC story of the project.
"""

import json
from datetime import datetime, timedelta

from backend.models import db, Alert, Incident, IncidentEvent, SuspiciousIP
from backend.utils.helpers import safe_json_dumps, utcnow_naive
from backend.utils.settings import get_setting
from backend.utils.logger import get_logger

log = get_logger("cybershield.alerts")

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Alert types that auto-create an incident immediately (attack-like events)
INCIDENT_AUTO_TYPES = {"PORT_SCAN", "EXCESSIVE_CONNECTIONS",
                       "TRAFFIC_ANOMALY", "SUSPICIOUS_IP"}


class AlertManager:
    """Per-ingest-batch manager; batches run inside a Flask app context."""

    def __init__(self):
        self.session_new_alerts = []      # Alerts created in this batch
        self.session_new_incidents = []

    # ------------------------------------------------------------------ #
    def create_alert(self, alert_type, severity, source_ip, reason,
                     destination_ip=None, details=None):
        """Create + persist an alert, honoring the dedupe window."""
        dedupe = get_setting("alert_dedupe_seconds", 30)
        cutoff = utcnow_naive() - timedelta(seconds=dedupe)
        duplicate = Alert.query.filter(
            Alert.alert_type == alert_type,
            Alert.source_ip == source_ip,
            Alert.destination_ip == (destination_ip or ""),
            Alert.created_at >= cutoff,
        ).first()
        if duplicate:
            return duplicate          # suppress duplicate within window

        alert = Alert(
            alert_type=alert_type,
            severity=severity if severity in SEVERITY_RANK else "MEDIUM",
            source_ip=source_ip,
            destination_ip=destination_ip or "",
            reason=reason[:512],
            details_json=safe_json_dumps(details or {}),
            status="NEW",
        )
        db.session.add(alert)
        db.session.flush()            # assign alert.id
        self.session_new_alerts.append(alert)
        log.info("ALERT [%s] %s -> %s: %s",
                 severity, source_ip, destination_ip or "-", reason)
        return alert

    # ------------------------------------------------------------------ #
    def escalate_alerts(self, alerts):
        """
        Turn alert clusters into incidents.

        Policy: the first alert of each INCIDENT_AUTO_TYPE opens (or joins)
        an incident for its source IP; related alerts attach to the same
        incident so the investigation timeline tells one coherent story.
        """
        incidents = []
        for alert in alerts or []:
            if alert.alert_type not in INCIDENT_AUTO_TYPES:
                continue
            incident = self._find_open_incident(alert.source_ip, alert.alert_type)
            if incident is None:
                incident = self._create_incident(alert)
                incidents.append(incident)
                # The incident's opening event already describes this alert,
                # so link it without repeating it on the timeline.
                self._attach_alert(incident, alert, announce=False)
            else:
                self._attach_alert(incident, alert)
        return incidents

    def _find_open_incident(self, source_ip, alert_type):
        return Incident.query.filter(
            Incident.source_ip == source_ip,
            Incident.status.in_(("OPEN", "INVESTIGATING")),
        ).order_by(Incident.id.desc()).first()

    def _create_incident(self, alert):
        incident = Incident(
            title=f"{alert.alert_type.replace('_', ' ').title()} from {alert.source_ip}",
            severity=alert.severity,
            status="OPEN",
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            description=alert.reason,
        )
        incident.generate_ref()
        db.session.add(incident)
        db.session.flush()
        incident.events.append(IncidentEvent(
            event_type="DETECTION",
            message=f"Auto-created from {alert.alert_type} alert #{alert.id}: "
                    f"{alert.reason}",
            actor="detection-engine",
        ))
        self.session_new_incidents.append(incident)
        log.info("INCIDENT %s opened (%s) for %s",
                 incident.incident_ref, incident.severity, alert.source_ip)
        return incident

    def _attach_alert(self, incident, alert, announce=True):
        """Link an alert to its incident; `announce` adds a timeline entry."""
        if alert.incident_id == incident.id:
            return
        alert.incident_id = incident.id
        # incident severity = highest of its alerts
        if SEVERITY_RANK.get(alert.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = alert.severity
        if announce:
            incident.events.append(IncidentEvent(
                event_type="DETECTION",
                message=f"Related alert attached: [{alert.severity}] "
                        f"{alert.alert_type} - {alert.reason}",
                actor="detection-engine",
            ))

    # ------------------------------------------------------------------ #
    @staticmethod
    def add_manual_event(incident, message, actor, event_type="NOTE"):
        """Investigator note / status change on the incident timeline."""
        event = IncidentEvent(incident_id=incident.id, event_type=event_type,
                              message=message, actor=actor)
        db.session.add(event)
        db.session.commit()
        return event

    @staticmethod
    def set_incident_status(incident, new_status, actor):
        incident.status = new_status
        if new_status == "CLOSED":
            incident.closed_at = utcnow_naive()
            # close its alerts too
            for a in incident.alerts:
                a.status = "RESOLVED"
        incident.events.append(IncidentEvent(
            event_type="STATUS",
            message=f"Status changed to {new_status}", actor=actor,
        ))
        db.session.commit()

    # ------------------------------------------------------------------ #
    @staticmethod
    def acknowledge_alert(alert, actor):
        alert.status = "ACKNOWLEDGED"
        alert.acknowledged = True
        if alert.incident_id:
            AlertManager.add_manual_event(
                Incident.query.get(alert.incident_id),
                f"Alert #{alert.id} acknowledged", actor, "ACTION")
        db.session.commit()

    @staticmethod
    def resolve_alert(alert, actor):
        alert.status = "RESOLVED"
        if alert.incident_id:
            AlertManager.add_manual_event(
                Incident.query.get(alert.incident_id),
                f"Alert #{alert.id} resolved", actor, "ACTION")
        db.session.commit()


__all__ = ["AlertManager", "SEVERITY_RANK"]
