"""
CyberShield - Excessive connection detector
===========================================

Rule: more than `conn_flood_threshold` connection attempts (TCP SYN without
ACK) from one source to ONE destination within `conn_flood_window_seconds`
raises an EXCESSIVE_CONNECTIONS alert. This mirrors SYN-flood-style behavior
where an attacker repeatedly opens connections to exhaust a service.
"""

from backend.utils.settings import get_setting
from backend.utils.logger import get_logger

log = get_logger("cybershield.detect.connflood")


class ConnectionFloodDetector:
    name = "EXCESSIVE_CONNECTIONS"

    def evaluate(self, features, alert_manager):
        alerts = []
        threshold = get_setting("conn_flood_threshold", 30)
        window = get_setting("conn_flood_window_seconds", 10)

        for src, dst_map in features["conn_attempts"].items():
            for dst, times in dst_map.items():
                if len(times) <= threshold:
                    continue
                severity = "HIGH" if len(times) > threshold * 2 else "MEDIUM"
                reason = (f"Source IP made {len(times)} connection attempts "
                          f"to {dst} within {window} seconds")
                details = {
                    "connection_attempts": len(times),
                    "destination": dst,
                    "window_seconds": window,
                    "threshold": threshold,
                }
                alerts.append(alert_manager.create_alert(
                    alert_type=self.name, severity=severity,
                    source_ip=src, destination_ip=dst,
                    reason=reason, details=details,
                ))
        return alerts
