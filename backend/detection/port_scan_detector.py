"""
CyberShield - Port scan detector
================================

Rule: if one source IP contacts MORE than `port_scan_port_threshold` unique
destination ports within `port_scan_window_seconds`, raise a PORT_SCAN alert.
Severity escalates to HIGH past `port_scan_high_threshold` unique ports.

Thresholds are read live from the settings table (Settings page), never
hardcoded at call sites.
"""

from datetime import timedelta

from backend.analyzer.feature_extractor import ports_contacted_in_window
from backend.utils.settings import get_setting
from backend.utils.logger import get_logger

log = get_logger("cybershield.detect.portscan")


class PortScanDetector:
    name = "PORT_SCAN"

    def evaluate(self, features, alert_manager):
        alerts = []
        port_threshold = get_setting("port_scan_port_threshold", 10)
        high_threshold = get_setting("port_scan_high_threshold", 25)
        window = get_setting("port_scan_window_seconds", 10)

        for src, unique_ports in features["unique_ports"].items():
            if len(unique_ports) <= port_threshold:
                continue
            contacted = ports_contacted_in_window(features, src)
            ports = [p for p, _ts in contacted]
            severity = "HIGH" if len(ports) > high_threshold else "MEDIUM"

            reason = (f"Source IP contacted {len(ports)} unique ports "
                      f"within {window} seconds")
            details = {
                "ports": ports[:50],
                "port_count": len(ports),
                "window_seconds": window,
                "threshold": port_threshold,
                "top_ports": sorted(ports)[:20],
            }
            dst = features.get("last_dst", {}).get(src)
            alerts.append(alert_manager.create_alert(
                alert_type=self.name, severity=severity,
                source_ip=src, destination_ip=dst,
                reason=reason, details=details,
            ))
        return alerts
