"""
CyberShield - Traffic anomaly detector (DoS-like)
=================================================

Rule: more than `traffic_anomaly_pps_threshold` packets from one source within
`traffic_anomaly_window_seconds` (any protocol) raises a TRAFFIC_ANOMALY
alert - a volumetric pattern typical of DoS/DoS-like flooding. This is a
volume-heuristic, not a guarantee: it flags DoS-LIKE bursts for investigation.
"""

from backend.utils.settings import get_setting
from backend.utils.logger import get_logger

log = get_logger("cybershield.detect.anomaly")


class TrafficAnomalyDetector:
    name = "TRAFFIC_ANOMALY"

    def evaluate(self, features, alert_manager):
        alerts = []
        threshold = get_setting("traffic_anomaly_pps_threshold", 120)
        window = get_setting("traffic_anomaly_window_seconds", 10)

        for src, times in features["packet_times"].items():
            if len(times) <= threshold:
                continue
            pps = len(times) / max(window, 1)
            severity = "CRITICAL" if pps > threshold * 2 else "HIGH"
            reason = (f"Source IP sent {len(times)} packets in {window} seconds "
                      f"({pps:.1f} pkt/s) - DoS-like volumetric burst")
            dst = features["last_dst"].get(src)
            details = {
                "packet_count": len(times),
                "packets_per_second": round(pps, 1),
                "window_seconds": window,
                "threshold": threshold,
                "protocols": dict(features["protocol_counts"]),
            }
            alerts.append(alert_manager.create_alert(
                alert_type=self.name, severity=severity,
                source_ip=src, destination_ip=dst,
                reason=reason, details=details,
            ))
        return alerts
