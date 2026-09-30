"""
CyberShield - Detection engine
==============================

Coordinates the rule-based detectors. Each detector is a small class with an
`evaluate(features, alert_mgr)` method that inspects the extracted features
and emits alerts through the AlertManager. Rules are intentionally simple and
explainable - this is an educational SOC, not a black box.

Future enhancement (clearly optional, NOT implemented): machine-learning based
anomaly scoring could complement these deterministic rules.
"""

from backend.detection.port_scan_detector import PortScanDetector
from backend.detection.connection_detector import ConnectionFloodDetector
from backend.detection.traffic_anomaly_detector import TrafficAnomalyDetector
from backend.detection.suspicious_ip_detector import SuspiciousIPDetector
from backend.utils.logger import get_logger

log = get_logger("cybershield.detection")


class DetectionEngine:
    """Runs every enabled detector over one window of features."""

    def __init__(self):
        self.detectors = [
            PortScanDetector(),
            ConnectionFloodDetector(),
            TrafficAnomalyDetector(),
            SuspiciousIPDetector(),
        ]

    def evaluate(self, features, alert_manager):
        """Run all detectors; return the flat list of new Alert rows."""
        new_alerts = []
        for detector in self.detectors:
            try:
                new_alerts.extend(detector.evaluate(features, alert_manager))
            except Exception as exc:              # one rule failing never stops the rest
                log.exception("Detector %s failed: %s", detector.name, exc)
        return new_alerts
