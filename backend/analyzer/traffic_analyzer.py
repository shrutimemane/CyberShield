"""
CyberShield - Traffic analyzer (pipeline orchestrator)
======================================================

The heart of the app: batches of normalized packets flow through

    parse -> persist -> feature extraction -> detection rules -> alerting

`ingest()` is the single entry point used by live capture, demo mode and PCAP
import, guaranteeing identical analysis regardless of the traffic source.
"""

from backend.models import db, PacketRecord
from backend.analyzer.packet_parser import parse_many
from backend.analyzer.feature_extractor import sliding_windows
from backend.detection.detection_engine import DetectionEngine
from backend.alerts.alert_manager import AlertManager
from backend.utils.settings import get_setting
from backend.utils.logger import get_logger

log = get_logger("cybershield.analyzer")


class TrafficAnalyzer:
    # Upper bound on detection passes per batch: keeps a huge PCAP upload
    # responsive while still scanning the whole capture end to end.
    MAX_WINDOWS_PER_BATCH = 25

    def __init__(self):
        self.engine = DetectionEngine()

    # ------------------------------------------------------------------ #
    def ingest(self, packets) -> dict:
        """
        Process one batch of packets end-to-end. Returns a summary dict:
        {parsed, stored, alerts_created, incidents_created,
         flagged_sources, windows_evaluated}

        The batch is tiled into consecutive detection windows (see
        feature_extractor.sliding_windows) so PCAP imports - which replay
        traffic from the past - are analyzed across their entire timeline.
        """
        records = parse_many(packets)
        if not records:
            return {"parsed": 0, "stored": 0, "alerts_created": 0,
                    "incidents_created": 0, "flagged_sources": [],
                    "windows_evaluated": 0}

        for r in records:
            db.session.add(r)
        db.session.flush()  # assign PKs before detection uses the rows

        window = get_setting("traffic_anomaly_window_seconds",
                             self._cfg("TRAFFIC_ANOMALY_WINDOW_SECONDS"))
        window = max(int(window or 10), 5)

        alerts, incidents, flagged = [], [], set()
        windows_evaluated = 0
        for features in sliding_windows([self._to_dict(r) for r in records],
                                        window_seconds=window,
                                        max_windows=self.MAX_WINDOWS_PER_BATCH):
            windows_evaluated += 1
            alert_mgr = AlertManager()
            window_alerts = self.engine.evaluate(features, alert_mgr)
            alerts.extend(window_alerts)
            incidents.extend(alert_mgr.escalate_alerts(window_alerts))
            flagged.update(a.source_ip for a in window_alerts)

        self._mark_flagged(records, flagged)
        db.session.commit()

        unique_alerts = {a.id for a in alerts if a.id is not None}
        return {
            "parsed": len(records),
            "stored": len(records),
            "alerts_created": len(unique_alerts),
            "incidents_created": len({i.id for i in incidents if i.id is not None}),
            "flagged_sources": sorted(flagged),
            "windows_evaluated": windows_evaluated,
        }

    # ------------------------------------------------------------------ #
    @staticmethod
    def _to_dict(record: PacketRecord) -> dict:
        return {
            "capture_id": record.capture_id, "timestamp": record.timestamp,
            "src_ip": record.src_ip, "dst_ip": record.dst_ip,
            "src_port": record.src_port, "dst_port": record.dst_port,
            "protocol": record.protocol, "length": record.length,
            "tcp_flags": record.tcp_flags,
        }

    @staticmethod
    def _mark_flagged(records, flagged_sources: set):
        if not flagged_sources:
            return
        for r in records:
            if r.src_ip in flagged_sources:
                r.status = "FLAGGED"
                r.alert_reason = "Source IP has active security alerts"

    @staticmethod
    def _cfg(key):
        from flask import current_app
        return current_app.config.get(key)
