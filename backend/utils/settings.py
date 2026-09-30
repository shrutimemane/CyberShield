"""
CyberShield - Runtime settings service
======================================

Detection thresholds are stored in the `settings` table so analysts can tune
them live from the Settings page without editing code. Config values act as
defaults on first boot. Always read thresholds through get_setting() so the
rest of the code has a single source of truth.
"""

from backend.models import db, Setting


def get_setting(key: str, default):
    """Return a setting as int, falling back to the provided default."""
    row = Setting.query.filter_by(key=key).first()
    if row is None:
        return default
    try:
        return int(row.value)
    except (TypeError, ValueError):
        return default


def get_all_settings():
    return {s.key: s.value for s in Setting.query.all()}


def update_settings(updates: dict):
    """Validate + persist threshold updates. Returns (ok, error_message)."""
    int_keys = {
        "port_scan_port_threshold", "port_scan_window_seconds",
        "port_scan_high_threshold", "conn_flood_threshold",
        "conn_flood_window_seconds", "traffic_anomaly_pps_threshold",
        "traffic_anomaly_window_seconds", "suspicious_ip_event_threshold",
        "alert_dedupe_seconds",
    }
    for key, value in (updates or {}).items():
        if key not in int_keys:
            continue
        try:
            ivalue = int(value)
        except (TypeError, ValueError):
            return False, f"{key} must be an integer"
        if ivalue < 1:
            return False, f"{key} must be at least 1"
        row = Setting.query.filter_by(key=key).first()
        if row:
            row.value = str(ivalue)
    db.session.commit()
    return True, None


__all__ = ["get_setting", "get_all_settings", "update_settings"]
