"""
CyberShield - Configuration
===========================

Central configuration for the application.

Environment variables (see .env.example) override defaults where present.
Runtime-changeable detection thresholds are stored in the database `settings`
table and are managed from the Settings page (backend/utils/settings.py).
"""

import os
from datetime import timedelta

from dotenv import load_dotenv

# Load .env from the project root (CyberShield/.env) when present.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class Config:
    """Base configuration - values here are safe defaults for classroom use."""

    SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-demo-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "database", "cybershield.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Sessions
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Directories
    BASE_DIR = BASE_DIR
    DATA_DIR = os.path.join(BASE_DIR, "data")
    PCAP_DIR = os.path.join(DATA_DIR, "pcaps")
    REPORT_DIR = os.path.join(DATA_DIR, "reports")
    DB_DIR = os.path.join(BASE_DIR, "database")

    # Authentication
    DEFAULT_ADMIN_USER = os.getenv("CYBERSHIELD_ADMIN_USER", "admin")
    DEFAULT_ADMIN_PASSWORD = os.getenv("CYBERSHIELD_ADMIN_PASSWORD", "admin123")

    # Live capture
    CAPTURE_INTERFACE = os.getenv("CYBERSHIELD_INTERFACE") or None
    CAPTURE_PROMISCUOUS = _env_bool("CYBERSHIELD_PROMISCUOUS", False)
    MAX_PACKETS_IN_MEMORY = 5000          # ring buffer size for live monitor page
    LIVE_POLL_SECONDS = 2                 # dashboard/traffic poll interval

    # Demo traffic generator
    DEMO_HOSTS = [
        "192.168.1.10", "192.168.1.11", "192.168.1.12",
        "192.168.1.20", "192.168.1.25",
        "192.168.1.1",  # router/gateway
        "10.0.0.5", "10.0.0.6",
        "172.16.0.9",
    ]
    DEMO_ATTACKER_IP = os.getenv("CYBERSHIELD_ATTACKER_IP", "203.0.113.66")
    DEMO_INTERNAL_VICTIM = "192.168.1.1"

    # ---- Detection thresholds (defaults; runtime copies live in DB) ----
    # Port scan: > X unique destination ports from one source within Y seconds
    PORT_SCAN_PORT_THRESHOLD = 10
    PORT_SCAN_WINDOW_SECONDS = 10

    # Excessive connections: > X connection attempts (SYN) from one source
    # to one destination within Y seconds
    CONN_FLOOD_THRESHOLD = 30
    CONN_FLOOD_WINDOW_SECONDS = 10

    # Traffic anomaly / DoS-like: > X packets from one source in Y seconds
    # (any protocol) - volumetric burst
    TRAFFIC_ANOMALY_PPS_THRESHOLD = 120
    TRAFFIC_ANOMALY_WINDOW_SECONDS = 10

    # Suspicious IP: >= X distinct detection events linked to one IP
    SUSPICIOUS_IP_EVENT_THRESHOLD = 2

    # Severity auto-escalation: unique-port count at which a port scan is HIGH
    PORT_SCAN_HIGH_THRESHOLD = 25

    # Capture pipeline
    PROCESSING_BATCH_INTERVAL = 1.0       # seconds between analyzer passes
    ALERT_DEDUPE_SECONDS = 30             # suppress identical alerts within window

    # Reports
    REPORT_COMPANY_NAME = "CyberShield Security Operations"
