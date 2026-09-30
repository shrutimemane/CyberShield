"""
CyberShield - Database bootstrap
================================

Creates the SQLite database, all tables, the default admin account and the
default detection settings. Called automatically by app.py on startup.
"""

import os

from sqlalchemy import text

from backend.models import db, User, Setting


def get_session():
    """Create a short-lived SQLAlchemy session (must be used inside app context)."""
    return db.session


def init_db(app):
    """Bind SQLAlchemy to the Flask app, create tables and seed defaults."""
    db.init_app(app)
    with app.app_context():
        db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        db.create_all()
        _migrate_schema()
        _seed_admin()
        _seed_settings()


def _migrate_schema():
    """Safe, idempotent SQLite column migration.

    db.create_all() only creates missing TABLES - it never alters existing
    ones. Older databases (before registration was added) lack the users
    .email / .full_name columns, so we add them via ALTER TABLE when absent.
    Existing rows get defaults (admin keeps working; email can be set later).
    No data is ever dropped.
    """
    result = db.session.execute(text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"))
    if not result.first():
        return  # users table will be created fresh by create_all()
    cols = {row[1] for row in db.session.execute(text("PRAGMA table_info(users)"))}
    if "email" not in cols:
        db.session.execute(text(
            "ALTER TABLE users ADD COLUMN email VARCHAR(120) NOT NULL DEFAULT ''"))
        # Backfill existing rows so the unique index cannot collide
        # (old databases only hold the seeded admin account).
        db.session.execute(text(
            "UPDATE users SET email = username || '@local.invalid' WHERE email = ''"))
        db.session.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)"))
    if "full_name" not in cols:
        db.session.execute(text(
            "ALTER TABLE users ADD COLUMN full_name VARCHAR(80) DEFAULT ''"))
    db.session.commit()


def _seed_admin():
    """Create the default admin account (hashes only - never plaintext)."""
    from flask import current_app
    username = current_app.config["DEFAULT_ADMIN_USER"]
    password = current_app.config["DEFAULT_ADMIN_PASSWORD"]
    if not User.query.filter_by(username=username).first():
        u = User(username=username, role="Admin / Security Analyst")
        u.set_password(password)
        db.session.add(u)
        db.session.commit()


def _seed_settings():
    """Insert default detection thresholds if not already present."""
    from flask import current_app
    defaults = [
        ("port_scan_port_threshold", current_app.config["PORT_SCAN_PORT_THRESHOLD"],
         "Port scan: unique destination ports per source IP"),
        ("port_scan_window_seconds", current_app.config["PORT_SCAN_WINDOW_SECONDS"],
         "Port scan: sliding time window (seconds)"),
        ("port_scan_high_threshold", current_app.config["PORT_SCAN_HIGH_THRESHOLD"],
         "Port scan: unique ports at which severity becomes HIGH"),
        ("conn_flood_threshold", current_app.config["CONN_FLOOD_THRESHOLD"],
         "Excessive connections: connection attempts per destination"),
        ("conn_flood_window_seconds", current_app.config["CONN_FLOOD_WINDOW_SECONDS"],
         "Excessive connections: sliding window (seconds)"),
        ("traffic_anomaly_pps_threshold", current_app.config["TRAFFIC_ANOMALY_PPS_THRESHOLD"],
         "Traffic anomaly: packets per source within window"),
        ("traffic_anomaly_window_seconds", current_app.config["TRAFFIC_ANOMALY_WINDOW_SECONDS"],
         "Traffic anomaly: sliding window (seconds)"),
        ("suspicious_ip_event_threshold", current_app.config["SUSPICIOUS_IP_EVENT_THRESHOLD"],
         "Suspicious IP: distinct alerts needed to flag an IP"),
        ("alert_dedupe_seconds", current_app.config["ALERT_DEDUPE_SECONDS"],
         "Suppress identical alerts within this window (seconds)"),
    ]
    for key, value, desc in defaults:
        if not Setting.query.filter_by(key=key).first():
            db.session.add(Setting(key=key, value=str(value), description=desc))
    db.session.commit()


def reset_db(app):
    """Drop everything and recreate (used by tests / --reset flag)."""
    with app.app_context():
        db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        db.drop_all()
        db.create_all()
        _migrate_schema()
        _seed_admin()
        _seed_settings()


__all__ = ["db", "get_session", "init_db", "reset_db"]
