"""
CyberShield - Database Models
=============================

SQLAlchemy models. Every table is created automatically on first run by
backend/database.py's init_db(). The schema covers:

* User               - login accounts (hashed passwords)
* Setting            - runtime-editable detection thresholds
* PacketRecord       - summarized packets (live capture, demo or PCAP import)
* Alert              - detection-engine output with severity + explanation
* Incident           - grouped/escalated incidents created from alerts
* IncidentEvent      - evidence timeline entries attached to incidents
* SuspiciousIP       - aggregate risk profile per source IP
* PCAPFile           - uploaded PCAP metadata
* FirewallRule       - simulated firewall rules (block/allow per IP/port)
* AuditLog           - security-relevant user actions
"""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """Timezone-aware UTC now (stored naive-UTC for SQLite simplicity)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True,
                      default="")
    full_name = db.Column(db.String(80), default="")
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default="admin")  # Admin / Security Analyst
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, raw: str):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, raw)


class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256), default="")
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)


class PacketRecord(db.Model):
    __tablename__ = "packets"

    id = db.Column(db.Integer, primary_key=True)
    capture_id = db.Column(db.String(64), index=True)   # live | demo | pcap:<name>
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(16), default="OTHER")
    length = db.Column(db.Integer, default=0)
    tcp_flags = db.Column(db.String(32), default="")
    status = db.Column(db.String(16), default="NORMAL")  # NORMAL | FLAGGED
    alert_reason = db.Column(db.String(256), default="")


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(64), index=True)     # PORT_SCAN / CONN_FLOOD / ...
    severity = db.Column(db.String(16), default="LOW")    # LOW / MEDIUM / HIGH / CRITICAL
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    reason = db.Column(db.String(512), nullable=False)
    details_json = db.Column(db.Text, default="{}")       # JSON blob (ports, counts, ...)
    status = db.Column(db.String(24), default="NEW")      # NEW / ACKNOWLEDGED / RESOLVED
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    acknowledged = db.Column(db.Boolean, default=False)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=True)

    @property
    def is_open(self):
        return self.status in ("NEW", "ACKNOWLEDGED")


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_ref = db.Column(db.String(32), unique=True)  # INC-0001 ...
    title = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(16), default="MEDIUM")
    status = db.Column(db.String(24), default="OPEN")     # OPEN / INVESTIGATING / CONTAINED / CLOSED
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    description = db.Column(db.String(1024), default="")
    risk_score = db.Column(db.Integer, default=0)         # 0-100
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    closed_at = db.Column(db.DateTime)

    events = db.relationship(
        "IncidentEvent", backref="incident", cascade="all, delete-orphan",
        lazy="dynamic", order_by="IncidentEvent.created_at",
    )
    alerts = db.relationship("Alert", backref="incident", lazy="dynamic")

    def generate_ref(self):
        if not self.incident_ref:
            last = Incident.query.order_by(Incident.id.desc()).first()
            n = (last.id if last else 0) + 1
            self.incident_ref = f"INC-{n:04d}"
        return self.incident_ref


class IncidentEvent(db.Model):
    """Timeline entry: investigation note, auto-detection event or action."""
    __tablename__ = "incident_events"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)
    event_type = db.Column(db.String(32), default="NOTE")  # NOTE / DETECTION / ACTION / STATUS
    message = db.Column(db.String(1024), nullable=False)
    actor = db.Column(db.String(64), default="system")
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class SuspiciousIP(db.Model):
    """Rolling aggregate risk profile for source IPs seen in alerts."""
    __tablename__ = "suspicious_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, index=True, nullable=False)
    first_seen = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow)
    alert_count = db.Column(db.Integer, default=0)
    packet_count = db.Column(db.Integer, default=0)
    categories = db.Column(db.String(256), default="")    # csv of detection types
    risk_score = db.Column(db.Integer, default=0)         # 0-100
    is_blocked = db.Column(db.Boolean, default=False)     # set via firewall simulator


class PCAPFile(db.Model):
    __tablename__ = "pcap_files"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    stored_path = db.Column(db.String(512), nullable=False)
    size_bytes = db.Column(db.Integer, default=0)
    packet_count = db.Column(db.Integer, default=0)
    alerts_found = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=utcnow)
    analysis_summary = db.Column(db.Text, default="{}")


class FirewallRule(db.Model):
    """Simulated firewall: education only - no packets are actually blocked."""
    __tablename__ = "firewall_rules"

    id = db.Column(db.Integer, primary_key=True)
    rule_type = db.Column(db.String(16), default="BLOCK")   # BLOCK / ALLOW
    target = db.Column(db.String(64), nullable=False)       # IP or ip:port
    reason = db.Column(db.String(256), default="")
    hit_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=utcnow)
    active = db.Column(db.Boolean, default=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(64), default="system")
    action = db.Column(db.String(128), nullable=False)
    detail = db.Column(db.String(512), default="")
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
