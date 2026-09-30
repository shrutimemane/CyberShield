"""
CyberShield - Flask application
===============================

Single entry module: creates the app, initializes the database, registers all
page routes and JSON APIs, and manages the background capture workers
(live sniffer + demo traffic generator).

Design notes
------------
* All analysis (live / demo / PCAP) funnels through TrafficAnalyzer.ingest()
  so detection behaves identically for every traffic source.
* Capture threads run with their own app context; SQLite uses WAL to tolerate
  concurrent reads from the dashboard while capture writes.
* Every route is protected by @login_required except login/static assets.
"""

import os
import json
import time
import csv
import io
import threading
from datetime import timedelta, datetime

from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, send_file, abort)
from functools import wraps
from sqlalchemy import func, or_
from sqlalchemy.exc import OperationalError

from backend.config import Config
from backend.models import (db, User, PacketRecord, Alert, Incident,
                            IncidentEvent, SuspiciousIP, PCAPFile,
                            FirewallRule, AuditLog, Setting)
from backend.database import init_db
from backend.analyzer.traffic_analyzer import TrafficAnalyzer
from backend.analyzer.risk_engine import (calculate_global_risk, risk_label,
                                          risk_color, risk_factors)
from backend.alerts.alert_manager import AlertManager, SEVERITY_RANK
from backend.capture.packet_sniffer import LiveSniffer
from backend.capture.demo_traffic import (DemoTrafficThread, generate_demo_batch,
                                          generate_attack_only,
                                          generate_demo_sequence)
from backend.capture.pcap_reader import read_pcap
from backend.utils.evidence import hash_file, hash_alert, hash_incident
from backend.utils.firewall_simulator import simulate as fw_simulate
from backend.utils.helpers import (is_private_ip, ip_scope, safe_json_loads, fmt_dt,
                                   human_bytes, slugify, utcnow_naive)
from backend.utils.settings import get_setting, get_all_settings, update_settings
from backend.utils.validators import (ValidationError, validate_registration,
                                      validate_firewall_target,
                                      validate_simulate_payload)
from backend.reports.report_generator import (generate_pdf_report,
                                              generate_html_report,
                                              collect_report_data,
                                              PDF_AVAILABLE)
from backend.utils.logger import get_logger

log = get_logger("cybershield.app")

# --------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------- #
template_dir = os.path.join(Config.BASE_DIR, "frontend", "templates")
static_dir = os.path.join(Config.BASE_DIR, "frontend", "static")

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config.from_object(Config)

# SQLite concurrency tuning: allow cross-thread use + WAL journaling
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"check_same_thread": False}}
init_db(app)


analyzer = TrafficAnalyzer()
APP_LOCK = threading.Lock()          # serializes ingest batches


def safe_commit(retries: int = 4, delay: float = 0.2) -> bool:
    """Commit, retrying briefly while SQLite is locked by a capture thread.

    Returns True on success. A momentary lock never turns into a 500 for the
    analyst: the write is retried, and a permanent failure is logged instead.
    """
    from sqlalchemy.exc import OperationalError
    for attempt in range(retries):
        try:
            db.session.commit()
            return True
        except OperationalError as exc:                 # pragma: no cover
            db.session.rollback()
            if "locked" not in str(exc).lower() or attempt == retries - 1:
                log.warning("Database write failed: %s", exc)
                return False
            time.sleep(delay * (attempt + 1))
    return False


def _tune_sqlite_pragmas():
    """Enable WAL + busy timeout so dashboard reads coexist with capture writes.

    SQLite allows a single writer: the live/demo capture threads ingest while
    web requests also write (audit log, status changes), so a generous busy
    timeout matters - the writer waits instead of failing with
    "database is locked".
    """
    from sqlalchemy import event
    with app.app_context():
        engine = db.engine
        if engine.name == "sqlite":
            @event.listens_for(engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, _rec):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=15000")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.close()


_tune_sqlite_pragmas()


def ingest_packets(packets):
    """Thread-safe ingest entry point used by all capture sources."""
    if not packets:
        return {"parsed": 0, "alerts_created": 0}
    with APP_LOCK, app.app_context():
        try:
            return analyzer.ingest(packets)
        except Exception:
            db.session.rollback()
            log.exception("Ingest failed")
            return {"parsed": 0, "alerts_created": 0, "error": True}


# --------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------- #
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required"), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            user.last_login = utcnow_naive()
            db.session.add(AuditLog(actor=user.username,
                                    action="LOGIN", detail="Web login"))
            db.session.commit()
            next_url = request.args.get("next") or url_for("dashboard")
            if not next_url.startswith("/"):
                next_url = url_for("dashboard")
            return redirect(next_url)
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Self-service account creation (passwords stored as Werkzeug hashes)."""
    if request.method == "POST":
        try:
            fields = validate_registration(
                request.form.get("full_name"),
                request.form.get("username"),
                request.form.get("email"),
                request.form.get("password"),
                request.form.get("confirm_password"),
            )
        except ValidationError as ve:
            return render_template("register.html", error=ve.message,
                                   form=request.form), 400
        if User.query.filter_by(username=fields["username"]).first():
            return render_template("register.html",
                                   error="That username is already taken.",
                                   form=request.form), 400
        if User.query.filter_by(email=fields["email"]).first():
            return render_template("register.html",
                                   error="An account with that email already exists.",
                                   form=request.form), 400
        user = User(username=fields["username"], email=fields["email"],
                    full_name=fields["full_name"],
                    role="Security Analyst")
        user.set_password(fields["password"])  # hashed - never stored plaintext
        db.session.add(user)
        db.session.add(AuditLog(actor=fields["username"], action="REGISTER",
                                detail="Account created via registration page"))
        db.session.commit()
        flash("Account created successfully. Please sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="LOGOUT", detail=""))
    db.session.commit()
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------- #
# Page routes (SOC-style UI; packet detail stays secondary)
# --------------------------------------------------------------------- #
@app.route("/")
@login_required
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@app.route("/traffic")
@login_required
def traffic():
    return render_template("traffic.html", active="traffic")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html", active="alerts")


@app.route("/incidents")
@login_required
def incidents_page():
    return render_template("incidents.html", active="incidents")


@app.route("/incidents/<int:incident_id>")
@login_required
def incident_details(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    events = incident.events.order_by(IncidentEvent.created_at.asc()).all()
    alerts = incident.alerts.order_by(Alert.created_at.desc()).all()
    return render_template("incident_details.html", active="incidents",
                           incident=incident, events=events, alerts=alerts,
                           fmt_dt=fmt_dt,
                           evidence_hash=hash_incident(incident))


@app.route("/ips")
@login_required
def ips_page():
    return render_template("ips.html", active="ips")


@app.route("/pcap")
@login_required
def pcap_page():
    files = PCAPFile.query.order_by(PCAPFile.uploaded_at.desc()).all()
    return render_template("pcap_analysis.html", active="pcap",
                           pcap_files=files, fmt_dt=fmt_dt,
                           human_bytes=human_bytes)


@app.route("/reports")
@login_required
def reports_page():
    reports_dir = app.config["REPORT_DIR"]
    os.makedirs(reports_dir, exist_ok=True)
    files = []
    for name in sorted(os.listdir(reports_dir), reverse=True):
        if name.endswith((".pdf", ".html")):
            path = os.path.join(reports_dir, name)
            files.append({"name": name, "size": human_bytes(
                os.path.getsize(path))})
    return render_template("reports.html", active="reports",
                           report_files=files, pdf_ok=PDF_AVAILABLE)


@app.route("/firewall")
@login_required
def firewall_page():
    rules = FirewallRule.query.order_by(FirewallRule.created_at.desc()).all()
    return render_template("firewall.html", active="firewall", rules=rules,
                           fmt_dt=fmt_dt)


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", active="settings",
                           settings=get_all_settings(),
                           capture_available=LiveSniffer.available())


# --------------------------------------------------------------------- #
# Dashboard / stats API
# --------------------------------------------------------------------- #
def _dashboard_stats():
    cutoff = utcnow_naive() - timedelta(hours=24)
    total_packets = PacketRecord.query.count()
    last_hour = utcnow_naive() - timedelta(minutes=5)
    active_conns = db.session.query(func.count(func.distinct(
        func.concat(PacketRecord.src_ip, ":", func.coalesce(PacketRecord.src_port, 0))
    ))).filter(PacketRecord.timestamp >= last_hour).scalar() or 0

    open_alerts = Alert.query.filter(Alert.status.in_(("NEW", "ACKNOWLEDGED")))
    open_incidents = Incident.query.filter(
        Incident.status.in_(("OPEN", "INVESTIGATING")))
    suspicious = SuspiciousIP.query.filter(SuspiciousIP.risk_score >= 20).count()

    # --- chart data: alerts by severity ------------------------------- #
    sev_rows = db.session.query(Alert.severity, func.count(Alert.id)).filter(
        Alert.created_at >= cutoff).group_by(Alert.severity).all()
    alerts_by_severity = {s: 0 for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    for sev, cnt in sev_rows:
        if sev in alerts_by_severity:
            alerts_by_severity[sev] = cnt

    # --- chart data: alerts by type ------------------------------------ #
    type_rows = db.session.query(Alert.alert_type, func.count(Alert.id)).filter(
        Alert.created_at >= cutoff).group_by(Alert.alert_type).all()

    # --- chart data: packets last 10 minutes (per minute) -------------- #
    packets_timeline = []
    for i in range(9, -1, -1):
        t_end = utcnow_naive() - timedelta(minutes=i)
        t_start = t_end - timedelta(minutes=1)
        cnt = PacketRecord.query.filter(
            PacketRecord.timestamp >= t_start,
            PacketRecord.timestamp < t_end).count()
        packets_timeline.append({"time": t_end.strftime("%H:%M"),
                                 "packets": cnt})

    # --- chart data: protocol split ------------------------------------ #
    proto_rows = db.session.query(PacketRecord.protocol,
                                  func.count(PacketRecord.id)).group_by(
        PacketRecord.protocol).all()

    # --- chart data: alerts per hour, stacked by severity (last 12h) ---- #
    hourly_cutoff = utcnow_naive() - timedelta(hours=12)
    hour_rows = db.session.query(
        func.strftime("%Y-%m-%d %H:00", Alert.created_at).label("hour"),
        Alert.severity, func.count(Alert.id)).filter(
        Alert.created_at >= hourly_cutoff).group_by("hour", Alert.severity).all()
    hour_map = {}
    for hour, sev, cnt in hour_rows:
        hour_map.setdefault(hour, {s: 0 for s in
                                   ("LOW", "MEDIUM", "HIGH", "CRITICAL")})[sev] = cnt
    now_hour = utcnow_naive().replace(minute=0, second=0, microsecond=0)
    alerts_hourly = []
    for i in range(11, -1, -1):
        h = (now_hour - timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
        alerts_hourly.append({"hour": h[11:], "counts": hour_map.get(h, {
            s: 0 for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")})})

    # --- chart data: top source IPs by packet volume -------------------- #
    top_talkers = db.session.query(
        PacketRecord.src_ip, func.count(PacketRecord.id).label("packets")
    ).group_by(PacketRecord.src_ip).order_by(
        func.count(PacketRecord.id).desc()).limit(6).all()

    risk = calculate_global_risk()

    # --- card sub-stats: alert split + resolved count for trend context - #
    alerts_24h = Alert.query.filter(Alert.created_at >= cutoff)
    alerts_critical = alerts_24h.filter(
        Alert.severity.in_(("CRITICAL", "HIGH"))).count()
    resolved_24h = Alert.query.filter(
        Alert.created_at >= cutoff,
        Alert.status == "RESOLVED").count()
    blocked_ips = SuspiciousIP.query.filter(
        SuspiciousIP.risk_score >= 20,
        SuspiciousIP.is_blocked.is_(True)).count()

    return {
        "cards": {
            "total_packets": total_packets,
            "active_connections": active_conns,
            "security_alerts": alerts_24h.count(),
            "alerts_high_priority": alerts_critical,
            "alerts_resolved_24h": resolved_24h,
            "open_alerts": open_alerts.count(),
            "suspicious_ips": suspicious,
            "blocked_ips": blocked_ips,
            "open_incidents": open_incidents.count(),
            "risk_score": risk,                      # None = insufficient data
            "risk_label": risk_label(risk),
            "risk_color": risk_color(risk),
            "risk_factors": risk_factors(),
            "demo_data": capture_status().get("demo_running", False),
        },
        "charts": {
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_type": dict(type_rows),
            "packets_timeline": packets_timeline,
            "protocols": dict(proto_rows),
            "alerts_hourly": alerts_hourly,
            "top_talkers": [{"src_ip": ip, "packets": n}
                            for ip, n in top_talkers],
        },
        "recent_alerts": [_alert_dict(a) for a in
                          Alert.query.order_by(Alert.created_at.desc()).limit(8)],
        "top_suspicious": [{
            "ip": s.ip, "risk_score": s.risk_score,
            "alert_count": s.alert_count, "categories": s.categories,
            "is_blocked": s.is_blocked}
            for s in SuspiciousIP.query.filter(
                SuspiciousIP.risk_score >= 20).order_by(
                SuspiciousIP.risk_score.desc()).limit(6)],
        "recent_incidents": [{
            "id": i.id,
            "ref": i.incident_ref, "title": i.title, "severity": i.severity,
            "status": i.status, "created": fmt_dt(i.created_at)}
            for i in Incident.query.order_by(
                Incident.created_at.desc()).limit(5)],
        "capture_status": capture_status(),
    }


def _alert_dict(a: Alert):
    return {
        "id": a.id, "type": a.alert_type, "severity": a.severity,
        "source_ip": a.source_ip, "destination_ip": a.destination_ip,
        "reason": a.reason, "status": a.status,
        "created": fmt_dt(a.created_at), "incident_id": a.incident_id,
        "details": safe_json_loads(a.details_json),
    }


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    return jsonify(_dashboard_stats())


@app.route("/api/metrics/timeline")
@login_required
def api_metrics_timeline():
    """Time-series for the dashboard charts.

    Query params:
      hours: look-back window, one of 1, 6, 24, 168 (default 24; other
             values are clamped to the nearest allowed bucket).
    Returns buckets with packets (total), alerts (by severity) and a
    summary. All values come from real PacketRecord/Alert rows - no
    synthetic history is generated; empty buckets are simply zero.
    """
    try:
        hours = int(request.args.get("hours", 24))
    except (TypeError, ValueError):
        hours = 24
    allowed = (1, 6, 24, 168)
    hours = min(allowed, key=lambda h: abs(h - hours))  # clamp to nearest

    end = utcnow_naive()
    start = end - timedelta(hours=hours)

    if hours <= 6:
        n_buckets, step = hours * 12, timedelta(minutes=5)   # 5-min buckets
    elif hours <= 24:
        n_buckets, step = 24, timedelta(hours=1)             # hourly
    else:
        n_buckets, step = 28, timedelta(hours=6)             # 6-hourly

    def bucket_key(ts):
        if ts is None:
            return None
        idx = int((ts - start).total_seconds() // step.total_seconds())
        return idx if 0 <= idx < n_buckets else None

    pkt_rows = db.session.query(PacketRecord.timestamp, PacketRecord.length).filter(
        PacketRecord.timestamp >= start, PacketRecord.timestamp <= end).all()
    packets = [0] * n_buckets
    volume = [0] * n_buckets
    for ts, length in pkt_rows:
        idx = bucket_key(ts)
        if idx is not None:
            packets[idx] += 1
            volume[idx] += (length or 0)

    alert_rows = db.session.query(
        Alert.created_at, Alert.severity).filter(
        Alert.created_at >= start, Alert.created_at <= end).all()
    sev_series = {s: [0] * n_buckets
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for ts, sev in alert_rows:
        idx = bucket_key(ts)
        if idx is not None and sev in sev_series:
            sev_series[sev][idx] += 1

    buckets = []
    for i in range(n_buckets):
        b_start = start + i * step
        label = b_start.strftime("%H:%M") if hours <= 24 \
            else b_start.strftime("%d %b %H:%M")
        buckets.append({
            "label": label,
            "iso": b_start.strftime("%Y-%m-%dT%H:%M:%S"),
            "packets": packets[i],
            "bytes": volume[i],
            **{f"alerts_{s.lower()}": sev_series[s][i]
               for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        })

    return jsonify({
        "hours": hours,
        "interval_minutes": int(step.total_seconds() // 60),
        "buckets": buckets,
        "summary": {
            "packets": sum(packets),
            "bytes": sum(volume),
            "alerts": sum(sum(v) for v in sev_series.values()),
            "alerts_by_severity": {s: sum(v) for s, v in sev_series.items()},
        },
    })


@app.route("/api/alerts/export")
@login_required
def api_alerts_export():
    """Download the latest alerts as CSV (analyst evidence hand-off)."""
    rows = Alert.query.order_by(Alert.created_at.desc()).limit(1000).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "time_utc", "severity", "type", "source_ip",
                     "destination_ip", "status", "incident_id", "reason"])
    for a in rows:
        writer.writerow([a.id, fmt_dt(a.created_at), a.severity, a.alert_type,
                         a.source_ip, a.destination_ip or "", a.status,
                         a.incident_id or "", a.reason])
    buf.seek(0)
    stamp = utcnow_naive().strftime("%Y%m%d-%H%M%S")
    return send_file(io.BytesIO(buf.getvalue().encode("utf-8")),
                     mimetype="text/csv", as_attachment=True,
                     download_name=f"cybershield_alerts_{stamp}.csv")


@app.route("/api/alerts/unread-count")
@login_required
def api_alerts_unread_count():
    n = Alert.query.filter(Alert.status == "NEW").count()
    return jsonify({"new_alerts": n})


# --------------------------------------------------------------------- #
# Live traffic API
# --------------------------------------------------------------------- #
@app.route("/api/traffic")
@login_required
def api_traffic():
    limit = min(int(request.args.get("limit", 100)), 500)
    flagged_only = request.args.get("flagged") == "1"
    q = PacketRecord.query
    if flagged_only:
        q = q.filter_by(status="FLAGGED")
    rows = q.order_by(PacketRecord.timestamp.desc(), PacketRecord.id.desc()) \
        .limit(limit).all()
    return jsonify({
        "packets": [{
            "id": p.id, "time": p.timestamp.strftime("%H:%M:%S") if p.timestamp else "-",
            "ts": fmt_dt(p.timestamp, "%Y-%m-%d %H:%M:%S"),
            "src_ip": p.src_ip, "dst_ip": p.dst_ip,
            "src_port": p.src_port, "dst_port": p.dst_port,
            "protocol": p.protocol, "length": p.length,
            "tcp_flags": p.tcp_flags, "status": p.status,
            "reason": p.alert_reason or "",
        } for p in rows],
        "capture_status": capture_status(),
    })


# --------------------------------------------------------------------- #
# Capture control (live + demo)
# --------------------------------------------------------------------- #
sniffer = LiveSniffer(ingest_packets,
                      interface=Config.CAPTURE_INTERFACE,
                      promiscuous=Config.CAPTURE_PROMISCUOUS)
demo_thread = None


def capture_status():
    return {
        "live_running": sniffer.is_running,
        "live_available": sniffer.available(),
        "live_error": sniffer.last_error,
        "live_captured": sniffer.captured_count,
        "demo_running": bool(demo_thread and demo_thread.is_alive()),
        "interface": sniffer.interface or "default",
    }


@app.route("/api/capture/status")
@login_required
def api_capture_status():
    return jsonify(capture_status())


@app.route("/api/capture/start", methods=["POST"])
@login_required
def api_capture_start():
    global sniffer
    iface = (request.json or {}).get("interface") if request.is_json else None
    if iface is not None:
        sniffer.stop()
        sniffer = LiveSniffer(ingest_packets, interface=iface,
                              promiscuous=Config.CAPTURE_PROMISCUOUS)
    ok = sniffer.start()
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="CAPTURE_START",
                            detail=f"iface={sniffer.interface} ok={ok}"))
    safe_commit()
    if not ok:
        return jsonify({
            "started": False,
            "error": sniffer.last_error or "Live capture is unavailable.",
            "message": "Live capture is unavailable. Use PCAP Analysis or Demo Mode.",
            "status": capture_status()}), 200
    return jsonify({"started": True, "status": capture_status()})


@app.route("/api/capture/stop", methods=["POST"])
@login_required
def api_capture_stop():
    global demo_thread
    sniffer.stop()
    if demo_thread and demo_thread.is_alive():
        demo_thread.stop()
        demo_thread = None
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="CAPTURE_STOP", detail=""))
    safe_commit()
    return jsonify({"stopped": True, "status": capture_status()})


@app.route("/api/demo/start", methods=["POST"])
@login_required
def api_demo_start():
    global demo_thread
    if demo_thread and demo_thread.is_alive():
        return jsonify({"started": True, "status": capture_status()})
    demo_thread = DemoTrafficThread(ingest_packets, interval=2.0)
    demo_thread.start()
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="DEMO_START", detail="Demo traffic enabled"))
    safe_commit()
    return jsonify({"started": True, "status": capture_status()})


@app.route("/api/demo/inject", methods=["POST"])
@login_required
def api_demo_inject():
    """Inject one scripted attack scenario (safe, in-DB only)."""
    scenario = (request.json or {}).get("scenario", "port_scan")
    try:
        packets = generate_attack_only(scenario)
    except KeyError:
        return jsonify(error="Unknown scenario"), 400
    result = ingest_packets(packets)
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="DEMO_INJECT", detail=f"scenario={scenario}"))
    safe_commit()
    return jsonify({"injected": len(packets), "scenario": scenario,
                    "result": result})


@app.route("/api/demo/seed", methods=["POST"])
@login_required
def api_demo_seed():
    """Seed one full demo batch (benign + all attack scenarios)."""
    result = ingest_packets(generate_demo_batch(n_benign=60, include_attacks=True))
    return jsonify({"seeded": True, "result": result})


# --------------------------------------------------------------------- #
# Alerts API
# --------------------------------------------------------------------- #
@app.route("/api/alerts")
@login_required
def api_alerts():
    status = request.args.get("status", "all")
    severity = request.args.get("severity", "all")
    alert_type = request.args.get("type", "all")
    q = Alert.query
    if status and status != "all":
        q = q.filter(Alert.status == status)
    if severity and severity != "all":
        q = q.filter(Alert.severity == severity)
    if alert_type and alert_type != "all":
        q = q.filter(Alert.alert_type == alert_type)
    rows = q.order_by(Alert.created_at.desc()).limit(300).all()
    return jsonify({"alerts": [_alert_dict(a) for a in rows]})


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
def api_alert_ack(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    AlertManager.acknowledge_alert(alert, session.get("username", "?"))
    return jsonify(ok=True)


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def api_alert_resolve(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    AlertManager.resolve_alert(alert, session.get("username", "?"))
    return jsonify(ok=True)


@app.route("/api/alerts/<int:alert_id>/evidence")
@login_required
def api_alert_evidence(alert_id):
    """SHA-256 chain-of-custody hash for one alert."""
    alert = Alert.query.get_or_404(alert_id)
    return jsonify(alert_id=alert.id, sha256=hash_alert(alert))


# --------------------------------------------------------------------- #
# Incidents API
# --------------------------------------------------------------------- #
@app.route("/api/incidents")
@login_required
def api_incidents():
    status = request.args.get("status", "all")
    q = Incident.query
    if status and status != "all":
        q = q.filter(Incident.status == status)
    rows = q.order_by(Incident.created_at.desc()).limit(200).all()
    return jsonify({"incidents": [{
        "id": i.id, "ref": i.incident_ref, "title": i.title,
        "severity": i.severity, "status": i.status,
        "source_ip": i.source_ip, "created": fmt_dt(i.created_at),
        "alerts": i.alerts.count(),
        "events": i.events.count(),
    } for i in rows]})


@app.route("/api/incidents/<int:incident_id>/note", methods=["POST"])
@login_required
def api_incident_note(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    message = (request.json or {}).get("message", "").strip()
    if not message:
        return jsonify(error="Note text required"), 400
    AlertManager.add_manual_event(incident, message[:1000],
                                  session.get("username", "?"), "NOTE")
    return jsonify(ok=True)


@app.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
@login_required
def api_incident_status(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    new_status = (request.json or {}).get("status", "")
    if new_status not in ("OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"):
        return jsonify(error="Invalid status"), 400
    AlertManager.set_incident_status(incident, new_status,
                                     session.get("username", "?"))
    return jsonify(ok=True, status=new_status)


# --------------------------------------------------------------------- #
# IP analysis API
# --------------------------------------------------------------------- #
def _ip_profile(ip):
    alerts = Alert.query.filter_by(source_ip=ip).order_by(
        Alert.created_at.desc()).all()
    packets = PacketRecord.query.filter_by(src_ip=ip).order_by(
        PacketRecord.timestamp.desc()).limit(500).all()
    row = SuspiciousIP.query.filter_by(ip=ip).first()
    ports = sorted({p.dst_port for p in packets if p.dst_port})
    protocols = {}
    for p in packets:
        protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
    destinations = {}
    for p in packets:
        destinations[p.dst_ip] = destinations.get(p.dst_ip, 0) + 1
    top_dests = sorted(destinations.items(), key=lambda kv: -kv[1])[:10]
    fw = fw_simulate(ip, None, None)
    return {
        "ip": ip,
        "is_private": is_private_ip(ip),
        "scope": ip_scope(ip),
        "risk_score": row.risk_score if row else min(100, len(alerts) * 10),
        "alert_count": len(alerts),
        "packet_count": len(packets),
        "categories": (row.categories if row else
                       ",".join(sorted({a.alert_type for a in alerts}))),
        "first_seen": fmt_dt(row.first_seen) if row else fmt_dt(
            alerts[-1].created_at if alerts else None),
        "last_seen": fmt_dt(row.last_seen if row else
                            (alerts[0].created_at if alerts else None)),
        "unique_ports": len(ports),
        "ports": ports[:40],
        "protocols": protocols,
        "top_destinations": [{"ip": d, "count": c} for d, c in top_dests],
        "firewall_decision": fw["action"],
        "is_blocked": bool(row.is_blocked) if row else False,
        "alerts": [_alert_dict(a) for a in alerts[:20]],
        "recent_packets": [{
            "time": fmt_dt(p.timestamp), "dst_ip": p.dst_ip,
            "dst_port": p.dst_port, "protocol": p.protocol,
            "length": p.length, "flags": p.tcp_flags, "status": p.status,
        } for p in packets[:25]],
    }


@app.route("/api/ips")
@login_required
def api_ips():
    """Suspicious IP table: IPs from alerts + aggregates, ranked by risk."""
    rows = SuspiciousIP.query.order_by(SuspiciousIP.risk_score.desc()).all()
    alert_ips = {a.source_ip for a in Alert.query.all()}
    known = {r.ip for r in rows}
    out = [{
        "ip": r.ip, "risk_score": r.risk_score, "alert_count": r.alert_count,
        "categories": r.categories, "is_blocked": r.is_blocked,
        "last_seen": fmt_dt(r.last_seen), "is_private": is_private_ip(r.ip),
        "scope": ip_scope(r.ip),
    } for r in rows]
    for ip in sorted(alert_ips - known):
        cnt = Alert.query.filter_by(source_ip=ip).count()
        worst = (Alert.query.filter_by(source_ip=ip)
                 .order_by(Alert.created_at.desc()).first())
        out.append({
            "ip": ip,
            "risk_score": min(100, cnt * 10),
            "alert_count": cnt,
            "categories": worst.alert_type if worst else "",
            "is_blocked": False,
            "last_seen": fmt_dt(worst.created_at) if worst else "-",
            "is_private": is_private_ip(ip),
            "scope": ip_scope(ip),
        })
    out.sort(key=lambda r: -r["risk_score"])
    return jsonify({"ips": out[:100]})


@app.route("/api/ips/<path:ip>")
@login_required
def api_ip_detail(ip):
    return jsonify(_ip_profile(ip))


# --------------------------------------------------------------------- #
# PCAP analysis API
# --------------------------------------------------------------------- #
@app.route("/api/pcap/upload", methods=["POST"])
@login_required
def api_pcap_upload():
    file = request.files.get("pcap_file")
    if not file or not file.filename:
        return jsonify(error="Choose a .pcap or .pcapng file first"), 400
    filename = slugify(os.path.splitext(file.filename)[0]) + \
        os.path.splitext(file.filename)[1].lower()
    if not filename.endswith((".pcap", ".pcapng", ".cap")):
        return jsonify(error="Only .pcap / .pcapng / .cap files are supported"), 400

    os.makedirs(app.config["PCAP_DIR"], exist_ok=True)
    path = os.path.join(app.config["PCAP_DIR"], filename)
    file.save(path)

    packets, err = read_pcap(path)
    if err:
        return jsonify(error=err), 400

    result = ingest_packets(packets)
    pcap = PCAPFile(
        filename=filename, stored_path=path,
        size_bytes=os.path.getsize(path),
        packet_count=len(packets),
        alerts_found=result.get("alerts_created", 0),
        analysis_summary=json.dumps({
            "protocols": {},
            "top_talkers": {},
            "sha256": hash_file(path),
        }),
    )
    # quick summary for display
    protos, talkers = {}, {}
    for p in packets:
        protos[p["protocol"]] = protos.get(p["protocol"], 0) + 1
        talkers[p["src_ip"]] = talkers.get(p["src_ip"], 0) + 1
    pcap.analysis_summary = json.dumps({
        "protocols": protos,
        "top_talkers": dict(sorted(talkers.items(), key=lambda kv: -kv[1])[:10]),
        "sha256": hash_file(path),
    })
    db.session.add(pcap)
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="PCAP_UPLOAD", detail=filename))
    db.session.commit()
    return jsonify({
        "ok": True, "id": pcap.id, "filename": filename,
        "packets": len(packets), "alerts_created": result.get("alerts_created", 0),
        "incidents_created": result.get("incidents_created", 0),
        "sha256": hash_file(path),
    })


@app.route("/api/pcap/<int:pcap_id>/reanalyze", methods=["POST"])
@login_required
def api_pcap_reanalyze(pcap_id):
    pcap = PCAPFile.query.get_or_404(pcap_id)
    packets, err = read_pcap(pcap.stored_path)
    if err:
        return jsonify(error=err), 400
    result = ingest_packets(packets)
    pcap.alerts_found = pcap.alerts_found + result.get("alerts_created", 0)
    db.session.commit()
    return jsonify(ok=True, result=result)


@app.route("/api/pcap/<int:pcap_id>")
@login_required
def api_pcap_detail(pcap_id):
    pcap = PCAPFile.query.get_or_404(pcap_id)
    summary = safe_json_loads(pcap.analysis_summary)
    return jsonify({
        "id": pcap.id, "filename": pcap.filename,
        "size": human_bytes(pcap.size_bytes), "packets": pcap.packet_count,
        "alerts_found": pcap.alerts_found,
        "uploaded": fmt_dt(pcap.uploaded_at),
        "sha256": summary.get("sha256"),
        "protocols": summary.get("protocols", {}),
        "top_talkers": summary.get("top_talkers", {}),
    })


@app.route("/api/pcap/<int:pcap_id>/delete", methods=["POST"])
@login_required
def api_pcap_delete(pcap_id):
    pcap = PCAPFile.query.get_or_404(pcap_id)
    try:
        if os.path.exists(pcap.stored_path):
            os.remove(pcap.stored_path)
    except OSError:
        pass
    db.session.delete(pcap)
    db.session.commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------- #
# Firewall simulator API
# --------------------------------------------------------------------- #
@app.route("/api/firewall/rules", methods=["GET", "POST"])
@login_required
def api_firewall_rules():
    if request.method == "POST":
        data = request.json or {}
        rule_type = data.get("rule_type", "BLOCK").upper()
        if rule_type not in ("BLOCK", "ALLOW"):
            return jsonify(error="rule_type must be BLOCK or ALLOW"), 400
        try:
            target = validate_firewall_target(data.get("target"))
        except ValidationError as ve:
            return jsonify(error=ve.message), 400
        rule = FirewallRule(rule_type=rule_type, target=target[:64],
                            reason=(data.get("reason") or "")[:256])
        db.session.add(rule)
        db.session.add(AuditLog(actor=session.get("username", "?"),
                                action="FW_RULE_ADD", detail=f"{rule_type} {target}"))
        db.session.commit()
        return jsonify(ok=True, id=rule.id)
    rules = FirewallRule.query.order_by(FirewallRule.id.asc()).all()
    return jsonify({"rules": [{
        "id": r.id, "type": r.rule_type, "target": r.target,
        "reason": r.reason, "hits": r.hit_count, "active": r.active,
    } for r in rules]})


@app.route("/api/firewall/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def api_firewall_toggle(rule_id):
    rule = FirewallRule.query.get_or_404(rule_id)
    rule.active = not rule.active
    db.session.commit()
    return jsonify(ok=True, active=rule.active)


@app.route("/api/firewall/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
def api_firewall_delete(rule_id):
    rule = FirewallRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return jsonify(ok=True)


@app.route("/api/firewall/simulate", methods=["POST"])
@login_required
def api_firewall_simulate():
    data = request.json or {}
    try:
        src, dst_port = validate_simulate_payload(data.get("src_ip"),
                                                  data.get("dst_port"))
    except ValidationError as ve:
        return jsonify(error=ve.message), 400
    result = fw_simulate(src, None, dst_port)
    return jsonify({
        "action": result["action"],
        "matched_rule": (result["rule"].target if result["rule"] else None),
        "note": "Simulation only - CyberShield never blocks real traffic.",
    })


# --------------------------------------------------------------------- #
# Reports API
# --------------------------------------------------------------------- #
@app.route("/api/reports/generate", methods=["POST"])
@login_required
def api_reports_generate():
    fmt = (request.json or {}).get("format", "pdf")
    hours = int((request.json or {}).get("hours", 24))
    hours = min(max(hours, 1), 168)

    if fmt == "pdf" and PDF_AVAILABLE:
        path, err = generate_pdf_report(hours)
        if err:
            flash(f"PDF failed: {err} - opened HTML report instead")
            fmt = "html"
        else:
            db.session.add(AuditLog(actor=session.get("username", "?"),
                                    action="REPORT_PDF",
                                    detail=os.path.basename(path)))
            db.session.commit()
            return jsonify(ok=True, format="pdf",
                           url=url_for("api_report_download",
                                       filename=os.path.basename(path)))
    data = collect_report_data(hours)
    html = generate_html_report(hours)
    out_dir = app.config["REPORT_DIR"]
    os.makedirs(out_dir, exist_ok=True)
    fname = f"report-{utcnow_naive().strftime('%Y%m%d-%H%M%S')}.html"
    with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as fh:
        fh.write(html)
    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="REPORT_HTML", detail=fname))
    db.session.commit()
    return jsonify(ok=True, format="html", url=url_for("api_report_download",
                                                       filename=fname))


@app.route("/api/reports/download/<path:filename>")
@login_required
def api_report_download(filename):
    safe = slugify(os.path.splitext(filename)[0]) + \
        os.path.splitext(filename)[1].lower()
    path = os.path.join(app.config["REPORT_DIR"], safe)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True)


# --------------------------------------------------------------------- #
# Settings API
# --------------------------------------------------------------------- #
@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "POST":
        ok, err = update_settings(request.json or {})
        if not ok:
            return jsonify(error=err), 400
        db.session.add(AuditLog(actor=session.get("username", "?"),
                                action="SETTINGS_UPDATE",
                                detail=json.dumps(request.json or {})))
        db.session.commit()
        return jsonify(ok=True, settings=get_all_settings())
    return jsonify(settings=get_all_settings())


@app.route("/api/system/reset", methods=["POST"])
@login_required
def api_system_reset():
    """Wipe traffic/alerts/incidents and restore the clean demo baseline.

    Users, settings and uploaded PCAP files are kept. The demo dataset is
    re-ingested so the app is never left in an empty state that looks broken -
    the analyst always gets a known-good starting point for a demo or viva.
    """
    for model in (Alert, IncidentEvent, Incident, SuspiciousIP, PacketRecord,
                  AuditLog):
        model.query.delete()
    safe_commit()

    reseeded = 0
    with APP_LOCK:
        for batch in generate_demo_sequence(n_benign=15):
            analyzer.ingest(batch)
            reseeded += len(batch)

    db.session.add(AuditLog(actor=session.get("username", "?"),
                            action="SYSTEM_RESET",
                            detail=f"Security data reset, {reseeded} demo packets reseeded"))
    db.session.commit()
    return jsonify(ok=True, reseeded=reseeded)


# --------------------------------------------------------------------- #
# Template helpers + error handlers
# --------------------------------------------------------------------- #
@app.context_processor
def inject_globals():
    return {"app_name": "CyberShield",
            "app_tagline": "Real-Time Network Intrusion Detection & Security Monitoring",
            "username": session.get("username", ""),
            "role": session.get("role", "")}


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return render_template("error.html", code=404,
                           message="Page not found"), 404


@app.errorhandler(OperationalError)
def database_busy(e):
    """SQLite write contention: ask the caller to retry instead of a 500.

    Capture threads write packet batches while the analyst clicks around, so a
    momentary lock is normal and must never look like a crash.
    """
    db.session.rollback()
    log.warning("Database contention: %s", e)
    if request.path.startswith("/api/"):
        return jsonify(error="Database busy - please retry in a moment"), 503
    return render_template("error.html", code=503,
                           message="Database is busy - please retry"), 503


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    if request.path.startswith("/api/"):
        return jsonify(error="Internal server error"), 500
    return render_template("error.html", code=500,
                           message="Unexpected server error"), 500


# --------------------------------------------------------------------- #
# First-run demo seed: make the dashboard meaningful immediately
# --------------------------------------------------------------------- #
def _first_run_seed():
    with app.app_context():
        flag = db.session.get(Setting, "seeded_first_run")
        if flag is None and PacketRecord.query.count() == 0:
            seeded = 0
            with APP_LOCK:
                # Fed one scenario at a time so the seeded incident has a real
                # timeline (scan -> flood -> volumetric burst, escalating).
                for batch in generate_demo_sequence():
                    analyzer.ingest(batch)
                    seeded += len(batch)
            db.session.add(Setting(key="seeded_first_run", value="1",
                                   description="Internal flag"))
            db.session.commit()
            log.info("First-run demo data seeded (%d packets)", seeded)


_first_run_seed()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
