"""
CyberShield - Security report generator
=======================================

Produces downloadable PDF security reports (ReportLab) summarizing a time
window of REAL application data: alerts by severity/type, incidents, top
suspicious IPs, traffic profile and recommendations. An HTML variant doubles
as the on-screen printable report.
"""

import os
import time
from collections import Counter
from datetime import timedelta

from flask import current_app

from backend.models import (Alert, Incident, PacketRecord, SuspiciousIP,
                            PCAPFile, AuditLog)
from backend.utils.helpers import human_bytes, utcnow_naive
from backend.utils.logger import get_logger

log = get_logger("cybershield.reports")

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle)
    PDF_AVAILABLE = True
except Exception:  # pragma: no cover
    PDF_AVAILABLE = False

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_HEX = "0123456789ABCDEF"


def _report_id():
    return f"RPT-{time.strftime('%Y%m%d')}-{int(time.time()) % 100000:05d}"


def collect_report_data(hours: int = 24):
    """Gather everything the report needs from the database."""
    since = utcnow_naive() - timedelta(hours=hours)

    alerts = Alert.query.filter(Alert.created_at >= since).all()
    incidents = Incident.query.filter(Incident.created_at >= since).all()
    packets = PacketRecord.query.filter(PacketRecord.timestamp >= since).all()
    suspicious = (SuspiciousIP.query.order_by(SuspiciousIP.risk_score.desc())
                  .limit(10).all())
    pcaps = PCAPFile.query.order_by(PCAPFile.uploaded_at.desc()).limit(5).all()

    sev_counter = Counter(a.severity for a in alerts)
    type_counter = Counter(a.alert_type for a in alerts)
    proto_counter = Counter(p.protocol for p in packets)
    bytes_total = sum(p.length or 0 for p in packets)

    from backend.analyzer.risk_engine import calculate_global_risk, risk_label
    risk = calculate_global_risk()

    return {
        "generated_at": utcnow_naive(),
        "hours": hours,
        "risk_score": risk,
        "risk_label": risk_label(risk),
        "total_packets": len(packets),
        "total_bytes": bytes_total,
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "open_incidents": sum(1 for i in incidents if i.status != "CLOSED"),
        "alerts_by_severity": {s: sev_counter.get(s, 0) for s in SEVERITY_ORDER},
        "alerts_by_type": dict(type_counter.most_common()),
        "protocols": dict(proto_counter),
        "top_suspicious": [
            {"ip": s.ip, "risk": s.risk_score, "alerts": s.alert_count,
             "categories": s.categories, "blocked": s.is_blocked}
            for s in suspicious],
        "recent_incidents": [
            {"ref": i.incident_ref, "title": i.title, "severity": i.severity,
             "status": i.status, "created": i.created_at}
            for i in sorted(incidents, key=lambda x: x.created_at,
                            reverse=True)[:10]],
        "pcap_files": [{"name": p.filename, "packets": p.packet_count,
                        "alerts": p.alerts_found} for p in pcaps],
    }


def generate_pdf_report(hours: int = 24) -> tuple[str, str]:
    """
    Build a PDF report for the last `hours` hours.
    Returns (absolute_path, error). path is None on failure.
    """
    if not PDF_AVAILABLE:
        return None, "PDF engine unavailable - HTML report generated instead"

    data = collect_report_data(hours)
    out_dir = current_app.config["REPORT_DIR"]
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{_report_id()}.pdf")

    try:
        doc = SimpleDocTemplate(path, pagesize=A4, title="CyberShield Security Report")
        styles = getSampleStyleSheet()
        h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                            textColor=colors.HexColor("#0b2545"), spaceAfter=2)
        h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                            textColor=colors.HexColor("#13315c"), spaceBefore=14)
        normal = styles["BodyText"]

        story = [
            Paragraph("CyberShield - Security Report", h1),
            Paragraph("Real-Time Network Intrusion Detection &amp; Security Monitoring",
                      styles["Italic"]),
            Spacer(1, 6),
            Paragraph(f"Period: last {hours} hours &nbsp;|&nbsp; "
                      f"Generated: {data['generated_at']:%Y-%m-%d %H:%M:%S} UTC "
                      f"&nbsp;|&nbsp; Risk score: {data['risk_score']}/100 "
                      f"({data['risk_label']})", normal),
            Spacer(1, 10),
        ]

        def table(rows, widths, header=True):
            t = Table(rows, colWidths=widths)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#13315c")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#8da9c4")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#eef3fa")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            return t

        # ---- executive summary -------------------------------------- #
        story.append(Paragraph("1. Executive Summary", h2))
        story.append(Table([
            ["Metric", "Value"],
            ["Packets analyzed", f"{data['total_packets']:,} "
                                 f"({human_bytes(data['total_bytes'])})"],
            ["Security alerts", f"{data['total_alerts']:,}"],
            ["Incidents", f"{data['total_incidents']:,} "
                          f"({data['open_incidents']} open)"],
            ["Security risk score", f"{data['risk_score']}/100 "
                                    f"({data['risk_label']})"],
        ], colWidths=[220, 280]))

        # ---- alerts --------------------------------------------------- #
        story.append(Paragraph("2. Alerts by Severity", h2))
        story.append(Table(
            [["Severity", "Count"]] +
            [[s, str(data["alerts_by_severity"][s])] for s in SEVERITY_ORDER],
            colWidths=[220, 280]))

        story.append(Paragraph("3. Alerts by Detection Type", h2))
        type_rows = [["Detection type", "Count"]] + [
            [t, str(c)] for t, c in data["alerts_by_type"].items()]
        if len(type_rows) == 1:
            type_rows.append(["No alerts recorded in this period", "0"])
        story.append(Table(type_rows, colWidths=[300, 200]))

        # ---- incidents ------------------------------------------------ #
        story.append(Paragraph("4. Recent Incidents", h2))
        inc_rows = [["Ref", "Title", "Severity", "Status"]] + [
            [i["ref"], i["title"][:45], i["severity"], i["status"]]
            for i in data["recent_incidents"]]
        if len(inc_rows) == 1:
            inc_rows.append(["-", "No incidents in this period", "-", "-"])
        story.append(Table(inc_rows, colWidths=[70, 230, 90, 110]))

        # ---- suspicious IPs ------------------------------------------- #
        story.append(Paragraph("5. Top Suspicious IPs", h2))
        sus_rows = [["IP", "Risk", "Alerts", "Categories", "Blocked"]] + [
            [s["ip"], f"{s['risk']}/100", str(s["alerts"]),
             s["categories"] or "-", "yes" if s["blocked"] else "no"]
            for s in data["top_suspicious"]]
        if len(sus_rows) == 1:
            sus_rows.append(["-", "No suspicious IPs", "-", "-", "-"])
        story.append(Table(sus_rows, colWidths=[120, 60, 55, 190, 75]))

        # ---- recommendations ------------------------------------------ #
        story.append(Paragraph("6. Recommendations", h2))
        recs = _recommendations(data)
        for r in recs:
            story.append(Paragraph(f"- {r}", normal))

        story.append(Spacer(1, 14))
        story.append(Paragraph(
            "Note: CyberShield is an educational rule-based monitoring tool. "
            "Findings indicate DoS-LIKE or suspicious patterns for investigation "
            "and are not proof of a successful attack.", styles["Italic"]))

        doc.build(story)
        log.info("PDF report generated: %s", path)
        return path, None
    except Exception as exc:
        log.exception("PDF report failed")
        return None, str(exc)


def _recommendations(data) -> list:
    recs = []
    sev = data["alerts_by_severity"]
    if sev["CRITICAL"] or sev["HIGH"]:
        recs.append("Investigate all HIGH/CRITICAL alerts and the incidents "
                    "created from them; block or rate-limit the involved source IPs "
                    "at the real firewall if confirmed malicious.")
    if "PORT_SCAN" in data["alerts_by_type"]:
        recs.append("Port scanning observed: close unused services on exposed "
                    "hosts and consider tarpitting repeated scanners.")
    if "EXCESSIVE_CONNECTIONS" in data["alerts_by_type"]:
        recs.append("Excessive connection attempts observed: enable SYN cookies "
                    "and per-source connection limits on public services.")
    if "TRAFFIC_ANOMALY" in data["alerts_by_type"]:
        recs.append("Volumetric (DoS-like) bursts observed: verify upstream "
                    "filtering/rate limiting and confirm service health.")
    if data["top_suspicious"]:
        recs.append("Review the top suspicious IPs on the IP Analysis page and "
                    "add simulator BLOCK rules to preview firewall behavior.")
    if not recs:
        recs.append("No significant threats in this period. Keep monitoring and "
                    "review detection thresholds on the Settings page.")
    return recs


def generate_html_report(hours: int = 24) -> str:
    """On-screen / printable HTML version of the same report data."""
    from backend.utils.helpers import fmt_dt
    data = collect_report_data(hours)
    sev = data["alerts_by_severity"]

    def row(cells, tag="td"):
        return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>"

    sus_rows = "".join(row([s["ip"], f"{s['risk']}/100", s["alerts"],
                            s["categories"] or "-",
                            "yes" if s["blocked"] else "no"])
                       for s in data["top_suspicious"]) or \
        row(["-", "-", "-", "-", "-"])
    inc_rows = "".join(row([i["ref"], i["title"], i["severity"], i["status"]])
                       for i in data["recent_incidents"]) or \
        row(["-", "No incidents", "-", "-"])

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>CyberShield Security Report</title>
<style>
 body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #182848; }}
 h1 {{ color: #0b2545; margin-bottom: 2px; }}
 h2 {{ color: #13315c; border-bottom: 2px solid #8da9c4; padding-bottom: 4px; margin-top: 28px; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
 th, td {{ border: 1px solid #8da9c4; padding: 6px 10px; font-size: 14px; text-align: left; }}
 th {{ background: #13315c; color: white; }}
 tr:nth-child(even) td {{ background: #eef3fa; }}
 .meta {{ color: #5a6d8a; }}
 .risk {{ font-size: 18px; font-weight: 600; }}
 @media print {{ body {{ margin: 12mm; }} }}
</style></head><body>
<h1>CyberShield - Security Report</h1>
<p class="meta">Real-Time Network Intrusion Detection &amp; Security Monitoring<br>
Period: last {hours} hours | Generated: {fmt_dt(data['generated_at'])} UTC |
Risk: <span class="risk">{data['risk_score']}/100 ({data['risk_label']})</span></p>

<h2>1. Executive Summary</h2>
<table>{row(["Packets analyzed", f"{data['total_packets']:,} ({human_bytes(data['total_bytes'])})"], 'th')}
{row(["Security alerts", data['total_alerts']], 'th')}
{row(["Incidents", f"{data['total_incidents']} ({data['open_incidents']} open)"], 'th')}
{row(["Risk score", f"{data['risk_score']}/100"], 'th')}</table>

<h2>2. Alerts by Severity</h2>
<table>{row(["CRITICAL", "HIGH", "MEDIUM", "LOW"], 'th')}
{row([sev['CRITICAL'], sev['HIGH'], sev['MEDIUM'], sev['LOW']])}</table>

<h2>3. Alerts by Detection Type</h2>
<table>{row(["Detection type", "Count"], 'th')}
{''.join(row([t, c]) for t, c in data['alerts_by_type'].items()) or row(['No alerts in this period', '0'])}</table>

<h2>4. Recent Incidents</h2>
<table>{row(["Ref", "Title", "Severity", "Status"], 'th')}{inc_rows}</table>

<h2>5. Top Suspicious IPs</h2>
<table>{row(["IP", "Risk", "Alerts", "Categories", "Blocked"], 'th')}{sus_rows}</table>

<h2>6. Recommendations</h2>
<ul>{''.join(f'<li>{r}</li>' for r in _recommendations(data))}</ul>

<p class="meta">Educational rule-based monitoring: findings are DoS-LIKE / suspicious
patterns for investigation, not proof of successful attacks.</p>
</body></html>"""
