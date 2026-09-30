# CyberShield — Project Report Documentation

*Real-Time Network Intrusion Detection and Security Monitoring System*
*Diploma in Computer Engineering — Cyber Security microproject*

---

## 1. Abstract

CyberShield is a lightweight, educational mini Security Operations Center (mini-SOC) that
monitors network traffic from three safe sources (live capture, imported PCAP files, and a
built-in demo generator), extracts traffic features over sliding time windows, and applies
explainable rule-based detections for port scanning, excessive connection attempts,
DoS-like volumetric bursts and repeated suspicious behavior. Detections raise
severity-classified alerts, cluster into incidents with an investigation timeline, update
per-IP risk profiles and a global risk score, and are summarized in downloadable PDF/HTML
security reports. All state is persisted in SQLite. The system is deliberately safe: demo
attacks are synthetic packets stored only inside CyberShield's own database, and no packet
is ever sent to any external system.

## 2. Objectives

1. Capture or import network traffic (live / PCAP / demo).
2. Parse packets into a normalized record format.
3. Extract sliding-window traffic features.
4. Detect suspicious behavior with configurable, explainable rules.
5. Generate alerts with severity and human-readable reasons.
6. Escalate alert clusters into investigate-able incidents.
7. Provide an investigation interface with evidence hashing.
8. Maintain security event history in a database.
9. Compute an application-wide security risk score.
10. Generate downloadable security reports.
11. Provide a safe demo mode for classroom demonstration.
12. Demonstrate core cybersecurity concepts in one integrated platform.

## 3. Existing system

Wireshark is the standard free packet-analysis tool: it captures traffic and lets an analyst
inspect packets in depth. It is excellent for manual, packet-level investigation and remains
the recommended external verification tool for this project. However, its focus is manual
analysis — an analyst must notice a pattern themselves, and there is no built-in alerting,
incident tracking, risk scoring or reporting workflow. CyberShield does not replace Wireshark;
it adds an automated detection/alerting/incident-management layer on top of traffic that
Wireshark (or any tool) can capture, and CyberShield can re-analyze the same PCAP files
Wireshark produces.

## 4. Proposed system

CyberShield provides, in one web application:

* Traffic monitoring with a live packet view (secondary to the SOC workflow)
* Automated rule-based detection (port scan, excessive connections, DoS-like anomaly, suspicious IP)
* Alert generation with severity classification and dedupe
* Suspicious-IP aggregation with per-IP risk scores
* Incident management with status workflow and investigation timeline
* Evidence integrity via SHA-256 hashing of PCAPs, alerts and incidents
* Security analytics: charts, risk gauge, protocol profile, top talkers
* PDF + HTML security reports generated from live database data
* A firewall **rule simulator** (educational only — no real blocking)
* A safe demo mode with scripted, synthetic attack scenarios

## 5. Course / syllabus alignment

| Syllabus item | How CyberShield demonstrates it |
|---|---|
| **CO1** — Identify software threats and attacks | DoS/DDoS-like bursts, port scans, connection floods and repeated suspicious activity are detected, explained and investigated |
| **Unit I** — Threats & attacks (DoS/DDoS, sniffing, phishing, spoofing, network attacks) | Detection rules mirror the network behavior of these threats; limitations (e.g., no payload-level phishing detection) are documented |
| **LLO 1.1** — Investigate network traffic for cyberattacks using Wireshark; identify patterns of DoS/DDoS, phishing or scanning | Wireshark is used to capture lab traffic → the PCAP is uploaded to CyberShield, which automates pattern identification (scans, floods, bursts); the manual Wireshark step and automated CyberShield step complement each other |

The project intentionally claims alignment only with CO1 and the network-traffic practical —
not with every course outcome.

## 6. System architecture

```
NETWORK / PCAP / DEMO INPUT
        ↓
PACKET CAPTURE (Scapy sniffer, fails soft)  |  PCAP READER  |  DEMO GENERATOR
        ↓
PACKET PARSER (validation → normalized PacketRecord)
        ↓
FEATURE EXTRACTION (sliding window: unique ports, SYN rates, packet rates)
        ↓
DETECTION ENGINE (4 rule-based detectors, DB-backed thresholds)
        ↓
ALERT MANAGER (severity, dedupe, explanation) → INCIDENT ESCALATION
        ↓
SUSPICIOUS-IP AGGREGATION → RISK ENGINE (0–100)
        ↓
SQLite (SQLAlchemy models)
        ↓
FLASK API + SOC DASHBOARD → INVESTIGATION (timeline, evidence hash) → REPORTS
```

### Modules

| Module | File(s) | Responsibility |
|---|---|---|
| Capture | `capture/packet_sniffer.py`, `pcap_reader.py`, `demo_traffic.py` | Acquire packets from live/PCAP/demo sources |
| Parser | `analyzer/packet_parser.py` | Validate + normalize into `PacketRecord` |
| Features | `analyzer/feature_extractor.py` | Windowed aggregates consumed by detectors |
| Detection | `detection/*` | Four independent rule detectors + engine |
| Alerts | `alerts/alert_manager.py` | Create/dedupe alerts, escalate incidents |
| Risk | `analyzer/risk_engine.py` | Global 0–100 score from real data |
| Storage | `models.py`, `database.py` | 10 SQLAlchemy tables, SQLite (WAL) |
| API/UI | `app.py`, `frontend/*` | Pages + JSON APIs + capture control |
| Reports | `reports/report_generator.py` | PDF (ReportLab) + HTML reports |
| Utils | `utils/*` | Logger, runtime settings, evidence hashing, firewall simulator |

## 7. Detection rules (as implemented)

| Rule | Trigger (defaults) | Severity |
|---|---|---|
| **PORT_SCAN** | One source contacts **> 10 unique destination ports** within **10 s** | MEDIUM; **HIGH** if > 25 ports |
| **EXCESSIVE_CONNECTIONS** | One source makes **> 30 TCP SYN** attempts to **one destination** within **10 s** | MEDIUM; HIGH if > 2× threshold |
| **TRAFFIC_ANOMALY** | One source sends **> 120 packets** within **10 s** (any protocol) | HIGH; CRITICAL if > 2× threshold |
| **SUSPICIOUS_IP** | IP accumulates **≥ 2 alert events** with risk score ≥ 20 | MEDIUM/HIGH by risk score |

All thresholds live in the `settings` table and are editable on the Settings page — nothing is hardcoded at call sites. Alerts are deduplicated per type/source/destination within a configurable window (default 30 s).

### Risk score model (educational heuristic)

`risk = Σ weighted open alerts (last 24 h) + Σ weighted open incidents + min(20, 2 × suspicious IPs)`, capped to 0–100, with a dampener so one noisy rule cannot pin the meter. Labels: SECURE < LOW < ELEVATED < HIGH < CRITICAL.

## 8. Database design (10 tables)

`users` (hashed credentials) · `settings` (runtime thresholds) · `packets` (normalized packet records) · `alerts` (type/severity/source/reason/status/evidence) · `incidents` (ref, severity, status workflow) · `incident_events` (timeline: DETECTION/NOTE/ACTION/STATUS) · `suspicious_ips` (aggregated risk per IP) · `pcap_files` (upload metadata + SHA-256 + summary) · `firewall_rules` (simulator rules) · `audit_logs` (user actions).

## 9. Security features

* Passwords hashed (Werkzeug PBKDF2), sessions HTTPOnly + SameSite
* `@login_required` on every SOC page and API route
* **Self-service registration** with server-side validation: unique username + email,
  email format, password policy (min 8 chars, letters + numbers), confirmation match;
  passwords are hashed with Werkzeug and never logged or returned by any API.
  A safe idempotent SQLite migration (`database._migrate_schema`) adds the
  `users.email` / `users.full_name` columns without touching existing rows.
* **Strict firewall target validation** on both client (`static/js/validators.js`)
  and server (`utils/validators.py`): only IPv4, IPv4:port (1–65535) and the `any`
  wildcard are accepted; malformed IPs (e.g. `999.1.1.1`, `012.02.32.0444`,
  `192.168.1.1.5`), out-of-range ports and CIDR are rejected with HTTP 400 and
  never saved.
* SHA-256 chain-of-custody hashes for PCAP files, alerts and incident timelines
* Audit log of logouts, registrations, captures, uploads, settings changes, report generation
* Demo attacker IPs use documentation-reserved TEST-NET ranges (RFC 5737)
* Firewall module is a simulator: it never blocks or injects packets

**Risk score formula (documented, not hardcoded).** The global risk score is the
sum of four individually capped factors computed from open alerts (last 24h,
severity-weighted, flood-dampened, capped 40), open incidents (severity-weighted,
capped 25), the suspicious-IP watchlist (capped 20) and a small pressure tilt for
the highest open severity (+0/+2/+6/+10). With no open alerts, incidents or
watchlist entries the engine returns *Insufficient Data* instead of inventing a
number; a single alert therefore can no longer pin the meter at 100/CRITICAL.
Display ranges: 0–24 LOW · 25–49 MODERATE · 50–74 HIGH · 75–100 CRITICAL
(shared by backend `analyzer/risk_engine.py` and the dashboard UI).

## 10. Testing summary

20 automated offline tests (`tests/test_detection.py`) cover: unique-port feature extraction,
packet exclusion outside the window, sliding-window tiling of long batches, packet-rate
computation, all four detectors (positive cases), benign negative cases (including *randomised*
benign demo traffic that must stay silent), end-to-end ingest → alert → incident, alert dedupe,
demo-data attack content and timestamps, replay of an old PCAP-style batch, address-scope
classification, login redirect, and login + dashboard API flow, plus the registration
workflow (valid signup, invalid email, password mismatch, duplicate username/email,
hashed-password storage, new-user login) and the strict firewall target validation table
(accept IPv4 / IPv4:port / `any`; reject `999.1.1.1`, `192.168.1`, `192.168.1.1.5`,
`abc.def.ghi.jkl`, `203.0.113.66:99999`, `012.02.32.0444`, CIDR and empty input).
Run with `python -m pytest tests/ -v`.

An end-to-end HTTP verification sweep (`scripts/verify_http.py`) logs into a running server
and exercises every page and API — dashboard, traffic, alerts (+acknowledge/evidence),
incidents (+notes/status), IP analysis, PCAP upload/re-analyze, firewall rules + simulation
+ target-validation rejections, registration incl. duplicate/invalid rejections, settings
persistence, demo injection, capture start/stop, PDF/HTML report generation and download,
and the system reset — reporting PASS/FAIL per check (68 checks).

Runtime verification performed for this report: 53/53 unit tests passing and 68/68 HTTP
checks passing, with the UI exercised through rendered pages (login, registration, firewall
two-column layout, dashboard, demo mode, alert acknowledgement, incident timeline/status,
IP drill-down + BLOCK rule, PCAP upload of `samples/demo_portscan.pcap`, report generation).

## 11. Limitations (stated honestly)

* Rule-based only: no machine learning (ML is a documented optional future enhancement)
* Does not detect every attack class; payload-level attacks (phishing pages, malware) are out of scope
* SQLite is ideal for classroom scale, not enterprise throughput
* Live capture needs OS privileges (admin + Npcap on Windows); the app degrades gracefully to PCAP/Demo modes
* Alerts indicate *suspicious patterns for investigation*, not confirmed intrusions

## 12. Future enhancements (optional, not implemented)

ML anomaly scoring to complement rules; WebSocket live push; GeoIP enrichment; email/syslog/Teams alert delivery; Elasticsearch/ClickHouse retention; user roles beyond a single analyst.

## 13. References

1. Stallings, W. & Brown, L. — *Computer Security: Principles and Practice*
2. Scarfone, K. & Mell, P. — NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*
3. Scapy documentation — https://scapy.readthedocs.io
4. Flask documentation — https://flask.palletsprojects.com
5. Wireshark User's Guide — https://www.wireshark.org/docs
6. ReportLab User Guide — https://docs.reportlab.com
7. OWASP Testing Guide (context for detection categories)
