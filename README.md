# CyberShield — Real-Time Network Intrusion Detection & Security Monitoring System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)]()
[![Flask](https://img.shields.io/badge/Flask-3.x-green)]()
[![SQLite](https://img.shields.io/badge/SQLite-3-lightgrey)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

A lightweight **mini Security Operations Center (mini-SOC)** built as a Diploma-level Cyber Security microproject. CyberShield monitors network traffic, applies explainable rule-based detections, raises security alerts with severity, escalates them into incidents for investigation, computes a security risk score, and produces security reports — all from a single Flask application.

> **Educational & safety notice**
> CyberShield is built for **learning and demonstration on your own machine / lab network / PCAP files**.
> It is **not** a replacement for production security tooling, it does **not** detect every attack, and it
> **never generates or sends attack traffic** toward any system. Demo scenarios are synthetic packets stored
> only in CyberShield's own database. Findings are "DoS-like / suspicious patterns for investigation",
> not proof of compromise.

---

## ✨ Features

| Area | What you get |
|---|---|
| **Dashboard** | Compact SOC metric cards with sub-stats, **documented risk score** (0–100 from capped factors; shows *Insufficient Data* instead of a fake number on a quiet network; 0–24 LOW · 25–49 MODERATE · 50–74 HIGH · 75–100 CRITICAL), **time-range filters (1H/6H/24H/7D)**, traffic-over-time line chart (packets + volume), alerts-over-time stacked by severity, severity doughnut with counts/percentages, top suspicious IPs, recent alerts + incidents, monitoring-status strip |
| **Live Traffic** | Packet table with src/dst IP, ports, protocol, length, TCP flags, status (NORMAL/FLAGGED), live polling, "flagged only" filter |
| **Detection Engine** | Rule-based: **Port Scan**, **Excessive Connections**, **Traffic Anomaly (DoS-like)**, **Suspicious IP** — thresholds editable in Settings |
| **Alerts** | Severity (LOW/MEDIUM/HIGH/CRITICAL), status workflow (NEW → ACKNOWLEDGED → RESOLVED), dedupe window, human-readable reasons, **SHA-256 evidence hash per alert** |
| **Incidents** | Auto-created from alert clusters, **investigation timeline**, notes, status workflow (OPEN → INVESTIGATING → CONTAINED → CLOSED), incident SHA-256 |
| **IP Analysis** | Watchlist ranked by risk, per-IP drill-down (risk gauge, categories, protocols, top destinations, packet history, alert history) |
| **PCAP Analysis** | Upload `.pcap/.pcapng/.cap` (e.g. from Wireshark) → parsed with Scapy → run through the same detection engine; SHA-256 of file; top talkers; re-analyze |
| **Firewall Simulator** | BLOCK/ALLOW rule table, first-match simulation, **strict target validation** (IPv4, IPv4:port, `any`; malformed IPs/ports/CIDR rejected with 400 on both client and server), two-column SOC layout, **clearly marked EDUCATIONAL ONLY** — never blocks real traffic |
| **Reports** | **PDF (ReportLab)** + printable HTML executive reports from live DB data; downloadable archive |
| **Auth** | Session login (hashed passwords via Werkzeug), **self-service registration** (full name, unique username + email, password policy, show/hide, inline validation), logout, all SOC pages protected, audit log of logins/actions |
| **Demo Mode** | One-click synthetic traffic (benign + 3 scripted attack scenarios) so the entire pipeline works with zero risk |
| **Sample PCAP** | `samples/demo_portscan.pcap` ships with the project so PCAP forensics can be demonstrated without capturing anything yourself |

## 🧠 Architecture

```
NETWORK / PCAP / DEMO INPUT
        ↓
PACKET CAPTURE (Scapy sniffer)  |  PCAP READER  |  DEMO GENERATOR
        ↓
PACKET PARSER  (normalize → PacketRecord)
        ↓
FEATURE EXTRACTION  (sliding-window aggregates: unique ports, SYN rates, pps)
        ↓
DETECTION ENGINE  (4 rule-based detectors, DB-backed thresholds)
        ↓
ALERT MANAGER  (severity, dedupe, explanation)  →  INCIDENT ESCALATION
        ↓
SUSPICIOUS-IP AGGREGATION  →  RISK ENGINE (0–100)
        ↓
SQLite (SQLAlchemy)
        ↓
FLASK API + SOC DASHBOARD  →  INVESTIGATION  →  REPORTS
```

Modules live under `backend/` (`capture/`, `analyzer/`, `detection/`, `alerts/`,
`reports/`, `utils/`) and the UI under `frontend/` (`templates/`, `static/`).

### How the analysis window works

Detection is window-based: each ingest batch is tiled into consecutive windows and
every window is evaluated, so a batch that spans more than one window is still fully
analyzed (bounded to 25 passes per batch to stay responsive on large PCAP files).
The window **ends at the newest packet of the batch** rather than at the wall clock —
that is what lets a PCAP captured last week, or a saved batch of packets, produce
alerts today instead of being silently ignored.

## 📁 Project structure

```
CyberShield/
├── backend/
│   ├── app.py                  # Flask app: routes + APIs + capture control
│   ├── config.py               # all tunables + env overrides
│   ├── database.py             # init/seed/reset
│   ├── models.py               # SQLAlchemy models
│   ├── capture/
│   │   ├── packet_sniffer.py   # optional live capture (fails soft)
│   │   ├── pcap_reader.py      # Scapy PCAP parsing
│   │   └── demo_traffic.py     # safe synthetic traffic
│   ├── analyzer/
│   │   ├── packet_parser.py
│   │   ├── feature_extractor.py
│   │   ├── traffic_analyzer.py # the ingest pipeline
│   │   └── risk_engine.py      # global risk score
│   ├── detection/
│   │   ├── detection_engine.py
│   │   ├── port_scan_detector.py
│   │   ├── connection_detector.py
│   │   ├── traffic_anomaly_detector.py
│   │   └── suspicious_ip_detector.py
│   ├── alerts/alert_manager.py
│   ├── reports/report_generator.py
│   └── utils/  (logger, settings, helpers, evidence hashing, firewall sim)
├── frontend/
│   ├── templates/  (login, dashboard, traffic, alerts, incidents,
│   │                incident_details, ips, pcap_analysis, firewall,
│   │                reports, settings, error, base)
│   └── static/     (style.css + per-page JS)
├── data/  (pcaps/, reports/, cybershield.log)
├── database/cybershield.db      # auto-created on first run
├── samples/
│   ├── make_sample_pcap.py      # builds a safe demo capture with Scapy
│   └── demo_portscan.pcap       # ready-made capture (benign + 3 attacks)
├── scripts/verify_http.py       # end-to-end HTTP verification sweep
├── tests/test_detection.py      # 20 offline unit tests
├── docs/                        # project report documentation
├── run.py
├── requirements.txt
├── .env.example
└── README.md
```

## 🚀 Quick start (Windows)

```bat
:: 1) from the CyberShield folder
python -m venv venv
venv\Scripts\activate

:: 2) install dependencies
pip install -r requirements.txt

:: 3) run
python run.py
```

Open **http://127.0.0.1:5000** and log in:

| Username | Password |
|---|---|
| `admin` | `admin123` |

> The SQLite database, demo data, folders and admin account are created automatically on first run.

### Optional: real live capture (admin recommended)
Live sniffing needs raw-socket rights — on Windows install **Npcap** (<https://npcap.com>) and run the terminal **as Administrator**. If it can't start, CyberShield tells you:
`Live capture is unavailable. Use PCAP Analysis or Demo Mode.` — and everything else keeps working.

### CLI flags
```bat
python run.py --reset        :: wipe + reseed database
python run.py --port 8080
python run.py --no-seed      :: start with empty dashboard
```

## 🧪 Tests

```bat
venv\Scripts\python -m pytest tests\ -v
```

53 offline tests cover the feature extractor + sliding windows, all four detectors
(positive *and* negative), the ingest→alert→incident flow, alert dedupe, demo-data
content, replayed (old) PCAP batches, address-scope labelling, the
login-protected dashboard API, **the registration workflow** (valid signup,
invalid email, password mismatch, duplicate username/email, hashed passwords,
new-user login) and **the strict firewall target validation** (every malformed
input from the spec table plus first-match-wins behavior).

### End-to-end HTTP verification (optional)

With the app running in another terminal:

```bat
venv\Scripts\python scripts\verify_http.py --base http://127.0.0.1:5000
```

It logs in and exercises every page and API (dashboard, traffic, alerts + ack, incidents
+ notes/status, IP analysis, PCAP upload, firewall rules + simulation + target-validation
rejections, **registration** incl. duplicate/invalid rejections, settings, demo
injection, capture start/stop, PDF/HTML report download, system reset) and prints a
PASS/FAIL summary. If you cannot keep a server running, run the self-contained
variant that hosts Flask in-process:

```bat
venv\Scripts\python scripts\run_verify_inline.py
```

## 🎨 UI design system

The interface uses the "Jade pebble morning" palette as reusable CSS variables in
`frontend/static/css/style.css`: sage green `#7B9669` (brand/accents), dark forest
`#404E3D` (navigation), muted teal `#6C8480` (secondary), soft sage `#BAC8B1` and
light grey `#E6E6E6` (surfaces/borders). **Yellow** buttons mark primary actions,
**red** marks destructive ones. Charts reuse the same palette via Chart.js defaults.

## 🎬 Suggested demo flow (for your presentation)

1. **Login** → Dashboard: note the risk score & cards.
2. **Settings → Demo Attack Scenarios** → click **Port Scan**.
3. Go to **Alerts**: a `PORT_SCAN` alert with reason *"Source IP contacted N unique ports within 10 seconds"* appeared; severity MEDIUM/HIGH.
4. **Incidents**: an incident was auto-created — open it, **add an investigation note**, change status to *Investigating → Contained → Closed*; watch the timeline + SHA-256 evidence hash.
5. **IP Analysis**: the demo attacker `203.0.113.66` is flagged with risk score & categories; add a **BLOCK rule** and check the **Firewall Simulator** verdict.
6. **PCAP**: upload `samples/demo_portscan.pcap` (bundled) or any `.pcap` from your own lab/Wireshark → the same detection engine runs over it and alerts/incidents are created. Uploaded captures are analyzed on **their own timeline**, so an old file still produces findings.
   Rebuild the sample at any time with `venv\Scripts\python samples\make_sample_pcap.py`.
7. **Reports**: generate a **PDF** → download and open.
8. **Dashboard**: risk score & charts all reflect the activity you just created.

## ⚙️ Configuration

Everything has safe defaults; see `.env.example`:

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | demo value | Flask session secret (change for real use) |
| `CYBERSHIELD_ADMIN_USER` / `_PASSWORD` | admin / admin123 | first-run admin account |
| `CYBERSHIELD_INTERFACE` | auto | capture interface name |
| `CYBERSHIELD_ATTACKER_IP` | 203.0.113.66 | demo attacker (TEST-NET-2, safe) |

Detection thresholds are **not** in `.env` — tune them live on the **Settings** page (stored in DB, applied on next ingest).

**Settings → Reset Security Data** clears packets, alerts, incidents and audit logs and
immediately re-ingests the demo baseline, so the app is never left in an empty state;
**Seed Full Demo Data** adds another full demo batch on top of the current data.

## 🔒 Security notes for this project

* Passwords stored as **Werkzeug hashes**, never plaintext; sessions are HTTPOnly cookies.
* Login required for every SOC page and API.
* All demo/attack IPs use documentation-reserved ranges (TEST-NET) — nothing on the internet is contacted or attacked.
* The firewall module is a **simulator** for policy learning; it does not filter packets.
* Audit log records logins and sensitive actions.

## 📚 Documentation

The `docs/` folder contains the report-ready documentation: abstract, objectives, existing vs proposed system, architecture, module descriptions, syllabus mapping (CO1 / Unit I / LLO 1.1), test cases, screenshots guide, future enhancements (ML as **optional**), limitations, references and a viva question bank. Start with [`docs/PROJECT_REPORT.md`](docs/PROJECT_REPORT.md).

## 🧭 Future enhancements (explicitly optional, not implemented)

* ML-based anomaly scoring to *complement* (not replace) the explainable rules
* WebSocket push instead of polling
* GeoIP enrichment, Syslog/email/Teams alert channels
* Elasticsearch/ClickHouse storage for long-term retention

## 📜 License

MIT — for educational use.
