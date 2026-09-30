# CyberShield — Viva / Demonstration Question Bank

Short, exam-ready answers for the microproject viva.

## Basics

**Q. What is CyberShield in one line?**
A mini-SOC web application that monitors traffic, detects suspicious patterns with rules, raises alerts, manages incidents, visualizes risk and generates reports.

**Q. Why is it not "a Wireshark clone"?**
Wireshark is a manual packet analyzer. CyberShield adds an automated detection/alerting/incident layer on top of traffic — packet details exist but the SOC workflow (alerts → incidents → investigation → reports) is the focus. CyberShield happily consumes Wireshark's PCAP files.

**Q. Which language and stack?**
Python 3 + Flask backend, SQLite via SQLAlchemy, Scapy for packet parsing/capture, ReportLab for PDF reports, and HTML/CSS/JS (Bootstrap + Chart.js) frontend.

## Detection logic

**Q. How does port scan detection work?**
For every source IP we count unique destination ports contacted inside a sliding window (default 10 s). More than 10 unique ports ⇒ PORT_SCAN alert (MEDIUM; HIGH above 25 ports). The reason string includes the counts, e.g. "contacted 15 unique ports within 10 seconds".

**Q. How is a DoS-like anomaly detected?**
Volumetric heuristic: more than 120 packets from one source within 10 seconds ⇒ TRAFFIC_ANOMALY alert (HIGH, CRITICAL above 2×). We always call it "DoS-like" because volume alone is not proof of a real DoS.

**Q. Why rules and not machine learning?**
Rules are explainable, tunable at runtime, testable offline, and sufficient for the syllabus scope. ML is listed as an optional future enhancement to complement — not replace — the rules.

**Q. What stops duplicate alerts?**
A dedupe window (default 30 s): identical alert type + source + destination inside the window returns the existing alert instead of a new row.

## Data & integrity

**Q. How is evidence integrity shown?**
SHA-256 hashes: of uploaded PCAP files, of each alert's canonical fields, and of an incident plus its full timeline. If anything is altered, the hash changes — the same idea analysts use for chain of custody.

**Q. How is the risk score computed?**
From real data only: weighted open alerts (last 24 h) + weighted open incidents + a small term for suspicious IPs, capped 0–100 with a dampener for alert floods. A clean network shows ~0.

**Q. Where is data stored?**
SQLite file `database/cybershield.db` (WAL mode) with 10 tables, created automatically on first run.

## Safety & ethics

**Q. Does CyberShield attack anything?**
No. It only listens passively or reads files. Demo "attacks" are synthetic packets generated inside its own database — nothing leaves the machine. Demo attacker IPs use the TEST-NET-2 documentation range.

**Q. Does the firewall actually block traffic?**
No — it is clearly labeled a simulator. It evaluates rules against records to teach policy behavior ("first match wins"); no real packets are filtered.

**Q. What does an alert mean, legally/practically?**
A suspicious pattern worth investigating — not proof of a successful attack. The UI and reports state this explicitly.

## Demo walkthrough (2 minutes)

1. Login `admin / admin123` → Dashboard (risk gauge, real counters).
2. Settings → inject **Port Scan** scenario.
3. Alerts page → PORT_SCAN alert with explanation; Ack it.
4. Incidents → auto-created incident; add a note; set status INVESTIGATING → CONTAINED → CLOSED.
5. IP Analysis → attacker profile with risk gauge; add BLOCK rule; Firewall page → verdict DENY.
6. Reports → generate PDF, download.
7. PCAP page → upload any Wireshark capture → detections run on it.
