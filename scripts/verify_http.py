"""
CyberShield - live HTTP verification sweep
==========================================

Runs against a server started with `python run.py` and exercises every public
API end to end with a real login session: pages, dashboard, traffic, alerts
(ack/resolve/evidence), incidents, IP analysis, PCAP upload, firewall rules +
simulation, settings, demo injection and report generation.

    venv\\Scripts\\python scripts\\verify_http.py --base http://127.0.0.1:5057

Exit code 0 = every check passed. This is a manual verification helper for
development; the pytest suite in tests/ is the automated one.
"""

import argparse
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import CookieJar

PASS, FAIL = [], []


def _client(base):
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    return opener


def _req(opener, base, path, method="GET", data=None, headers=None, raw=False,
         form=False):
    url = base.rstrip("/") + path
    body, hdrs = None, dict(headers or {})
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = data if raw else json.dumps(data).encode()
            if not raw:
                hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=120) as resp:
            payload = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "json" in ctype:
                return resp.status, json.loads(payload or b"{}")
            return resp.status, payload if raw else payload.decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:200]


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(name)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}{' - ' + str(detail) if detail else ''}")


def login(opener, base, user="admin", password="admin123"):
    url = base.rstrip("/") + "/login"
    body = urllib.parse.urlencode({"username": user, "password": password}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
    with opener.open(req, timeout=30) as resp:
        return resp.status, resp.geturl()


def multipart(path, field, filename):
    boundary = uuid.uuid4().hex
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    with open(filename, "rb") as fh:
        content = fh.read()
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{field}"; filename="{os.path.basename(filename)}"\r\n'.encode(),
        f"Content-Type: {ctype}\r\n\r\n".encode(),
        content,
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:5057")
    parser.add_argument("--pcap", default=os.path.join("samples", "demo_portscan.pcap"))
    args = parser.parse_args()
    base = args.base
    opener = _client(base)

    print("\n== auth ==")
    status, landing = login(opener, base)
    check("login accepted", status == 200 and "/dashboard" in landing, landing)

    print("\n== registration ==")
    import random
    suffix = random.randint(1000, 9999)
    uname, uemail = f"verify{suffix}", f"verify{suffix}@example.com"
    status, body = _req(opener, base, "/register")
    check("register page renders", status == 200 and "Create Account" in body, status)
    status, body = _req(opener, base, "/register", method="POST", form=True, data={
        "full_name": "Verify Bot", "username": uname, "email": uemail,
        "password": "verify123", "confirm_password": "verify123"})
    # urllib follows the 302 to /login (which shows the success flash)
    check("register new user (redirects to login)",
          status == 200 and "Access Console" in body, status)
    # duplicates rejected with 400
    status, _ = _req(opener, base, "/register", method="POST", form=True, data={
        "full_name": "Verify Bot", "username": uname,
        "email": f"x{suffix}@example.com", "password": "verify123",
        "confirm_password": "verify123"})
    check("duplicate username rejected", status == 400, status)
    status, _ = _req(opener, base, "/register", method="POST", form=True, data={
        "full_name": "Verify Bot", "username": f"other{suffix}",
        "email": uemail, "password": "verify123", "confirm_password": "verify123"})
    check("duplicate email rejected", status == 400, status)
    status, _ = _req(opener, base, "/register", method="POST", form=True, data={
        "full_name": "V", "username": f"bad{suffix}", "email": "broken",
        "password": "verify123", "confirm_password": "verify123"})
    check("invalid email rejected", status == 400, status)
    status, _ = _req(opener, base, "/register", method="POST", form=True, data={
        "full_name": "Verify Bot", "username": f"mismatch{suffix}",
        "email": f"m{suffix}@example.com", "password": "verify123",
        "confirm_password": "different999"})
    check("password mismatch rejected", status == 400, status)
    # the new account can actually sign in
    ro = _client(base)
    status, _ = _req(ro, base, "/login", method="POST", form=True,
                     data={"username": uname, "password": "verify123"})
    check("new user can login", status == 200, status)

    print("\n== pages ==")
    for path in ("/dashboard", "/traffic", "/alerts", "/incidents", "/ips",
                 "/pcap", "/firewall", "/reports", "/settings"):
        status, body = _req(opener, base, path)
        check(f"GET {path}", status == 200 and "Traceback" not in body, status)

    print("\n== dashboard & traffic ==")
    status, dash = _req(opener, base, "/api/dashboard")
    check("dashboard api", status == 200 and "cards" in dash, status)
    if status == 200:
        cards = dash["cards"]
        check("dashboard numbers are real",
              cards["total_packets"] > 0 and cards["risk_score"] >= 0,
              f"packets={cards['total_packets']} risk={cards['risk_score']}")
        check("chart data present", all(k in dash["charts"] for k in
              ("alerts_by_severity", "alerts_by_type", "packets_timeline", "protocols")))
    status, traffic = _req(opener, base, "/api/traffic?limit=5")
    check("traffic api", status == 200 and "packets" in traffic, status)

    print("\n== dashboard risk & timeline ==")
    cards = dash.get("cards", {})
    if cards.get("risk_score") is None:
        check("risk is Insufficient Data on quiet db", cards.get("risk_label") == "INSUFFICIENT DATA", cards.get("risk_label"))
    else:
        check("risk label matches score ranges",
              (cards["risk_score"] >= 75) == (cards["risk_label"] == "CRITICAL") or
              (25 <= cards["risk_score"] <= 74) == (cards["risk_label"] in ("MODERATE", "HIGH")),
              f"score={cards['risk_score']} label={cards['risk_label']}")
        check("risk factors explained", "risk_factors" in cards and
              "open_alerts_24h" in cards["risk_factors"], cards.get("risk_factors"))
    check("risk is not pinned at 100",
          cards.get("risk_score") is None or cards["risk_score"] < 100 or
          cards.get("risk_factors", {}).get("open_alerts_24h", 0) > 20,
          f"score={cards.get('risk_score')}")
    for hours in (1, 6, 24, 168):
        status, tl = _req(opener, base, f"/api/metrics/timeline?hours={hours}")
        check(f"timeline {hours}h buckets", status == 200 and len(tl.get("buckets", [])) > 0,
              f"{len(tl.get('buckets', []))} buckets")
    status, _ = _req(opener, base, "/api/metrics/timeline?hours=abc")
    check("timeline invalid param clamps (200)", status == 200, status)
    check("top suspicious ips present", "top_suspicious" in dash, "")

    print("\n== alerts ==")
    status, alerts = _req(opener, base, "/api/alerts")
    rows = alerts.get("alerts", alerts) if isinstance(alerts, dict) else []
    check("alerts list", status == 200 and len(rows) > 0, f"{len(rows)} alerts")
    check("alerts carry severity + reason",
          all(r.get("severity") and r.get("reason") for r in rows[:3]))
    if rows:
        aid = rows[0]["id"]
        status, _ = _req(opener, base, f"/api/alerts/{aid}/ack", method="POST", data={})
        check("alert acknowledge", status == 200, status)
        status, body = _req(opener, base, f"/api/alerts/{aid}/evidence")
        check("alert evidence hash", status == 200 and len(body.get("sha256", "")) == 64, body)

    print("\n== incidents ==")
    status, incidents = _req(opener, base, "/api/incidents")
    rows = incidents.get("incidents", incidents) if isinstance(incidents, dict) else []
    check("incidents list", status == 200 and len(rows) > 0, f"{len(rows)} incidents")
    if rows:
        iid = rows[0]["id"]
        status, body = _req(opener, base, f"/incidents/{iid}")
        check("incident details page", status == 200 and "Investigation Timeline" in body)
        status, _ = _req(opener, base, f"/api/incidents/{iid}/note", method="POST",
                         data={"message": "verify_http.py smoke note"})
        check("incident note", status == 200, status)
        status, _ = _req(opener, base, f"/api/incidents/{iid}/status", method="POST",
                         data={"status": "CONTAINED"})
        check("incident status change", status == 200, status)
        status, body = _req(opener, base, f"/incidents/{iid}")
        check("timeline shows note + status",
              "smoke note" in body and "CONTAINED" in body)

    print("\n== ip analysis ==")
    status, ips = _req(opener, base, "/api/ips")
    rows = ips.get("ips", ips) if isinstance(ips, dict) else []
    check("ips list", status == 200 and len(rows) > 0, f"{len(rows)} ips")
    if rows:
        ip = rows[0]["ip"]
        status, detail = _req(opener, base, f"/api/ips/{ip}")
        check(f"ip detail ({ip})", status == 200, status)

    print("\n== firewall simulator ==")
    status, created = _req(opener, base, "/api/firewall/rules", method="POST",
                           data={"target": "203.0.113.66", "rule_type": "BLOCK",
                                 "reason": "verify_http.py"})
    check("create firewall rule", status == 200 and created.get("ok"), created)
    status, sim = _req(opener, base, "/api/firewall/simulate", method="POST",
                       data={"src_ip": "203.0.113.66", "dst_port": 80})
    check("simulate traffic against rules",
          status == 200 and sim.get("action") == "DENY", sim)
    status, rules = _req(opener, base, "/api/firewall/rules")
    check("firewall rule list", status == 200 and len(rules.get("rules", [])) >= 1, rules)

    print("\n== firewall target validation ==")
    for bad in ("999.1.1.1", "192.168.1", "192.168.1.1.5", "abc.def.ghi.jkl",
                "203.0.113.66:99999", "012.02.32.0444", "192.168.1.0/24", ""):
        status, _ = _req(opener, base, "/api/firewall/rules", method="POST",
                         data={"target": bad, "rule_type": "BLOCK"})
        check(f"reject invalid target {bad!r}", status == 400, status)
    for good in ("10.255.255.10", "10.255.255.11:8080", "any"):
        status, body = _req(opener, base, "/api/firewall/rules", method="POST",
                            data={"target": good, "rule_type": "ALLOW",
                                  "reason": "verify_http validation"})
        check(f"accept valid target {good!r}", status == 200 and body.get("ok"), status)
    # simulate endpoint validates too
    status, _ = _req(opener, base, "/api/firewall/simulate", method="POST",
                     data={"src_ip": "999.9.9.9", "dst_port": 80})
    check("simulate rejects invalid src_ip", status == 400, status)

    print("\n== settings ==")
    status, body = _req(opener, base, "/api/settings", method="POST",
                        data={"port_scan_port_threshold": 12})
    check("update threshold", status == 200, status)
    status, cfg = _req(opener, base, "/api/settings")
    check("threshold persisted", status == 200 and
          str(cfg.get("settings", {}).get("port_scan_port_threshold")) == "12")
    _req(opener, base, "/api/settings", method="POST", data={"port_scan_port_threshold": 10})

    print("\n== demo injection ==")
    for scenario in ("port_scan", "conn_flood", "dos"):
        status, body = _req(opener, base, "/api/demo/inject", method="POST",
                            data={"scenario": scenario})
        check(f"inject {scenario}", status == 200 and body.get("result"), body)
    status, body = _req(opener, base, "/api/demo/seed", method="POST", data={})
    check("seed demo batch", status == 200, status)

    print("\n== capture control (fails soft) ==")
    status, body = _req(opener, base, "/api/capture/status")
    check("capture status", status == 200 and "live_running" in body, status)
    status, body = _req(opener, base, "/api/capture/start", method="POST", data={})
    check("capture start responds (soft failure ok)", status == 200 and "started" in body, body)
    status, _ = _req(opener, base, "/api/capture/stop", method="POST", data={})
    check("capture stop", status == 200, status)

    print("\n== pcap upload ==")
    if os.path.isfile(args.pcap):
        body, headers = multipart("/api/pcap/upload", "pcap_file", args.pcap)
        status, up = _req(opener, base, "/api/pcap/upload", method="POST",
                          data=body, headers=headers, raw=True)
        check("upload sample pcap", status == 200 and isinstance(up, dict) and up.get("ok"),
              up if isinstance(up, str) else {k: up.get(k) for k in ("id", "packets", "alerts_found")})
        if isinstance(up, dict) and up.get("id"):
            status, detail = _req(opener, base, f"/api/pcap/{up['id']}")
            check("pcap detail", status == 200 and detail.get("packets", 0) > 0, detail)
            status, re_ = _req(opener, base, f"/api/pcap/{up['id']}/reanalyze", method="POST", data={})
            check("pcap re-analyze", status == 200, re_)
            status, dele = _req(opener, base, f"/api/pcap/{up['id']}/delete",
                                method="POST", data={})
            check("pcap delete", status == 200 and dele.get("ok"), dele)
            status, gone = _req(opener, base, f"/api/pcap/{up['id']}")
            check("deleted pcap is gone", status == 404, status)
    else:
        check("upload sample pcap", False, f"{args.pcap} missing")

    print("\n== reports ==")
    status, gen = _req(opener, base, "/api/reports/generate", method="POST",
                       data={"format": "pdf", "hours": 168})
    pdf_url = gen.get("url") if isinstance(gen, dict) else None
    check("generate PDF report", status == 200 and gen.get("format") == "pdf" and pdf_url, gen)
    if pdf_url:
        status, blob = _req(opener, base, pdf_url, raw=True)
        check("download PDF", status == 200 and blob[:4] == b"%PDF",
              f"{len(blob)} bytes" if isinstance(blob, bytes) else blob)
    status, gen_html = _req(opener, base, "/api/reports/generate", method="POST",
                            data={"format": "html", "hours": 168})
    html_url = gen_html.get("url") if isinstance(gen_html, dict) else None
    check("generate HTML report",
          status == 200 and gen_html.get("format") == "html" and html_url, gen_html)
    if html_url:
        status, doc = _req(opener, base, html_url)
        check("download HTML report",
              status == 200 and "cybershield" in doc.lower() and "<html" in doc.lower(),
              f"{len(doc)} chars" if isinstance(doc, str) else doc)
    status, listing = _req(opener, base, "/reports")
    check("report page lists generated files",
          status == 200 and ("RPT-" in listing or ".pdf" in listing or ".html" in listing))

    print("\n== system reset (leaves a clean seeded state) ==")
    status, body = _req(opener, base, "/api/system/reset", method="POST", data={})
    check("reset database (reseeded)", status == 200 and body.get("reseeded", 0) > 0, body)
    status, dash = _req(opener, base, "/api/dashboard")
    check("dashboard recovers after reset",
          status == 200 and dash["cards"]["total_packets"] > 0,
          f"packets={dash['cards']['total_packets']} alerts={dash['cards']['security_alerts']}")

    print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
    for name in FAIL:
        print(f"  failed: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    raise SystemExit(main())
