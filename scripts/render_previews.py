"""Render real CyberShield templates to self-contained HTML previews.

Used only for offline UI inspection (the sandbox reaps long-running dev
servers). Pages are rendered through the actual Flask test client with the
real CSS/JS inlined; fetch() is stubbed with a snapshot of genuine API data
so JS-driven tables/charts display real seeded numbers.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import app  # noqa: E402
from backend.database import reset_db  # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "previews")


def _inline(html: str) -> str:
    """Inline local CSS/JS so the file is self-contained."""
    def css_sub(m):
        path = m.group(1)
        if path.startswith("/static/"):
            fp = os.path.join(app.root_path, path[len("/static/"):])
            if os.path.isfile(fp):
                return "<style>\n" + open(fp, encoding="utf-8").read() + "\n</style>"
        return m.group(0)

    def js_sub(m):
        path = m.group(1)
        if path.startswith("/static/"):
            fp = os.path.join(app.root_path, path[len("/static/"):])
            if os.path.isfile(fp):
                return "<script>\n" + open(fp, encoding="utf-8").read() + "\n</script>"
        return m.group(0)

    html = re.sub(r'<link[^>]*href="(/static/[^"]+)"[^>]*>', css_sub, html)
    html = re.sub(r'<script src="(/static/[^"]+)"></script>', js_sub, html)
    return html


def _stub_fetch(html: str, api_map: dict) -> str:
    """Replace fetch() with a resolver serving real captured API payloads."""
    stub = ("<script>\nwindow.__CS_SNAPSHOT__ = " +
            json.dumps(api_map) +
            ";\nwindow.fetch = function (url) {\n"
            "  const key = url.split('?')[0];\n"
            "  const hit = window.__CS_SNAPSHOT__[key] !== undefined\n"
            "    ? window.__CS_SNAPSHOT__[key] : window.__CS_SNAPSHOT__['*'];\n"
            "  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(hit),\n"
            "    text: () => Promise.resolve(JSON.stringify(hit)), blob: () => Promise.resolve(new Blob([JSON.stringify(hit)])) });\n"
            "};\n</script>")
    return html.replace("</head>", stub + "\n</head>")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with app.app_context():
        reset_db(app)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})

    def grab(path):
        r = client.get(path)
        return r.get_json() if r.is_json else r.data.decode("utf-8", "replace")

    dash = grab("/api/dashboard")
    alerts = grab("/api/alerts")
    traffic = grab("/api/traffic?limit=100")
    rules = grab("/api/firewall/rules")
    ips = grab("/api/ips")

    pages = {
        "register.html": ("/register", {}),
        "login.html": ("/login", {}),
        "firewall.html": ("/firewall", {"*": {}, "/api/firewall/rules": rules}),
        "dashboard.html": ("/dashboard", {"*": {}, "/api/dashboard": dash}),
        "alerts.html": ("/alerts", {"*": {}, "/api/alerts": alerts}),
        "traffic.html": ("/traffic", {"*": {}, "/api/traffic": traffic}),
        "ips.html": ("/ips", {"*": {}, "/api/ips": ips}),
    }
    for fname, (path, api_map) in pages.items():
        html = grab(path)
        html = _inline(html)
        if api_map:
            html = _stub_fetch(html, api_map)
        out = os.path.join(OUT_DIR, fname)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"{fname}: {len(html)//1024} KB")

    print("done ->", OUT_DIR)


if __name__ == "__main__":
    main()
