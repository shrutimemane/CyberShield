"""Run the HTTP verification sweep against an in-process Flask server.

Works around the sandbox reaping detached child processes: the server runs as
a daemon thread inside THIS process, so it lives as long as the sweep does.
Usage:  ../venv/Scripts/python scripts/run_verify_inline.py [port]
"""
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import app  # noqa: E402
import scripts.verify_http as vh  # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5072
BASE = f"http://127.0.0.1:{PORT}"


def main():
    t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=PORT,
                               threaded=True, use_reloader=False, debug=False),
        daemon=True)
    t.start()
    for _ in range(45):
        time.sleep(1)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2)
            break
        except Exception:
            pass
    else:
        print("server failed to start")
        return 1
    sys.argv = ["verify_http.py", "--base", BASE]
    return vh.main()


if __name__ == "__main__":
    raise SystemExit(main())
