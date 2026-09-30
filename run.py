#!/usr/bin/env python
"""
CyberShield - launcher
======================

Usage:
    python run.py                 # start web app at http://127.0.0.1:5000
    python run.py --port 8080     # custom port
    python run.py --reset         # wipe database and reseed
"""

import argparse
import os
import sys

# Ensure the project root is importable when launched from any cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser(description="CyberShield launcher")
    parser.add_argument("--port", type=int,
                        default=int(os.getenv("CYBERSHIELD_PORT", "5000")))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--reset", action="store_true",
                        help="Reset the database before starting")
    parser.add_argument("--no-seed", action="store_true",
                        help="Skip first-run demo data seeding")
    args = parser.parse_args()

    # Import after sys.path fix so `backend.*` resolves
    from backend.app import app, _first_run_seed
    from backend.database import reset_db
    from backend.models import db, Setting

    if args.reset:
        with app.app_context():
            reset_db(app)
        print("[*] Database reset complete")

    if args.no_seed:
        with app.app_context():
            db.session.add(Setting(key="seeded_first_run", value="1",
                                   description="Internal flag"))
            db.session.commit()

    print("=" * 64)
    print("  CyberShield - Real-Time Network Intrusion Detection &")
    print("  Security Monitoring System")
    print("=" * 64)
    print(f"  URL:      http://{args.host}:{args.port}")
    print("  Login:    admin / admin123")
    print("  Mode:     PCAP Analysis or Demo Mode if live capture is")
    print("            unavailable (requires admin/Npcap on Windows).")
    print("=" * 64)

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
