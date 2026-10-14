"""
LabTrace · LogLens — Entry point

Starts the background log collectors + detection scheduler, then serves
the app on 127.0.0.1:5000 (set LOGLENS_ALLOW_LAN=1 to bind 0.0.0.0).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Windows consoles default to cp1252 — force UTF-8 for the banner
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from app.config import HOST, PORT, DEBUG
from app.main import app
from app.collector import start_collector, stop_collector
from app.scheduler import start_scheduler, stop_scheduler


def main():
    print("")
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║   LabTrace · LogLens  —  Secure Cyber Edition    ║")
    print("  ║   Local SIEM · No Cloud · Human-in-the-loop     ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print("")
    print(f"  Interface : http://{HOST}:{PORT}")
    print(f"  Dashboard : http://{HOST}:{PORT}/dashboard")
    print(f"  Live Monitor : http://{HOST}:{PORT}/monitor")
    print("")
    print("  Demo Login:")
    print("    admin   / LabTrace@2025")
    print("    analyst / Analyst@2025")
    print("")
    print("  Collectors: Windows/Auth-log · File Watch (data/incoming) · "
          "Syslog UDP:5140")
    print("  Detection : every 30s (R1–R6 explainable rules)")
    print("")

    start_collector()
    start_scheduler()

    try:
        try:
            from waitress import serve
            print(f"  Serving with waitress on {HOST}:{PORT}")
            serve(app, host=HOST, port=PORT)
        except ImportError:
            print(f"  waitress not installed — falling back to Flask dev server")
            app.run(host=HOST, port=PORT, debug=DEBUG)
    except KeyboardInterrupt:
        print("\n  Shutting down…")
    finally:
        stop_scheduler()
        stop_collector()


if __name__ == "__main__":
    main()
