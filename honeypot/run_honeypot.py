"""Launches all three emulated attacker-facing surfaces from the build guide's
layer 1 (Emulated Service Layer) together, sharing one Session Manager, one
locally fine-tuned Response Engine, and one TTP store / dashboard:

  - fake HTTP terminal + fake admin login  -> http://localhost:5000/  and /login
  - fake Telnet-style raw shell             -> localhost:2323 (telnet/nc)
  - fake MySQL wire-protocol listener       -> localhost:3307 (mysql -h ... -P 3307)
  - live dashboard                          -> http://localhost:5000/dashboard

Run `python run_dashboard.py` instead if you only want the HTTP surface.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from emulation import fake_db, fake_telnet  # noqa: E402
from dashboard.app import app  # noqa: E402

if __name__ == "__main__":
    telnet_port = int(os.environ.get("TELNET_PORT", fake_telnet.DEFAULT_PORT))
    db_port = int(os.environ.get("DB_PORT", fake_db.DEFAULT_PORT))

    fake_telnet.serve(telnet_port, in_thread=True)
    fake_db.serve(db_port, in_thread=True)

    print(f"[run_honeypot] HTTP terminal + login + dashboard on http://0.0.0.0:5000")
    print(f"[run_honeypot] fake telnet shell on 0.0.0.0:{telnet_port}")
    print(f"[run_honeypot] fake MySQL listener on 0.0.0.0:{db_port}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
