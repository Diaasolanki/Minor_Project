"""Convenience launcher: sets PYTHONPATH and starts the Flask app."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dashboard.app import app  # noqa: E402

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
