"""Flask app: fake HTTP terminal + fake admin login + live dashboard.

Stands in for Cowrie+React+WebSockets from the build guide at coursework scale:
same request flow (section 2.1) — command in, Session Manager fetches state, Response
Engine produces output + delta, delta applied, event logged, dashboard reads from the
same SQLite store. Shares its ResponseEngine/classifier/session registry with the
fake Telnet and fake DB surfaces via engine.session_runner, so all three protocol
surfaces show up in one dashboard.
"""
from __future__ import annotations

import json
import os
import sys

from flask import Flask, Response, jsonify, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emulation.fake_webapp import init_portal_db, portal_bp  # noqa: E402
from engine.session_runner import REGISTRY, get_engine  # noqa: E402
from ttp import store  # noqa: E402

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")

app = Flask(__name__, template_folder="templates", static_folder="static")
# Needed for the fake vulnerable web portal's own session cookie (Flask's
# `session` object) — a fixed dev key is fine here since nothing behind this
# app is real; it never protects anything worth protecting.
app.secret_key = "honeypot-dev-key-not-a-real-secret"
app.register_blueprint(portal_bp)

store.init_db()
init_portal_db()
get_engine()  # load the model once at startup rather than on first request

# Decoy credentials: matches the password baked into the fake /var/www/app/config.php
# and deploy.sh files in state/fakefs.py, so an attacker who reads those fake files
# and tries them here gets a consistent (still fake) payoff.
FAKE_ADMIN_USER = "admin"
FAKE_ADMIN_PASS = "Str0ng!AppPass2023"


@app.route("/")
def index():
    return render_template("terminal.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/session/new", methods=["POST"])
def api_new_session():
    src_ip = request.remote_addr or "0.0.0.0"
    sess = REGISTRY.create(src_ip, protocol="http")
    return jsonify({"session_id": sess.session_id, "banner": sess.state.banner(),
                    "prompt": sess.state.shell_prompt()})


@app.route("/api/session/<sid>/run", methods=["POST"])
def api_run(sid):
    command = request.json.get("command", "")
    src_ip = request.remote_addr or "0.0.0.0"
    sess = REGISTRY.get_or_create(sid, src_ip, protocol="http")
    result = sess.run_command(command)
    return jsonify({
        "display_output": result["display_output"],
        "prompt": sess.state.shell_prompt(),
        "engine": result["engine"],
        "latency_ms": round(result["latency_ms"], 1),
        "close": result.get("close", False),
    })


@app.route("/api/sessions")
def api_sessions():
    return jsonify(store.list_sessions())


@app.route("/api/session/<sid>")
def api_session_detail(sid):
    detail = store.get_session(sid)
    if detail is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(detail)


@app.route("/api/session/<sid>/stix")
def api_session_stix(sid):
    bundle = store.to_stix_bundle(sid)
    body = json.dumps(bundle, indent=2)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=session-{sid[:8]}-stix.json"})


@app.route("/api/stats")
def api_stats():
    sessions = store.list_sessions(limit=1000)
    skills, intents, protocols = {}, {}, {}
    for s in sessions:
        if s["classifier_skill"]:
            skills[s["classifier_skill"]] = skills.get(s["classifier_skill"], 0) + 1
        if s["classifier_intent"]:
            intents[s["classifier_intent"]] = intents.get(s["classifier_intent"], 0) + 1
        proto = s.get("protocol") or "http"
        protocols[proto] = protocols.get(proto, 0) + 1
    return jsonify({"total_sessions": len(sessions), "skill_breakdown": skills,
                    "intent_breakdown": intents, "protocol_breakdown": protocols})


@app.route("/api/metrics")
def api_metrics():
    """Evaluation-plan data (build guide section 7): latency, MITRE technique
    coverage, engine usage, engagement time — plus the classifier's own
    held-out per-class F1 report, read straight from training-time output.
    """
    live = store.get_metrics()
    classifier_eval = {}
    eval_path = os.path.join(MODELS_DIR, "classifier_eval.json")
    if os.path.exists(eval_path):
        with open(eval_path, encoding="utf8") as f:
            classifier_eval = json.load(f)
    return jsonify({"live": live, "classifier_eval": classifier_eval})


# ---------------------------------------------------------------------------
# Fake HTTP login surface (build guide 2, layer 1: "a fake login flow that
# behaves like a real misconfigured server"). Always rejects except the decoy
# credential, which just leads to another fake page — never real access to
# anything, since nothing behind this is real.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def fake_login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    src_ip = request.remote_addr or "0.0.0.0"
    sess = REGISTRY.create(src_ip, protocol="http-login")

    if username == FAKE_ADMIN_USER and password == FAKE_ADMIN_PASS:
        sess.log_raw_event(f"LOGIN success user={username}", "302 Found -> /admin/dashboard",
                           "oracle-fallback", "T1078", "Initial Access")
        return render_template("login.html", error=None, success=True)

    sess.log_raw_event(f"LOGIN attempt user={username} pass={password}",
                       "401 Unauthorized: Invalid credentials", "oracle-fallback",
                       "T1110", "Credential Access")
    return render_template("login.html", error="Invalid username or password.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
