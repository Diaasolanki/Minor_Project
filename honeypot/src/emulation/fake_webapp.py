"""Fake vulnerable "company portal" web application (build guide layer 1: a
web attack surface alongside the shell/DB/login surfaces). Adds the class of
vulnerabilities a real intranet app gets popped for — SQL injection, stored
XSS, IDOR/privilege escalation, and a weak-credential hidden admin panel —
as a genuinely exploitable but fully contained local decoy, feeding the same
Session Manager / TTP store / classifier as every other surface here.

Inspired by the "Website" component of the HoneyScope project
(github.com/Guptaharshal1515/HoneyScope): its four intentional web
vulnerabilities (SQLi auth bypass, stored XSS, IDOR + privilege escalation,
weak admin credentials) are reproduced here as a Flask blueprint wired into
this project's own session/TTP/classifier pipeline, rather than HoneyScope's
Wazuh/Cowrie/Raspberry-Pi/Gemini stack (out of scope — see README for why).

Every request is logged through the shared SessionRunner exactly like the
Telnet and DB surfaces, with a simple attack-pattern detector choosing the
MITRE ATT&CK technique to tag: T1190 (SQLi), T1059 (stored XSS payload),
T1078 (IDOR/privilege escalation and weak-credential login).
"""
from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager

from flask import Blueprint, redirect, render_template, request, session, url_for

from engine.session_runner import REGISTRY

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "portal.db")
DB_PATH = os.path.abspath(DB_PATH)

portal_bp = Blueprint("portal", __name__, url_prefix="/portal")

SEED_USERS = [
    ("admin", "admin123", "admin@techcorp-internal.com", "admin"),
    ("jsmith", "password123", "john.smith@techcorp-internal.com", "employee"),
    ("agarcia", "welcome1", "ana.garcia@techcorp-internal.com", "employee"),
    ("mwilson", "letmein", "mike.wilson@techcorp-internal.com", "manager"),
]

SQLI_PATTERN = re.compile(
    r"('\s*or\s*'|'\s*--|--\s*$|;\s*--|union\s+select|'\s*=\s*'|1\s*=\s*1|or\s+1\s*=\s*1)",
    re.IGNORECASE,
)
XSS_PATTERN = re.compile(
    r"(<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+onerror|<svg[^>]*onload)",
    re.IGNORECASE,
)


def init_portal_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL, password TEXT NOT NULL, email TEXT NOT NULL, "
        "role TEXT NOT NULL DEFAULT 'employee')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER, username TEXT, comment TEXT, "
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            SEED_USERS,
        )
    conn.commit()
    conn.close()


@contextmanager
def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _portal_session():
    """One honeypot SessionRunner per browser session, shared across all portal routes."""
    sid = session.get("_honeypot_sid")
    src_ip = request.remote_addr or "0.0.0.0"
    if sid:
        return REGISTRY.get_or_create(sid, src_ip, protocol="webapp")
    sess = REGISTRY.create(src_ip, protocol="webapp")
    session["_honeypot_sid"] = sess.session_id
    return sess


def _log(description: str, output: str, technique: str | None, tactic: str | None) -> None:
    _portal_session().log_raw_event(description, output, "oracle-fallback", technique, tactic)


# ---------------------------------------------------------------------- login
@portal_bp.route("/login", methods=["GET", "POST"])
def portal_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        is_sqli = bool(SQLI_PATTERN.search(username) or SQLI_PATTERN.search(password))

        # INTENTIONALLY VULNERABLE: string-concatenated SQL — real SQL injection
        # against a fully local, fake decoy database. Never touches real user data.
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        with _db() as conn:
            try:
                result = conn.execute(query).fetchone()
                if result is None:
                    fallback = "SELECT * FROM users WHERE username = '" + username + "'"
                    result = conn.execute(fallback).fetchone()
            except sqlite3.Error as e:
                result = None
                error = f"Database error: {e}"

        if result:
            session["portal_user_id"] = result["id"]
            session["portal_username"] = result["username"]
            session["portal_role"] = result["role"]
            _log(f"PORTAL_LOGIN success user={username!r} pass={password!r}",
                "302 Found -> /portal/dashboard",
                "T1190" if is_sqli else "T1078",
                "Initial Access")
            return redirect(url_for("portal.portal_dashboard"))

        if not error:
            error = "Invalid credentials. Please try again."
        _log(f"PORTAL_LOGIN failed user={username!r} pass={password!r}",
            f"401: {error}", "T1190" if is_sqli else "T1110", "Credential Access")

    return render_template("portal_login.html", error=error)


@portal_bp.route("/logout")
def portal_logout():
    session.pop("portal_user_id", None)
    session.pop("portal_username", None)
    session.pop("portal_role", None)
    return redirect(url_for("portal.portal_login"))


# ------------------------------------------------------------------- dashboard
@portal_bp.route("/dashboard")
def portal_dashboard():
    if not session.get("portal_user_id"):
        return redirect(url_for("portal.portal_login"))
    with _db() as conn:
        comments = conn.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    return render_template("portal_dashboard.html", username=session["portal_username"],
                          role=session["portal_role"], user_id=session["portal_user_id"],
                          comments=comments)


@portal_bp.route("/submit_comment", methods=["POST"])
def portal_submit_comment():
    if not session.get("portal_user_id"):
        return redirect(url_for("portal.portal_login"))
    comment_text = request.form.get("comment", "")
    if comment_text:
        with _db() as conn:
            conn.execute(
                "INSERT INTO comments (user_id, username, comment) VALUES (?, ?, ?)",
                (session["portal_user_id"], session["portal_username"], comment_text),
            )
        if XSS_PATTERN.search(comment_text):
            _log(f"PORTAL_COMMENT payload={comment_text!r}",
                "200 OK (comment stored, rendered unescaped)", "T1059", "Execution")
        else:
            _log(f"PORTAL_COMMENT text={comment_text!r}", "200 OK (comment stored)", None, None)
    return redirect(url_for("portal.portal_dashboard"))


# --------------------------------------------------------------------- profile
@portal_bp.route("/profile", methods=["GET", "POST"])
def portal_profile():
    if not session.get("portal_user_id"):
        return redirect(url_for("portal.portal_login"))

    own_id = session["portal_user_id"]
    # INTENTIONALLY VULNERABLE: no check that the requested user_id belongs to
    # the logged-in user — classic IDOR.
    requested_id = request.args.get("user_id", own_id)
    message = None

    with _db() as conn:
        if request.method == "POST":
            target_id = request.form.get("user_id", requested_id)
            new_username = request.form.get("username", "")
            new_email = request.form.get("email", "")
            new_role = request.form.get("role", "")
            conn.execute(
                "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
                (new_username, new_email, new_role, target_id),
            )
            message = "Profile updated successfully."
            requested_id = target_id
            if str(target_id) != str(own_id):
                _log(f"PORTAL_PROFILE_EDIT actor={own_id} target={target_id} new_role={new_role!r}",
                    "200 OK (edited another user's profile)", "T1078", "Privilege Escalation")
            elif new_role != session.get("portal_role"):
                _log(f"PORTAL_PROFILE_EDIT actor={own_id} self_role_change={new_role!r}",
                    "200 OK (self-escalated role)", "T1078", "Privilege Escalation")

        user = conn.execute("SELECT * FROM users WHERE id = ?", (requested_id,)).fetchone()

    if str(requested_id) != str(own_id) and request.method == "GET":
        _log(f"PORTAL_PROFILE_VIEW actor={own_id} target={requested_id}",
            "200 OK (viewed another user's profile via IDOR)", "T1078", "Privilege Escalation")

    if user is None:
        return "User not found", 404
    return render_template("portal_profile.html", user=user, message=message)


# ----------------------------------------------------------------- admin panel
@portal_bp.route("/admin", methods=["GET", "POST"])
def portal_admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # INTENTIONALLY VULNERABLE: hardcoded weak/default credentials.
        if username == "admin" and password == "admin123":
            session["portal_admin"] = True
            _log(f"PORTAL_ADMIN_LOGIN success user={username!r}",
                "302 Found -> /portal/admin/dashboard", "T1078", "Initial Access")
            return redirect(url_for("portal.portal_admin_dashboard"))
        error = "Access denied."
        _log(f"PORTAL_ADMIN_LOGIN failed user={username!r} pass={password!r}",
            "401: Access denied", "T1110", "Credential Access")
    return render_template("portal_admin.html", error=error)


@portal_bp.route("/admin/dashboard")
def portal_admin_dashboard():
    if not session.get("portal_admin"):
        return redirect(url_for("portal.portal_admin_login"))
    return render_template("portal_admin_dashboard.html")
