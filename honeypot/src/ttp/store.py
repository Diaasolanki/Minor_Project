"""Durable TTP logging store. SQLite stands in for the Postgres+Redis pair described
in the build guide's section 5/6 — same schema, single-file deployment for a
coursework-scale project.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "ttp.db")
DB_PATH = os.path.abspath(DB_PATH)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_ip TEXT,
    hostname TEXT,
    protocol TEXT DEFAULT 'http',
    started_at REAL,
    ended_at REAL,
    classifier_skill TEXT,
    classifier_intent TEXT,
    classifier_confidence REAL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    timestamp REAL,
    raw_command TEXT,
    llm_output TEXT,
    engine TEXT,
    mitre_technique TEXT,
    mitre_tactic TEXT,
    latency_ms REAL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as c:
        c.executescript(SCHEMA)
        cols = {row["name"] for row in c.execute("PRAGMA table_info(sessions)").fetchall()}
        if "protocol" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN protocol TEXT DEFAULT 'http'")


def new_session_id() -> str:
    return str(uuid.uuid4())


def start_session(session_id: str, source_ip: str, hostname: str, protocol: str = "http") -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO sessions (session_id, source_ip, hostname, protocol, started_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, source_ip, hostname, protocol, time.time()),
        )


def end_session(session_id: str) -> None:
    with _conn() as c:
        c.execute("UPDATE sessions SET ended_at = ? WHERE session_id = ?",
                  (time.time(), session_id))


def log_event(session_id: str, raw_command: str, llm_output: str, engine: str,
              mitre_technique: str | None, mitre_tactic: str | None,
              latency_ms: float) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO events (session_id, timestamp, raw_command, llm_output, engine, "
            "mitre_technique, mitre_tactic, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, time.time(), raw_command, llm_output, engine,
             mitre_technique, mitre_tactic, latency_ms),
        )


def update_classification(session_id: str, skill: str, intent: str, confidence: float) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE sessions SET classifier_skill = ?, classifier_intent = ?, "
            "classifier_confidence = ? WHERE session_id = ?",
            (skill, intent, confidence, session_id),
        )


def get_session_commands(session_id: str) -> list[str]:
    with _conn() as c:
        rows = c.execute(
            "SELECT raw_command FROM events WHERE session_id = ? ORDER BY id", (session_id,)
        ).fetchall()
    return [r["raw_command"] for r in rows]


def list_sessions(limit: int = 100) -> list[dict]:
    """Sessions with event_count and engagement_seconds (build guide 7:
    "Engagement time: average session duration vs. a static Cowrie baseline")
    computed from the span between first and last logged event.
    """
    with _conn() as c:
        rows = c.execute(
            """
            SELECT s.*,
                   COUNT(e.id) AS event_count,
                   COALESCE(MAX(e.timestamp) - MIN(e.timestamp), 0) AS engagement_seconds
            FROM sessions s
            LEFT JOIN events e ON e.session_id = s.session_id
            GROUP BY s.session_id
            ORDER BY s.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_metrics() -> dict:
    """Aggregate stats for the dashboard's evaluation panel (build guide section 7):
    latency distribution, MITRE technique/tactic frequency, engine usage, engagement time.
    """
    with _conn() as c:
        latency = c.execute(
            "SELECT AVG(latency_ms) AS avg_ms, MAX(latency_ms) AS max_ms, COUNT(*) AS n "
            "FROM events WHERE latency_ms > 0"
        ).fetchone()
        technique_rows = c.execute(
            "SELECT mitre_technique, mitre_tactic, COUNT(*) AS n FROM events "
            "WHERE mitre_technique IS NOT NULL "
            "GROUP BY mitre_technique, mitre_tactic ORDER BY n DESC"
        ).fetchall()
        engine_rows = c.execute(
            "SELECT engine, COUNT(*) AS n FROM events WHERE engine IS NOT NULL GROUP BY engine"
        ).fetchall()
        engagement_rows = c.execute(
            """
            SELECT COALESCE(MAX(e.timestamp) - MIN(e.timestamp), 0) AS secs
            FROM sessions s JOIN events e ON e.session_id = s.session_id
            GROUP BY s.session_id
            """
        ).fetchall()
    engagement = [r["secs"] for r in engagement_rows if r["secs"] and r["secs"] > 0]
    return {
        "latency": {"avg_ms": latency["avg_ms"] or 0, "max_ms": latency["max_ms"] or 0,
                   "n": latency["n"] or 0},
        "techniques": [dict(r) for r in technique_rows],
        "engines": [dict(r) for r in engine_rows],
        "engagement": {
            "avg_seconds": (sum(engagement) / len(engagement)) if engagement else 0,
            "max_seconds": max(engagement) if engagement else 0,
            "n": len(engagement),
        },
    }


def get_session(session_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        events = c.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY id", (session_id,)
        ).fetchall()
    d = dict(row)
    d["events"] = [dict(e) for e in events]
    return d


def to_stix_bundle(session_id: str) -> dict:
    """Minimal STIX 2.1 bundle export for interoperability with SOC tooling."""
    sess = get_session(session_id)
    if sess is None:
        return {}
    objects = [{
        "type": "x-honeypot-session",
        "id": "x-honeypot-session--" + session_id,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sess["started_at"])),
        "source_ip": sess["source_ip"],
        "hostname": sess["hostname"],
        "classifier_skill": sess["classifier_skill"],
        "classifier_intent": sess["classifier_intent"],
    }]
    for e in sess["events"]:
        if not e["mitre_technique"]:
            continue
        objects.append({
            "type": "attack-pattern",
            "id": "attack-pattern--" + str(uuid.uuid5(uuid.NAMESPACE_URL, str(e["id"]))),
            "name": e["mitre_technique"],
            "external_references": [{"source_name": "mitre-attack",
                                     "external_id": e["mitre_technique"]}],
            "x_command": e["raw_command"],
            "x_timestamp": e["timestamp"],
        })
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}
