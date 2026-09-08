"""Shared session runtime used by every emulated protocol surface (HTTP fake
terminal, fake Telnet, fake DB). One ResponseEngine + classifier pair is loaded
once and reused across all surfaces so the GPU model isn't loaded three times,
and every surface writes into the same TTP store / dashboard (build guide
section 2: layers are decoupled but share the Session Manager and TTP log).
"""
from __future__ import annotations

import os
import threading

from classifier.features import extract_features
from classifier.predict import Classifiers
from engine.response_engine import ResponseEngine
from state.fakefs import new_session
from ttp import store
from ttp.mitre_map import map_command

_engine_lock = threading.Lock()
_ENGINE: ResponseEngine | None = None
_CLASSIFIERS: Classifiers | None = None


def get_engine() -> ResponseEngine:
    global _ENGINE
    with _engine_lock:
        if _ENGINE is None:
            _ENGINE = ResponseEngine(use_model=os.environ.get("USE_LORA", "1") == "1")
        return _ENGINE


def get_classifiers() -> Classifiers:
    global _CLASSIFIERS
    with _engine_lock:
        if _CLASSIFIERS is None:
            _CLASSIFIERS = Classifiers()
        return _CLASSIFIERS


class SessionRunner:
    """One attacker session on any protocol surface: state + TTP logging + classification."""

    def __init__(self, session_id: str, src_ip: str, protocol: str = "http"):
        self.session_id = session_id
        self.protocol = protocol
        self.state = new_session(session_id, src_ip=src_ip)
        store.start_session(session_id, src_ip, self.state.hostname, protocol=protocol)

    def run_command(self, command: str) -> dict:
        result = get_engine().respond(self.state, command)
        self.state.apply_delta(result["state_delta"])
        self.state.history.append({"cmd": command, "out": result["display_output"]})
        mitre = map_command(command)
        store.log_event(
            self.session_id, command, result["display_output"], result["engine"],
            mitre[0] if mitre else None, mitre[2] if mitre else None, result["latency_ms"])
        self.reclassify()
        return result

    def log_raw_event(self, description: str, output: str, engine: str,
                      mitre_technique: str | None, mitre_tactic: str | None) -> None:
        """For non-shell surfaces (login attempts, DB auth) that don't go through the Oracle."""
        store.log_event(self.session_id, description, output, engine,
                        mitre_technique, mitre_tactic, 0.0)

    def reclassify(self) -> None:
        trace = [{"cmd": h["cmd"], "output": h["out"], "exit_code": 0,
                 "mitre_technique": (map_command(h["cmd"]) or (None,))[0]}
                 for h in self.state.history]
        if len(trace) < 2:
            return
        feats = extract_features(trace)
        skill, intent, conf = get_classifiers().predict(feats)
        store.update_classification(self.session_id, skill, intent, conf)

    def close(self) -> None:
        store.end_session(self.session_id)


class SessionRegistry:
    """Thread-safe session_id -> SessionRunner map, one per process."""

    def __init__(self):
        self._sessions: dict[str, SessionRunner] = {}
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str, src_ip: str, protocol: str = "http") -> SessionRunner:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionRunner(session_id, src_ip, protocol=protocol)
            return self._sessions[session_id]

    def create(self, src_ip: str, protocol: str = "http") -> SessionRunner:
        sid = store.new_session_id()
        with self._lock:
            self._sessions[sid] = SessionRunner(sid, src_ip, protocol=protocol)
            return self._sessions[sid]

    def drop(self, session_id: str) -> None:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess:
            sess.close()


REGISTRY = SessionRegistry()
