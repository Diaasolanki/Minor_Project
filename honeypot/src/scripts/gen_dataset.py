"""Generate labeled synthetic sessions (build guide 3.3) by running persona
scripts through the deterministic Oracle against a fresh SessionState.

Produces two artifacts:
  data/synthetic/sessions.jsonl   -- one labeled session per line (skill, intent,
                                      full command/output/state trace) for the classifier
  data/synthetic/llm_pairs.jsonl  -- (state, command) -> (display_output, state_delta)
                                      triples for supervised fine-tuning of the
                                      local response model
"""
from __future__ import annotations

import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emulation.oracle import Oracle
from scripts.personas import generate_session
from state.fakefs import new_session
from ttp.mitre_map import map_command

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic")
os.makedirs(OUT_DIR, exist_ok=True)


def build_prompt_state(state, command: str) -> dict:
    return {
        "hostname": state.hostname,
        "user": state.user,
        "cwd": state.cwd,
        "listing": state.fs_snapshot(),
        "recent": [{"cmd": h["cmd"], "out": h["out"][:160]} for h in state.history[-4:]],
        "command": command,
    }


def run_one(rng: random.Random, seed: int, persona: str | None = None) -> tuple[dict, list[dict]]:
    oracle = Oracle(rng=rng)
    sid = f"synthetic-{seed}"
    state = new_session(sid, src_ip="10.%d.%d.%d" % (rng.randint(0, 254), rng.randint(0, 254),
                                                      rng.randint(1, 254)), seed=seed)
    session = generate_session(rng, persona=persona)

    trace = []
    llm_pairs = []
    for cmd in session["commands"]:
        prompt_state = build_prompt_state(state, cmd)
        result = oracle.run(state, cmd)
        state.apply_delta(result["state_delta"])
        state.history.append({"cmd": cmd, "out": result["display_output"]})
        mitre = map_command(cmd)
        trace.append({
            "cmd": cmd,
            "output": result["display_output"],
            "exit_code": result["exit_code"],
            "mitre_technique": mitre[0] if mitre else None,
            "mitre_tactic": mitre[2] if mitre else None,
        })
        llm_pairs.append({
            "input_state": prompt_state,
            "display_output": result["display_output"],
            "state_delta": result["state_delta"],
        })

    record = {
        "session_id": sid,
        "persona": session["persona"],
        "skill": session["skill"],
        "intent": session["intent"],
        "src_ip": state.src_ip,
        "trace": trace,
    }
    return record, llm_pairs


def main(n_sessions: int = 800, seed: int = 42):
    rng_master = random.Random(seed)
    sessions_path = os.path.join(OUT_DIR, "sessions.jsonl")
    pairs_path = os.path.join(OUT_DIR, "llm_pairs.jsonl")

    persona_cycle = ["novice", "scripted_bot", "intermediate", "advanced"]
    with open(sessions_path, "w", encoding="utf8") as sf, \
         open(pairs_path, "w", encoding="utf8") as pf:
        for i in range(n_sessions):
            persona = persona_cycle[i % len(persona_cycle)]
            session_seed = rng_master.randint(0, 2**31)
            rng = random.Random(session_seed)
            record, pairs = run_one(rng, session_seed, persona=persona)
            sf.write(json.dumps(record) + "\n")
            for p in pairs:
                pf.write(json.dumps(p) + "\n")

    print(f"Wrote {n_sessions} sessions -> {sessions_path}")
    print(f"Wrote LLM training pairs -> {pairs_path}")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 800
    main(n_sessions=n)
