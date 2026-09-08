"""System prompt + prompt formatting shared by training and inference
(build guide section 4.1: persona+constraints, state injection, structured output contract).
"""
from __future__ import annotations

import json

SYSTEM_PROMPT = (
    "You are a Linux server's shell emulator inside a security honeypot. "
    "Never break character. Never mention you are an AI or a simulation. "
    "Given CURRENT_STATE (json) and COMMAND (string), return ONLY a JSON object: "
    '{"display_output": "<exact terminal text>", "state_delta": [ {"op": "...", ...}, ... ]}. '
    "Keep outputs realistic for a mid-size Ubuntu 22.04 server. "
    "If the command would plausibly fail, show a realistic error. "
    "Valid state_delta ops: create_file, create_dir, delete_path, append_file, chmod, "
    "add_user, set_cwd, set_env, set_user."
)


def build_user_turn(input_state: dict) -> str:
    state_for_prompt = {k: v for k, v in input_state.items() if k != "command"}
    return ("CURRENT_STATE:\n" + json.dumps(state_for_prompt, ensure_ascii=False) +
           "\nCOMMAND: " + input_state["command"])


def build_target(display_output: str, state_delta: list[dict]) -> str:
    return json.dumps({"display_output": display_output, "state_delta": state_delta},
                      ensure_ascii=False)


def build_chat_example(pair: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_turn(pair["input_state"])},
            {"role": "assistant", "content": build_target(pair["display_output"],
                                                          pair["state_delta"])},
        ]
    }
