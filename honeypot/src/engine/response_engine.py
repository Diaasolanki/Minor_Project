"""LLM Response Engine (build guide section 2/4.1) — local, fine-tuned, no API key.

Loads the base model + LoRA adapter once, generates structured JSON
(display_output, state_delta) for a given session state and command. Falls back
to the deterministic Oracle whenever the model's output is malformed or empty,
so the honeypot never stalls or breaks character (build guide 6.1, section 9 risk table).
"""
from __future__ import annotations

import json
import os
import re
import time

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from emulation.oracle import Oracle
from engine.prompt import SYSTEM_PROMPT, build_user_turn
from state.fakefs import SessionState

BASE_MODEL = os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-1.5B-Instruct")
ADAPTER_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models", "response_lora")
MERGED_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models", "response_merged")

# Phrases that would break the honeypot's character; post-filter per build guide 9.
DISALLOWED_PHRASES = ["as an ai", "i am an ai", "language model", "i cannot", "i'm sorry",
                      "as a simulation", "openai", "anthropic"]


class ResponseEngine:
    def __init__(self, use_model: bool = True, device: str | None = None):
        self.oracle = Oracle()
        self.model = None
        self.tokenizer = None
        self.use_model = use_model and (os.path.isdir(MERGED_DIR) or os.path.isdir(ADAPTER_DIR))
        if self.use_model:
            self._load_model(device)

    def _load_model(self, device: str | None) -> None:
        device_map = "auto" if device is None else device
        if os.path.isdir(MERGED_DIR):
            print(f"[engine] loading merged fine-tuned model {MERGED_DIR}")
            self.tokenizer = AutoTokenizer.from_pretrained(MERGED_DIR)
            self.model = AutoModelForCausalLM.from_pretrained(
                MERGED_DIR, torch_dtype=torch.bfloat16, device_map=device_map)
        else:
            print(f"[engine] loading base model {BASE_MODEL} + LoRA adapter {ADAPTER_DIR}")
            self.tokenizer = AutoTokenizer.from_pretrained(ADAPTER_DIR)
            base = AutoModelForCausalLM.from_pretrained(
                BASE_MODEL, torch_dtype=torch.bfloat16, device_map=device_map)
            self.model = PeftModel.from_pretrained(base, ADAPTER_DIR)
        self.model.eval()
        print("[engine] model ready")

    # ---------------------------------------------------------------- main API
    def respond(self, state: SessionState, command: str) -> dict:
        """Returns {'display_output', 'state_delta', 'engine', 'latency_ms'}."""
        t0 = time.time()
        if self.use_model:
            parsed = self._generate(state, command)
            if parsed is not None and self._is_safe(parsed["display_output"]):
                parsed["engine"] = "lora-qwen2.5-1.5b"
                parsed["latency_ms"] = (time.time() - t0) * 1000
                return parsed
        # fallback: deterministic oracle (also used before training / on malformed output)
        result = self.oracle.run(state, command)
        return {"display_output": result["display_output"], "state_delta": result["state_delta"],
               "engine": "oracle-fallback", "latency_ms": (time.time() - t0) * 1000}

    def _generate(self, state: SessionState, command: str) -> dict | None:
        prompt_state = state.prompt_state()
        prompt_state["command"] = command
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_turn(prompt_state)},
        ]
        text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer(text, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            out = self.model.generate(
                **inputs, max_new_tokens=256, do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id)
        gen = self.tokenizer.decode(out[0][inputs["input_ids"].shape[1]:],
                                    skip_special_tokens=True)
        return self._parse_json(gen)

    @staticmethod
    def _parse_json(text: str) -> dict | None:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            obj = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
        if "display_output" not in obj:
            return None
        obj.setdefault("state_delta", [])
        if not isinstance(obj["state_delta"], list):
            obj["state_delta"] = []
        return obj

    @staticmethod
    def _is_safe(text: str) -> bool:
        low = text.lower()
        return not any(p in low for p in DISALLOWED_PHRASES)
