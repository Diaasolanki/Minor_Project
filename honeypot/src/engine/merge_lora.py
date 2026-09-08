"""Merge the trained LoRA adapter into the base model and save a standalone
checkpoint. Removes the per-layer adapter delta computation from every forward
pass at inference time (small but free latency win once trained)."""
from __future__ import annotations

import os
import sys

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

BASE_MODEL = os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-1.5B-Instruct")
ADAPTER_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models", "response_lora")
MERGED_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models", "response_merged")


def main():
    print(f"Loading base {BASE_MODEL} ...")
    tokenizer = AutoTokenizer.from_pretrained(ADAPTER_DIR)
    base = AutoModelForCausalLM.from_pretrained(BASE_MODEL, torch_dtype=torch.bfloat16)
    print(f"Applying LoRA adapter from {ADAPTER_DIR} ...")
    model = PeftModel.from_pretrained(base, ADAPTER_DIR)
    print("Merging ...")
    merged = model.merge_and_unload()
    os.makedirs(MERGED_DIR, exist_ok=True)
    merged.save_pretrained(MERGED_DIR)
    tokenizer.save_pretrained(MERGED_DIR)
    print(f"Saved merged model to {MERGED_DIR}")


if __name__ == "__main__":
    main()
