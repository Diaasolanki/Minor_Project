"""LoRA fine-tune a small open-weight model on the oracle-generated
(state, command) -> (display_output, state_delta) pairs.

This is the "self-hosted" response engine described in build guide section 4.1's
stretch goal, done as the primary engine (no hosted API key involved at all).
Base model: Qwen2.5-1.5B-Instruct (~3GB fp16, fits comfortably on a 12GB GPU
with room for LoRA + optimizer states).
"""
from __future__ import annotations

import json
import os
import sys

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import (AutoModelForCausalLM, AutoTokenizer, DataCollatorForLanguageModeling,
                          Trainer, TrainingArguments)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.prompt import build_chat_example  # noqa: E402

BASE_MODEL = os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-1.5B-Instruct")
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic", "llm_pairs.jsonl")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models", "response_lora")
MAX_LEN = 1024


def load_pairs(path: str, limit: int | None = None) -> list[dict]:
    out = []
    with open(path, encoding="utf8") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            out.append(json.loads(line))
    return out


def tokenize_example(tokenizer, example: dict) -> dict:
    chat = build_chat_example(example)["messages"]
    prompt_text = tokenizer.apply_chat_template(
        chat[:-1], tokenize=False, add_generation_prompt=True)
    full_text = tokenizer.apply_chat_template(
        chat, tokenize=False, add_generation_prompt=False)
    prompt_ids = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
    full_ids = tokenizer(full_text, add_special_tokens=False)["input_ids"]
    full_ids = full_ids[:MAX_LEN]
    labels = list(full_ids)
    prompt_len = min(len(prompt_ids), len(full_ids))
    for i in range(prompt_len):
        labels[i] = -100
    return {"input_ids": full_ids, "labels": labels,
           "attention_mask": [1] * len(full_ids)}


class Collator:
    def __init__(self, pad_id: int):
        self.pad_id = pad_id

    def __call__(self, batch):
        max_len = max(len(b["input_ids"]) for b in batch)
        input_ids, labels, attn = [], [], []
        for b in batch:
            pad = max_len - len(b["input_ids"])
            input_ids.append(b["input_ids"] + [self.pad_id] * pad)
            labels.append(b["labels"] + [-100] * pad)
            attn.append(b["attention_mask"] + [0] * pad)
        return {
            "input_ids": torch.tensor(input_ids),
            "labels": torch.tensor(labels),
            "attention_mask": torch.tensor(attn),
        }


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    print(f"Loading base model {BASE_MODEL} ...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, torch_dtype=torch.bfloat16, device_map="auto")

    lora_config = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj",
                        "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    print("Loading + tokenizing dataset ...")
    pairs = load_pairs(DATA_PATH, limit=limit)
    print(f"{len(pairs)} training pairs")
    tokenized = [tokenize_example(tokenizer, p) for p in pairs]
    ds = Dataset.from_list(tokenized)
    split = ds.train_test_split(test_size=0.05, seed=42)

    args = TrainingArguments(
        output_dir=OUT_DIR,
        num_train_epochs=3,
        per_device_train_batch_size=4,
        per_device_eval_batch_size=4,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        warmup_steps=max(1, int(0.03 * (14200 // (4 * 4)) * 3)),
        lr_scheduler_type="cosine",
        logging_steps=20,
        eval_strategy="steps",
        eval_steps=100,
        save_strategy="epoch",
        save_total_limit=2,
        bf16=True,
        report_to=[],
        dataloader_num_workers=0,
    )

    trainer = Trainer(
        model=model, args=args,
        train_dataset=split["train"], eval_dataset=split["test"],
        data_collator=Collator(tokenizer.pad_token_id),
    )
    resume_ckpt = None
    if os.path.isdir(OUT_DIR):
        ckpts = [d for d in os.listdir(OUT_DIR) if d.startswith("checkpoint-")]
        if ckpts:
            resume_ckpt = os.path.join(OUT_DIR, sorted(ckpts, key=lambda d: int(d.split("-")[1]))[-1])
            print(f"Resuming from {resume_ckpt}")
    trainer.train(resume_from_checkpoint=resume_ckpt)

    print(f"Saving LoRA adapter to {OUT_DIR}")
    model.save_pretrained(OUT_DIR)
    tokenizer.save_pretrained(OUT_DIR)

    eval_metrics = trainer.evaluate()
    with open(os.path.join(OUT_DIR, "eval_metrics.json"), "w", encoding="utf8") as f:
        json.dump(eval_metrics, f, indent=2)
    print("Final eval:", eval_metrics)


if __name__ == "__main__":
    main()
