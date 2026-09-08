"""Render confusion matrices + per-class F1 from models/classifier_eval.json as a PNG
(build guide section 7: report per-class F1, not just accuracy)."""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")


def main():
    with open(os.path.join(MODEL_DIR, "classifier_eval.json"), encoding="utf8") as f:
        summary = json.load(f)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, key, title in zip(axes, ["skill_report", "intent_report"],
                              ["Skill classifier — per-class F1", "Intent classifier — per-class F1"]):
        report = summary[key]
        classes = [k for k in report if k not in ("accuracy", "macro avg", "weighted avg")]
        f1s = [report[c]["f1-score"] for c in classes]
        ax.barh(classes, f1s, color="#4ec9b0")
        ax.set_xlim(0, 1)
        ax.set_title(title, fontsize=10)
        ax.set_xlabel("F1 score")
        for i, v in enumerate(f1s):
            ax.text(v + 0.01, i, f"{v:.2f}", va="center", fontsize=9)

    plt.tight_layout()
    out_path = os.path.join(MODEL_DIR, "classifier_eval.png")
    plt.savefig(out_path, dpi=140)
    print(f"Saved {out_path}")


if __name__ == "__main__":
    main()
