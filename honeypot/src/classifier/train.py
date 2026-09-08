"""Train the skill-level and intent classifiers (build guide 4.2, Approach A).

Two independent XGBoost multi-class models sharing the same feature vector.
Evaluated with a held-out split and per-class F1 (imbalanced classes).
"""
from __future__ import annotations

import json
import os
import sys

import joblib
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from classifier.features import FEATURE_NAMES, extract_batch  # noqa: E402

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic", "sessions.jsonl")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def load_records(path: str) -> list[dict]:
    with open(path, encoding="utf8") as f:
        return [json.loads(line) for line in f]


def train_one(X, y_raw, name: str):
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    clf = XGBClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.08,
        subsample=0.9, colsample_bytree=0.9, eval_metric="mlogloss",
        objective="multi:softprob", random_state=42,
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    report = classification_report(y_test, preds, target_names=le.classes_,
                                   output_dict=True, zero_division=0)
    print(f"\n=== {name} classifier ===")
    print(classification_report(y_test, preds, target_names=le.classes_, zero_division=0))
    print("Confusion matrix (rows=true, cols=pred):")
    print(le.classes_)
    print(confusion_matrix(y_test, preds))

    importances = dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist()))
    top = sorted(importances.items(), key=lambda kv: -kv[1])[:6]
    print("Top features:", top)

    joblib.dump({"model": clf, "label_encoder": le, "report": report,
                "feature_importances": importances},
               os.path.join(MODEL_DIR, f"{name}_classifier.joblib"))
    return report


def main():
    records = load_records(DATA_PATH)
    print(f"Loaded {len(records)} labeled sessions")
    X, skills, intents = extract_batch(records)
    X = np.array(X)

    skill_report = train_one(X, skills, "skill")
    intent_report = train_one(X, intents, "intent")

    summary = {"n_sessions": len(records), "skill_report": skill_report,
              "intent_report": intent_report}
    with open(os.path.join(MODEL_DIR, "classifier_eval.json"), "w", encoding="utf8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved models + eval report to {MODEL_DIR}")


if __name__ == "__main__":
    main()
