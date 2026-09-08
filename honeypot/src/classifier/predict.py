"""Thin runtime wrapper around the trained skill/intent classifiers for the dashboard."""
from __future__ import annotations

import os

import joblib
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")


class Classifiers:
    def __init__(self):
        self.skill = self._load("skill")
        self.intent = self._load("intent")

    @staticmethod
    def _load(name: str):
        path = os.path.join(MODEL_DIR, f"{name}_classifier.joblib")
        if not os.path.exists(path):
            return None
        return joblib.load(path)

    def predict(self, features: list[float]) -> tuple[str, str, float]:
        x = np.array([features])
        skill_label, skill_conf = self._predict_one(self.skill, x, default="unknown")
        intent_label, intent_conf = self._predict_one(self.intent, x, default="unknown")
        return skill_label, intent_label, min(skill_conf, intent_conf)

    @staticmethod
    def _predict_one(bundle, x, default: str) -> tuple[str, float]:
        if bundle is None:
            return default, 0.0
        model, le = bundle["model"], bundle["label_encoder"]
        proba = model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        return le.inverse_transform([idx])[0], float(proba[idx])
