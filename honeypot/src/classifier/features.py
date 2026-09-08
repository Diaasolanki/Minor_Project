"""Session -> feature vector for the skill/intent classifier (build guide 4.2, Approach A)."""
from __future__ import annotations

import re
import statistics

OBFUSCATION_PAT = re.compile(r"base64|\\x[0-9a-f]{2}|eval\(|\$\(.*\)|`.*`", re.IGNORECASE)
DOWNLOAD_PAT = re.compile(r"\b(wget|curl|scp|nc|ncat|tftp)\b", re.IGNORECASE)
PRIVESC_PAT = re.compile(r"\bsudo\b|\bsu\b|-perm\s*-4000|passwd\b", re.IGNORECASE)
PERSISTENCE_PAT = re.compile(r"crontab|useradd|adduser|authorized_keys|systemctl\s+enable",
                             re.IGNORECASE)
ANTIFORENSIC_PAT = re.compile(r"history\s+-c|unset\s+HISTFILE|rm\s+.*\.bash_history|"
                              r"iptables\s+-F|dmesg\s+-C", re.IGNORECASE)
RECON_PAT = re.compile(r"\buname\b|\bwhoami\b|\bid\b|\bps\b|\bnetstat\b|\bss\b|\bifconfig\b",
                       re.IGNORECASE)

FEATURE_NAMES = [
    "command_count", "unique_command_ratio", "avg_command_length",
    "obfuscation_count", "download_count", "privesc_count", "persistence_count",
    "antiforensic_count", "recon_ratio", "distinct_mitre_techniques",
    "distinct_mitre_tactics", "pipe_chain_count", "error_ratio",
    "root_action_count", "session_command_diversity",
]


def extract_features(trace: list[dict]) -> list[float]:
    cmds = [t["cmd"] for t in trace]
    n = len(cmds) or 1

    unique_ratio = len(set(cmds)) / n
    avg_len = statistics.mean(len(c) for c in cmds) if cmds else 0.0
    obf = sum(1 for c in cmds if OBFUSCATION_PAT.search(c))
    dl = sum(1 for c in cmds if DOWNLOAD_PAT.search(c))
    priv = sum(1 for c in cmds if PRIVESC_PAT.search(c))
    persist = sum(1 for c in cmds if PERSISTENCE_PAT.search(c))
    antifor = sum(1 for c in cmds if ANTIFORENSIC_PAT.search(c))
    recon = sum(1 for c in cmds if RECON_PAT.search(c)) / n
    techniques = {t["mitre_technique"] for t in trace if t.get("mitre_technique")}
    tactics = {t["mitre_tactic"] for t in trace if t.get("mitre_tactic")}
    pipes = sum(1 for c in cmds if "|" in c)
    errors = sum(1 for t in trace if t.get("exit_code", 0) != 0) / n
    diversity = len(set(c.split()[0] for c in cmds if c.split())) / n

    return [
        float(len(cmds)), unique_ratio, avg_len, float(obf), float(dl), float(priv),
        float(persist), float(antifor), recon, float(len(techniques)), float(len(tactics)),
        float(pipes), errors, 0.0, diversity,
    ]


def extract_batch(records: list[dict]) -> tuple[list[list[float]], list[str], list[str]]:
    X, skills, intents = [], [], []
    for r in records:
        X.append(extract_features(r["trace"]))
        skills.append(r["skill"])
        intents.append(r["intent"])
    return X, skills, intents
