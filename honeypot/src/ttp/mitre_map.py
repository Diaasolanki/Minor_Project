"""Command-pattern -> MITRE ATT&CK technique lookup.

Deliberately a plain ordered list of (regex, technique_id, technique_name, tactic)
tuples rather than a database — this is the "labeling schema" described in the
build guide (section 3.2 / 4.3), kept simple and auditable for a report.
"""
from __future__ import annotations

import re

# Ordered: first matching pattern wins. Broad "recon" patterns go last.
RULES: list[tuple[str, str, str, str]] = [
    (r"\bcat\s+.*(passwd|shadow)\b", "T1003", "OS Credential Dumping", "Credential Access"),
    (r"\bcat\s+.*\.(ssh)/.*", "T1552.004", "Private Keys", "Credential Access"),
    (r"\bmysql\b.*-p", "T1552.001", "Credentials In Files", "Credential Access"),
    (r"\bhistory\b|\.bash_history", "T1552.003", "Bash History", "Credential Access"),
    (r"\bfind\b.*-perm.*4000|-perm.*u=s", "T1548.001", "Setuid and Setgid", "Privilege Escalation"),
    (r"\bsudo\s+-l\b", "T1069.001", "Local Groups (permissions discovery)", "Discovery"),
    (r"\bsu\b|\bsudo\s+su\b|\bsudo\s+-i\b", "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    (r"\bcrontab\s+-e\b|/etc/cron", "T1053.003", "Cron", "Persistence"),
    (r"\b(useradd|adduser)\b", "T1136.001", "Local Account", "Persistence"),
    (r"\bssh-keygen\b|authorized_keys", "T1098.004", "SSH Authorized Keys", "Persistence"),
    (r"\bchattr\b", "T1222.002", "Linux File and Directory Permissions Modification", "Defense Evasion"),
    (r"\bhistory\s+-c\b|unset\s+HISTFILE|rm\s+.*\.bash_history", "T1070.003", "Clear Command History", "Defense Evasion"),
    (r"\b(wget|curl)\b.*\|\s*(sh|bash)", "T1105", "Ingress Tool Transfer (pipe-to-shell)", "Command and Control"),
    (r"\b(wget|curl)\b", "T1105", "Ingress Tool Transfer", "Command and Control"),
    (r"\bnc\b|\bncat\b|/dev/tcp/", "T1095", "Non-Application Layer Protocol", "Command and Control"),
    (r"\bscp\b|\brsync\b.*@", "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    (r"\btar\s+c|\bgzip\b|\bzip\b", "T1560", "Archive Collected Data", "Collection"),
    (r"\bbase64\b", "T1027", "Obfuscated Files or Information", "Defense Evasion"),
    (r"\bdocker\s+ps\b|\bdocker\s+images\b", "T1613", "Container and Resource Discovery", "Discovery"),
    (r"\biptables\b|\bufw\b", "T1562.004", "Disable or Modify System Firewall", "Defense Evasion"),
    (r"\bsystemctl\s+(stop|disable)\b|\bservice\s+\S+\s+stop\b", "T1489", "Service Stop", "Impact"),
    (r"\bkill\b|\bkillall\b", "T1489", "Service Stop", "Impact"),
    (r"\bnmap\b", "T1046", "Network Service Discovery", "Discovery"),
    (r"\bping\b", "T1018", "Remote System Discovery", "Discovery"),
    (r"\bnetstat\b|\bss\b\s", "T1049", "System Network Connections Discovery", "Discovery"),
    (r"\bps\b|\btop\b|\bhtop\b", "T1057", "Process Discovery", "Discovery"),
    (r"\bwhoami\b|\bid\b\s*$|\bgroups\b", "T1033", "System Owner/User Discovery", "Discovery"),
    (r"\buname\b|\blsb_release\b|/etc/os-release", "T1082", "System Information Discovery", "Discovery"),
    (r"\bifconfig\b|\bip\s+a", "T1016", "System Network Configuration Discovery", "Discovery"),
    (r"\bfind\b|\blocate\b", "T1083", "File and Directory Discovery", "Discovery"),
    (r"\bcrypto|xmrig|minerd|stratum\+tcp", "T1496", "Resource Hijacking", "Impact"),
    (r"^(ls|cd|pwd|cat|echo)\b", "T1082", "System Information Discovery", "Discovery"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), tid, name, tactic) for p, tid, name, tactic in RULES]


def map_command(command: str) -> tuple[str, str, str] | None:
    """Return (technique_id, technique_name, tactic) for a raw shell command, or None."""
    for pattern, tid, name, tactic in _COMPILED:
        if pattern.search(command):
            return tid, name, tactic
    return None


def map_session(commands: list[str]) -> list[dict]:
    out = []
    for c in commands:
        hit = map_command(c)
        if hit:
            tid, name, tactic = hit
            out.append({"command": c, "technique_id": tid, "technique_name": name, "tactic": tactic})
    return out
