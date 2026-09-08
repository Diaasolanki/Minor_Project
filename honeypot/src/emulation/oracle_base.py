"""Deterministic shell oracle.

Two jobs:
  1. Generate ground-truth (state, command) -> (display_output, state_delta) pairs
     used as the supervised training set for the local response model.
  2. Act as the runtime fallback whenever the trained model returns something
     unusable, so the honeypot never stalls or breaks character.

It is a *simulator*, not an executor: no subprocess, no exec, no eval, ever.
"""
from __future__ import annotations

import posixpath
import random
import re
import shlex
import time
from typing import Any

from state.fakefs import DISTRO, KERNEL, SessionState

PS_HEADER = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
PS_ROWS = [
    "root           1  0.0  0.1 168352 11908 ?        Ss   Mar14   0:22 /sbin/init",
    "root         412  0.0  0.0  63120  6284 ?        Ss   Mar14   0:01 /lib/systemd/systemd-journald",
    "root         688  0.0  0.0  15432  6912 ?        Ss   Mar14   0:03 /usr/sbin/sshd -D",
    "www-data     901  0.1  0.4 214776 34120 ?        S    Mar14   1:42 nginx: worker process",
    "mysql       1044  0.7  4.2 1842112 341880 ?      Ssl  Mar14  18:07 /usr/sbin/mysqld",
    "root        1190  0.0  0.0  17984  3204 ?        Ss   Mar14   0:00 /usr/sbin/cron -f",
    "deploy      2214  0.0  0.1  19204  9812 ?        Ss   06:11   0:00 /lib/systemd/systemd --user",
]
NETSTAT = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      688/sshd: /usr/sbin
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      899/nginx: master p
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      1044/mysqld
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      773/redis-server
tcp6       0      0 :::22                   :::*                    LISTEN      688/sshd: /usr/sbin"""
IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.12.41  netmask 255.255.255.0  broadcast 10.0.12.255
        ether 02:42:0a:00:0c:29  txqueuelen 1000  (Ethernet)
        RX packets 8842193  bytes 4127884412 (4.1 GB)
        TX packets 6120884  bytes 1884120334 (1.8 GB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 41288  bytes 3812004 (3.8 MB)"""
DF = """Filesystem      Size  Used Avail Use% Mounted on
udev            7.8G     0  7.8G   0% /dev
tmpfs           1.6G  1.7M  1.6G   1% /run
/dev/sda1        79G   37G   38G  50% /
tmpfs           7.9G     0  7.9G   0% /dev/shm
/dev/sda15      105M  6.1M   99M   6% /boot/efi"""
FREE = """               total        used        free      shared  buff/cache   available
Mem:            15Gi       5.8Gi       1.2Gi       412Mi       8.4Gi       9.1Gi
Swap:          4.0Gi        12Mi       4.0Gi"""
SUDO_L = r"""Matching Defaults entries for {user} on {host}:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User {user} may run the following commands on {host}:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl restart nginx
    (ALL : ALL) NOPASSWD: /usr/bin/rsync"""

BINARIES = {
    "ls", "cd", "pwd", "cat", "echo", "whoami", "id", "uname", "ps", "netstat", "ss",
    "ifconfig", "ip", "df", "free", "uptime", "date", "hostname", "history", "env",
    "export", "mkdir", "rmdir", "touch", "rm", "cp", "mv", "chmod", "chown", "wget",
    "curl", "nc", "ncat", "python3", "python", "perl", "bash", "sh", "sudo", "su",
    "apt", "apt-get", "yum", "systemctl", "service", "crontab", "useradd", "adduser",
    "passwd", "groups", "last", "w", "who", "find", "grep", "head", "tail", "wc",
    "sort", "uniq", "tar", "gzip", "unzip", "scp", "ssh", "ssh-keygen", "mysql",
    "docker", "kill", "killall", "top", "htop", "lscpu", "lsblk", "mount", "dmesg",
    "iptables", "ufw", "nmap", "git", "make", "gcc", "wc", "awk", "sed", "xxd", "base64",
    "chattr", "lsattr", "nohup", "screen", "tmux", "exit", "logout", "clear",
}


def _fmt_ls_long(state: SessionState, node: dict, path: str) -> str:
    entries = node["children"]
    lines = [f"total {max(4, len(entries) * 4)}"]
    lines.append(f"{node['mode']} {len([e for e in entries.values() if e['type']=='dir'])+2:>3} "
                 f"{node['owner']:<8} {node['group']:<8} {4096:>7} {node['mtime']} .")
    lines.append(f"drwxr-xr-x  22 root     root        4096 Mar 14 09:21 ..")
    for name, child in sorted(entries.items()):
        nlink = len(child["children"]) + 2 if child["type"] == "dir" else 1
        lines.append(f"{child['mode']} {nlink:>3} {child['owner']:<8} {child['group']:<8} "
                     f"{child['size']:>7} {child['mtime']} {name}")
    return "\n".join(lines)


def _fmt_ls_short(node: dict, show_hidden: bool = False) -> str:
    names = sorted(n for n in node["children"] if show_hidden or not n.startswith("."))
    if not names:
        return ""
    return "  ".join(names)
