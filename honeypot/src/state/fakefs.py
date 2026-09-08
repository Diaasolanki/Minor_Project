"""Fake filesystem + session state for the honeypot.

Nothing here ever touches the real host filesystem. All paths are virtual and
live entirely in a dict, so an attacker can `rm -rf /` all they like.
"""
from __future__ import annotations

import copy
import posixpath
import random
import time
from dataclasses import dataclass, field
from typing import Any


HOSTNAME_POOL = ["web-prod-03", "app-srv-01", "db-node-02", "vm-ubuntu-07", "srv-backup-1"]
DISTRO = "Ubuntu 22.04.4 LTS"
KERNEL = "5.15.0-105-generic"


def _file(content: str = "", mode: str = "-rw-r--r--", owner: str = "root",
          group: str = "root", size: int | None = None, mtime: str = "Mar 14 09:21") -> dict:
    return {
        "type": "file",
        "content": content,
        "mode": mode,
        "owner": owner,
        "group": group,
        "size": len(content) if size is None else size,
        "mtime": mtime,
    }


def _dir(mode: str = "drwxr-xr-x", owner: str = "root", group: str = "root",
         mtime: str = "Mar 14 09:21") -> dict:
    return {"type": "dir", "children": {}, "mode": mode, "owner": owner,
            "group": group, "size": 4096, "mtime": mtime}


PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
deploy:x:1000:1000:Deploy User,,,:/home/deploy:/bin/bash
svc_backup:x:1001:1001:Backup Service,,,:/home/svc_backup:/bin/bash
"""

SHADOW = """root:$6$rounds=656000$8HqTn2Yl$K1nQ.dJ4pFvY/xhLm2wR0aB9cCzZ7eN3sT6uV8wX1yA2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z:19812:0:99999:7:::
deploy:$6$rounds=656000$Lm4Rt9Xz$P2oQ.aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6cD7eF8gH9iJ0kL1mN:19790:0:99999:7:::
svc_backup:$6$rounds=656000$Qw8Er2Ty$Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8cB7aZ6yX5wV4uT3sR2qP1oN0mL:19801:0:99999:7:::
"""

MOTD = """Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {date}

  System load:  0.14              Processes:             142
  Usage of /:   47.2% of 78.21GB  Users logged in:       0
  Memory usage: 38%               IPv4 address for eth0: 10.0.12.41
  Swap usage:   0%

23 updates can be applied immediately.
12 of these updates are standard security updates.

Last login: {last} from 10.0.12.7
"""


def default_fs() -> dict:
    root = _dir()
    c = root["children"]

    c["etc"] = _dir()
    etc = c["etc"]["children"]
    etc["passwd"] = _file(PASSWD)
    etc["shadow"] = _file(SHADOW, mode="-rw-r-----", group="shadow")
    etc["hostname"] = _file("web-prod-03\n")
    etc["hosts"] = _file("127.0.0.1 localhost\n127.0.1.1 web-prod-03\n")
    etc["os-release"] = _file(
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n')
    etc["crontab"] = _file(
        "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n")
    etc["ssh"] = _dir()
    etc["ssh"]["children"]["sshd_config"] = _file(
        "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n")
    etc["mysql"] = _dir()
    etc["mysql"]["children"]["my.cnf"] = _file(
        "[mysqld]\nbind-address = 0.0.0.0\ndatadir = /var/lib/mysql\n")

    c["root"] = _dir(mode="drwx------", mtime="Apr 02 14:03")
    rootd = c["root"]["children"]
    rootd[".bash_history"] = _file(
        "apt update\nsystemctl restart nginx\nmysql -u root -p\ndocker ps\nexit\n",
        mode="-rw-------")
    rootd[".ssh"] = _dir(mode="drwx------")
    rootd[".ssh"]["children"]["authorized_keys"] = _file(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vT2mQ8kL9nR4xW1pZ3dF6hJ0sA5bN2cV8yU4tE7iO deploy@build-01\n",
        mode="-rw-------")

    c["home"] = _dir()
    home = c["home"]["children"]
    for user, uid in (("deploy", "deploy"), ("svc_backup", "svc_backup")):
        home[user] = _dir(owner=uid, group=uid, mtime="Apr 11 08:55")
        h = home[user]["children"]
        h[".bashrc"] = _file("# ~/.bashrc\nexport PATH=$PATH:$HOME/bin\n", owner=uid, group=uid)
        h[".profile"] = _file("# ~/.profile\n", owner=uid, group=uid)
    home["deploy"]["children"][".bash_history"] = _file(
        "cd /var/www/app\ngit pull\n./deploy.sh staging\nmysql -u appuser -p appdb\n",
        mode="-rw-------", owner="deploy", group="deploy")
    home["deploy"]["children"]["deploy.sh"] = _file(
        "#!/bin/bash\n# deploy helper\nDB_HOST=10.0.12.55\nDB_USER=appuser\n"
        "DB_PASS=Str0ng!AppPass2023\nrsync -az ./build/ /var/www/app/\n",
        mode="-rwxr-xr-x", owner="deploy", group="deploy")

    c["var"] = _dir()
    var = c["var"]["children"]
    var["log"] = _dir()
    var["log"]["children"]["auth.log"] = _file(
        "Apr 18 03:11:02 web-prod-03 sshd[2214]: Accepted password for deploy from 10.0.12.7 port 51422 ssh2\n",
        mode="-rw-r-----", group="adm", size=184320)
    var["log"]["children"]["syslog"] = _file("", mode="-rw-r-----", group="adm", size=942081)
    var["www"] = _dir(owner="www-data", group="www-data")
    var["www"]["children"]["app"] = _dir(owner="www-data", group="www-data")
    app = var["www"]["children"]["app"]["children"]
    app["index.php"] = _file("<?php require_once 'config.php'; ?>\n", owner="www-data", group="www-data")
    app["config.php"] = _file(
        "<?php\n$DB_HOST='10.0.12.55';\n$DB_USER='appuser';\n"
        "$DB_PASS='Str0ng!AppPass2023';\n$DB_NAME='appdb';\n",
        owner="www-data", group="www-data")
    var["lib"] = _dir()
    var["lib"]["children"]["mysql"] = _dir(owner="mysql", group="mysql", mode="drwx------")

    c["tmp"] = _dir(mode="drwxrwxrwt", mtime="Apr 18 06:02")
    c["opt"] = _dir()
    c["usr"] = _dir()
    c["usr"]["children"]["bin"] = _dir()
    c["usr"]["children"]["local"] = _dir()
    c["usr"]["children"]["local"]["children"]["bin"] = _dir()
    c["bin"] = _dir()
    c["sbin"] = _dir()
    c["boot"] = _dir()
    c["dev"] = _dir()
    c["proc"] = _dir()
    c["sys"] = _dir()
    c["srv"] = _dir()
    c["mnt"] = _dir()
    c["media"] = _dir()
    c["run"] = _dir()
    c["lib"] = _dir()
    return root


@dataclass
class SessionState:
    """Everything that must stay consistent for the length of one attacker session."""

    session_id: str
    hostname: str = "web-prod-03"
    user: str = "root"
    cwd: str = "/root"
    fs: dict = field(default_factory=default_fs)
    users: list[str] = field(default_factory=lambda: ["root", "deploy", "svc_backup", "www-data"])
    env: dict[str, str] = field(default_factory=lambda: {
        "HOME": "/root", "USER": "root", "SHELL": "/bin/bash",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "xterm-256color", "LANG": "en_US.UTF-8",
    })
    history: list[dict[str, str]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    src_ip: str = "0.0.0.0"

    # ---------- path helpers ----------
    def resolve(self, path: str) -> str:
        if not path:
            return self.cwd
        path = path.replace("~", self.env.get("HOME", "/root"))
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        return posixpath.normpath(path)

    def node(self, path: str) -> dict | None:
        path = self.resolve(path)
        node = self.fs
        if path == "/":
            return node
        for part in path.strip("/").split("/"):
            if node.get("type") != "dir":
                return None
            node = node["children"].get(part)
            if node is None:
                return None
        return node

    def parent_of(self, path: str) -> tuple[dict | None, str]:
        path = self.resolve(path)
        parent_path, name = posixpath.split(path)
        return self.node(parent_path or "/"), name

    # ---------- mutations ----------
    def apply_delta(self, delta: list[dict[str, Any]]) -> None:
        """Apply the structured state mutations produced by the response engine."""
        for op in delta or []:
            kind = op.get("op")
            try:
                if kind == "create_file":
                    self._create_file(op["path"], op.get("content", ""),
                                      op.get("mode", "-rw-r--r--"), op.get("size"))
                elif kind == "create_dir":
                    self._create_dir(op["path"])
                elif kind == "delete_path":
                    self._delete(op["path"])
                elif kind == "append_file":
                    n = self.node(op["path"])
                    if n and n["type"] == "file":
                        n["content"] += op.get("content", "")
                        n["size"] = len(n["content"])
                    else:
                        self._create_file(op["path"], op.get("content", ""))
                elif kind == "chmod":
                    n = self.node(op["path"])
                    if n:
                        n["mode"] = op.get("mode", n["mode"])
                elif kind == "add_user":
                    if op["user"] not in self.users:
                        self.users.append(op["user"])
                        self._create_dir(f"/home/{op['user']}")
                        n = self.node("/etc/passwd")
                        if n:
                            uid = 1002 + len(self.users)
                            n["content"] += (f"{op['user']}:x:{uid}:{uid}::"
                                             f"/home/{op['user']}:/bin/bash\n")
                            n["size"] = len(n["content"])
                elif kind == "set_cwd":
                    self.cwd = self.resolve(op["path"])
                elif kind == "set_env":
                    self.env[op["key"]] = op.get("value", "")
                elif kind == "set_user":
                    self.user = op["user"]
                    self.env["USER"] = op["user"]
            except (KeyError, TypeError):
                continue  # malformed delta from the model: ignore, never crash

    def _create_dir(self, path: str) -> None:
        path = self.resolve(path)
        node = self.fs
        for part in path.strip("/").split("/"):
            if not part:
                continue
            if node["type"] != "dir":
                return
            node = node["children"].setdefault(part, _dir(owner=self.user, group=self.user))

    def _create_file(self, path: str, content: str = "", mode: str = "-rw-r--r--",
                     size: int | None = None) -> None:
        parent, name = self.parent_of(path)
        if parent is None:
            self._create_dir(posixpath.dirname(self.resolve(path)))
            parent, name = self.parent_of(path)
        if parent and parent["type"] == "dir":
            parent["children"][name] = _file(content, mode=mode, owner=self.user,
                                             group=self.user, size=size, mtime="Apr 18 06:14")

    def _delete(self, path: str) -> None:
        parent, name = self.parent_of(path)
        if parent and parent["type"] == "dir":
            parent["children"].pop(name, None)

    # ---------- serialization for the model prompt ----------
    def fs_snapshot(self, path: str | None = None, depth: int = 1) -> dict:
        """Compact view of the filesystem near `path` — keeps prompt tokens bounded."""
        path = path or self.cwd
        node = self.node(path)
        if node is None or node["type"] != "dir":
            return {}

        def walk(n: dict, d: int) -> dict:
            out = {}
            for name, child in list(n["children"].items())[:40]:
                if child["type"] == "dir":
                    out[name + "/"] = walk(child, d - 1) if d > 0 else {}
                else:
                    out[name] = child["size"]
            return out

        return walk(node, depth - 1)

    def prompt_state(self, window: int = 6) -> dict:
        return {
            "hostname": self.hostname,
            "user": self.user,
            "cwd": self.cwd,
            "distro": DISTRO,
            "kernel": KERNEL,
            "users": self.users,
            "listing": self.fs_snapshot(),
            "recent": [
                {"cmd": h["cmd"], "out": h["out"][:200]} for h in self.history[-window:]
            ],
        }

    def shell_prompt(self) -> str:
        home = self.env.get("HOME", "/root")
        cwd = "~" + self.cwd[len(home):] if self.cwd.startswith(home) else self.cwd
        sym = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.hostname}:{cwd}{sym} "

    def banner(self) -> str:
        return MOTD.format(date=time.strftime("%a %b %d %H:%M:%S %Z %Y"),
                           last=time.strftime("%a %b %d %H:%M:%S %Y"))

    def snapshot(self) -> dict:
        return {"cwd": self.cwd, "user": self.user, "users": list(self.users),
                "env": dict(self.env), "fs": copy.deepcopy(self.fs)}


def new_session(session_id: str, src_ip: str = "0.0.0.0", seed: int | None = None) -> SessionState:
    rng = random.Random(seed)
    host = rng.choice(HOSTNAME_POOL)
    st = SessionState(session_id=session_id, hostname=host, src_ip=src_ip)
    n = st.node("/etc/hostname")
    if n:
        n["content"] = host + "\n"
    return st
