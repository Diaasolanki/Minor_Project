"""Attacker-facing command handlers: download, persistence, priv-esc, recon, services.

These are the commands that actually matter for TTP capture, so their simulated
output is written to be plausible enough to survive a skilled attacker's eye.
"""
from __future__ import annotations

import posixpath
import random
import re

from emulation.oracle_base import SUDO_L

APT_UPDATE = """Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]
Get:3 http://security.ubuntu.com/ubuntu jammy-security InRelease [129 kB]
Fetched 257 kB in 1s (241 kB/s)
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
23 packages can be upgraded. Run 'apt list --upgradable' to see them."""

MYSQL_BANNER = """Welcome to the MySQL monitor.  Commands end with ; or \\g.
Your MySQL connection id is 8841
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement."""

DOCKER_PS = """CONTAINER ID   IMAGE                 COMMAND                  CREATED        STATUS        PORTS                    NAMES
9f2c41b8ad03   nginx:1.24-alpine     "/docker-entrypoint.."   3 weeks ago    Up 3 weeks    0.0.0.0:80->80/tcp       app-proxy
41ac8e2b7d19   mysql:8.0             "docker-entrypoint.s.."  3 weeks ago    Up 3 weeks    0.0.0.0:3306->3306/tcp   app-db
c7d3f019ba52   redis:7-alpine        "docker-entrypoint.s.."  3 weeks ago    Up 3 weeks    127.0.0.1:6379->6379/tcp app-cache"""

LAST_OUT = """deploy   pts/0        10.0.12.7        Thu Apr 18 03:11   still logged in
deploy   pts/0        10.0.12.7        Wed Apr 17 19:44 - 21:02  (01:18)
root     pts/1        10.0.12.9        Tue Apr 16 08:20 - 09:41  (01:21)
reboot   system boot  5.15.0-105-gener Mon Mar 14 09:21   still running

wtmp begins Mon Mar 14 09:21:02 2024"""


class AttackCommands:
    """Download, persistence, escalation and service commands."""

    # ---------------------------------------------------------------- download
    def _cmd_wget(self, state, argv, cmd):
        urls = [a for a in argv[1:] if a.startswith("http") or a.startswith("ftp")]
        if not urls:
            return self._err("wget: missing URL\nUsage: wget [OPTION]... [URL]...")
        url = urls[0]
        name = posixpath.basename(url.split("?")[0]) or "index.html"
        if "-O" in argv:
            try:
                name = argv[argv.index("-O") + 1]
            except IndexError:
                pass
        size = self.rng.randint(512, 260000)
        host = re.sub(r"^\w+://", "", url).split("/")[0]
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", host) is not None
        ip = host.split(":")[0] if is_ip else "%d.%d.%d.%d" % tuple(
            self.rng.randint(1, 254) for _ in range(4))
        ts = "2024-04-18 06:14:%02d" % self.rng.randint(10, 59)
        lines = ["--%s--  %s" % (ts, url)]
        if not is_ip:
            lines.append("Resolving %s (%s)... %s" % (host, host, ip))
        lines += [
            "Connecting to %s (%s)|%s|:80... connected." % (host, host, ip),
            "HTTP request sent, awaiting response... 200 OK",
            "Length: %d (%dK) [application/octet-stream]" % (size, max(1, size // 1024)),
            "Saving to: '%s'" % name,
            "",
            "%-12s100%%[===================>]  %.2fK  --.-KB/s    in 0.04s" % (name, size / 1024),
            "",
            "%s (%.1f MB/s) - '%s' saved [%d/%d]" % (ts, self.rng.uniform(1.2, 9.8),
                                                     name, size, size),
        ]
        return self._ok("\n".join(lines),
                        [{"op": "create_file", "path": state.resolve(name),
                          "content": "#!/bin/sh\n# downloaded payload\n",
                          "mode": "-rw-r--r--", "size": size}])

    def _cmd_curl(self, state, argv, cmd):
        urls = [a for a in argv[1:] if a.startswith("http")]
        if not urls:
            return self._err("curl: try 'curl --help' for more information")
        url = urls[0]
        if "-o" in argv or "-O" in argv:
            name = posixpath.basename(url.split("?")[0]) or "index.html"
            if "-o" in argv:
                try:
                    name = argv[argv.index("-o") + 1]
                except IndexError:
                    pass
            size = self.rng.randint(512, 260000)
            out = ("  %% Total    %% Received %% Xferd  Average Speed   Time    Time     "
                   "Time  Current\n                                 Dload  Upload   Total   "
                   "Spent    Left  Speed\n100 %5d  100 %5d    0     0   %4dk      0 "
                   "--:--:-- --:--:-- --:--:--  %4dk"
                   % (size, size, self.rng.randint(80, 900), self.rng.randint(80, 900)))
            return self._ok(out, [{"op": "create_file", "path": state.resolve(name),
                                   "content": "#!/bin/sh\n", "size": size}])
        if "ifconfig.me" in url or "ipinfo" in url or "icanhazip" in url:
            return self._ok("203.0.113.%d" % self.rng.randint(2, 250))
        return self._ok("<!DOCTYPE html>\n<html>\n<head><title>200 OK</title></head>\n"
                        "<body>\n<h1>It works!</h1>\n</body>\n</html>")

    def _cmd_nc(self, state, argv, cmd):
        if "-l" in argv:
            return self._ok("")
        return self._err("nc: connect to %s port %s (tcp) failed: Connection refused"
                         % (argv[-2] if len(argv) > 2 else "host", argv[-1]))

    _cmd_ncat = _cmd_nc

    def _cmd_scp(self, state, argv, cmd):
        return self._err("ssh: connect to host %s port 22: Connection timed out\n"
                         "lost connection" % (argv[-1].split(":")[0] if ":" in argv[-1] else argv[-1]))

    def _cmd_ssh(self, state, argv, cmd):
        target = argv[-1]
        return self._err("ssh: connect to host %s port 22: Connection timed out"
                         % (target.split("@")[-1]))

    def _cmd_nmap(self, state, argv, cmd):
        target = argv[-1]
        return self._err("bash: nmap: command not found", 127)

    def _cmd_ping(self, state, argv, cmd):
        target = argv[-1]
        return self._ok("PING %s (8.8.8.8) 56(84) bytes of data.\n"
                        "^C\n--- %s ping statistics ---\n"
                        "4 packets transmitted, 0 received, 100%% packet loss, time 3072ms"
                        % (target, target))

    # ------------------------------------------------------------- persistence
    def _cmd_crontab(self, state, argv, cmd):
        if "-l" in argv:
            node = state.node("/var/spool/cron/crontabs/%s" % state.user)
            if node is None:
                return self._err("no crontab for %s" % state.user)
            return self._ok(node["content"].rstrip("\n"))
        if "-e" in argv:
            return self._ok("no crontab for %s - using an empty one\ncrontab: installing new crontab"
                            % state.user,
                            [{"op": "create_file",
                              "path": "/var/spool/cron/crontabs/%s" % state.user,
                              "content": "# edited\n"}])
        if "-r" in argv:
            return self._ok("", [{"op": "delete_path",
                                  "path": "/var/spool/cron/crontabs/%s" % state.user}])
        return self._ok("")

    def _cmd_useradd(self, state, argv, cmd):
        names = [a for a in argv[1:] if not a.startswith("-")]
        if not names:
            return self._err("useradd: missing operand")
        if state.user != "root":
            return self._err("useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; "
                             "try again later.")
        user = names[-1]
        if user in state.users:
            return self._err("useradd: user '%s' already exists" % user)
        return self._ok("", [{"op": "add_user", "user": user}])

    _cmd_adduser = _cmd_useradd

    def _cmd_usermod(self, state, argv, cmd):
        if state.user != "root":
            return self._err("usermod: Permission denied.")
        return self._ok("")

    def _cmd_passwd(self, state, argv, cmd):
        target = argv[-1] if len(argv) > 1 else state.user
        if state.user != "root" and target != state.user:
            return self._err("passwd: You may not view or modify password information for %s."
                             % target)
        return self._ok("New password: \nRetype new password: \n"
                        "passwd: password updated successfully")

    def _cmd_ssh_keygen(self, state, argv, cmd):
        return self._ok("Generating public/private rsa key pair.\n"
                        "Your identification has been saved in %s/.ssh/id_rsa\n"
                        "Your public key has been saved in %s/.ssh/id_rsa.pub\n"
                        "The key fingerprint is:\n"
                        "SHA256:8Kj2mQ9pL4nR7xW1zA5bC3dE6fG8hI0jK2lM4nO6pQ8 %s@%s"
                        % (state.env.get("HOME", "/root"), state.env.get("HOME", "/root"),
                           state.user, state.hostname),
                        [{"op": "create_file",
                          "path": state.env.get("HOME", "/root") + "/.ssh/id_rsa",
                          "content": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
                          "mode": "-rw-------"}])

    def _cmd_chattr(self, state, argv, cmd):
        if state.user != "root":
            return self._err("chattr: Operation not permitted while setting flags on %s" % argv[-1])
        return self._ok("")

    def _cmd_history_clear(self, state, argv, cmd):
        return self._ok("")

    # -------------------------------------------------------------- escalation
    def _cmd_su(self, state, argv, cmd):
        target = argv[-1] if len(argv) > 1 and not argv[-1].startswith("-") else "root"
        if state.user == "root":
            return self._ok("", [{"op": "set_user", "user": target}])
        return self._err("Password: \nsu: Authentication failure")

    def _cmd_sudo(self, state, argv, cmd):
        return self._handle_sudo(state, argv)

    # ---------------------------------------------------------------- services
    def _cmd_systemctl(self, state, argv, cmd):
        if len(argv) < 2:
            return self._ok("")
        action = argv[1]
        unit = argv[2] if len(argv) > 2 else ""
        if action == "status":
            return self._ok(
                "● %s - %s Service\n"
                "     Loaded: loaded (/lib/systemd/system/%s.service; enabled; vendor preset: enabled)\n"
                "     Active: active (running) since Thu 2024-03-14 09:21:44 UTC; 5 weeks 0 days ago\n"
                "   Main PID: 899 (%s)\n"
                "      Tasks: 5 (limit: 18985)\n"
                "     Memory: 34.2M\n"
                "        CPU: 1min 42.118s" % (unit, unit.capitalize(), unit, unit))
        if action in ("stop", "start", "restart", "enable", "disable", "daemon-reload"):
            if state.user != "root":
                return self._err("Failed to %s %s.service: Interactive authentication required.\n"
                                 "See system logs and 'systemctl status %s.service' for details."
                                 % (action, unit, unit))
            return self._ok("")
        if action == "list-units":
            return self._ok("UNIT                    LOAD   ACTIVE SUB     DESCRIPTION\n"
                            "cron.service            loaded active running Regular background program\n"
                            "mysql.service           loaded active running MySQL Community Server\n"
                            "nginx.service           loaded active running A high performance web server\n"
                            "ssh.service             loaded active running OpenBSD Secure Shell server")
        return self._ok("")

    def _cmd_service(self, state, argv, cmd):
        return self._cmd_systemctl(state, ["systemctl", argv[2] if len(argv) > 2 else "status",
                                           argv[1] if len(argv) > 1 else ""], cmd)

    def _cmd_apt(self, state, argv, cmd):
        if len(argv) < 2:
            return self._err("apt 2.4.11 (amd64)\nUsage: apt [options] command")
        action = argv[1]
        if action == "update":
            if state.user != "root":
                return self._err("Reading package lists... Done\n"
                                 "E: Could not open lock file /var/lib/apt/lists/lock - "
                                 "open (13: Permission denied)")
            return self._ok(APT_UPDATE)
        if action in ("install", "remove", "purge"):
            pkgs = [a for a in argv[2:] if not a.startswith("-")]
            if state.user != "root":
                return self._err("E: Could not open lock file /var/lib/dpkg/lock-frontend - "
                                 "open (13: Permission denied)\n"
                                 "E: Unable to acquire the dpkg frontend lock")
            return self._ok("Reading package lists... Done\nBuilding dependency tree... Done\n"
                            "Reading state information... Done\n"
                            "The following NEW packages will be installed:\n  %s\n"
                            "0 upgraded, %d newly installed, 0 to remove and 23 not upgraded.\n"
                            "Need to get 412 kB of archives.\n"
                            "After this operation, 1,284 kB of additional disk space will be used.\n"
                            "Setting up %s ...\nProcessing triggers for man-db (2.10.2-1) ..."
                            % (" ".join(pkgs), len(pkgs), pkgs[0] if pkgs else ""))
        return self._ok("")

    _cmd_apt_get = _cmd_apt

    def _cmd_yum(self, state, argv, cmd):
        return self._err("bash: yum: command not found", 127)

    def _cmd_mysql(self, state, argv, cmd):
        if "-p" in cmd or "--password" in cmd:
            if "-e" in argv:
                return self._ok("ERROR 1045 (28000): Access denied for user '%s'@'localhost' "
                                "(using password: YES)" % (
                                    argv[argv.index("-u") + 1] if "-u" in argv else "root"))
            return self._ok(MYSQL_BANNER + "\n\nmysql> ")
        return self._err("ERROR 1045 (28000): Access denied for user '%s'@'localhost' "
                         "(using password: NO)"
                         % (argv[argv.index("-u") + 1] if "-u" in argv else state.user))

    def _cmd_docker(self, state, argv, cmd):
        if len(argv) > 1 and argv[1] == "ps":
            if state.user != "root":
                return self._err("permission denied while trying to connect to the Docker daemon "
                                 "socket at unix:///var/run/docker.sock")
            return self._ok(DOCKER_PS)
        if len(argv) > 1 and argv[1] == "images":
            return self._ok("REPOSITORY   TAG          IMAGE ID       CREATED        SIZE\n"
                            "nginx        1.24-alpine  a8758716bb6a   3 months ago   42.6MB\n"
                            "mysql        8.0          3b6fd8b9e1a3   3 months ago   564MB\n"
                            "redis        7-alpine     0c3e1a4f9d21   4 months ago   30.2MB")
        return self._ok("")

    def _cmd_iptables(self, state, argv, cmd):
        if state.user != "root":
            return self._err("iptables v1.8.7 (nf_tables): Could not fetch rule set generation id: "
                             "Permission denied (you must be root)")
        return self._ok("Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n"
                        "\nChain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n"
                        "\nChain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination")

    def _cmd_ufw(self, state, argv, cmd):
        if state.user != "root":
            return self._err("ERROR: You need to be root to run this script")
        return self._ok("Status: active\n\nTo                         Action      From\n"
                        "--                         ------      ----\n"
                        "22/tcp                     ALLOW       Anywhere\n"
                        "80/tcp                     ALLOW       Anywhere\n"
                        "3306/tcp                   ALLOW       10.0.12.0/24")

    def _cmd_last(self, state, argv, cmd):
        return self._ok(LAST_OUT)

    def _cmd_w(self, state, argv, cmd):
        return self._ok(" 06:14:22 up 35 days,  4:02,  1 user,  load average: 0.14, 0.09, 0.06\n"
                        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                        "deploy   pts/0    10.0.12.7        03:11    2.00s  0.08s  0.00s w")

    def _cmd_who(self, state, argv, cmd):
        return self._ok("deploy   pts/0        2024-04-18 03:11 (10.0.12.7)")

    def _cmd_dmesg(self, state, argv, cmd):
        if state.user != "root":
            return self._err("dmesg: read kernel buffer failed: Operation not permitted")
        return self._ok("[    0.000000] Linux version 5.15.0-105-generic (buildd@lcy02-amd64-089)\n"
                        "[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-105-generic\n"
                        "[    2.114882] EXT4-fs (sda1): mounted filesystem with ordered data mode")

    def _cmd_mount(self, state, argv, cmd):
        return self._ok("/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"
                        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
                        "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=1602816k)")

    def _cmd_kill(self, state, argv, cmd):
        pid = argv[-1]
        if not pid.isdigit():
            return self._err("kill: %s: arguments must be process or job IDs" % pid)
        if state.user != "root" and int(pid) < 1000:
            return self._err("kill: (%s): Operation not permitted" % pid)
        return self._ok("")

    _cmd_killall = _cmd_kill

    # ------------------------------------------------------------- interpreters
    def _cmd_python3(self, state, argv, cmd):
        if "-c" in argv:
            return self._ok("")
        if len(argv) > 1 and not argv[1].startswith("-"):
            if state.node(argv[1]) is None:
                return self._err("python3: can't open file '%s': [Errno 2] "
                                 "No such file or directory" % state.resolve(argv[1]))
            return self._ok("")
        return self._ok("Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\n"
                        'Type "help", "copyright", "credits" or "license" for more information.\n>>> ')

    _cmd_python = _cmd_python3

    def _cmd_perl(self, state, argv, cmd):
        return self._ok("")

    def _cmd_bash(self, state, argv, cmd):
        if len(argv) > 1 and not argv[1].startswith("-"):
            if state.node(argv[1]) is None:
                return self._err("bash: %s: No such file or directory" % argv[1], 127)
        return self._ok("")

    _cmd_sh = _cmd_bash

    def _cmd_base64(self, state, argv, cmd):
        import base64 as _b
        targets = [a for a in argv[1:] if not a.startswith("-")]
        if not targets:
            return self._ok("")
        node = state.node(targets[0])
        if node is None:
            return self._err("base64: %s: No such file or directory" % targets[0])
        if "-d" in argv:
            try:
                return self._ok(_b.b64decode(node["content"]).decode("utf8", "replace"))
            except Exception:
                return self._err("base64: invalid input")
        return self._ok(_b.b64encode(node["content"].encode()).decode())

    def _cmd_tar(self, state, argv, cmd):
        files = [a for a in argv[1:] if not a.startswith("-")]
        flags = argv[1] if len(argv) > 1 and argv[1].startswith("-") else ""
        if "c" in flags:
            out = files[0] if files else "archive.tar"
            return self._ok("", [{"op": "create_file", "path": state.resolve(out),
                                  "content": "", "size": self.rng.randint(4096, 900000)}])
        if files and state.node(files[0]) is None:
            return self._err("tar (child): %s: Cannot open: No such file or directory\n"
                             "tar: Error is not recoverable: exiting now" % files[0])
        return self._ok("")

    def _cmd_gzip(self, state, argv, cmd):
        return self._ok("")

    def _cmd_unzip(self, state, argv, cmd):
        f = argv[-1]
        if state.node(f) is None:
            return self._err("unzip:  cannot find or open %s, %s.zip or %s.ZIP." % (f, f, f))
        return self._ok("Archive:  %s\n  inflating: payload.sh" % f)

    def _cmd_git(self, state, argv, cmd):
        if len(argv) > 1 and argv[1] == "clone":
            repo = argv[-1]
            name = posixpath.basename(repo).replace(".git", "")
            return self._ok("Cloning into '%s'...\nremote: Enumerating objects: 128, done.\n"
                            "remote: Total 128 (delta 41), reused 112 (delta 28)\n"
                            "Receiving objects: 100%% (128/128), 44.21 KiB | 2.21 MiB/s, done.\n"
                            "Resolving deltas: 100%% (41/41), done." % name,
                            [{"op": "create_dir", "path": state.resolve(name)}])
        return self._ok("")

    def _cmd_exit(self, state, argv, cmd):
        return {"display_output": "logout", "state_delta": [], "exit_code": 0, "close": True}

    _cmd_logout = _cmd_exit
