"""Command handlers for the deterministic Oracle (mixed into Oracle via subclassing)."""
from __future__ import annotations

import posixpath
import re
import time

from state.fakefs import KERNEL

from emulation.oracle_base import (DF, FREE, IFCONFIG, NETSTAT, PS_HEADER, PS_ROWS,
                                   SUDO_L, _fmt_ls_long, _fmt_ls_short)


class CoreCommands:
    """Filesystem, identity and host-info commands."""

    def _cmd_ls(self, state, argv, cmd):
        flags = [a for a in argv[1:] if a.startswith("-")]
        targets = [a for a in argv[1:] if not a.startswith("-")] or [state.cwd]
        long = any("l" in f for f in flags)
        hidden = any("a" in f for f in flags)
        outs = []
        for t in targets:
            node = state.node(t)
            if node is None:
                outs.append("ls: cannot access '%s': No such file or directory" % t)
                continue
            if node["type"] == "file":
                outs.append(t)
                continue
            outs.append(_fmt_ls_long(state, node, t) if long else _fmt_ls_short(node, hidden))
        return self._ok("\n".join(o for o in outs if o != ""))

    def _cmd_cd(self, state, argv, cmd):
        target = argv[1] if len(argv) > 1 else state.env.get("HOME", "/root")
        node = state.node(target)
        if node is None:
            return self._err("bash: cd: %s: No such file or directory" % target)
        if node["type"] != "dir":
            return self._err("bash: cd: %s: Not a directory" % target)
        return self._ok("", [{"op": "set_cwd", "path": state.resolve(target)}])

    def _cmd_pwd(self, state, argv, cmd):
        return self._ok(state.cwd)

    def _cmd_cat(self, state, argv, cmd):
        outs = []
        for t in [a for a in argv[1:] if not a.startswith("-")]:
            node = state.node(t)
            if node is None:
                outs.append("cat: %s: No such file or directory" % t)
            elif node["type"] == "dir":
                outs.append("cat: %s: Is a directory" % t)
            elif t.endswith("shadow") and state.user != "root":
                outs.append("cat: %s: Permission denied" % t)
            elif node["mode"].startswith("-rw-------") and state.user != "root":
                outs.append("cat: %s: Permission denied" % t)
            else:
                outs.append(node["content"].rstrip("\n"))
        return self._ok("\n".join(outs))

    def _expand(self, state, text):
        for k, v in state.env.items():
            text = text.replace("$" + k, v).replace("${%s}" % k, v)
        return text

    def _cmd_echo(self, state, argv, cmd):
        body = cmd[5:].strip()
        m = re.search(r"^(.*?)\s*(>>?)\s*(\S+)$", body)
        if m:
            text = self._expand(state, m.group(1).strip().strip("\"'"))
            op = "append_file" if m.group(2) == ">>" else "create_file"
            return self._ok("", [{"op": op, "path": state.resolve(m.group(3)),
                                  "content": text + "\n"}])
        return self._ok(self._expand(state, body.strip("\"'")))

    def _cmd_whoami(self, state, argv, cmd):
        return self._ok(state.user)

    def _cmd_id(self, state, argv, cmd):
        if state.user == "root":
            return self._ok("uid=0(root) gid=0(root) groups=0(root)")
        return self._ok("uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo)"
                        % (state.user, state.user, state.user))

    def _cmd_groups(self, state, argv, cmd):
        return self._ok("root" if state.user == "root" else "%s sudo" % state.user)

    def _cmd_uname(self, state, argv, cmd):
        if "-a" in argv:
            return self._ok("Linux %s %s #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 "
                            "x86_64 x86_64 x86_64 GNU/Linux" % (state.hostname, KERNEL))
        if "-r" in argv:
            return self._ok(KERNEL)
        return self._ok("Linux")

    def _cmd_hostname(self, state, argv, cmd):
        return self._ok(state.hostname)

    def _cmd_ps(self, state, argv, cmd):
        return self._ok("\n".join([PS_HEADER] + PS_ROWS))

    def _cmd_top(self, state, argv, cmd):
        head = ("top - 06:14:22 up 35 days,  4:02,  1 user,  load average: 0.14, 0.09, 0.06\n"
                "Tasks: 142 total,   1 running, 141 sleeping,   0 stopped,   0 zombie\n"
                "%Cpu(s):  1.2 us,  0.4 sy,  0.0 ni, 98.3 id,  0.1 wa,  0.0 hi,  0.0 si")
        return self._ok(head + "\n" + "\n".join(PS_ROWS[:5]))

    _cmd_htop = _cmd_top

    def _cmd_netstat(self, state, argv, cmd):
        return self._ok(NETSTAT)

    _cmd_ss = _cmd_netstat

    def _cmd_ifconfig(self, state, argv, cmd):
        return self._ok(IFCONFIG)

    def _cmd_ip(self, state, argv, cmd):
        if len(argv) > 1 and argv[1].startswith("a"):
            return self._ok(
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n"
                "    inet 10.0.12.41/24 brd 10.0.12.255 scope global eth0")
        if len(argv) > 1 and argv[1].startswith("r"):
            return self._ok("default via 10.0.12.1 dev eth0 proto static\n"
                            "10.0.12.0/24 dev eth0 proto kernel scope link src 10.0.12.41")
        return self._ok("")

    def _cmd_df(self, state, argv, cmd):
        return self._ok(DF)

    def _cmd_free(self, state, argv, cmd):
        return self._ok(FREE)

    def _cmd_uptime(self, state, argv, cmd):
        return self._ok(" 06:14:22 up 35 days,  4:02,  1 user,  load average: 0.14, 0.09, 0.06")

    def _cmd_date(self, state, argv, cmd):
        return self._ok(time.strftime("%a %b %d %H:%M:%S UTC %Y"))

    def _cmd_lscpu(self, state, argv, cmd):
        return self._ok("Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\n"
                        "CPU(s):                  8\nModel name:              "
                        "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz")

    def _cmd_lsblk(self, state, argv, cmd):
        return self._ok("NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
                        "sda       8:0    0   80G  0 disk\n"
                        "|-sda1    8:1    0 79.9G  0 part /\n"
                        "`-sda15   8:15   0  106M  0 part /boot/efi")

    def _cmd_env(self, state, argv, cmd):
        return self._ok("\n".join("%s=%s" % (k, v) for k, v in state.env.items()))

    def _cmd_export(self, state, argv, cmd):
        if len(argv) > 1 and "=" in argv[1]:
            k, _, v = argv[1].partition("=")
            return self._ok("", [{"op": "set_env", "key": k, "value": v}])
        return self._ok("")

    def _cmd_history(self, state, argv, cmd):
        return self._ok("\n".join("%5d  %s" % (i + 1, h["cmd"])
                                  for i, h in enumerate(state.history)))

    def _cmd_clear(self, state, argv, cmd):
        return self._ok("")

    def _cmd_mkdir(self, state, argv, cmd):
        return self._ok("", [{"op": "create_dir", "path": state.resolve(a)}
                             for a in argv[1:] if not a.startswith("-")])

    def _cmd_touch(self, state, argv, cmd):
        return self._ok("", [{"op": "create_file", "path": state.resolve(a), "content": ""}
                             for a in argv[1:] if not a.startswith("-")])

    def _cmd_rm(self, state, argv, cmd):
        targets = [a for a in argv[1:] if not a.startswith("-")]
        recursive = any("r" in a for a in argv[1:] if a.startswith("-"))
        outs, delta = [], []
        for t in targets:
            node = state.node(t)
            if node is None:
                outs.append("rm: cannot remove '%s': No such file or directory" % t)
            elif node["type"] == "dir" and not recursive:
                outs.append("rm: cannot remove '%s': Is a directory" % t)
            else:
                delta.append({"op": "delete_path", "path": state.resolve(t)})
        return {"display_output": "\n".join(outs), "state_delta": delta,
                "exit_code": 1 if outs else 0}

    def _cmd_cp(self, state, argv, cmd):
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) < 2:
            return self._err("cp: missing destination file operand")
        src, dst = args[0], args[-1]
        node = state.node(src)
        if node is None:
            return self._err("cp: cannot stat '%s': No such file or directory" % src)
        dnode = state.node(dst)
        if dnode and dnode["type"] == "dir":
            dst = posixpath.join(dst, posixpath.basename(src))
        return self._ok("", [{"op": "create_file", "path": state.resolve(dst),
                              "content": node.get("content", ""), "mode": node["mode"]}])

    def _cmd_mv(self, state, argv, cmd):
        r = self._cmd_cp(state, argv, cmd)
        if r["exit_code"] == 0:
            args = [a for a in argv[1:] if not a.startswith("-")]
            r["state_delta"].append({"op": "delete_path", "path": state.resolve(args[0])})
        return r

    def _cmd_chmod(self, state, argv, cmd):
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) < 2:
            return self._err("chmod: missing operand")
        bits = {"7": "rwx", "6": "rw-", "5": "r-x", "4": "r--", "1": "--x", "0": "---"}
        mode = args[0]
        if mode.isdigit() and len(mode) == 3:
            perm = "-" + "".join(bits.get(c, "rwx") for c in mode)
        else:
            perm = "-rwxr-xr-x" if "x" in mode else "-rw-r--r--"
        delta = []
        for t in args[1:]:
            if state.node(t) is None:
                return self._err("chmod: cannot access '%s': No such file or directory" % t)
            delta.append({"op": "chmod", "path": state.resolve(t), "mode": perm})
        return self._ok("", delta)

    def _cmd_chown(self, state, argv, cmd):
        if state.user == "root":
            return self._ok("")
        return self._err("chown: changing ownership of '%s': Operation not permitted" % argv[-1])

    def _cmd_find(self, state, argv, cmd):
        root = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else state.cwd
        node = state.node(root)
        if node is None:
            return self._err("find: '%s': No such file or directory" % root)
        name_pat = None
        if "-name" in argv:
            name_pat = argv[argv.index("-name") + 1].strip("\"'").replace("*", "")
        suid = "-perm" in cmd and ("4000" in cmd or "u=s" in cmd)
        results = []

        def walk(n, path):
            if len(results) > 200:
                return
            for name, child in sorted(n.get("children", {}).items()):
                p = posixpath.join(path, name)
                if suid:
                    if child["type"] == "file" and "s" in child["mode"]:
                        results.append(p)
                elif name_pat is None or name_pat in name:
                    results.append(p)
                if child["type"] == "dir":
                    walk(child, p)

        walk(node, state.resolve(root))
        if suid and not results:
            results = ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/chsh",
                       "/usr/bin/newgrp", "/usr/lib/openssh/ssh-keysign"]
        return self._ok("\n".join(results))

    def _cmd_grep(self, state, argv, cmd):
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) < 2:
            return self._ok("")
        pat, targets = args[0].strip("\"'"), args[1:]
        outs = []
        for t in targets:
            node = state.node(t)
            if node is None:
                outs.append("grep: %s: No such file or directory" % t)
                continue
            if node["type"] == "dir":
                outs.append("grep: %s: Is a directory" % t)
                continue
            for line in node["content"].split("\n"):
                if pat in line:
                    outs.append("%s:%s" % (t, line) if len(targets) > 1 else line)
        return self._ok("\n".join(outs))

    def _cmd_head(self, state, argv, cmd):
        return self._head_tail(state, argv, head=True)

    def _cmd_tail(self, state, argv, cmd):
        return self._head_tail(state, argv, head=False)

    def _head_tail(self, state, argv, head):
        n = 10
        if "-n" in argv:
            try:
                n = int(argv[argv.index("-n") + 1])
            except (IndexError, ValueError):
                pass
        targets = [a for a in argv[1:] if not a.startswith("-") and not a.isdigit()]
        outs = []
        for t in targets:
            node = state.node(t)
            if node is None:
                outs.append("%s: cannot open '%s' for reading: No such file or directory"
                            % ("head" if head else "tail", t))
                continue
            lines = node["content"].rstrip("\n").split("\n")
            outs.append("\n".join(lines[:n] if head else lines[-n:]))
        return self._ok("\n".join(outs))

    def _cmd_wc(self, state, argv, cmd):
        targets = [a for a in argv[1:] if not a.startswith("-")]
        outs = []
        for t in targets:
            node = state.node(t)
            if node is None:
                outs.append("wc: %s: No such file or directory" % t)
            else:
                c = node["content"]
                outs.append("%7d %7d %7d %s" % (c.count("\n"), len(c.split()), len(c), t))
        return self._ok("\n".join(outs))
