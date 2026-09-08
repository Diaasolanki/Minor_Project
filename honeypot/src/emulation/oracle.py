"""The deterministic Oracle: dispatch, pipelines and safety plumbing.

Assembled from the command mixins. This is a *simulator*: it never calls
subprocess/exec/eval on attacker input, by construction.
"""
from __future__ import annotations

import random
import re
import shlex
from typing import Any

from emulation.oracle_attack import AttackCommands
from emulation.oracle_base import BINARIES, SUDO_L
from emulation.oracle_cmds import CoreCommands
from state.fakefs import SessionState


class OracleBase:
    def __init__(self, rng: random.Random | None = None):
        self.rng = rng or random.Random()

    # ------------------------------------------------------------------ entry
    def run(self, state: SessionState, command: str) -> dict[str, Any]:
        """Return {'display_output': str, 'state_delta': list, 'exit_code': int}."""
        command = (command or "").strip()
        if not command:
            return self._ok("")
        if command.startswith("#"):
            return self._ok("")

        if "&&" in command or ";" in command or "||" in command:
            return self._run_chain(state, command)
        if "|" in command:
            return self._handle_pipe(state, command)

        try:
            argv = shlex.split(command)
        except ValueError:
            argv = command.split()
        if not argv:
            return self._ok("")

        # strip a leading redirect-free env assignment like FOO=bar cmd
        while len(argv) > 1 and re.match(r"^\w+=", argv[0]):
            argv = argv[1:]

        binary = argv[0]
        if binary == "sudo" and len(argv) > 1:
            if argv[1] == "-l":
                return self._handle_sudo(state, argv)
            if state.user == "root":
                return self.run(state, " ".join(argv[1:]))
            return self._handle_sudo(state, argv)

        if binary.startswith("./") or binary.startswith("/") or "/" in binary:
            exec_result = self._exec_path(state, binary, argv)
            if exec_result is not None:
                return exec_result

        handler = getattr(self, "_cmd_" + binary.replace("-", "_"), None)
        if handler is None:
            if binary in BINARIES:
                return self._ok("")
            return self._err("%s: command not found" % binary, 127)
        return handler(state, argv, command)

    def _run_chain(self, state: SessionState, command: str) -> dict:
        parts = [p.strip() for p in re.split(r"&&|\|\||;", command) if p.strip()]
        outs: list[str] = []
        delta: list[dict] = []
        for p in parts:
            r = self.run(state, p)
            if r["display_output"]:
                outs.append(r["display_output"])
            delta += r["state_delta"]
            state.apply_delta(r["state_delta"])
        return {"display_output": "\n".join(outs), "state_delta": delta, "exit_code": 0}

    # --------------------------------------------------------------- plumbing
    @staticmethod
    def _ok(out: str, delta: list | None = None) -> dict:
        return {"display_output": out, "state_delta": delta or [], "exit_code": 0}

    @staticmethod
    def _err(out: str, code: int = 1) -> dict:
        return {"display_output": out, "state_delta": [], "exit_code": code}

    def _handle_pipe(self, state: SessionState, command: str) -> dict:
        head, _, tail = command.partition("|")
        upstream = self.run(state, head.strip())
        text = upstream["display_output"]
        tail_argv = tail.strip().split()
        if not tail_argv:
            return upstream
        f, lines = tail_argv[0], (text.split("\n") if text else [])

        if f == "grep" and len(tail_argv) > 1:
            pat = tail_argv[-1].strip("\"'")
            inv = "-v" in tail_argv
            lines = [l for l in lines if (pat in l) != inv]
        elif f == "wc":
            return self._ok("%7d" % len(lines))
        elif f == "head":
            n = int(tail_argv[2]) if "-n" in tail_argv and len(tail_argv) > 2 else 10
            lines = lines[:n]
        elif f == "tail":
            n = int(tail_argv[2]) if "-n" in tail_argv and len(tail_argv) > 2 else 10
            lines = lines[-n:]
        elif f == "sort":
            lines = sorted(lines)
        elif f == "uniq":
            lines = list(dict.fromkeys(lines))
        elif f in ("sh", "bash"):
            return self._ok("")  # curl|sh — "runs" silently, as the real thing often does
        elif f == "base64":
            import base64 as _b
            return self._ok(_b.b64encode(text.encode()).decode())
        elif f in ("awk", "cut", "sed", "tr", "xargs"):
            pass  # pass text through; close enough for a first-pass filter
        return {"display_output": "\n".join(lines),
                "state_delta": upstream["state_delta"], "exit_code": 0}

    def _exec_path(self, state: SessionState, binary: str, argv: list[str]) -> dict | None:
        """Attacker invoking a file by path: ./payload.sh, /tmp/x, /usr/bin/id ..."""
        node = state.node(binary)
        if node is None:
            base = binary.rsplit("/", 1)[-1]
            if getattr(self, "_cmd_" + base.replace("-", "_"), None) and binary.startswith("/"):
                return self.run(state, " ".join([base] + argv[1:]))
            return self._err("bash: %s: No such file or directory" % binary, 127)
        if node["type"] == "dir":
            return self._err("bash: %s: Is a directory" % binary, 126)
        if "x" not in node["mode"]:
            return self._err("bash: %s: Permission denied" % binary, 126)
        return self._ok("")  # executes silently, like most dropped payloads

    def _handle_sudo(self, state: SessionState, argv: list[str]) -> dict:
        sub = argv[1]
        if sub == "-l":
            return self._ok(SUDO_L.format(user=state.user, host=state.hostname))
        if sub in ("su", "-i", "-s", "bash", "sh"):
            return self._err("[sudo] password for %s: \nSorry, try again.\n"
                             "[sudo] password for %s: \n"
                             "sudo: 2 incorrect password attempts" % (state.user, state.user))
        if "systemctl" in sub or "rsync" in sub:
            return self.run(state, " ".join(argv[1:]))
        return self._err("[sudo] password for %s: \nSorry, user %s is not allowed to execute "
                         "'%s' as root on %s." % (state.user, state.user,
                                                  " ".join(argv[1:]), state.hostname))


class Oracle(CoreCommands, AttackCommands, OracleBase):
    """The full deterministic simulator."""
