"""Fake Telnet/SSH-style raw TCP shell (build guide layer 1: "Exposes fake
SSH/Telnet ... endpoints that attackers connect to"). A real `telnet` or `nc`
client can connect to this and get a line-based shell backed by the same
Session Manager, Response Engine and TTP pipeline as the HTTP fake terminal —
distinct transport, same brain, one dashboard.

Deliberately raw sockets rather than a Telnet-protocol (RFC 854) negotiation
implementation or a Cowrie/paramiko SSH server: enough to demonstrate a second
attacker-facing surface without pulling in a second heavyweight dependency.
"""
from __future__ import annotations

import os
import socketserver
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.session_runner import REGISTRY  # noqa: E402
from ttp import store  # noqa: E402

DEFAULT_PORT = 2323  # 23 requires elevated privileges on most systems


class TelnetHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        src_ip = self.client_address[0]
        sess = REGISTRY.create(src_ip, protocol="telnet")
        try:
            self.wfile.write(sess.state.banner().encode("utf8", "replace"))
            self.wfile.write(sess.state.shell_prompt().encode("utf8", "replace"))
            self.wfile.flush()
            for raw_line in self.rfile:
                try:
                    line = raw_line.decode("utf8", "replace").rstrip("\r\n")
                except UnicodeDecodeError:
                    continue
                if not line.strip():
                    self.wfile.write(sess.state.shell_prompt().encode("utf8", "replace"))
                    self.wfile.flush()
                    continue
                result = sess.run_command(line)
                out = result["display_output"]
                if out:
                    self.wfile.write((out + "\n").encode("utf8", "replace"))
                if result.get("close"):
                    self.wfile.flush()
                    break
                self.wfile.write(sess.state.shell_prompt().encode("utf8", "replace"))
                self.wfile.flush()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            REGISTRY.drop(sess.session_id)


class ThreadingTelnetServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(port: int = DEFAULT_PORT, in_thread: bool = False):
    store.init_db()
    server = ThreadingTelnetServer(("0.0.0.0", port), TelnetHandler)
    print(f"[fake_telnet] listening on 0.0.0.0:{port}")
    if in_thread:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, t
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    serve(port)
