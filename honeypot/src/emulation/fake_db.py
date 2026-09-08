"""Fake MySQL-wire-protocol TCP listener (build guide layer 1: "a fake database
that throws plausible errors" / section 6.2: "custom TCP listener speaking
MySQL/Postgres wire protocol basics ... enough to produce believable
connection/error banners").

Implements just the initial handshake packet (protocol v10 greeting) and the
authentication response -> ERROR packet exchange. Never parses real SQL and
never touches a real database; every connection attempt is logged as a TTP
event (credential access probing) regardless of what credentials are sent.
"""
from __future__ import annotations

import os
import socketserver
import struct
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.session_runner import REGISTRY  # noqa: E402
from ttp import store  # noqa: E402

DEFAULT_PORT = 3307  # 3306 may already be bound; 3307 avoids clashing with a real MySQL
SERVER_VERSION = b"8.0.36-0ubuntu0.22.04.1"


def _packet(payload: bytes, seq: int) -> bytes:
    length = len(payload)
    return struct.pack("<I", length | (seq << 24))[:3] + bytes([seq]) + payload


def _handshake_v10() -> bytes:
    protocol_version = b"\x0a"
    server_version = SERVER_VERSION + b"\x00"
    thread_id = struct.pack("<I", 8841)
    auth_plugin_data_1 = b"ABCDEFGH"
    filler = b"\x00"
    capability_flags_1 = struct.pack("<H", 0xFFFF)
    charset = b"\xff"
    status_flags = struct.pack("<H", 2)
    capability_flags_2 = struct.pack("<H", 0xC1FF)
    auth_plugin_data_len = b"\x15"
    reserved = b"\x00" * 10
    auth_plugin_data_2 = b"IJKLMNOPQRST\x00"
    auth_plugin_name = b"mysql_native_password\x00"
    payload = (protocol_version + server_version + thread_id + auth_plugin_data_1 + filler +
              capability_flags_1 + charset + status_flags + capability_flags_2 +
              auth_plugin_data_len + reserved + auth_plugin_data_2 + auth_plugin_name)
    return _packet(payload, 0)


def _err_packet(seq: int, code: int, sqlstate: str, message: str) -> bytes:
    payload = (b"\xff" + struct.pack("<H", code) + b"#" + sqlstate.encode() + message.encode())
    return _packet(payload, seq)


class MysqlHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        src_ip = self.client_address[0]
        sess = REGISTRY.create(src_ip, protocol="db")
        user = "unknown"
        try:
            self.request.sendall(_handshake_v10())
            data = self.request.recv(4096)
            user = self._extract_user(data) or "unknown"
            err = _err_packet(2, 1045, "28000",
                              f"Access denied for user '{user}'@'{src_ip}' (using password: YES)")
            self.request.sendall(err)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            sess.log_raw_event(
                f"DB_CONNECT user={user} src={src_ip}",
                "ERROR 1045 (28000): Access denied", "oracle-fallback",
                "T1110", "Credential Access")
            REGISTRY.drop(sess.session_id)

    @staticmethod
    def _extract_user(packet: bytes) -> str | None:
        # Handshake response v41: header(4) + caps(4) + max_packet(4) + charset(1) + reserved(23)
        try:
            offset = 4 + 4 + 4 + 1 + 23
            end = packet.index(b"\x00", offset)
            return packet[offset:end].decode("utf8", "replace") or None
        except (ValueError, IndexError):
            return None


class ThreadingMysqlServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(port: int = DEFAULT_PORT, in_thread: bool = False):
    store.init_db()
    server = ThreadingMysqlServer(("0.0.0.0", port), MysqlHandler)
    print(f"[fake_db] listening on 0.0.0.0:{port}")
    if in_thread:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, t
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    serve(port)
