"""A minimal dashboard client for the harnesses: read the live feed, send commands.

    from feed import Feed
    f = Feed("127.0.0.1", 18080)
    for event in f.events(): ...
    f.send({"command": "approve", ...})

Stdlib only; run with the repo root on PYTHONPATH (it reuses gateway.websocket).
"""
import base64
import json
import os
import socket
import struct

from gateway import websocket as ws


def masked_text(obj):
    """A client->server text frame. Client frames MUST be masked (RFC 6455)."""
    payload = json.dumps(obj).encode()
    n, mask = len(payload), os.urandom(4)
    header = bytes([0x80 | ws.OP_TEXT])
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack("!Q", n)
    return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


class Feed:
    def __init__(self, host, port, timeout=120):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET /events HTTP/1.1\r\nHost: {host}:{port}\r\n"
                           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        self.rfile = self.sock.makefile("rb")
        status = self.rfile.readline()
        while self.rfile.readline() not in (b"\r\n", b"", b"\n"):
            pass
        if b"101" not in status:
            raise ConnectionError(f"handshake failed: {status!r}")

    def events(self):
        while True:
            try:
                opcode, payload = ws.read_message(self.rfile)
            except (ws.ConnectionClosed, OSError):
                return
            if opcode != ws.OP_TEXT:
                continue
            try:
                yield json.loads(payload)
            except ValueError:
                continue

    def send(self, cmd):
        self.sock.sendall(masked_text(cmd))
