"""A minimal dashboard client for T06: connect to the live feed, wait until the agent is
active, then send the `stop` command — exactly what the dashboard button does.

usage: python3 dashboard.py HOST PORT [trigger_event]   (run from the repo root; stdlib only)

It reads events (server frames are unmasked; reuse gateway.websocket.read_message) until it
sees `trigger_event` (default: tool_call), then sends one masked text frame with the stop
command and exits 0. Prints what it did.
"""
import base64
import json
import os
import socket
import struct
import sys

from gateway import websocket as ws

HOST, PORT = sys.argv[1], int(sys.argv[2])
TRIGGER = sys.argv[3] if len(sys.argv) > 3 else "tool_call"


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


sock = socket.create_connection((HOST, PORT), timeout=30)
key = base64.b64encode(os.urandom(16)).decode()
sock.sendall((f"GET /events HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
              "Upgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
rfile = sock.makefile("rb")
status = rfile.readline()
while rfile.readline() not in (b"\r\n", b"", b"\n"):
    pass
if b"101" not in status:
    print(f"dashboard: handshake failed: {status!r}", flush=True)
    sys.exit(1)
print("dashboard: connected, watching the feed", flush=True)

while True:
    try:
        opcode, payload = ws.read_message(rfile)
    except (ws.ConnectionClosed, OSError):
        print("dashboard: feed closed before the trigger", flush=True)
        sys.exit(1)
    if opcode != ws.OP_TEXT:
        continue
    try:
        event = json.loads(payload)
    except ValueError:
        continue
    if event.get("type") == TRIGGER:
        sock.sendall(masked_text({"command": "stop", "by": "t06@dashboard"}))
        print(f"dashboard: saw {TRIGGER} (seq {event.get('seq')}), sent STOP", flush=True)
        sys.exit(0)
