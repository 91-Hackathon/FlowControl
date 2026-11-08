"""Live feed: a small server the dashboard connects to.

  ws://localhost:8080/events   WebSocket. Gateway -> dashboard: every event, as JSON.
                               Dashboard -> gateway: commands (see protocol/EVENTS.md).
  http://localhost:8080/       A debug page that shows the feed (gateway/viewer.html).

A dashboard that connects late first receives all events so far, then live ones.
"""
import ipaddress
import json
import os
import pathlib
import re
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import websocket as ws

VIEWER = pathlib.Path(__file__).with_name("viewer.html")
SEND_TIMEOUT = 2  # seconds; a stuck client is dropped instead of slowing the gateway
# The dashboard's static files, served at /dashboard/ on this same port (compose mounts them
# read-only). Same origin as the feed, and like the feed, refused to the agent network.
DASHBOARD_DIR = pathlib.Path(os.environ.get("FC_DASHBOARD_DIR", "dashboard")).resolve()
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml",
                 ".md": "text/plain; charset=utf-8"}
# Browsers let any web page open a WebSocket to localhost, and the feed takes commands
# (approve, stop, switch protections). So a browser connection must come from a page on this
# machine: the gateway's own /dashboard/, a local dev server, or the desktop app (file://).
# FC_LIVE_ORIGINS adds more, comma-separated (e.g. http://10.0.0.5:8080 for a LAN dashboard).
LOCAL_ORIGIN = re.compile(r"https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?")
EXTRA_ORIGINS = {o.strip().rstrip("/").lower() for o in os.environ.get("FC_LIVE_ORIGINS", "").split(",") if o.strip()}


def origin_ok(origin):
    """No Origin header = not a browser (a script, the tests): allowed; the network check still applies."""
    if origin is None:
        return True
    origin = origin.strip().rstrip("/").lower()
    return origin in ("null", "file:") or origin in EXTRA_ORIGINS or bool(LOCAL_ORIGIN.fullmatch(origin))


class Client:
    def __init__(self, conn, label):
        self.conn = conn
        self.label = label
        self._lock = threading.Lock()  # broadcasts and pong replies come from different threads

    def send(self, payload, opcode=ws.OP_TEXT):
        with self._lock:
            self.conn.sendall(ws.encode_frame(payload, opcode))


class Hub:
    """Keeps the event history and the connected dashboards, and fans events out."""

    def __init__(self, on_command=None):
        self.history = []
        self.clients = []
        self.on_command = on_command or (lambda cmd: print(f"command received (not handled yet): {cmd}", flush=True))
        self._lock = threading.Lock()

    def add(self, client):
        with self._lock:  # hold the lock so no event slips in between history and live
            try:
                for text in self.history:
                    client.send(text)
            except OSError:
                return False
            self.clients.append(client)
            return True

    def remove(self, client):
        with self._lock:
            if client in self.clients:
                self.clients.remove(client)

    def broadcast(self, event):
        text = json.dumps(event, ensure_ascii=False)
        with self._lock:
            self.history.append(text)
            for client in list(self.clients):
                try:
                    client.send(text)
                except OSError:
                    self.clients.remove(client)


class WebSocketSink:
    """Event sink (see sinks.py) that pushes every event to connected dashboards."""

    def __init__(self, hub):
        self.hub = hub

    def write(self, event):
        self.hub.broadcast(event)


def make_handler(hub, deny_nets=()):
    class LiveHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # browsers require 1.1 for the WebSocket upgrade

        def denied(self):
            """The feed accepts commands, so the agent's own network must never reach it."""
            try:
                ip = ipaddress.ip_address(self.client_address[0])
            except ValueError:
                return True  # can't tell where it's from: refuse
            return any(ip in net for net in deny_nets)

        def do_GET(self):
            if self.denied():
                body = b'{"error": "FlowControl gateway: the dashboard feed is not reachable from the agent network"}'
                self.send_response(403)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
                print(f"refused dashboard feed connection from the agent network ({self.client_address[0]})", flush=True)
                return
            path = self.path.split("?")[0]
            if path == "/events" and "websocket" in self.headers.get("upgrade", "").lower():
                self.serve_websocket()
            elif path in ("/", "/index.html"):
                self.serve_viewer()
            elif path == "/dashboard":
                self.send_response(301)
                self.send_header("location", "/dashboard/")
                self.send_header("content-length", "0")
                self.end_headers()
            elif path.startswith("/dashboard/"):
                self.serve_dashboard(path[len("/dashboard/"):] or "index.html")
            else:
                self.send_error(404)

        def serve_dashboard(self, rel):
            target = (DASHBOARD_DIR / rel).resolve()
            if DASHBOARD_DIR not in target.parents or not target.is_file():  # no ../ escapes
                self.send_error(404)
                return
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("content-type", CONTENT_TYPES.get(target.suffix, "application/octet-stream"))
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def serve_viewer(self):
            body = VIEWER.read_bytes()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def serve_websocket(self):
            key = self.headers.get("sec-websocket-key")
            if not key:
                self.send_error(400, "missing Sec-WebSocket-Key")
                return
            if not origin_ok(self.headers.get("origin")):
                print(f"refused dashboard feed connection from web page {self.headers.get('origin')!r:.80}", flush=True)
                self.send_error(403, "FlowControl gateway: the feed only accepts dashboards on this machine")
                return
            self.send_response(101, "Switching Protocols")
            self.send_header("upgrade", "websocket")
            self.send_header("connection", "Upgrade")
            self.send_header("sec-websocket-accept", ws.accept_key(key))
            self.end_headers()
            self.wfile.flush()

            limit_send_time(self.connection, SEND_TIMEOUT)
            client = Client(self.connection, f"{self.client_address[0]}:{self.client_address[1]}")
            if not hub.add(client):
                return
            print(f"dashboard connected ({client.label})", flush=True)
            try:
                self.read_loop(client)
            finally:
                hub.remove(client)
                self.close_connection = True
                print(f"dashboard disconnected ({client.label})", flush=True)

        def read_loop(self, client):
            while True:
                try:
                    opcode, payload = ws.read_message(self.rfile)
                except (ws.ConnectionClosed, OSError):
                    return
                if opcode == ws.OP_CLOSE:
                    try:
                        client.send(payload[:2], ws.OP_CLOSE)
                    except OSError:
                        pass
                    return
                if opcode == ws.OP_PING:
                    client.send(payload, ws.OP_PONG)
                elif opcode == ws.OP_TEXT:
                    self.handle_command(payload)

        def handle_command(self, payload):
            try:
                cmd = json.loads(payload)
            except ValueError:
                print(f"ignored non-JSON message from dashboard: {payload[:80]!r}", flush=True)
                return
            if isinstance(cmd, dict) and "command" in cmd:
                hub.on_command(cmd)
            else:
                print(f"ignored message without 'command': {cmd!r:.80}", flush=True)

        def log_message(self, *args):
            pass

    return LiveHandler


def limit_send_time(sock, seconds):
    """Make sends fail after `seconds` while reads still wait forever (OS-level send timeout)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", seconds, 0))
    except OSError:
        pass  # not supported here: sends just block, which is fine for a local dashboard


def start(hub, host, port, deny_nets=()):
    """Start the live server in a background thread. Returns the server (for its address / shutdown).

    deny_nets: networks whose connections are refused (the agent's network).
    """
    server = ThreadingHTTPServer((host, port), make_handler(hub, deny_nets))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
