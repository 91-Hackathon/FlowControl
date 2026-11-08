"""Live feed: connect like a browser would, check history + live events + commands.

Run with: python3 -m unittest discover -t . -s tests
"""
import base64
import json
import os
import socket
import struct
import time
import unittest
import urllib.error
import urllib.request

from gateway import live
from gateway import websocket as ws


class RawClient:
    """A minimal WebSocket client (what a browser does), so the test needs no libraries."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            "GET /events HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        self.rfile = self.sock.makefile("rb")
        status = self.rfile.readline()
        headers = {}
        while (line := self.rfile.readline()) not in (b"\r\n", b""):
            k, v = line.decode().split(":", 1)
            headers[k.strip().lower()] = v.strip()
        assert b"101" in status, status
        assert headers["sec-websocket-accept"] == ws.accept_key(key)

    def recv_json(self):
        opcode, payload = ws.read_message(self.rfile)
        assert opcode == ws.OP_TEXT, opcode
        return json.loads(payload)

    def send(self, payload, opcode=ws.OP_TEXT):
        """Clients must mask their frames."""
        data = payload.encode() if isinstance(payload, str) else payload
        mask = os.urandom(4)
        header = bytes([0x80 | opcode]) + bytes([0x80 | len(data)]) if len(data) < 126 \
            else bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", len(data))
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def close(self):
        self.rfile.close()  # the file wrapper keeps the socket open until it's closed too
        self.sock.close()


def wait_for(predicate, timeout=2):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class LiveFeedTest(unittest.TestCase):
    def setUp(self):
        self.commands = []
        self.hub = live.Hub(on_command=self.commands.append)
        self.server = live.start(self.hub, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.sink = live.WebSocketSink(self.hub)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_late_client_gets_history_then_live_events(self):
        self.sink.write({"seq": 1, "type": "session_start"})
        self.sink.write({"seq": 2, "type": "tool_call"})
        client = RawClient(self.port)
        self.assertEqual(client.recv_json()["seq"], 1)
        self.assertEqual(client.recv_json()["seq"], 2)
        self.sink.write({"seq": 3, "type": "llm_call", "data": {"text": "x" * 70000}})  # 64-bit length frame
        self.assertEqual(client.recv_json()["seq"], 3)
        client.close()

    def test_two_clients_both_receive(self):
        a, b = RawClient(self.port), RawClient(self.port)
        self.assertTrue(wait_for(lambda: len(self.hub.clients) == 2))
        self.sink.write({"seq": 1})
        self.assertEqual(a.recv_json()["seq"], 1)
        self.assertEqual(b.recv_json()["seq"], 1)
        a.close()
        b.close()

    def test_commands_ping_and_close(self):
        client = RawClient(self.port)
        client.send(json.dumps({"command": "stop", "session_id": "sess_01"}))
        client.send("not json")  # ignored, connection stays up
        self.assertTrue(wait_for(lambda: self.commands == [{"command": "stop", "session_id": "sess_01"}]))

        client.send(b"hi", ws.OP_PING)
        self.assertEqual(ws.read_message(client.rfile), (ws.OP_PONG, b"hi"))

        client.send(struct.pack("!H", 1000), ws.OP_CLOSE)
        self.assertEqual(ws.read_message(client.rfile)[0], ws.OP_CLOSE)
        self.assertTrue(wait_for(lambda: self.hub.clients == []))
        client.close()

    def test_dead_client_is_dropped_and_others_keep_working(self):
        dead, alive = RawClient(self.port), RawClient(self.port)
        self.assertTrue(wait_for(lambda: len(self.hub.clients) == 2))
        dead.close()
        self.assertTrue(wait_for(lambda: len(self.hub.clients) == 1))
        self.sink.write({"seq": 1})
        self.assertEqual(alive.recv_json()["seq"], 1)
        alive.close()

    def test_debug_page_is_served(self):
        html = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5).read().decode()
        self.assertIn("new WebSocket", html)

    def test_dashboard_is_served_and_cannot_escape_its_folder(self):
        page = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/dashboard/", timeout=5).read().decode()
        self.assertIn("FlowControl", page)
        js = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/dashboard/app.js", timeout=5)
        self.assertIn("javascript", js.headers.get("content-type"))
        for bad in ("/dashboard/../gateway/credentials.py", "/dashboard/../../policy/default.toml"):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}{bad}", timeout=5)
            self.assertEqual(cm.exception.code, 404)


class DeniedNetworkTest(unittest.TestCase):
    """The feed accepts commands: connections from the agent's network must be refused."""

    def setUp(self):
        import ipaddress
        self.commands = []
        self.hub = live.Hub(on_command=self.commands.append)
        # Pretend 127.0.0.0/8 is the agent network, so this test's own connections are refused.
        self.server = live.start(self.hub, "127.0.0.1", 0, deny_nets=[ipaddress.ip_network("127.0.0.0/8")])
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_page_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_websocket_refused_and_no_command_gets_through(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((
            "GET /events HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        status = sock.makefile("rb").readline()
        sock.close()
        self.assertIn(b"403", status)
        self.assertEqual(self.hub.clients, [])
        self.assertEqual(self.commands, [])



class OriginTests(unittest.TestCase):
    """A web page elsewhere must not be able to drive the feed through the operator's browser."""

    def test_local_pages_and_the_desktop_app_allowed(self):
        for origin in (None, "http://localhost:8080", "http://127.0.0.1:5173", "http://[::1]:8080/", "file://", "null"):
            self.assertTrue(live.origin_ok(origin), origin)

    def test_other_sites_refused(self):
        for origin in ("https://evil.example.com", "http://localhost.evil.com", "http://127.0.0.1.nip.io:8080", ""):
            self.assertFalse(live.origin_ok(origin), origin)


if __name__ == "__main__":
    unittest.main()
