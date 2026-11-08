"""The forward proxy: allowed destinations go through, denied ones get a 403 and never connect.

Run with: python3 -m unittest discover -t . -s tests
"""
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gateway import policy, proxy


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from origin"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def echo_server():
    """A raw TCP server that echoes back whatever it receives (stands in for a tunneled host)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=_echo, args=(conn,), daemon=True).start()

    def _echo(conn):
        with conn:
            while data := conn.recv(4096):
                conn.sendall(data)

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = serve(ThreadingHTTPServer(("127.0.0.1", 0), Origin))
        cls.origin_port = cls.origin.server_address[1]
        cls.echo, cls.echo_port = echo_server()
        cls.decisions = []

        def decide(method, host, port):
            # Allow only 127.0.0.1; deny everything else. Record calls so tests can check them.
            allowed = host == "127.0.0.1"
            d = (policy.EgressDecision("allow", "allowlist", "ok", "allowlist") if allowed
                 else policy.EgressDecision("block", "unknown_destination", "no", "unknown"))
            cls.decisions.append((method, host, port, d.verdict))
            return d

        cls.proxy = proxy.start("127.0.0.1", 0, decide)
        cls.proxy_host, cls.proxy_port = cls.proxy.server_address

    @classmethod
    def tearDownClass(cls):
        for s in (cls.proxy, cls.origin):
            s.shutdown()
            s.server_close()
        cls.echo.close()

    def http_through_proxy(self, url):
        """Send an absolute-form request through the proxy; return (status_line, body)."""
        s = socket.create_connection((self.proxy_host, self.proxy_port), timeout=5)
        host = url.split("/")[2]
        s.sendall(f"GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        return head.split(b"\r\n")[0].decode(), body

    def connect_through_proxy(self, host, port):
        """Send a CONNECT; return (status_line, socket). The socket is live only if 200."""
        s = socket.create_connection((self.proxy_host, self.proxy_port), timeout=5)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(1)
        return head.split(b"\r\n")[0].decode(), s

    def test_allowed_http_is_forwarded(self):
        status, body = self.http_through_proxy(f"http://127.0.0.1:{self.origin_port}/pkg")
        self.assertIn("200", status)
        self.assertEqual(body, b"hello from origin")

    def test_denied_http_never_reaches_the_origin(self):
        status, body = self.http_through_proxy("http://blocked.example/steal")
        self.assertIn("403", status)
        self.assertIn(b"egress denied", body)
        self.assertIn(("GET", "blocked.example", 80, "block"), self.decisions)

    def test_allowed_connect_tunnels_bytes(self):
        status, s = self.connect_through_proxy("127.0.0.1", self.echo_port)
        self.assertIn("200", status)
        s.sendall(b"ping through the tunnel")
        self.assertEqual(s.recv(4096), b"ping through the tunnel")
        s.close()

    def test_denied_connect_is_refused(self):
        status, s = self.connect_through_proxy("evil.example", 443)
        self.assertIn("403", status)
        s.close()
        self.assertIn(("CONNECT", "evil.example", 443, "block"), self.decisions)

    def test_metadata_and_link_local_are_refused(self):
        # resolve_safe rejects the cloud metadata address and link-local, even if a host were allowed.
        self.assertIsNotNone(proxy.resolve_safe("169.254.169.254", 80)[1])
        self.assertIsNotNone(proxy.resolve_safe("169.254.0.1", 80)[1])
        self.assertIsNone(proxy.resolve_safe("127.0.0.1", 80)[1], "loopback allowed by default (opt-in to deny)")


if __name__ == "__main__":
    unittest.main()
