"""Forward proxy: the runner's one controlled door to the network.

The runner has no direct route out (internal Docker network, proven by T00). Its HTTP(S) tools
are pointed here with HTTP_PROXY / HTTPS_PROXY, so every outbound request arrives as either:

  CONNECT host:443        an HTTPS tunnel  -> we see only the destination host, then encrypted bytes
  GET http://host/path    a plain request  -> we see the whole request and response

For each, a `decide(method, host, port)` callback (provided by the gateway) returns an
EgressDecision from the policy and the session's taint state, and emits the events. Allowed
HTTPS is spliced through untouched; a denied request gets a 403 and never reaches the host.

This proxy is a control point, not the isolation boundary: a determined process could ignore
the proxy variables, but then the internal network gives it nowhere to go (T00). The proxy is
how *legitimate* tools get a door that applies policy; the network is what guarantees there is
no other door.
"""
import ipaddress
import os
import select
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import forwarder

CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 300

# Addresses the proxy refuses to connect to, even for an allowlisted host — defense against DNS
# rebinding to an internal target. Default: cloud metadata and link-local (169.254/16, fe80::/10).
# Loopback and the private ranges Docker itself uses are opt-in (FC_EGRESS_DENY_PRIVATE=1), so the
# default doesn't break container-to-container test sinks.
DENY_NETS = [ipaddress.ip_network(n) for n in ("169.254.0.0/16", "fe80::/10")]
if os.environ.get("FC_EGRESS_DENY_PRIVATE"):
    DENY_NETS += [ipaddress.ip_network(n) for n in
                  ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def resolve_safe(host, port):
    """Resolve `host` and return (sockaddr, None) for the first address that isn't denied, or
    (None, reason). Connecting to the resolved address (not the name) closes the rebinding window."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return None, f"cannot resolve {host} ({exc})"
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if not any(ip in net for net in DENY_NETS):
            return (info[0], sockaddr), None
    return None, f"{host} resolves only to a denied address (metadata/link-local/internal)"


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    decide = None  # set by start(): decide(method, host, port) -> EgressDecision (and emits events)

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(":")
        host = host or self.path
        try:
            port = int(port) if port else 443
        except ValueError:
            return self.deny_plain(400, "bad CONNECT target")
        decision = self.decide("CONNECT", host, port)
        if decision.blocked:
            return self.refuse(decision)
        target, err = resolve_safe(host, port)
        if err:
            return self.deny_plain(403, f"FlowControl gateway: egress denied (unsafe_address). {err}")
        try:
            family, sockaddr = target
            upstream = socket.socket(family, socket.SOCK_STREAM)
            upstream.settimeout(CONNECT_TIMEOUT)
            upstream.connect(sockaddr)
        except OSError as exc:
            return self.deny_plain(502, f"cannot reach {host}:{port}: {exc}")
        self.send_response(200, "Connection established")
        self.end_headers()
        self.close_connection = True
        splice(self.connection, upstream)

    # Absolute-form HTTP (plain) arrives as a normal method with the full URL as the path.
    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_PUT(self):
        self.forward()

    def do_DELETE(self):
        self.forward()

    def do_HEAD(self):
        self.forward()

    def do_PATCH(self):
        self.forward()

    def forward(self):
        self.close_connection = True
        if not self.path.startswith("http://"):
            return self.deny_plain(400, "this is a forward proxy; use an absolute URL or CONNECT")
        url = urlsplit(self.path)
        host, port = url.hostname or "", url.port or 80
        decision = self.decide(self.command, host, port)
        if decision.blocked:
            return self.refuse(decision)
        target, err = resolve_safe(host, port)
        if err:
            return self.deny_plain(403, f"FlowControl gateway: egress denied (unsafe_address). {err}")
        address = target[1][0]  # connect to the address just checked, not a fresh lookup
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        path = url.path + ("?" + url.query if url.query else "")
        try:
            conn, resp = forwarder.open_on(host, port, self.command, path or "/", self.headers, body, address)
        except OSError as exc:
            return self.deny_plain(502, f"cannot reach {host}: {exc}")
        try:
            self.send_response(resp.status)
            for k, v in forwarder.response_headers(resp):
                self.send_header(k, v)
            self.send_header("connection", "close")
            self.end_headers()
            while chunk := resp.read1(8192):
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()

    def refuse(self, decision):
        """Policy said no: a 403 the tool surfaces, so nothing reaches the host."""
        self.deny_plain(403, f"FlowControl gateway: egress denied ({decision.rule}). {decision.reason}")

    def deny_plain(self, status, message):
        body = (message + "\n").encode()
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(body)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass  # the gateway prints its own lines


def splice(a, b):
    """Pump bytes both ways between two sockets until either side closes."""
    socks = [a, b]
    try:
        while True:
            readable, _, errored = select.select(socks, [], socks, IDLE_TIMEOUT)
            if errored or not readable:
                break
            for src in readable:
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            b.close()
        except OSError:
            pass


def start(host, port, decide):
    """Start the forward proxy in a background thread. Returns the server."""
    import threading
    handler = type("BoundProxyHandler", (ProxyHandler,), {"decide": staticmethod(decide)})
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
