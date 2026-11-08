"""Forwarding: send the agent's request to the real API and hand back the response.

This module knows nothing about logging or policy. It only moves bytes.
"""
import http.client

from . import config

# Headers that describe a single connection, not the message. They must not be
# copied from one connection to the next.
HOP_BY_HOP = {
    "host", "connection", "keep-alive", "transfer-encoding",
    "content-length", "accept-encoding", "proxy-connection", "upgrade",
}


def open_upstream(method, path, headers, body):
    """Send one request upstream. Returns (connection, response).

    The caller reads the response (it may be a long stream) and must close the connection.
    """
    conn_cls = http.client.HTTPConnection if config.UPSTREAM_SCHEME == "http" else http.client.HTTPSConnection
    conn = conn_cls(config.UPSTREAM_HOST, timeout=config.UPSTREAM_TIMEOUT)
    out = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
    out["content-length"] = str(len(body))
    conn.request(method, path, body=body or None, headers=out)
    return conn, conn.getresponse()


def open_on(host, port, method, path, headers, body, address=None):
    """Send one plain-HTTP request to an arbitrary host (used by the forward proxy). Returns
    (connection, response); the caller reads the response and closes the connection.
    `address`: the IP the proxy already checked; connect to it rather than resolving `host` again
    (a second lookup could be rebound to an internal address). The Host header stays `host`."""
    conn = http.client.HTTPConnection(address or host, port, timeout=config.UPSTREAM_TIMEOUT)
    out = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
    if not any(k.lower() == "host" for k in out):
        out["host"] = host if port == 80 else f"{host}:{port}"
    out["content-length"] = str(len(body))
    conn.request(method, path, body=body or None, headers=out)
    return conn, conn.getresponse()


def response_headers(resp):
    """Upstream response headers that are safe to pass back to the agent."""
    return [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP]
