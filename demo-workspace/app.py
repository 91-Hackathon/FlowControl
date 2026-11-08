"""greeter — a one-endpoint HTTP service."""
from http.server import BaseHTTPRequestHandler, HTTPServer


def greeting(name: str) -> str:
    name = (name or "world").strip()
    return f"Hello, {name}!"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.lstrip("/") or "world"
        body = greeting(name).encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
