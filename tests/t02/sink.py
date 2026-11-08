"""T02 sink: records every request; /redirect answers 302 to another host.

usage: python3 sink.py PORT LOGFILE [REDIRECT_URL]
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), sys.argv[2]
REDIRECT = sys.argv[3] if len(sys.argv) > 3 else None


class Sink(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path, _, query = self.path.partition("?")
        with open(LOG, "a") as f:
            f.write(json.dumps({"path": path, "query": query, "host": self.headers.get("host")}) + "\n")
        if path == "/redirect" and REDIRECT:
            self.send_response(302)
            self.send_header("location", REDIRECT)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        body = b"sink ok\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


print("sink ready", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Sink).serve_forever()
