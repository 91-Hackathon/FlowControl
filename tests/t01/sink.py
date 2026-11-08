"""T01 independent sink: an HTTP server that records every request it receives.

usage: python3 sink.py PORT LOGFILE

It is the ground truth for "did anything get out?". It runs on the egress network, off the
runner's internal network: the runner can reach it only if the gateway proxy forwards the
request. Each request is appended to LOGFILE as one JSON line (method, path, query, body).
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), sys.argv[2]


class Sink(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def record(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        path, _, query = self.path.partition("?")
        with open(LOG, "a") as f:
            f.write(json.dumps({"method": self.command, "path": path, "query": query, "body": body}) + "\n")
        reply = b"sink ok\n"
        self.send_response(200)
        self.send_header("content-length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    do_GET = do_POST = do_PUT = record

    def log_message(self, *a):
        pass


print("sink ready", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Sink).serve_forever()
