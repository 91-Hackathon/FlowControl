"""Credential broker: the agent's token is checked and swapped for the real key; failures stay inside.

Run with: python3 -m unittest discover -t . -s tests
"""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from gateway import config, credentials

TOKEN = "fc-session-test-token"
REAL = "sk-ant-real-key-for-tests"


def brokered(token=TOKEN, real=REAL):
    return mock.patch.multiple(config, SESSION_TOKEN=token, UPSTREAM_API_KEY=real)


class CheckTests(unittest.TestCase):
    def test_pass_through_when_no_session_token(self):
        with brokered(token="", real=""):
            r = credentials.check({"x-api-key": "users-own-key", "content-type": "application/json"})
        self.assertTrue(r.ok)
        self.assertEqual(r.headers["x-api-key"], "users-own-key")

    def test_token_in_x_api_key_is_swapped_for_real_key(self):
        with brokered():
            r = credentials.check({"x-api-key": TOKEN, "anthropic-version": "2023-06-01"})
        self.assertTrue(r.ok)
        self.assertEqual(r.headers["x-api-key"], REAL)
        self.assertEqual(r.headers["anthropic-version"], "2023-06-01")
        self.assertNotIn(TOKEN, json.dumps(r.headers))

    def test_bearer_token_is_accepted_and_removed(self):
        with brokered():
            r = credentials.check({"Authorization": f"Bearer {TOKEN}"})
        self.assertTrue(r.ok)
        self.assertEqual(r.headers, {"x-api-key": REAL})

    def test_wrong_or_missing_token_is_refused(self):
        for headers in ({"x-api-key": "guess"}, {"authorization": "Bearer guess"}, {}):
            with brokered():
                r = credentials.check(headers)
            self.assertFalse(r.ok, headers)
            self.assertEqual(r.status, 403)  # 403 so the agent stops instead of retrying

    def test_no_real_key_fails_closed(self):
        with brokered(real=""):
            r = credentials.check({"x-api-key": TOKEN})
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 403)  # not 5xx: agents retry those and hang
        self.assertIn("no upstream API key", r.message)


class FakeAPI(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    seen = []  # headers of every request that reached the "API"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        FakeAPI.seen.append({k.lower(): v for k, v in self.headers.items()})
        body = b'{"type":"message","content":[]}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class BrokerEndToEnd(unittest.TestCase):
    """Real HTTP through the gateway to a fake API that records what it receives."""

    @classmethod
    def setUpClass(cls):
        from gateway import events, server
        from gateway.session import Session
        from gateway.sinks import JsonlSink

        cls.tmp = tempfile.TemporaryDirectory()
        cls.sink = JsonlSink(os.path.join(cls.tmp.name, "events.jsonl"))
        cls.patches = [
            mock.patch.multiple(config, UPSTREAM_SCHEME="http", SESSION_TOKEN=TOKEN, UPSTREAM_API_KEY=REAL),
            mock.patch.object(server.GatewayHandler, "bus", events.EventBus(Session(), [cls.sink])),
        ]
        cls.api = ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI)
        threading.Thread(target=cls.api.serve_forever, daemon=True).start()
        cls.patches.append(mock.patch.object(config, "UPSTREAM_HOST", f"127.0.0.1:{cls.api.server_address[1]}"))
        for p in cls.patches:
            p.start()
        cls.gw = ThreadingHTTPServer(("127.0.0.1", 0), server.GatewayHandler)
        threading.Thread(target=cls.gw.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.gw, cls.api):
            srv.shutdown()
            srv.server_close()
        for p in reversed(cls.patches):
            p.stop()
        cls.sink.close()
        cls.tmp.cleanup()

    def setUp(self):
        FakeAPI.seen.clear()

    def post(self, headers, path="/v1/messages/count_tokens"):
        conn = http.client.HTTPConnection("127.0.0.1", self.gw.server_address[1], timeout=10)
        conn.request("POST", path, body="{}", headers={"content-type": "application/json", **headers})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_api_receives_real_key_never_the_token(self):
        status, _ = self.post({"x-api-key": TOKEN})
        self.assertEqual(status, 200)
        self.assertEqual(len(FakeAPI.seen), 1)
        self.assertEqual(FakeAPI.seen[0]["x-api-key"], REAL)
        self.assertNotIn(TOKEN, json.dumps(FakeAPI.seen[0]))

    def test_non_model_path_is_not_relayed(self):
        """Even with the right token, the gateway is not a generic relay for the real key."""
        for path in ("/v1/files", "/v1/messages/batches", "/v1/models", "/../v1/files"):
            status, data = self.post({"x-api-key": TOKEN}, path)
            self.assertEqual(status, 403, path)
            self.assertIn("path not allowed", json.loads(data)["error"]["message"])
        self.assertEqual(FakeAPI.seen, [])

    def test_model_path_with_query_is_relayed(self):
        status, _ = self.post({"x-api-key": TOKEN}, "/v1/messages/count_tokens?beta=true")
        self.assertEqual(status, 200)
        self.assertEqual(len(FakeAPI.seen), 1)

    def test_wrong_token_never_reaches_the_api(self):
        status, data = self.post({"x-api-key": "stolen-or-guessed"})
        self.assertEqual(status, 403)
        self.assertEqual(FakeAPI.seen, [])
        err = json.loads(data)
        self.assertEqual(err["type"], "error")
        self.assertEqual(err["error"]["type"], "permission_error")
        self.assertIn("unknown session token", err["error"]["message"])
        self.assertNotIn(REAL, data.decode())


if __name__ == "__main__":
    unittest.main()
