"""End-to-end: fake LLM API <- gateway <- fake agent request. Checks the events it writes.

Run with: python3 -m unittest discover tests
"""
import http.client
import json
import os
import pathlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gateway import config, policy
from gateway.session import first_user_text
from tests.test_inspector import STREAM, sse

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "protocol" / "events.schema.json").read_text())

try:
    import jsonschema
except ImportError:  # validation is skipped if jsonschema isn't installed
    jsonschema = None


TEXT_ONLY = sse(
    {"type": "message_start", "message": {"model": "claude-haiku-5-5", "usage": {"input_tokens": 50}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Fix test"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 3}},
)


# The model asks to edit the agent's own settings: the default policy blocks it.
EDIT_SETTINGS = sse(
    {"type": "message_start", "message": {"model": "claude-opus-5-5", "usage": {"input_tokens": 900}}},
    {"type": "content_block_start", "index": 0,
     "content_block": {"type": "tool_use", "id": "toolu_9", "name": "Edit", "input": {}}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(
        {"file_path": "/workspace/.claude/settings.json", "old_string": "{}", "new_string": "{\"hooks\": {}}"})}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 40}},
    {"type": "message_stop"},
)


def tool_use(index, call_id, name, inp):
    return [
        {"type": "content_block_start", "index": index,
         "content_block": {"type": "tool_use", "id": call_id, "name": name, "input": {}}},
        {"type": "content_block_delta", "index": index,
         "delta": {"type": "input_json_delta", "partial_json": json.dumps(inp)}},
        {"type": "content_block_stop", "index": index},
    ]


# The demo storyline in one response: read a third-party README (untrusted), read another
# (already untrusted: no new mark), read .env (sensitive -> tainted), then try to rewrite the
# agent's settings (blocked).
TAINT_CHAIN = sse(
    {"type": "message_start", "message": {"model": "claude-opus-5-5", "usage": {"input_tokens": 900}}},
    *tool_use(0, "toolu_r1", "Read", {"file_path": "/workspace/vendor/fastquote/README.md"}),
    *tool_use(1, "toolu_r2", "Read", {"file_path": "/workspace/vendor/fastquote/CHANGELOG.md"}),
    *tool_use(2, "toolu_r3", "Read", {"file_path": "/workspace/.env"}),
    *tool_use(3, "toolu_e1", "Edit", {"file_path": "/workspace/.claude/settings.json",
                                      "old_string": "{}", "new_string": "{}"}),
    {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 90}},
    {"type": "message_stop"},
)


# What Claude Code really did in the live test (2026-11-07): read both files with one Bash command.
BASH_READ_COMMAND = (
    "cat /workspace/vendor/fastquote/README.md; echo \"=====ENV KEYS=====\"; "
    "sed -E 's/^([[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*)=.*/\\1=<redacted>/' /workspace/.env")
BASH_READ = sse(
    {"type": "message_start", "message": {"model": "claude-opus-5-5", "usage": {"input_tokens": 900}}},
    *tool_use(0, "toolu_b1", "Bash", {"command": BASH_READ_COMMAND, "description": "Read the README and .env keys"}),
    {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 60}},
    {"type": "message_stop"},
)


class FakeAPI(BaseHTTPRequestHandler):
    """Requests with tools get a canned tool-calling stream; side requests get plain text."""
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)))
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        if not body.get("tools"):
            self.wfile.write(TEXT_ONLY)
        elif "settings" in json.dumps(body.get("messages")):
            self.wfile.write(EDIT_SETTINGS)
        elif "chain" in json.dumps(body.get("messages")):
            self.wfile.write(TAINT_CHAIN)
        elif "bash read" in json.dumps(body.get("messages")):
            self.wfile.write(BASH_READ)
        else:
            self.wfile.write(STREAM)

    def log_message(self, *args):
        pass


def start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class GatewayCase(unittest.TestCase):
    """Starts a fake API and a gateway in front of it, with the repository's default policy."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.events_file = os.path.join(cls.tmp.name, "events.jsonl")
        api = start(ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI))
        config.UPSTREAM_SCHEME = "http"
        config.UPSTREAM_HOST = f"127.0.0.1:{api.server_address[1]}"
        config.EVENTS_FILE = cls.events_file

        from gateway import events, server
        from gateway.session import Session
        from gateway.sinks import JsonlSink
        cls.sink = JsonlSink(cls.events_file)
        server.GatewayHandler.bus = events.EventBus(Session(), [cls.sink])
        server.GatewayHandler.policy = policy.load(ROOT / "policy" / "default.toml")
        cls.gw = start(ThreadingHTTPServer(("127.0.0.1", 0), server.GatewayHandler))
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.gw, cls.api):
            srv.shutdown()
            srv.server_close()
        cls.sink.close()
        cls.tmp.cleanup()

    def send(self, body, path="/v1/messages?beta=true"):
        conn = http.client.HTTPConnection("127.0.0.1", self.gw.server_address[1], timeout=10)
        conn.request("POST", path, body=json.dumps(body), headers={"content-type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def read_events(self):
        return [json.loads(line) for line in pathlib.Path(self.events_file).read_text().splitlines()]

    def validate(self, evs):
        if jsonschema:
            validator = jsonschema.Draft202012Validator(SCHEMA)
            for e in evs:
                validator.validate(e)


class GatewayEventsTest(GatewayCase):
    def test_agent_turn_produces_events(self):
        # A side request without tools (like Claude Code's title generator) must not start the session.
        self.send({"model": "claude-haiku-5-5", "messages": [{"role": "user", "content": "make a title"}]})
        status, data = self.send({
            "model": "claude-opus-5-5",
            "tools": [{"name": "Bash"}],
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "<system-reminder>ignore me</system-reminder>"},
                {"type": "text", "text": "Fix the failing test"},
            ]}],
        })
        self.assertEqual(status, 200)
        self.assertEqual(data, STREAM, "agent must receive the response byte-for-byte")

        evs = self.read_events()
        types = [e["type"] for e in evs]
        # The canned stream reads .env, which the default policy marks sensitive: one taint event.
        self.assertEqual(types, ["llm_call", "session_start", "tool_call", "tool_call", "taint", "llm_call"])
        self.assertEqual([e["seq"] for e in evs], [1, 2, 3, 4, 5, 6])
        self.assertEqual(evs[1]["data"]["task"], "Fix the failing test")
        self.assertEqual(evs[2]["data"]["summary"], "Bash: ls -la")
        self.assertEqual(evs[3]["data"]["path"], ".env")
        self.assertEqual([(e["level"], e["data"]["blocked"]) for e in evs[2:4]], [("green", False)] * 2)
        taint = evs[4]
        self.assertEqual(taint["data"], {"tag": "sensitive", "source": ".env",
                                         "from_state": "clean", "to_state": "sensitive",
                                         "rule": "secrets", "advisory": False})
        self.assertEqual(taint["caused_by"], [evs[3]["event_id"]], "taint points at the read that caused it")
        self.assertEqual((taint["level"], taint["session_state"]), (None, "sensitive"))
        self.assertEqual(evs[3]["session_state"], "clean", "the read itself is logged before the mark")
        self.assertEqual(evs[5]["data"]["tool_calls_proposed"], 2)
        self.assertEqual(evs[5]["data"]["tool_calls_blocked"], 0)
        self.assertIn("default.toml", evs[1]["data"]["policy"])
        self.validate(evs)


class GatewayBlockTest(GatewayCase):
    def test_blocked_call_never_reaches_the_agent(self):
        from gateway import server
        status, data = self.send({
            "model": "claude-opus-5-5", "tools": [{"name": "Edit"}],
            "messages": [{"role": "user", "content": "add a hook to my settings"}],
        })
        self.assertEqual(status, 200)
        self.assertNotIn(b"tool_use", data)
        self.assertNotIn(b"toolu_9", data)
        self.assertIn(b"[FlowControl gateway] Blocked Edit: /workspace/.claude/settings.json", data)
        self.assertIn(b'"stop_reason": "end_turn"', data)

        evs = self.read_events()
        self.assertEqual([e["type"] for e in evs], ["session_start", "tool_call", "decision", "llm_call"])
        call, decision, llm = evs[1], evs[2], evs[3]
        self.assertEqual((call["level"], call["data"]["blocked"]), ("red", True))
        self.assertEqual(decision["data"]["target_event"], call["event_id"])
        self.assertEqual(decision["caused_by"], [call["event_id"]])
        self.assertEqual((decision["data"]["verdict"], decision["data"]["rule"]), ("block", "protected_config"))
        self.assertEqual(decision["data"]["policy_version"], server.GatewayHandler.policy.version)
        self.assertEqual(decision["session_state"], "blocked")
        self.assertEqual((llm["data"]["tool_calls_proposed"], llm["data"]["tool_calls_blocked"]), (1, 1))
        self.validate(evs)


class GatewayTaintTest(GatewayCase):
    def test_reads_mark_the_session_and_a_block_follows(self):
        status, data = self.send({
            "model": "claude-opus-5-5", "tools": [{"name": "Read"}, {"name": "Edit"}],
            "messages": [{"role": "user", "content": "run the chain"}],
        })
        self.assertEqual(status, 200)
        self.assertIn(b"toolu_r1", data, "reads are allowed: tainting never blocks")
        self.assertNotIn(b"toolu_e1", data)

        evs = self.read_events()
        brief = [(e["type"], e["session_state"]) for e in evs]
        self.assertEqual(brief, [
            ("session_start", "clean"),
            ("tool_call", "clean"),        # Read vendor/.../README.md
            ("taint", "untrusted"),
            ("tool_call", "untrusted"),    # Read vendor/.../CHANGELOG.md: already untrusted, no new taint
            ("tool_call", "untrusted"),    # Read .env
            ("taint", "tainted"),
            ("tool_call", "tainted"),      # Edit .claude/settings.json (red)
            ("decision", "blocked"),
            ("llm_call", "blocked"),
        ])
        t1, t2 = [e for e in evs if e["type"] == "taint"]
        self.assertEqual(t1["data"], {"tag": "untrusted", "source": "/workspace/vendor/fastquote/README.md",
                                      "from_state": "clean", "to_state": "untrusted",
                                      "rule": "third_party_code", "advisory": False})
        self.assertEqual(t2["data"], {"tag": "sensitive", "source": "/workspace/.env",
                                      "from_state": "untrusted", "to_state": "tainted",
                                      "rule": "secrets", "advisory": False})
        self.assertEqual(t1["caused_by"], [evs[1]["event_id"]])
        self.assertEqual(t2["caused_by"], [evs[4]["event_id"]])
        flags = [(e["untrusted_input_seen"], e["sensitive_data_seen"]) for e in evs]
        self.assertEqual(flags[0], (False, False))
        self.assertEqual(flags[2], (True, False))
        self.assertEqual(flags[-1], (True, True), "still visible after the session is blocked")
        self.validate(evs)


class GatewayBashTaintTest(GatewayCase):
    def test_one_bash_command_reading_both_files_marks_both(self):
        status, data = self.send({
            "model": "claude-opus-5-5", "tools": [{"name": "Bash"}],
            "messages": [{"role": "user", "content": "do the bash read"}],
        })
        self.assertEqual(status, 200)
        self.assertIn(b"toolu_b1", data, "the command itself is allowed: marking never blocks")

        evs = self.read_events()
        self.assertEqual([(e["type"], e["session_state"]) for e in evs], [
            ("session_start", "clean"),
            ("tool_call", "clean"),
            ("taint", "untrusted"),
            ("taint", "tainted"),
            ("llm_call", "tainted"),
        ])
        call_id = evs[1]["event_id"]
        t1, t2 = evs[2]["data"], evs[3]["data"]
        self.assertEqual((t1["tag"], t1["source"], t1["advisory"]), ("untrusted", "/workspace/vendor/fastquote/README.md", True))
        self.assertEqual((t2["tag"], t2["source"], t2["advisory"]), ("sensitive", "/workspace/.env", True))
        self.assertEqual([evs[2]["caused_by"], evs[3]["caused_by"]], [[call_id], [call_id]])
        self.validate(evs)


class DecideEgressTest(unittest.TestCase):
    """server.decide_egress: judge a destination, emit the events, mark the session on a trifecta."""

    def setup(self):
        from gateway import events, policy, server
        from gateway.session import Session
        captured = []
        session = Session()
        server.GatewayHandler.bus = events.EventBus(session, [type("S", (), {"write": lambda s, e: captured.append(e)})()])
        server.GatewayHandler.policy = policy.from_text(
            'version = "t"\n[egress]\nallow = ["registry.npmjs.org"]')
        return server, session, captured

    def test_clean_session_allowed_host(self):
        server, session, events_ = self.setup()
        d = server.decide_egress("CONNECT", "registry.npmjs.org", 443)
        self.assertFalse(d.blocked)
        self.assertEqual([e["type"] for e in events_], ["network_request"])
        self.assertEqual(events_[0]["data"]["blocked"], False)
        self.assertEqual((events_[0]["data"]["dest_category"], events_[0]["level"]), ("allowlist", "green"))
        self.assertFalse(session.blocked)

    def test_unknown_host_blocks_without_marking_the_session(self):
        server, session, events_ = self.setup()
        d = server.decide_egress("CONNECT", "evil.example", 443)
        self.assertTrue(d.blocked)
        types = [e["type"] for e in events_]
        self.assertEqual(types, ["network_request", "decision"])
        self.assertEqual(events_[1]["data"]["rule"], "unknown_destination")
        self.assertEqual(events_[1]["caused_by"], [events_[0]["event_id"]])
        self.assertFalse(session.blocked, "a routine unknown-host denial isn't the blocked state")

    def test_tainted_session_marks_blocked(self):
        server, session, events_ = self.setup()
        session.mark_taint("untrusted")
        session.mark_taint("sensitive")
        d = server.decide_egress("POST", "registry.npmjs.org", 443)  # an allowed host, but tainted
        self.assertTrue(d.blocked)
        self.assertEqual(events_[-1]["data"]["rule"], "lethal_trifecta")
        self.assertTrue(session.blocked)
        self.assertEqual(events_[-1]["session_state"], "blocked")


class GatewayStopTest(GatewayCase):
    def test_stop_ends_the_session_and_denies_further_requests(self):
        from gateway import server
        # A normal agent turn works.
        status, _ = self.send({"model": "claude-opus-5-5", "tools": [{"name": "Bash"}],
                               "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(status, 200)
        before = len(self.read_events())

        # The operator stops the run from the dashboard.
        server.handle_command({"command": "stop", "by": "alice@dashboard"})
        end = self.read_events()[-1]
        self.assertEqual(end["type"], "session_end")
        self.assertEqual((end["data"]["result"], end["session_state"], end["level"]), ("stopped", "ended", "red"))
        self.assertIn("alice@dashboard", end["data"]["summary"])

        # A second stop is a no-op (no extra event).
        server.handle_command({"command": "stop"})
        self.assertEqual(len(self.read_events()), before + 1)

        # Every further request is refused, nothing reaches the API.
        status2, data2 = self.send({"model": "claude-opus-5-5", "tools": [{"name": "Bash"}],
                                    "messages": [{"role": "user", "content": "keep going"}]})
        self.assertEqual(status2, 403)
        self.assertIn(b"stopped", data2)
        # And egress is denied regardless of destination.
        d = server.decide_egress("CONNECT", "registry.npmjs.org", 443)
        self.assertEqual((d.blocked, d.rule), (True, "session_stopped"))


class SessionTest(unittest.TestCase):
    def test_stopped_is_terminal(self):
        from gateway.session import Session
        s = Session()
        s.mark_taint("untrusted"); s.mark_blocked()
        self.assertEqual(s.state, "blocked")
        self.assertTrue(s.mark_stopped(by="ops"))
        self.assertEqual(s.state, "ended")           # terminal: overrides blocked/tainted
        self.assertEqual(s.stopped_by, "ops")
        self.assertFalse(s.mark_stopped(), "stopping twice is a no-op")

    def test_state_machine(self):
        from gateway.session import Session
        s = Session()
        self.assertEqual(s.state, "clean")
        self.assertEqual(s.mark_taint("untrusted"), (True, "clean", "untrusted"))
        self.assertEqual(s.mark_taint("untrusted"), (False, "untrusted", "untrusted"), "marks once")
        self.assertEqual(s.mark_taint("sensitive"), (True, "untrusted", "tainted"))
        self.assertEqual(s.state, "tainted")
        s.mark_blocked()
        self.assertEqual((s.state, s.taint_state), ("blocked", "tainted"), "blocked dominates; taint is kept")
        self.assertEqual(s.mark_taint("bogus"), (False, "tainted", "tainted"))
        s2 = Session()
        self.assertEqual(s2.mark_taint("sensitive"), (True, "clean", "sensitive"))

    def test_first_user_text(self):
        self.assertEqual(first_user_text([{"role": "user", "content": "  hi\nthere "}]), "hi there")
        self.assertIsNone(first_user_text([{"role": "assistant", "content": "x"}]))


if __name__ == "__main__":
    unittest.main()


class IntegrityTest(unittest.TestCase):
    def test_hash_chain_detects_tampering(self):
        from gateway import events
        from gateway.session import Session
        bus = events.EventBus(Session(), [])
        evs = [bus.emit("tool_call", {"tool": "Read", "summary": "x", "target": "local"}) for _ in range(5)]
        ok, bad = events.verify_chain(evs)
        self.assertTrue(ok, f"intact chain should verify (broke at {bad})")
        # Tamper with one event's data: the chain no longer verifies, and points at the edit.
        evs[2]["data"]["summary"] = "forged"
        ok, bad = events.verify_chain(evs)
        self.assertFalse(ok)
        self.assertEqual(bad, evs[2]["seq"])
        # Dropping an event (truncation) also breaks the chain.
        ok, bad = events.verify_chain(evs[:1] + evs[2:])
        self.assertFalse(ok)
