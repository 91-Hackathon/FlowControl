"""The gate: held tool calls are released unchanged or replaced; anything unreadable is cut off.

Run with: python3 -m unittest discover -t . -s tests
"""
import json
import unittest

from gateway.gate import ToolGate, parse_event
from tests.test_inspector import STREAM, sse

SSE = "text/event-stream; charset=utf-8"


def events_of(stream):
    """The JSON payloads of an SSE byte stream, in order."""
    out = []
    for raw in stream.replace(b"\r\n", b"\n").split(b"\n\n"):
        if raw.strip():
            _, data = parse_event(raw + b"\n\n")
            if data is not None:
                out.append(json.loads(data))
    return out


def run(stream, judge, chunk=8192, content_type=SSE):
    gate = ToolGate(content_type, judge)
    out = b"".join(gate.feed(stream[i:i + chunk]) for i in range(0, len(stream), chunk))
    return out + gate.finish(), gate


def block_tool(name):
    return lambda c: f"[FlowControl gateway] Blocked {c.name}" if c.name == name else None


class AllowTests(unittest.TestCase):
    def test_allowed_stream_is_byte_for_byte_identical_at_any_chunk_size(self):
        for size in (1, 3, 17, 64, 8192):
            seen = []
            out, gate = run(STREAM, lambda c: seen.append((c.name, c.input)), chunk=size)
            self.assertEqual(out, STREAM, size)
            self.assertEqual(seen, [("Bash", {"command": "ls -la"}), ("Read", {"file_path": ".env"})])
            self.assertEqual((gate.seen, gate.blocked), (2, 0))

    def test_crlf_streams_pass_too(self):
        crlf = STREAM.replace(b"\n", b"\r\n")
        out, _ = run(crlf, lambda c: None, chunk=5)
        self.assertEqual(out, crlf)

    def test_input_without_deltas_comes_from_the_start_block(self):
        s = sse({"type": "content_block_start", "index": 0,
                 "content_block": {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "rm -rf /"}}},
                {"type": "content_block_stop", "index": 0})
        seen = []
        run(s, lambda c: seen.append(c.input))
        self.assertEqual(seen, [{"command": "rm -rf /"}])


class BlockTests(unittest.TestCase):
    def test_blocked_call_is_replaced_and_turn_ends(self):
        only_bash = sse(*[e for e in events_of(STREAM)
                          if e.get("index") != 2 or e["type"] == "message_delta"])
        out, gate = run(only_bash, block_tool("Bash"), chunk=7)
        evs = events_of(out)
        self.assertNotIn(b"tool_use", out, "a blocked call must never reach the agent")
        self.assertNotIn(b"ls -la", out)
        starts = [e["content_block"] for e in evs if e["type"] == "content_block_start"]
        self.assertEqual([b["type"] for b in starts], ["text", "text"])
        notice = [e["delta"]["text"] for e in evs if e["type"] == "content_block_delta" and e["index"] == 1]
        self.assertEqual(notice, ["[FlowControl gateway] Blocked Bash"])
        stop = [e for e in evs if e["type"] == "message_delta"][0]
        self.assertEqual(stop["delta"]["stop_reason"], "end_turn")
        self.assertEqual(stop["usage"], {"output_tokens": 88}, "other fields are kept")
        self.assertEqual((gate.seen, gate.blocked), (1, 1))

    def test_one_of_two_blocked_keeps_the_other_and_tool_use(self):
        out, gate = run(STREAM, block_tool("Bash"), chunk=11)
        evs = events_of(out)
        tools = [e["content_block"]["name"] for e in evs
                 if e["type"] == "content_block_start" and e["content_block"]["type"] == "tool_use"]
        self.assertEqual(tools, ["Read"])
        self.assertEqual([e for e in evs if e["type"] == "message_delta"][0]["delta"]["stop_reason"], "tool_use")
        self.assertEqual([e["index"] for e in evs if e["type"] == "content_block_start"], [0, 1, 2])
        self.assertEqual((gate.seen, gate.blocked), (2, 1))

    def test_judge_crash_blocks(self):
        def boom(c):
            raise RuntimeError("sink full")
        out, gate = run(STREAM, boom)
        self.assertNotIn(b"tool_use", out)
        self.assertIn(b"couldn't judge this call", out)
        self.assertEqual(gate.blocked, 2)


class FailClosedTests(unittest.TestCase):
    def assert_cut_off(self, out):
        self.assertNotIn(b'"tool_use"', out)
        self.assertEqual(events_of(out)[-1]["type"], "error")

    def test_unreadable_event_cuts_the_stream(self):
        bad = STREAM.replace(b'"type": "content_block_start", "index": 1', b'"type": "content_block_start", "index": 1,,')
        out, _ = run(bad, lambda c: None)
        self.assert_cut_off(out)
        self.assertTrue(out.startswith(STREAM[:40]), "events before the bad one were already sent")

    def test_event_name_must_match_its_type(self):
        sneaky = (b"event: ping\ndata: " + json.dumps({"type": "content_block_start", "index": 0, "content_block": {
            "type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "x"}}}).encode() + b"\n\n")
        out, _ = run(sneaky, lambda c: None)
        self.assert_cut_off(out)

    def test_unparseable_tool_arguments_reach_the_judge_as_unreadable(self):
        s = sse({"type": "content_block_start", "index": 0,
                 "content_block": {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"comm"}},
                {"type": "content_block_stop", "index": 0})
        seen = []
        run(s, lambda c: seen.append(c.readable) or "blocked")
        self.assertEqual(seen, [False])

    def test_unexpected_event_inside_a_tool_call_cuts_the_stream(self):
        s = sse({"type": "content_block_start", "index": 0,
                 "content_block": {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}},
                {"type": "content_block_start", "index": 1,
                 "content_block": {"type": "tool_use", "id": "t2", "name": "Bash", "input": {}}})
        out, _ = run(s, lambda c: None)
        self.assert_cut_off(out)

    def test_truncated_tool_call_is_never_released(self):
        cut = STREAM[:STREAM.index(b'"index": 1, "delta"') + 40]
        out, gate = run(cut, lambda c: None, chunk=9)
        self.assertNotIn(b'"tool_use"', out)
        self.assertEqual(gate.seen, 0)

    def test_nothing_is_sent_after_a_failure(self):
        gate = ToolGate(SSE, lambda c: None)
        first = gate.feed(b"data: {not json}\n\n")
        self.assertIn(b"error", first)
        self.assertEqual(gate.feed(STREAM), b"")
        self.assertEqual(gate.finish(), b"")


class JsonResponseTests(unittest.TestCase):
    MESSAGE = {"id": "msg_1", "type": "message", "role": "assistant", "model": "m", "stop_reason": "tool_use",
               "content": [{"type": "text", "text": "ok"},
                           {"type": "tool_use", "id": "t1", "name": "Write", "input": {"file_path": "/workspace/.claude/x"}}],
               "usage": {"input_tokens": 1, "output_tokens": 1}}

    def test_untouched_when_allowed(self):
        body = json.dumps(self.MESSAGE).encode()
        out, gate = run(body, lambda c: None, chunk=10, content_type="application/json")
        self.assertEqual(out, body)
        self.assertEqual(gate.seen, 1)

    def test_blocked_call_replaced(self):
        out, _ = run(json.dumps(self.MESSAGE).encode(), block_tool("Write"), content_type="application/json")
        msg = json.loads(out)
        self.assertEqual([b["type"] for b in msg["content"]], ["text", "text"])
        self.assertEqual(msg["stop_reason"], "end_turn")

    def test_unreadable_json_is_an_error(self):
        out, _ = run(b'{"content": [', lambda c: None, content_type="application/json")
        self.assertEqual(json.loads(out)["type"], "error")


if __name__ == "__main__":
    unittest.main()
