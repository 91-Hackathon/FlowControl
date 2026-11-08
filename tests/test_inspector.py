"""Run with: python3 -m unittest discover tests"""
import json
import unittest

from gateway.describe import describe
from gateway.inspector import ResponseInspector, ToolCall, is_messages_call


def sse(*events):
    """Build an SSE stream the way the Anthropic API sends it."""
    return b"".join(
        f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events
    )


STREAM = sse(
    {"type": "message_start", "message": {"model": "claude-opus-5-5", "usage": {"input_tokens": 1200}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Let me look."}},
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1,
     "content_block": {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {}}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"comm"}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "and\": \"ls -la\"}"}},
    {"type": "content_block_stop", "index": 1},
    {"type": "content_block_start", "index": 2,
     "content_block": {"type": "tool_use", "id": "toolu_2", "name": "Read", "input": {}}},
    {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": "{\"file_path\": \".env\"}"}},
    {"type": "content_block_stop", "index": 2},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 88}},
    {"type": "message_stop"},
)


class StreamTests(unittest.TestCase):
    def run_stream(self, chunk_size):
        seen = []
        insp = ResponseInspector("text/event-stream; charset=utf-8", on_tool_call=seen.append)
        for i in range(0, len(STREAM), chunk_size):
            insp.feed(STREAM[i:i + chunk_size])
        return seen, insp.finish()

    def test_tool_calls_survive_any_chunk_boundary(self):
        for size in (1, 7, 64, 8192):
            seen, summary = self.run_stream(size)
            self.assertEqual([(c.name, c.input) for c in seen],
                             [("Bash", {"command": "ls -la"}), ("Read", {"file_path": ".env"})], size)
            self.assertEqual(summary.model, "claude-opus-5-5")
            self.assertEqual(summary.stop_reason, "tool_use")
            self.assertEqual(summary.input_tokens, 1200)
            self.assertEqual(summary.output_tokens, 88)

    def test_cached_tokens_are_counted_as_input(self):
        insp = ResponseInspector("text/event-stream")
        insp.feed(sse({"type": "message_start", "message": {"model": "m", "usage": {
            "input_tokens": 2, "cache_read_input_tokens": 15000, "cache_creation_input_tokens": 300}}}))
        summary = insp.finish()
        self.assertEqual(summary.input_tokens, 15302)
        self.assertEqual(summary.cached_input_tokens, 15300)

    def test_garbage_lines_are_ignored(self):
        insp = ResponseInspector("text/event-stream")
        insp.feed(b"data: not json\n\ndata: [1,2]\n\n: comment\n\n")
        self.assertEqual(insp.finish().tool_calls, [])


class JsonTests(unittest.TestCase):
    def test_plain_json_response(self):
        body = json.dumps({
            "model": "claude-haiku-5-5", "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "content": [{"type": "tool_use", "id": "t", "name": "Grep", "input": {"pattern": "TODO"}}],
        }).encode()
        insp = ResponseInspector("application/json")
        insp.feed(body[:20])
        insp.feed(body[20:])
        summary = insp.finish()
        self.assertEqual(summary.model, "claude-haiku-5-5")
        self.assertEqual([c.name for c in summary.tool_calls], ["Grep"])


class HelperTests(unittest.TestCase):
    def test_is_messages_call(self):
        self.assertTrue(is_messages_call("/v1/messages"))
        self.assertTrue(is_messages_call("/v1/messages?beta=true"))
        self.assertFalse(is_messages_call("/v1/messages/count_tokens?beta=true"))

    def test_describe(self):
        self.assertEqual(describe(ToolCall("1", "Bash", {"command": "ls\n-la"})), "Bash: ls -la")
        self.assertEqual(describe(ToolCall("2", "Read", {"file_path": ".env"})), "Read: .env")
        self.assertTrue(describe(ToolCall("3", "mcp__x__y", {"a": 1})).startswith("mcp__x__y: {"))
        self.assertTrue(describe(ToolCall("4", "Bash", {"command": "x" * 500})).endswith("..."))

    def test_event_input_keeps_200_chars(self):
        from gateway.events import tool_call
        data = tool_call(ToolCall("5", "Bash", {"command": "x" * 500}))
        self.assertEqual(len(data["input"]), 200)
        self.assertLess(len(data["summary"]), 140)


if __name__ == "__main__":
    unittest.main()
