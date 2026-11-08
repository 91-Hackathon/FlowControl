"""A scripted stand-in for the Anthropic API, so the real Claude Code can be driven without a key.

usage: python3 fake_model.py PORT SCENARIO_FILE REQUEST_LOG

For an agent turn (a request with tools) whose last message isn't a tool result, it answers
with the tool calls in SCENARIO_FILE (JSON: {"text": "...", "calls": [{"name", "input"}]}).
After tool results come back, it answers "done." Requests without tools (titles etc.) get "ok".
Every request body is appended to REQUEST_LOG, so the test can check what Claude Code sent back.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, SCENARIO, LOG = int(sys.argv[1]), json.load(open(sys.argv[2])), sys.argv[3]


def sse(*events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def blocks_for(body):
    """(content blocks, stop_reason) to answer this request with."""
    if not body.get("tools"):
        return [{"type": "text", "text": "ok"}], "end_turn"
    last = (body.get("messages") or [{}])[-1]
    content = last.get("content")
    if isinstance(content, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
        return [{"type": "text", "text": "done."}], "end_turn"
    blocks = [{"type": "text", "text": SCENARIO["text"]}]
    for i, call in enumerate(SCENARIO["calls"]):
        blocks.append({"type": "tool_use", "id": f"toolu_fake{i}", "name": call["name"], "input": call["input"]})
    return blocks, "tool_use"


def stream(blocks, stop_reason):
    events = [{"type": "message_start", "message": {
        "id": "msg_fake", "type": "message", "role": "assistant", "model": "claude-fake", "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            events += [{"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}},
                       {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}}]
        else:
            events += [{"type": "content_block_start", "index": i, "content_block": {**b, "input": {}}},
                       {"type": "content_block_delta", "index": i,
                        "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}}]
        events.append({"type": "content_block_stop", "index": i})
    events += [{"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                "usage": {"output_tokens": 20}},
               {"type": "message_stop"}]
    return sse(*events)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        body = json.loads(raw or b"{}")
        with open(LOG, "a") as f:
            f.write(json.dumps({"path": self.path, "body": body}) + "\n")
        path = self.path.split("?")[0]
        if path == "/v1/messages/count_tokens":
            return self.reply(200, "application/json", b'{"input_tokens": 10}')
        if path != "/v1/messages":
            return self.reply(404, "application/json", b'{"type":"error","error":{"type":"not_found_error","message":"fake"}}')
        blocks, stop = blocks_for(body)
        if body.get("stream"):
            return self.reply(200, "text/event-stream", stream(blocks, stop))
        msg = {"id": "msg_fake", "type": "message", "role": "assistant", "model": "claude-fake", "content": blocks,
               "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 20}}
        self.reply(200, "application/json", json.dumps(msg).encode())

    def do_GET(self):
        self.reply(404, "application/json", b'{"type":"error","error":{"type":"not_found_error","message":"fake"}}')

    def reply(self, status, content_type, data):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
