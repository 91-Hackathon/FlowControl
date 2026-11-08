"""Scripted model for T06: keeps the agent working, so a stop can interrupt it mid-run.

usage: python3 fake_model.py PORT MAX_STEPS

Each turn it proposes one more harmless step (`sleep 1; echo step N`), up to MAX_STEPS, then
says done. A run left alone does MAX_STEPS steps; a run stopped partway does fewer — that gap
is how the harness sees the stop took effect. No real key.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, MAX_STEPS = int(sys.argv[1]), int(sys.argv[2])


def sse(*events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def steps_done(body):
    """How many tool results the agent has already sent back = how many steps ran."""
    n = 0
    for msg in body.get("messages", []):
        content = msg.get("content")
        if isinstance(content, list):
            n += sum(1 for b in content if isinstance(b, dict) and b.get("type") == "tool_result")
    return n


def turn(body):
    done = steps_done(body)
    if done >= MAX_STEPS:
        return [{"type": "text", "text": "done."}], "end_turn"
    cmd = f"sleep 1; echo step {done + 1}"
    return ([{"type": "text", "text": f"Step {done + 1}."},
             {"type": "tool_use", "id": f"toolu_t06_{done + 1}", "name": "Bash",
              "input": {"command": cmd, "description": f"step {done + 1}"}}], "tool_use")


def stream(blocks, stop_reason):
    events = [{"type": "message_start", "message": {
        "model": "claude-fake", "content": [], "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            events += [{"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}},
                       {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}}]
        else:
            events += [{"type": "content_block_start", "index": i, "content_block": {**b, "input": {}}},
                       {"type": "content_block_delta", "index": i,
                        "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}}]
        events.append({"type": "content_block_stop", "index": i})
    events += [{"type": "message_delta", "delta": {"stop_reason": stop_reason}, "usage": {"output_tokens": 15}},
               {"type": "message_stop"}]
    return sse(*events)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        if self.path.split("?")[0] == "/v1/messages/count_tokens":
            return self.reply("application/json", b'{"input_tokens": 10}')
        if not body.get("tools"):
            return self.reply("text/event-stream", stream([{"type": "text", "text": "ok"}], "end_turn"))
        blocks, stop = turn(body)
        self.reply("text/event-stream", stream(blocks, stop))

    def reply(self, ctype, data):
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


print("fake model ready", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
