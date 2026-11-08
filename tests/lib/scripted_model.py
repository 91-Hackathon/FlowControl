"""Scripted stand-in for the Anthropic API, shared by the T02/T05/T07/T08/T11 harnesses. No real key.

usage: python3 scripted_model.py PORT SCRIPT_JSON REQUEST_LOG

SCRIPT_JSON:
  {
    "scenarios": {                       # chosen by a word in the typed prompt (case-insensitive)
      "deploy": [                        # one entry per turn step: the tool calls for that step
        [{"name": "Bash", "input": {"command": "./deploy.sh staging"}}],
        [{"name": "Bash", "input": {"command": "./deploy.sh production"}}]
      ]
    },
    "loop": {"word": "forever", "call": {...}},  # optional: repeat this call on every step (T07)
    "watch": ["MARKER"]                  # optional: log whether each marker appears in a request body
  }

Step = how many tool results the conversation already holds, so step N runs after the agent
returned the results of step N-1. After the last step the model says "done.". Requests with no
tools (titles, token counting) get a plain answer. The tool calls are scripted, so a block is the
gateway's doing, not the model declining (threat model §8: a synthetic tool-action replay).

Each request is logged as one JSON line: path, scenario, step, which watch markers the body
contains, and a short preview of each tool_result the agent sent back (what the model "saw").
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, SCRIPT, LOG = int(sys.argv[1]), json.load(open(sys.argv[2])), sys.argv[3]
SCENARIOS = SCRIPT.get("scenarios", {})
LOOP = SCRIPT.get("loop")
WATCH = SCRIPT.get("watch", [])


def sse(events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def message(blocks, stop_reason):
    events = [{"type": "message_start", "message": {
        "id": "msg_scripted", "type": "message", "role": "assistant", "model": "claude-scripted", "content": [],
        "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            events += [{"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}},
                       {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}}]
        else:
            events += [{"type": "content_block_start", "index": i,
                        "content_block": {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}},
                       {"type": "content_block_delta", "index": i,
                        "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}}]
        events.append({"type": "content_block_stop", "index": i})
    events += [{"type": "message_delta", "delta": {"stop_reason": stop_reason}, "usage": {"output_tokens": 20}},
               {"type": "message_stop"}]
    return sse(events)


DONE = message([{"type": "text", "text": "done."}], "end_turn")


def tool_results(messages):
    out = []
    for m in messages:
        if m.get("role") == "user" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    c = b.get("content")
                    if isinstance(c, list):
                        c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                    out.append(str(c or "")[:300])
    return out


def user_prompt(messages):
    """The prompt the user typed: the LAST text block of the first user message. Claude Code puts
    its own context (git status, reminders) in earlier blocks, and that text must not pick a scenario."""
    for m in messages:
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str):
                return c
            texts = [b.get("text", "") for b in c or [] if isinstance(b, dict) and b.get("type") == "text"]
            texts = [t for t in texts if not t.lstrip().startswith("<system-reminder>")]
            return texts[-1] if texts else ""
    return ""


def pick(prompt, words):
    low = prompt.lower()
    return next((w for w in words if w.lower() in low), None)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}"
        body = json.loads(raw)
        text = raw.decode("utf-8", "replace")
        messages = body.get("messages") or []
        prompt = user_prompt(messages)
        results = tool_results(messages)
        step = len(results) if not LOOP else sum(1 for m in messages if m.get("role") == "assistant")
        name = pick(prompt, SCENARIOS)
        if LOOP and pick(prompt, [LOOP["word"]]):
            name = "loop"
        entry = {"path": self.path.split("?")[0], "scenario": name, "step": step, "tools": bool(body.get("tools")),
                 "watch": {w: (w in text) for w in WATCH}, "results": results[-3:]}
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if entry["path"] == "/v1/messages/count_tokens":
            return self.reply(b'{"input_tokens": 10}')
        if not body.get("tools") or name is None:
            return self.send_stream(DONE)
        if name == "loop":
            calls = [LOOP["call"]]
        else:
            steps = SCENARIOS[name]
            if step >= len(steps):
                return self.send_stream(DONE)
            calls = steps[step]
        blocks = [{"type": "text", "text": f"Step {step + 1}."}]
        blocks += [{"type": "tool_use", "id": f"toolu_s{step}_{i}", **c} for i, c in enumerate(calls)]
        self.send_stream(message(blocks, "tool_use"))

    def reply(self, data):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def send_stream(self, data):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


print("scripted model ready", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
