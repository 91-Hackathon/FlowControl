"""Gate: hold back each tool call the model proposes until the policy has judged it.

The response streams to the agent as before, except that a `tool_use` block is held until
it is complete (the agent can't act on a half-received call anyway), judged, and then
either released byte-for-byte or replaced by a text block saying it was blocked. The agent
never receives a blocked call, so it can't run it, whatever its own permission settings are.

If every tool call in a response is blocked, stop_reason "tool_use" becomes "end_turn":
the agent stops and shows the notice instead of waiting for results that will never come.

Fail closed: anything the gate can't read is not forwarded. The response is cut off with
an API error event instead.

Only `tool_use` blocks are gated: those are the calls the agent executes. Server-side tools
(e.g. web search, which runs at the provider) are outside this gate.
"""
import json
import re

from .inspector import ToolCall

_LINE = re.compile(r"\r\n|\r|\n")  # SSE line endings (str.splitlines would also split on U+2028 etc.)


class ToolGate:
    def __init__(self, content_type, judge):
        """judge(ToolCall) returns None to allow the call, or the text to send instead of it."""
        self.streaming = "event-stream" in (content_type or "").lower()
        self.judge = judge
        self.seen = 0      # tool calls proposed in this response
        self.blocked = 0   # tool calls replaced
        self._buf = b""
        self._held = None  # the tool_use block being received
        self._out = []     # checked bytes ready to send
        self._failed = False

    # ---- public ---------------------------------------------------------------------
    def feed(self, chunk):
        """Upstream bytes in; the bytes that may be sent to the agent now out."""
        if self._failed:
            return b""
        self._buf += chunk
        if not self.streaming:
            return b""  # a plain JSON body is judged whole, in finish()
        try:
            self._drain()
        except Exception as exc:
            self._fail(f"couldn't read the model's response ({exc})")
        return self._take()

    def finish(self):
        """Call once upstream has ended. Returns the last bytes to send."""
        if self._failed:
            return b""
        try:
            if not self.streaming:
                self._out.append(self._judge_json(self._buf))
            else:
                self._drain()
                # An unfinished last event is dropped (as SSE clients do), and a tool call that
                # never completed is never released.
                self._buf, self._held = b"", None
        except Exception as exc:
            self._fail(f"couldn't read the model's response ({exc})")
        return self._take()

    # ---- streamed responses -------------------------------------------------------------
    def _take(self):
        out, self._out = b"".join(self._out), []
        return out

    def _drain(self):
        while (end := _event_end(self._buf)) >= 0:
            raw, self._buf = self._buf[:end], self._buf[end:]
            self._out.append(self._on_event(raw))

    def _on_event(self, raw):
        name, data = parse_event(raw)
        if data is None:  # comment or keep-alive: nothing an SSE client acts on
            if self._held is not None:
                self._held["events"].append(raw)
                return b""
            return raw
        ev = json.loads(data)
        if not isinstance(ev, dict):
            raise ValueError("event data isn't a JSON object")
        kind = ev.get("type")
        if name is not None and name != kind:
            raise ValueError(f"event name {name!r} doesn't match its type {kind!r}")

        if self._held is not None:
            return self._while_held(kind, ev, raw)
        if kind == "content_block_start" and (ev.get("content_block") or {}).get("type") == "tool_use":
            block = ev["content_block"]
            self._held = {"index": ev.get("index"), "id": block.get("id"), "name": block.get("name"),
                          "input": block.get("input"), "json": "", "has_delta": False, "events": [raw]}
            return b""
        if kind == "message_delta":
            return self._message_delta(ev, raw)
        return raw

    def _while_held(self, kind, ev, raw):
        held = self._held
        same_block = ev.get("index") == held["index"]
        if kind == "content_block_delta" and same_block:
            delta = ev.get("delta") or {}
            if delta.get("type") != "input_json_delta":
                raise ValueError(f"unexpected {delta.get('type')!r} inside a tool call")
            held["json"] += delta.get("partial_json") or ""
            held["has_delta"] = True
            held["events"].append(raw)
            return b""
        if kind == "content_block_stop" and same_block:
            held["events"].append(raw)
            self._held = None
            return self._release_or_replace(held)
        if kind == "ping":
            held["events"].append(raw)
            return b""
        if kind == "error":  # upstream gave up mid-call: drop the call, pass the error on
            self._held = None
            return raw
        raise ValueError(f"unexpected {kind!r} while a tool call was streaming")

    def _release_or_replace(self, held):
        # Same rule the Anthropic SDK uses: streamed JSON deltas, if any, are the input.
        if held["has_delta"]:
            try:
                value = json.loads(held["json"]) if held["json"].strip() else {}
            except ValueError:
                value = None
        else:
            value = held["input"] if held["input"] is not None else {}
        text = self._ask(held["id"], held["name"], value)
        if text is None:
            return b"".join(held["events"])
        i = held["index"]
        return (sse("content_block_start", {"type": "content_block_start", "index": i,
                                            "content_block": {"type": "text", "text": ""}})
                + sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                              "delta": {"type": "text_delta", "text": text}})
                + sse("content_block_stop", {"type": "content_block_stop", "index": i}))

    def _message_delta(self, ev, raw):
        delta = ev.get("delta") or {}
        if delta.get("stop_reason") == "tool_use" and self.seen and self.blocked == self.seen:
            return sse("message_delta", {**ev, "delta": {**delta, "stop_reason": "end_turn"}})
        return raw

    # ---- plain JSON responses -------------------------------------------------------------
    def _judge_json(self, body):
        msg = json.loads(body)
        if not isinstance(msg, dict):
            raise ValueError("response isn't a JSON object")
        content = msg.get("content")
        if not isinstance(content, list):
            return body
        new, changed = [], False
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                text = self._ask(block.get("id"), block.get("name"), block.get("input"))
                if text is not None:
                    new.append({"type": "text", "text": text})
                    changed = True
                    continue
            new.append(block)
        if not changed:
            return body  # untouched: the agent gets the original bytes
        msg = {**msg, "content": new}
        if msg.get("stop_reason") == "tool_use" and self.blocked == self.seen:
            msg["stop_reason"] = "end_turn"
        return json.dumps(msg, ensure_ascii=False).encode()

    # ---- shared ------------------------------------------------------------------------------
    def _ask(self, call_id, name, value):
        self.seen += 1
        readable = isinstance(value, dict) and isinstance(name, str)
        call = ToolCall(id=call_id, name=name if isinstance(name, str) else "?",
                        input=value if isinstance(value, dict) else {}, readable=readable)
        try:
            text = self.judge(call)
        except Exception as exc:  # judging failed: the call doesn't go through
            text = f"[FlowControl gateway] Blocked {call.name}: the gateway couldn't judge this call ({exc})."
        if text is not None:
            self.blocked += 1
        return text

    def _fail(self, reason):
        """Stop forwarding. Events already checked still go out; then an API error ends the response."""
        self._failed = True
        self._buf, self._held = b"", None
        payload = {"type": "error", "error": {
            "type": "api_error",
            "message": f"FlowControl gateway: {reason}. The response was stopped so nothing unchecked reaches the agent."}}
        self._out.append(sse("error", payload) if self.streaming else json.dumps(payload).encode())


def _event_end(buf):
    """Index just past the blank line that ends the first complete event, or -1."""
    ends = [i + n for i, n in ((buf.find(b"\n\n"), 2), (buf.find(b"\r\n\r\n"), 4)) if i >= 0]
    return min(ends) if ends else -1


def parse_event(raw):
    """(event name or None, data or None) for one SSE event."""
    name, data = None, []
    for line in _LINE.split(raw.decode("utf-8")):
        if not line or line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            name = value
        elif field == "data":
            data.append(value)
    return name, ("\n".join(data) if data else None)


def sse(name, data):
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode()
