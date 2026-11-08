"""Inspection: read the LLM's response as it streams past and pull out tool calls.

The model tells the agent what to do next by returning `tool_use` blocks
("run this command", "read this file"). The agent only executes them after the
response arrives, so seeing them here means the gateway knows what the agent is
about to do *before* it does it.

This module only parses, for the numbers in the log and the llm_call event. It doesn't
print, decide or change anything; blocking is gate.py's job.
"""
import json
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict
    readable: bool = True  # False if the arguments weren't valid JSON (the policy then blocks it)


@dataclass
class ResponseSummary:
    model: str | None = None
    stop_reason: str | None = None
    input_tokens: int | None = None      # all input, including the parts served from the prompt cache
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    tool_calls: list = field(default_factory=list)


class ResponseInspector:
    """Feed it response bytes chunk by chunk; it calls on_tool_call(ToolCall) as each one completes.

    Handles both streamed (text/event-stream) and plain JSON responses.
    """

    def __init__(self, content_type, on_tool_call=None):
        self.streaming = "event-stream" in (content_type or "")
        self.on_tool_call = on_tool_call or (lambda call: None)
        self.summary = ResponseSummary()
        self._buf = b""
        self._open_blocks = {}  # index -> {"id", "name", "json"} while a tool_use is streaming in

    # ---- public -------------------------------------------------------------
    def feed(self, chunk):
        self._buf += chunk
        if not self.streaming:
            return  # plain JSON: parse once at the end
        *lines, self._buf = self._buf.split(b"\n")  # keep a trailing partial line for next time
        for line in lines:
            line = line.strip()
            if line.startswith(b"data:"):
                try:
                    event = json.loads(line[5:])
                except ValueError:
                    continue
                if isinstance(event, dict):
                    self._on_event(event)

    def finish(self):
        """Call once the response has ended. Returns the ResponseSummary."""
        if not self.streaming and self._buf:
            try:
                message = json.loads(self._buf)
            except ValueError:
                message = None
            if isinstance(message, dict):
                self._on_message(message)
        return self.summary

    # ---- streamed events ------------------------------------------------------
    def _on_event(self, ev):
        kind = ev.get("type")
        if kind == "message_start":
            msg = ev.get("message", {})
            self.summary.model = msg.get("model")
            self._read_input_usage(msg.get("usage", {}))
        elif kind == "content_block_start":
            block = ev.get("content_block", {})
            if block.get("type") == "tool_use":
                self._open_blocks[ev.get("index")] = {"id": block.get("id"), "name": block.get("name"), "json": ""}
        elif kind == "content_block_delta":
            delta = ev.get("delta", {})
            block = self._open_blocks.get(ev.get("index"))
            if block is not None and delta.get("type") == "input_json_delta":
                block["json"] += delta.get("partial_json", "")
        elif kind == "content_block_stop":
            block = self._open_blocks.pop(ev.get("index"), None)
            if block is not None:
                self._emit(block["id"], block["name"], _parse_json(block["json"]))
        elif kind == "message_delta":
            self.summary.stop_reason = ev.get("delta", {}).get("stop_reason")
            self.summary.output_tokens = ev.get("usage", {}).get("output_tokens")

    # ---- plain JSON response ----------------------------------------------------
    def _on_message(self, msg):
        self.summary.model = msg.get("model")
        self.summary.stop_reason = msg.get("stop_reason")
        usage = msg.get("usage", {})
        self._read_input_usage(usage)
        self.summary.output_tokens = usage.get("output_tokens")
        for block in msg.get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                self._emit(block.get("id"), block.get("name"), block.get("input") or {})

    def _read_input_usage(self, usage):
        # With prompt caching, "input_tokens" only counts the uncached tail; the rest is
        # reported as cache reads/writes. Add them up so the number means "input size".
        cached = (usage.get("cache_read_input_tokens") or 0) + (usage.get("cache_creation_input_tokens") or 0)
        if usage.get("input_tokens") is not None or cached:
            self.summary.input_tokens = (usage.get("input_tokens") or 0) + cached
            self.summary.cached_input_tokens = cached

    def _emit(self, call_id, name, tool_input):
        call = ToolCall(id=call_id, name=name, input=tool_input)
        self.summary.tool_calls.append(call)
        self.on_tool_call(call)


def _parse_json(text):
    try:
        value = json.loads(text) if text else {}
        return value if isinstance(value, dict) else {"value": value}
    except ValueError:
        return {"_raw": text}


def is_messages_call(path):
    """True for the endpoint that carries the conversation (not token counting etc.)."""
    return path.split("?")[0] == "/v1/messages"
