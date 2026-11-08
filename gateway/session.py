"""Session: what the gateway knows about one agent run.

One gateway process = one session. The session's risk is two monotonic properties (threat
model §4, category 1): whether it has read untrusted content, and whether it has read
sensitive data. `state` (protocol/EVENTS.md `session_state`) is derived from them, with
`blocked` taking over once a dangerous action has been stopped.
"""
import threading
import time


class Session:
    def __init__(self, session_id="sess_01", agent="claude-code"):
        self.id = session_id
        self.agent = agent
        self.untrusted_input_seen = False   # read a third-party file, web page, tool result, ...
        self.sensitive_data_seen = False    # read .env, a key, a credential store, ...
        self.blocked = False                # a dangerous action was stopped (sticky until heal)
        self.stopped = False                # the run was revoked: deny everything from now on
        self.stopped_by = None
        self.started_at = time.monotonic()
        self.model_requests = 0             # counted for the budget (threat model category 6)
        self.read_sources = {}              # tool_use_id -> the file/URL that call read
        self.quarantined = set()            # sources withheld from the model on read (recovery 5.1)
        self.withheld = set()               # tool_use_ids already replaced (so we emit one event each)
        self.task = None
        self._lock = threading.Lock()

    def remember_read(self, tool_use_id, source):
        if tool_use_id and source:
            with self._lock:
                self.read_sources[tool_use_id] = source

    def quarantine(self, source):
        """Mark a source so its content is replaced before the model sees it. Returns the tool_use_ids affected."""
        with self._lock:
            self.quarantined.add(source)
            return [tid for tid, src in self.read_sources.items() if src == source]

    def quarantined_id(self, tool_use_id):
        """The quarantined source this tool result came from, or None."""
        src = self.read_sources.get(tool_use_id)
        return src if src in self.quarantined else None

    def count_model_request(self):
        with self._lock:
            self.model_requests += 1
            return self.model_requests

    def over_budget(self, max_requests, ttl_seconds):
        """(reason, detail) if the run has exhausted its request budget or its lifetime, else None.
        Called BEFORE the request is counted, so `max_requests` requests are served, not one more."""
        if max_requests and self.model_requests >= max_requests:
            return "budget", f"{self.model_requests} model requests (limit {max_requests})"
        if ttl_seconds and (time.monotonic() - self.started_at) > ttl_seconds:
            return "ttl", f"session older than {ttl_seconds}s"
        return None

    @property
    def taint_state(self):
        """clean / untrusted / sensitive / tainted, from the two properties."""
        if self.untrusted_input_seen and self.sensitive_data_seen:
            return "tainted"
        if self.untrusted_input_seen:
            return "untrusted"
        if self.sensitive_data_seen:
            return "sensitive"
        return "clean"

    @property
    def state(self):
        """The session_state for the envelope. `ended` (stopped) is terminal; then `blocked`."""
        if self.stopped:
            return "ended"
        return "blocked" if self.blocked else self.taint_state

    def mark_stopped(self, by="dashboard"):
        """Revoke the run. Returns True the first time (so session_end is emitted once)."""
        with self._lock:
            if self.stopped:
                return False
            self.stopped = True
            self.stopped_by = by
            return True

    def mark_taint(self, tag):
        """Set the property for `tag`. Returns (changed, from_taint_state, to_taint_state)."""
        with self._lock:
            before = self.taint_state
            if tag == "untrusted" and not self.untrusted_input_seen:
                self.untrusted_input_seen = True
            elif tag == "sensitive" and not self.sensitive_data_seen:
                self.sensitive_data_seen = True
            else:
                return False, before, before
            return True, before, self.taint_state

    def mark_blocked(self):
        with self._lock:
            self.blocked = True

    def claim_start(self, request_body):
        """Return the task text the first time a real agent turn is seen, else None.

        Claude Code also makes small side requests (e.g. generating a chat title) with
        no tools attached; those are skipped so the task is taken from the main loop.
        """
        if not isinstance(request_body, dict) or not request_body.get("tools"):
            return None
        with self._lock:
            if self.task is not None:
                return None
            self.task = first_user_text(request_body.get("messages", [])) or "(unknown task)"
            return self.task


def first_user_text(messages, limit=200):
    """The user's first prompt, without the system reminders Claude Code adds around it."""
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            parts = [content]
        elif isinstance(content, list):
            parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        else:
            parts = []
        text = " ".join(p.strip() for p in parts if p.strip() and not p.lstrip().startswith("<system-reminder>"))
        text = " ".join(text.split())
        if text:
            return text[:limit]
    return None
