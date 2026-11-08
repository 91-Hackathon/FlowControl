"""Approvals: hold a tool call until a human answers, or until it times out.

An "ask" decision (policy verdict) pauses the exact tool call the model proposed and asks the
dashboard to approve or deny it. The request thread blocks on the Pending below; the dashboard's
answer arrives on the live-feed thread and resolves it. The approval is bound to the call's
digest, so approving one action can't release a different one (threat model category 7).

Fail closed: no answer within the timeout is a denial.
"""
import hashlib
import json
import threading


def digest(call):
    """A stable fingerprint of a tool call, so an approval binds to this exact action."""
    body = json.dumps({"tool": call.name, "input": call.input}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()[:16]


class Pending:
    def __init__(self, event_id, action_digest, timeout_s):
        self.event_id = event_id          # the tool_call event this approval is for
        self.digest = action_digest
        self.timeout_s = timeout_s
        self.result = None                # "approved" / "denied" / "timeout"
        self.by = None
        self._done = threading.Event()
        self._lock = threading.Lock()

    def _set(self, result, by):
        with self._lock:
            if self._done.is_set():
                return False
            self.result, self.by = result, by
            self._done.set()
            return True

    def wait(self):
        if not self._done.wait(self.timeout_s):
            self._set("timeout", None)    # no answer in time: fail closed
        return self.result

    def resolve(self, result, digest=None, by=None):
        """Called from the dashboard side. Returns True if this answer took effect."""
        if digest is not None and digest != self.digest:
            return False  # the action changed since the card was shown: this answer isn't for it
        return self._set(result, by)


class Registry:
    def __init__(self):
        self._by_event = {}
        self._lock = threading.Lock()

    def open(self, event_id, action_digest, timeout_s):
        pending = Pending(event_id, action_digest, timeout_s)
        with self._lock:
            self._by_event[event_id] = pending
        return pending

    def resolve(self, event_id, result, digest=None, by=None):
        with self._lock:
            pending = self._by_event.get(event_id)
        return bool(pending) and pending.resolve(result, digest, by)

    def close(self, event_id):
        with self._lock:
            self._by_event.pop(event_id, None)

    def deny_all(self, result="denied"):
        """Resolve every still-open approval (used when the run is stopped)."""
        with self._lock:
            pendings = list(self._by_event.values())
        for p in pendings:
            p.resolve(result)
