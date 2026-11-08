"""Events: build messages in the format defined in protocol/EVENTS.md and send them to sinks.

Builders only fill in the fields; EventBus adds the envelope (id, seq, time, session)
and hands the finished event to every sink. Risk is decided in policy.py; tool calls get
its traffic light as `level`, other events stay null ("not judged").
"""
import hashlib
import json
import threading
from datetime import datetime, timezone

from . import config
from .describe import describe, key_detail

NETWORK_TOOLS = {"WebFetch", "WebSearch"}
MAX_INPUT = 200
GENESIS = "0" * 64


def _hash(prev_hash, event):
    """Chain hash: depends on this event and the one before it, so any later edit is detectable."""
    core = {k: event[k] for k in event if k != "hash"}
    return hashlib.sha256((prev_hash + json.dumps(core, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()


def verify_chain(events):
    """(True, None) if the hash chain is intact, else (False, seq of the first broken event)."""
    prev = GENESIS
    for e in events:
        if e.get("prev_hash") != prev or e.get("hash") != _hash(prev, e):
            return False, e.get("seq")
        prev = e["hash"]
    return True, None


class EventBus:
    def __init__(self, session, sinks):
        self.session = session
        self.sinks = list(sinks)
        self._seq = 0
        self._prev_hash = GENESIS
        self._lock = threading.Lock()  # requests are handled on several threads

    def emit(self, event_type, data, level=None, caused_by=None):
        with self._lock:
            self._seq += 1
            event = {
                "event_id": f"evt_{self._seq:04d}",
                "session_id": self.session.id,
                "seq": self._seq,
                "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "type": event_type,
                "level": level,
                "session_state": self.session.state,
                # The two properties session_state is derived from (threat model §9). Kept separate
                # because "blocked" hides them: the dashboard can still show what the session had read.
                "untrusted_input_seen": self.session.untrusted_input_seen,
                "sensitive_data_seen": self.session.sensitive_data_seen,
                "caused_by": caused_by or [],
                "data": data,
            }
            # Tamper-evident chain: each event commits to the previous one's hash (category 7).
            event["prev_hash"] = self._prev_hash
            event["hash"] = _hash(self._prev_hash, event)
            self._prev_hash = event["hash"]
            for sink in self.sinks:
                sink.write(event)
        return event


# ---- builders: one per event type the gateway can produce today ------------------

def session_start(session, task, policy=None):
    data = {"agent": session.agent, "task": task}
    if policy is not None:
        data["policy"] = "unavailable" if policy.error else f"{policy.source} ({policy.version})"
    return data


def llm_call(summary, duration_ms, overhead_ms, blocked=0, canary_hit=False):
    return {
        "provider": "anthropic",
        "destination": config.UPSTREAM_HOST,
        "model": summary.model or "unknown",
        "input_tokens": summary.input_tokens or 0,
        "cached_input_tokens": summary.cached_input_tokens or 0,
        "output_tokens": summary.output_tokens or 0,
        "tool_calls_proposed": len(summary.tool_calls),
        "tool_calls_blocked": blocked,         # replaced by the gate before the agent got them
        "canary_hit": canary_hit,              # a secret marker appeared in the request to the model
        "latency_ms": round(overhead_ms, 2),   # time the gateway itself added
        "duration_ms": round(duration_ms),     # whole round trip, mostly the model thinking
    }


def tool_call(call, decision=None):
    data = {
        "tool": call.name,
        "summary": describe(call),
        "input": key_detail(call, MAX_INPUT),
        "target": "network" if call.name in NETWORK_TOOLS else "local",
        "blocked": bool(decision and decision.blocked),
        "tool_use_id": call.id,
    }
    path = call.input.get("file_path") or call.input.get("notebook_path")
    if path:
        data["path"] = str(path)
    return data


def decision(target_event, d, policy_version):
    return {
        "target_event": target_event,
        "verdict": d.verdict,
        "rule": d.rule,
        "reason": d.reason,
        "decided_by": "rule",
        "advisory": d.advisory,          # True: matched on shell text (a miss would have proved nothing)
        "policy_version": policy_version,
    }


def taint(hit, from_state, to_state):
    return {
        "tag": hit.tag,
        "source": hit.source,
        "from_state": from_state,
        "to_state": to_state,
        "rule": hit.rule,           # the [[taint]] entry that matched
        "advisory": hit.advisory,   # True: matched on shell text (a miss would have proved nothing)
    }


def network_request(method, host, decision, latency_ms=None):
    return {
        "method": method,                 # GET, POST, CONNECT (an HTTPS tunnel)
        "destination": host,
        "dest_category": decision.category,  # "allowlist" or "unknown" (the model route is separate)
        "blocked": decision.blocked,
        "latency_ms": None if decision.blocked else latency_ms,
    }


def egress_decision(target_event, decision, policy_version):
    return {
        "target_event": target_event,
        "verdict": decision.verdict,
        "rule": decision.rule,
        "reason": decision.reason,
        "decided_by": "rule",
        "policy_version": policy_version,
    }


def session_end(result, summary):
    return {"result": result, "summary": summary}  # result: completed / stopped / failed


def approval_request(target_event, call, decision, action_digest, timeout_s, policy_version):
    from .describe import describe
    return {
        "target_event": target_event,
        "summary": describe(call),
        "reason": decision.reason,
        "timeout_s": timeout_s,
        "action_digest": action_digest,   # the approval binds to this exact action (category 7)
        "policy_version": policy_version,
    }


def approval_result(target_event, result, by):
    return {"target_event": target_event, "result": result, "by": by}  # approved / denied / timeout


def quarantine(source, tool_use_id=None):
    data = {"source": source, "placeholder": _quarantine_placeholder(source)}
    if tool_use_id:
        data["tool_use_id"] = tool_use_id
    return data


def heal(source, rolled_back_to, removed_events):
    """The full-recovery event (rollback + restart). rolled_back_to is the last clean event id."""
    return {
        "quarantined_source": source,
        "rolled_back_to": rolled_back_to,
        "removed_events": list(removed_events),
        "status": "success",
        "message_to_agent": f"The source {source} was withheld as untrusted; continue with the original task.",
    }


def _quarantine_placeholder(source):
    from .quarantine import placeholder
    return placeholder(source)
