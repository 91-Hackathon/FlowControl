"""T05 dashboard client: tries to misuse approvals, then answers one honestly.

usage: python3 dashboard.py HOST PORT   (repo root on PYTHONPATH)

Approval 1 (staging):     approve with a WRONG digest  -> must be ignored
                          approve with the right digest -> approved (the honest answer)
                          replay that same approve      -> must be ignored (already closed)
Approval 2 (production):  replay approval 1's message   -> must be ignored (wrong event)
                          approval 1's digest, retargeted at approval 2 -> must be ignored
                          then no answer                -> times out -> denied
Prints one line per action; exits when approval 2 has a result.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from feed import Feed  # noqa: E402

f = Feed(sys.argv[1], int(sys.argv[2]))
print("connected", flush=True)
first = None
for ev in f.events():
    t, d = ev.get("type"), ev.get("data", {})
    if t == "approval_request" and first is None:
        first = d
        f.send({"command": "approve", "target_event": d["target_event"], "action_digest": "0" * 16, "by": "t05@dashboard"})
        print(f"1: sent approve with a wrong digest for {d['summary']}", flush=True)
        time.sleep(1)
        f.send({"command": "approve", "target_event": d["target_event"], "action_digest": d["action_digest"], "by": "t05@dashboard"})
        print("1: sent approve with the right digest", flush=True)
    elif t == "approval_result" and first and d.get("target_event") == first["target_event"] and d.get("result") == "approved":
        time.sleep(0.5)
        f.send({"command": "approve", "target_event": first["target_event"], "action_digest": first["action_digest"], "by": "t05@dashboard"})
        print("1: replayed the approve after it closed", flush=True)
    elif t == "approval_request" and first is not None:
        f.send({"command": "approve", "target_event": first["target_event"], "action_digest": first["action_digest"], "by": "t05@dashboard"})
        print(f"2: replayed approval 1's message while waiting on {d['summary']}", flush=True)
        f.send({"command": "approve", "target_event": d["target_event"], "action_digest": first["action_digest"], "by": "t05@dashboard"})
        print("2: sent approval 1's digest retargeted at approval 2", flush=True)
        print("2: now giving no answer (should time out)", flush=True)
    elif t == "approval_result" and first and d.get("target_event") != first["target_event"]:
        print(f"2: result {d.get('result')}", flush=True)
        sys.exit(0)
