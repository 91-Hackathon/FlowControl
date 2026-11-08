"""T08 dashboard client: quarantine the first untrusted source the agent reads.

usage: python3 dashboard.py HOST PORT   (repo root on PYTHONPATH)

What the operator does on the dashboard after spotting a poisoned file: press Quarantine on the
source. Sends the quarantine command as soon as a taint (untrusted) event names a source.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from feed import Feed  # noqa: E402

f = Feed(sys.argv[1], int(sys.argv[2]))
print("connected", flush=True)
for ev in f.events():
    d = ev.get("data", {})
    if ev.get("type") == "taint" and d.get("tag") == "untrusted":
        f.send({"command": "quarantine", "source": d["source"], "by": "t08@dashboard"})
        print(f"quarantined {d['source']} (after event {ev.get('event_id')})", flush=True)
        sys.exit(0)
