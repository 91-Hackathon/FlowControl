"""Approvals: an "ask" tool call is held until the operator answers, bound to its action digest.

Run with: python3 -m unittest discover -t . -s tests
"""
import threading
import time
import unittest

from gateway import approvals, config, policy, server
from gateway.inspector import ToolCall
from gateway.session import Session

ASK_POLICY = policy.from_text(
    'version = "ask-test"\n'
    '[[rules]]\nid = "read_secrets"\ntools = ["Read"]\npaths = [".env", "*/.env"]\n'
    'verdict = "ask"\nreason = "Reading a secrets file needs approval."\n'
    '[[taint]]\nid = "secrets"\ntools = ["Read"]\npaths = [".env", "*/.env"]\ntag = "sensitive"\n')


class CapturedBus:
    def __init__(self):
        self.session = Session()
        self.events = []
        self.sinks = []
        self._seq = 0
        self._lock = threading.Lock()

    def emit(self, event_type, data, level=None, caused_by=None):
        with self._lock:
            self._seq += 1
            ev = {"event_id": f"evt_{self._seq:04d}", "seq": self._seq, "type": event_type,
                  "level": level, "session_state": self.session.state, "caused_by": caused_by or [], "data": data}
            self.events.append(ev)
            return ev


def handler():
    obj = server.GatewayHandler.__new__(server.GatewayHandler)  # no socket, just the methods + class attrs
    return obj


class ApprovalFlowTest(unittest.TestCase):
    def setUp(self):
        server.APPROVALS = approvals.Registry()
        server.GatewayHandler.policy = ASK_POLICY
        self.bus = CapturedBus()
        server.GatewayHandler.bus = self.bus
        self.call = ToolCall(id="toolu_a", name="Read", input={"file_path": "/workspace/.env"})

    def tearDown(self):
        server.APPROVALS.deny_all()

    def judge_async(self):
        result = {}
        t = threading.Thread(target=lambda: result.setdefault("r", handler().judge_tool_call(self.call)), daemon=True)
        t.start()
        return t, result

    def wait_for_request(self):
        for _ in range(200):
            req = [e for e in self.bus.events if e["type"] == "approval_request"]
            if req:
                return req[0]
            time.sleep(0.01)
        self.fail("no approval_request was emitted")

    def types(self):
        return [e["type"] for e in self.bus.events]

    def test_approve_releases_the_call_and_taints(self):
        t, result = self.judge_async()
        req = self.wait_for_request()
        self.assertEqual((req["level"], req["data"]["summary"]), ("yellow", "Read: /workspace/.env"))
        self.assertTrue(req["data"]["action_digest"])
        server.handle_command({"command": "approve", "target_event": req["data"]["target_event"], "by": "alice@phone"})
        t.join(5)
        self.assertIsNone(result["r"], "approved: the call is released unchanged")
        self.assertIn("approval_result", self.types())
        res = [e for e in self.bus.events if e["type"] == "approval_result"][0]
        self.assertEqual((res["data"]["result"], res["data"]["by"]), ("approved", "alice@phone"))
        self.assertTrue(self.bus.session.sensitive_data_seen, "the approved read marks the session sensitive")
        self.assertIn("taint", self.types())

    def test_deny_blocks_the_call(self):
        t, result = self.judge_async()
        req = self.wait_for_request()
        server.handle_command({"command": "deny", "target_event": req["data"]["target_event"], "by": "bob@phone"})
        t.join(5)
        self.assertIn("[FlowControl gateway] Blocked", result["r"])
        self.assertFalse(self.bus.session.sensitive_data_seen, "a denied read brings nothing in")
        self.assertEqual([e for e in self.bus.events if e["type"] == "decision"][0]["data"]["verdict"], "block")

    def test_wrong_digest_is_ignored(self):
        t, result = self.judge_async()
        req = self.wait_for_request()
        ok_before = server.APPROVALS.resolve(req["data"]["target_event"], "approved", digest="deadbeef")  # changed action
        self.assertFalse(ok_before, "an answer for a different action digest doesn't apply")
        server.handle_command({"command": "approve", "target_event": req["data"]["target_event"],
                               "action_digest": req["data"]["action_digest"], "by": "carol"})
        t.join(5)
        self.assertIsNone(result["r"])

    def test_timeout_denies(self):
        old = config.APPROVAL_TIMEOUT
        config.APPROVAL_TIMEOUT = 1
        try:
            t, result = self.judge_async()
            self.wait_for_request()
            t.join(5)
            self.assertIn("timeout", result["r"])
            self.assertEqual([e for e in self.bus.events if e["type"] == "approval_result"][0]["data"]["result"], "timeout")
        finally:
            config.APPROVAL_TIMEOUT = old

    def test_stop_releases_pending_approvals(self):
        t, result = self.judge_async()
        self.wait_for_request()   # the approval is open and waiting
        server.handle_command({"command": "stop", "by": "ops"})
        t.join(5)
        self.assertIn("[FlowControl gateway] Blocked", result["r"], "a held approval is denied when the run stops")


if __name__ == "__main__":
    unittest.main()
