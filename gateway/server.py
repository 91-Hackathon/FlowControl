"""HTTP server: accepts the agent's requests, forwards them, and reports what it sees.

Per request: receive -> forward -> stream the response back through the gate (which holds
each tool call until the policy has judged it) while the inspector reads it -> print a log
line and emit structured events.
"""
import json
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import approvals, config, credentials, events, forwarder, live, policy, proxy, quarantine, routes, settings
from .describe import describe
from .gate import ToolGate
from .inspector import ResponseInspector, is_messages_call
from .session import Session
from .sinks import JsonlSink

APPROVALS = approvals.Registry()  # open approvals waiting on the dashboard
SETTINGS = None  # set by run(): dashboard switches and operator rules on top of the policy file


def stamp():
    return datetime.now().strftime("%H:%M:%S")


class GatewayHandler(BaseHTTPRequestHandler):
    # HTTP/1.0 + "connection: close": the response body ends when we close the
    # socket, so streamed (SSE) responses pass through without re-chunking.
    protocol_version = "HTTP/1.0"
    bus = None     # set by run()
    policy = None  # set by run(): the rules tool calls are judged against

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        started = time.monotonic()
        self.overhead = 0.0  # seconds spent in gateway logic (not waiting on the network)
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""

        if self.bus.session.stopped:  # the run was revoked: nothing more reaches the API
            return self.refuse(403, "permission_error",
                               "FlowControl gateway: the session was stopped by the operator; no further requests are served.")
        watching = is_messages_call(self.path)   # a real agent turn (not token-counting etc.)
        if watching:
            over = self.policy.budget and self.bus.session.over_budget(config.MAX_MODEL_REQUESTS, config.SESSION_TTL)
            if over:
                self.auto_stop(*over)
                return self.refuse(403, "permission_error",
                                   f"FlowControl gateway: the run was stopped automatically ({over[1]}).")
            self.bus.session.count_model_request()
            body = self.quarantine_body(body)   # replace any poisoned source before it reaches the model
        self.canary_hit = self.policy.check_canaries and policy.body_has_canary(body, self.policy.canaries or config.CANARIES)
        auth = credentials.check(self.headers)
        if not auth.ok:  # refused here: nothing reaches the API
            return self.refuse(auth.status, auth.error_type, auth.message)
        if credentials.mode() == "brokered" and not routes.allowed(self.path):
            return self.refuse(403, "permission_error", f"FlowControl gateway: path not allowed: {self.path.split('?')[0]}")

        if watching:
            self.timed(self.note_request, body)

        try:
            conn, resp = forwarder.open_upstream(self.command, self.path, auth.headers, body)
        except OSError as exc:
            self.send_error(502, f"upstream unreachable: {exc}")
            self.log_line(502, started, len(body), 0)
            return

        inspector = gate = None
        if watching and resp.status == 200:
            content_type = resp.getheader("content-type")
            inspector = ResponseInspector(content_type)
            gate = ToolGate(content_type, judge=self.judge_tool_call)

        sent = 0
        try:
            self.send_response(resp.status)
            for k, v in forwarder.response_headers(resp):
                self.send_header(k, v)
            self.send_header("connection", "close")
            self.end_headers()
            while chunk := resp.read1(8192):
                if self.bus.session.stopped:  # revoked mid-stream: cut the response here
                    break
                if inspector:
                    try:
                        self.timed(inspector.feed, chunk)
                    except Exception as exc:  # stats only: losing them must not break the agent's traffic
                        print(f"[{stamp()}]   (inspector error, stats off for this response: {exc})", flush=True)
                        inspector = None
                sent += self.send_chunk(self.timed(gate.feed, chunk) if gate else chunk)
            if gate and not self.bus.session.stopped:
                sent += self.send_chunk(self.timed(gate.finish))
        except (BrokenPipeError, ConnectionResetError):
            pass  # the agent hung up early (e.g. user pressed Ctrl+C)
        finally:
            conn.close()
            summary = inspector.finish() if inspector else None
            if summary:
                duration_ms = (time.monotonic() - started) * 1000
                self.timed(self.bus.emit, "llm_call", events.llm_call(
                    summary, duration_ms, self.overhead * 1000, blocked=gate.blocked if gate else 0,
                    canary_hit=getattr(self, "canary_hit", False)))
            self.log_line(resp.status, started, len(body), sent, summary, gate)

    def send_chunk(self, data):
        if data:
            self.wfile.write(data)
            self.wfile.flush()
        return len(data)

    # ---- what happens at each point ------------------------------------------------
    def note_request(self, body):
        try:
            parsed = json.loads(body) if body else None
        except ValueError:
            return
        task = self.bus.session.claim_start(parsed)
        if task:
            print(f"[{stamp()}] session started: {task}", flush=True)
            self.bus.emit("session_start", events.session_start(self.bus.session, task, self.policy))

    def judge_tool_call(self, call):
        """Called by the gate for each complete tool call. None = let it through; text = send this instead."""
        decision = self.policy.judge(call)
        ev = self.bus.emit("tool_call", events.tool_call(call, decision), level=decision.level)
        if decision.asks:
            return self.ask_approval(call, decision, ev["event_id"])
        if decision.blocked:
            advisory = "  (advisory: shell text rule)" if decision.advisory else ""
            print(f"[{stamp()}]   BLOCKED {describe(call)}  [{decision.rule}]{advisory}", flush=True)
            self.bus.session.mark_blocked()
            self.bus.emit("decision", events.decision(ev["event_id"], decision, self.policy.version),
                          level=decision.level, caused_by=[ev["event_id"]])
            return policy.notice(call, decision)
        print(f"[{stamp()}]   -> {describe(call)}", flush=True)
        src = policy.taint_source(call)
        self.bus.session.remember_read(call.id, src)  # so a later quarantine can find this read
        self.note_taint(call, ev["event_id"])  # the content this allowed read brings in may mark the session
        return None

    def quarantine_body(self, body):
        """Replace quarantined sources in the outgoing request; emit one quarantine event per source."""
        new_body, withheld = quarantine.rewrite_body(body, self.bus.session)
        for tool_use_id, source in withheld:
            if tool_use_id in self.bus.session.withheld:
                continue
            self.bus.session.withheld.add(tool_use_id)
            print(f"[{stamp()}]   QUARANTINED on read: {source}", flush=True)
            self.bus.emit("quarantine", events.quarantine(source, tool_use_id), level="green")
        return new_body

    def ask_approval(self, call, decision, tool_event_id):
        """Hold the call until a human on the dashboard approves or denies it (or it times out)."""
        if self.bus.session.stopped:
            return policy.notice(call, decision)
        dig = approvals.digest(call)
        pending = APPROVALS.open(tool_event_id, dig, config.APPROVAL_TIMEOUT)
        print(f"[{stamp()}]   ASK {describe(call)}  [{decision.rule}] — waiting for approval", flush=True)
        self.bus.emit("approval_request",
                      events.approval_request(tool_event_id, call, decision, dig, config.APPROVAL_TIMEOUT, self.policy.version),
                      level="yellow", caused_by=[tool_event_id])
        result = pending.wait()   # blocks this request until the dashboard answers or it times out
        APPROVALS.close(tool_event_id)
        self.bus.emit("approval_result", events.approval_result(tool_event_id, result, pending.by),
                      level="green" if result == "approved" else "red", caused_by=[tool_event_id])
        if result == "approved":
            print(f"[{stamp()}]   APPROVED {describe(call)} (by {pending.by})", flush=True)
            self.note_taint(call, tool_event_id)
            return None
        print(f"[{stamp()}]   DENIED {describe(call)} ({result})", flush=True)
        self.bus.emit("decision", events.decision(tool_event_id,
                      policy.Decision("block", "red", decision.rule, f"Approval {result}: {decision.reason}"),
                      self.policy.version), level="red", caused_by=[tool_event_id])
        return (f"[FlowControl gateway] Blocked {describe(call)}\n"
                f"Approval {result} by the operator (rule: {decision.rule}).")

    def note_taint(self, call, tool_event_id):
        """If this allowed call brings in untrusted or sensitive content, mark the session (once per kind)."""
        for hit in self.policy.classify_taint(call):
            changed, from_state, to_state = self.bus.session.mark_taint(hit.tag)
            if not changed:
                continue  # already marked; the state transition was emitted the first time
            note = "  (advisory: from shell text)" if hit.advisory else ""
            print(f"[{stamp()}]   tainted {hit.tag}: {hit.source}  ({from_state} -> {to_state}){note}", flush=True)
            self.bus.emit("taint", events.taint(hit, from_state, to_state), caused_by=[tool_event_id])

    def timed(self, fn, *args):
        t = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self.overhead += time.perf_counter() - t

    def auto_stop(self, reason, detail):
        """The gateway stops the run itself (budget or lifetime exceeded), like a dashboard stop."""
        if self.bus.session.mark_stopped(by=f"auto:{reason}"):
            print(f"[{stamp()}] AUTO-STOP ({reason}): {detail}", flush=True)
            APPROVALS.deny_all()
            self.bus.emit("session_end", events.session_end("stopped", f"auto-stopped: {detail}"), level="red")

    def refuse(self, status, error_type, message):
        """Answer the agent ourselves; nothing goes upstream."""
        self.send_api_error(status, error_type, message)
        print(f"[{stamp()}] {self.command} {self.path} -> {status} refused: {message}", flush=True)

    def send_api_error(self, status, error_type, message):
        """An error in the API's own format, so the agent shows the message instead of crashing."""
        payload = json.dumps({"type": "error", "error": {"type": error_type, "message": message}}).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    # ---- terminal output ---------------------------------------------------------------
    def log_line(self, status, started, bytes_in, bytes_out, summary=None, gate=None):
        secs = time.monotonic() - started
        extra = ""
        if summary:
            extra = f"  {summary.model}  stop={summary.stop_reason}  tools={len(summary.tool_calls)}"
            if gate and gate.blocked:
                extra += f"  blocked={gate.blocked}"
        print(f"[{stamp()}] {self.command} {self.path} -> {status}  "
              f"{secs:.1f}s  in {bytes_in / 1024:.1f}KB  out {bytes_out / 1024:.1f}KB{extra}", flush=True)

    def log_message(self, *args):
        pass  # silence the default per-request log; we print our own


def handle_command(cmd):
    """A command from the dashboard over the live feed (protocol/EVENTS.md §5)."""
    bus = GatewayHandler.bus
    name = cmd.get("command")
    if name == "stop":
        if bus.session.mark_stopped(by=cmd.get("by") or "dashboard"):
            print(f"[{stamp()}] STOP from {bus.session.stopped_by}: revoking the run, "
                  f"denying all further requests", flush=True)
            APPROVALS.deny_all()  # release any held approvals as denied (revocation contract)
            bus.emit("session_end", events.session_end("stopped", f"run stopped by {bus.session.stopped_by}"),
                     level="red")
        else:
            print(f"[{stamp()}] STOP ignored: the run is already stopped", flush=True)
    elif name in ("approve", "deny"):
        result = "approved" if name == "approve" else "denied"
        ok = APPROVALS.resolve(cmd.get("target_event"), result, digest=cmd.get("action_digest"),
                               by=cmd.get("by") or "dashboard")
        if not ok:
            print(f"[{stamp()}] {name} ignored: no matching open approval for {cmd.get('target_event')}", flush=True)
    elif name == "quarantine":
        source = cmd.get("source")
        if source:
            affected = bus.session.quarantine(source)
            print(f"[{stamp()}] QUARANTINE {source} ({len(affected)} reads withheld from here on)", flush=True)
            # Confirm on the feed now; the per-read quarantine events follow on the next request.
            bus.emit("quarantine", events.quarantine(source, affected[0] if affected else None), level="green")
    elif name in ("set_protection", "add_rule", "remove_rule"):
        change_settings(name, cmd)
    else:
        print(f"[{stamp()}] command not handled yet: {name}", flush=True)


def change_settings(name, cmd):
    """Switch a protection, or add / remove an operator rule; swap in the new policy; announce it."""
    bus = GatewayHandler.bus
    by = str(cmd.get("by") or "dashboard")[:80]
    try:
        if name == "set_protection":
            change = SETTINGS.set_protection(cmd.get("id"), cmd.get("enabled"))
        elif name == "add_rule":
            _rule, change = SETTINGS.add_rule({**(cmd.get("rule") or {}), "by": by})
        else:
            change = SETTINGS.remove_rule(cmd.get("id"))
    except settings.SettingsError as exc:
        print(f"[{stamp()}] {name} refused: {exc}", flush=True)
        bus.emit("settings", {**SETTINGS.snapshot(), "error": str(exc), "by": by})
        return
    if not change:
        return
    GatewayHandler.policy = SETTINGS.effective()  # the next tool call is judged by the new policy
    weakened = change.startswith("Turned OFF")
    print(f"[{stamp()}] SETTINGS by {by}: {change}  (policy {SETTINGS.version()})", flush=True)
    bus.emit("settings", SETTINGS.snapshot(change, by), level="yellow" if weakened else None)


def decide_egress(method, host, port):
    """Called by the forward proxy for each outbound request. Judges it, emits events, returns
    the EgressDecision. A tainted session sending out (the lethal trifecta) also marks the
    session blocked — the headline red moment."""
    bus = GatewayHandler.bus
    session = bus.session
    if session.stopped:  # revoked: deny every destination
        decision = policy.EgressDecision("block", "session_stopped",
                                         "The run was stopped by the operator.", "unknown")
        ev = bus.emit("network_request", events.network_request(method, host, decision), level="red")
        bus.emit("decision", events.egress_decision(ev["event_id"], decision, GatewayHandler.policy.version),
                 level="red", caused_by=[ev["event_id"]])
        print(f"[{stamp()}] egress {method} {host}:{port} -> BLOCKED [session_stopped]", flush=True)
        return decision
    tainted = session.untrusted_input_seen and session.sensitive_data_seen
    decision = GatewayHandler.policy.judge_egress(host, tainted)
    ev = bus.emit("network_request", events.network_request(method, host, decision), level=decision.level)
    if decision.blocked:
        if decision.trifecta:
            session.mark_blocked()
        bus.emit("decision", events.egress_decision(ev["event_id"], decision, GatewayHandler.policy.version),
                 level="red", caused_by=[ev["event_id"]])
        print(f"[{stamp()}] egress {method} {host}:{port} -> BLOCKED [{decision.rule}]", flush=True)
    else:
        print(f"[{stamp()}] egress {method} {host}:{port} -> allowed [{decision.rule}]", flush=True)
    return decision


def run():
    global SETTINGS
    session = Session()
    SETTINGS = settings.Settings(policy.load(config.POLICY_FILE))
    GatewayHandler.policy = SETTINGS.effective()
    hub = live.Hub(on_command=handle_command)
    GatewayHandler.bus = events.EventBus(session, [JsonlSink(config.EVENTS_FILE), live.WebSocketSink(hub)])
    GatewayHandler.bus.emit("settings", SETTINGS.snapshot())  # dashboards learn the current protections

    # Print the status lines BEFORE binding the proxy port. The launcher's health check waits on
    # that port, so a line logged after the bind can race the check — the gateway looked like it
    # had "no real API key" when the key line simply hadn't been printed yet.
    key_note = "" if credentials.mode() == "pass-through" else (
        "  (real API key configured)" if config.UPSTREAM_API_KEY else "  (NO real API key: every request will be refused)")
    print(f"credentials: {credentials.mode()}{key_note}", flush=True)
    if credentials.mode() == "brokered":
        print(f"routes: only {', '.join(sorted(config.ALLOWED_PATHS))}", flush=True)
    p = GatewayHandler.policy
    if p.error:
        print(f"policy: UNAVAILABLE ({p.error}): every tool call will be blocked", flush=True)
    else:
        print(f"policy: {p.source}  version {p.version}  ({len(p.rules)} rules, {len(p.taint)} taint sources)", flush=True)
        egress_note = (f"{len(p.egress_allow)} allowed hosts" if p.egress_allow else "deny-all") + \
            (", blocked when tainted" if p.block_when_tainted else "")
        print(f"egress proxy -> http://{config.HOST}:{config.PROXY_PORT}  ({egress_note})", flush=True)
    print(f"events -> {config.EVENTS_FILE}", flush=True)
    deny_note = f"  (refused from: {', '.join(map(str, config.LIVE_DENY_NETS))})" if config.LIVE_DENY_NETS else ""
    print(f"live feed -> ws://{config.HOST}:{config.LIVE_PORT}/events  "
          f"(debug page: http://localhost:{config.LIVE_PORT}/){deny_note}", flush=True)

    live.start(hub, config.HOST, config.LIVE_PORT, deny_nets=config.LIVE_DENY_NETS)
    if credentials.mode() == "brokered":
        proxy.start(config.HOST, config.PROXY_PORT, decide_egress)
    server = ThreadingHTTPServer((config.HOST, config.PORT), GatewayHandler)  # binds the port the health check waits on
    print(f"FlowControl gateway listening on http://{config.HOST}:{config.PORT} "
          f"-> https://{config.UPSTREAM_HOST}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\ngateway stopped")
