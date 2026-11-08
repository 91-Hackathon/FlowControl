"""Settings: protections the dashboard can switch, and disallowed actions it can add, at run time.

The policy file (policy/default.toml) stays the source of truth and is never written. Settings
are a layer on top: effective() builds a new Policy from the file policy plus the current
switches and the operator's own rules, and the gateway swaps it in. Every change is announced
as a `settings` event, so it lands in the audit log and on every dashboard.

Protections are grouped by the eight threat categories (docs/threat-model.md §4). Some are
enforced by the deployment itself (internal network, credential broker, ...): those are listed
as `locked` — always on, shown so the operator sees the whole picture, never switchable here.

Who may change settings: only a dashboard on the live feed, which the agent's network can't
reach (config.LIVE_DENY_NETS). Turning a protection OFF weakens the run, so it is logged loudly.
"""
import re
import threading
import unicodedata

from . import policy as P

# id, category number, category title, label, detail, how it's applied
# kinds: ("rule", rule_id) / ("taint", [taint ids]) / ("flag", name) / ("locked", None)
PROTECTIONS = [
    ("isolated_runner", 0, "Gateway bypass", "Isolated runner",
     "The agent's only way out is through FlowControl.", ("locked", None)),
    ("fail_closed", 0, "Gateway bypass", "Fail closed",
     "Anything that can't be checked is blocked.", ("locked", None)),
    ("untrusted_sources", 1, "Prompt injection", "Flag outside content",
     "Web pages, MCP results and downloads mark the session untrusted.",
     ("taint", ["web_content", "mcp_result", "shell_fetch"])),
    ("quarantine", 1, "Prompt injection", "Quarantine",
     "Poisoned files are hidden from the model.", ("locked", None)),
    ("trifecta", 2, "Data exfiltration", "Lethal trifecta lock",
     "No outbound requests once the session is both untrusted and holding secrets.",
     ("flag", "block_when_tainted")),
    ("egress_allowlist", 2, "Data exfiltration", "Allowlist only",
     "Outbound requests may only reach approved hosts.", ("flag", "deny_unknown")),
    ("shell_upload", 2, "Data exfiltration", "Block curl / wget uploads",
     "Stops shell commands that send data out.", ("rule", "shell_upload")),
    ("canaries", 2, "Data exfiltration", "Canary keys",
     "Flags planted fake keys if they show up in traffic.", ("flag", "check_canaries")),
    ("protected_config", 3, "Dangerous actions", "Protect config and CI",
     "The agent can't edit its own settings, git hooks or CI workflows.", ("rule", "protected_config")),
    ("third_party_untrusted", 4, "Supply chain", "Flag vendored code",
     "vendor/, node_modules/ and third_party/ count as untrusted.", ("taint", ["third_party_code"])),
    ("credential_broker", 5, "Credentials", "Key broker",
     "The real API key never enters the agent's sandbox.", ("locked", None)),
    ("secrets_sensitive", 5, "Credentials", "Flag secret files",
     ".env, keys and credential files mark the session as holding secrets.", ("taint", ["secrets"])),
    ("budget", 6, "Runaway resources", "Budget and time limit",
     "Stops the run when it makes too many requests or runs too long.", ("flag", "budget")),
    ("bound_approvals", 7, "Approval abuse", "Exact-action approvals",
     "Approving one action never approves a different one; no answer means no.", ("locked", None)),
    ("feed_isolation", 7, "Approval abuse", "Private control panel",
     "The agent can't reach this dashboard or press its buttons.", ("locked", None)),
    ("audit_chain", 7, "Approval abuse", "Tamper-evident log",
     "Every event is hash-chained, so edits are detectable.", ("locked", None)),
]

# What an operator can disallow from the dashboard.
#   command  a Bash command containing this text (case-insensitive, literal, advisory)
#   read     reading a file matching this glob (also a Bash command that mentions it: advisory)
#   write    writing / editing a file matching this glob (same)
#   tool     any call of this tool (exact name, or prefix* like mcp__*)
#   host     reaching this host (exact, or *.suffix): proxy egress and WebFetch URLs
KINDS = {
    "command": ["Bash"],
    "read": ["Read", "Grep", "Glob", "NotebookRead", "Bash"],   # Bash: a command that mentions the path (advisory)
    "write": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"],
    "tool": None,
    "host": ["WebFetch"],
}
MAX_RULES = 50
MAX_PATTERN = 200


class SettingsError(ValueError):
    pass


class Settings:
    def __init__(self, base):
        self.base = base                     # the Policy loaded from the file
        self.enabled = {p[0]: True for p in PROTECTIONS}
        self.custom = []                     # [{id, kind, pattern, verdict, reason, label, by}]
        self.revision = 0
        self._next = 1
        self._lock = threading.Lock()

    # ---- what the dashboard sees ------------------------------------------------------
    def available(self, how):
        kind, arg = how
        if self.base.error:
            return kind == "locked"
        if kind == "rule":
            return any(r.id == arg for r in self.base.rules)
        if kind == "taint":
            return any(t.id in arg for t in self.base.taint)
        return True

    def snapshot(self, change=None, by=None):
        prots = []
        for pid, cat, cat_title, label, detail, how in PROTECTIONS:
            prots.append({
                "id": pid, "category": cat, "category_title": cat_title, "label": label, "detail": detail,
                "locked": how[0] == "locked", "available": self.available(how),
                "enabled": how[0] == "locked" or (self.enabled[pid] and self.available(how)),
            })
        data = {"protections": prots, "custom_rules": [dict(r) for r in self.custom],
                "policy_version": self.version(), "revision": self.revision}
        if change:
            data["change"] = change
            data["by"] = by or "dashboard"
        return data

    def version(self):
        return self.base.version + (f"+dash.{self.revision}" if self.revision else "")

    # ---- changes (each returns a short English description of what changed) -------------
    def set_protection(self, pid, enabled):
        with self._lock:
            entry = next((p for p in PROTECTIONS if p[0] == pid), None)
            if not entry:
                raise SettingsError(f"unknown protection {pid!r}")
            if entry[5][0] == "locked":
                raise SettingsError(f"{entry[3]!r} is enforced by the deployment and can't be switched off here")
            if not self.available(entry[5]):
                raise SettingsError(f"{entry[3]!r} isn't in the loaded policy file")
            enabled = bool(enabled)
            if self.enabled[pid] == enabled:
                return None
            self.enabled[pid] = enabled
            self.revision += 1
            return f"{'Turned on' if enabled else 'Turned OFF'}: {entry[3]}"

    def add_rule(self, spec):
        with self._lock:
            if len(self.custom) >= MAX_RULES:
                raise SettingsError(f"at most {MAX_RULES} custom rules")
            rule = clean_rule(spec)
            rule["id"] = f"custom_{self._next}"
            self._next += 1
            self.custom.append(rule)
            self.revision += 1
            return rule, f"Disallowed: {rule['label']} ({'ask first' if rule['verdict'] == 'ask' else 'block'})"

    def remove_rule(self, rid):
        with self._lock:
            rule = next((r for r in self.custom if r["id"] == rid), None)
            if not rule:
                raise SettingsError(f"no custom rule {rid!r}")
            self.custom.remove(rule)
            self.revision += 1
            return f"Removed rule: {rule['label']}"

    # ---- the policy the gateway enforces --------------------------------------------------
    def effective(self):
        b = self.base
        if b.error:
            return b  # fail closed stays fail closed
        off_rules, off_taint = set(), set()
        flags = {}
        for pid, _c, _t, _l, _d, (kind, arg) in PROTECTIONS:
            on = self.enabled[pid]
            if kind == "rule" and not on:
                off_rules.add(arg)
            elif kind == "taint" and not on:
                off_taint.update(arg)
            elif kind == "flag":
                flags[arg] = on
        # Adding a rule must never loosen the policy: operator BLOCK rules decide first, then the
        # file's rules, then operator ASK rules (so an "ask" can't downgrade a file block).
        mine = [to_rule(r) for r in self.custom]
        rules = [r for r in mine if r.verdict == "block"] + [r for r in b.rules if r.id not in off_rules] + \
            [r for r in mine if r.verdict == "ask"]
        deny_hosts = tuple((r["id"], r["pattern"], r["reason"], r["verdict"]) for r in self.custom if r["kind"] == "host")
        p = P.Policy(rules=rules, taint=[t for t in b.taint if t.id not in off_taint],
                     egress_allow=b.egress_allow,
                     block_when_tainted=b.block_when_tainted and flags.get("block_when_tainted", True),
                     canaries=b.canaries, version=self.version(), root=b.root, home=b.home, source=b.source)
        p.deny_unknown = flags.get("deny_unknown", True)
        p.check_canaries = flags.get("check_canaries", True)
        p.budget = flags.get("budget", True)
        p.deny_hosts = deny_hosts
        return p


def clean_rule(spec):
    """Validate an operator rule from the dashboard. Raises SettingsError."""
    if not isinstance(spec, dict):
        raise SettingsError("rule must be an object")
    kind = spec.get("kind")
    if kind not in KINDS:
        raise SettingsError(f"kind must be one of {sorted(KINDS)}")
    pattern = spec.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        raise SettingsError("pattern must be non-empty text")
    pattern = unicodedata.normalize("NFC", pattern.strip())
    if len(pattern) > MAX_PATTERN or any(ord(ch) < 32 for ch in pattern):
        raise SettingsError(f"pattern must be one line, at most {MAX_PATTERN} characters")
    if kind == "tool" and not re.fullmatch(r"[A-Za-z0-9_\-]+\*?", pattern):
        raise SettingsError("tool must be a tool name like Bash, WebFetch or mcp__*")
    if kind == "host":
        pattern = pattern.lower()
        if not re.fullmatch(r"(\*\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)*", pattern):
            raise SettingsError("host must look like example.com or *.example.com")
    verdict = spec.get("verdict", "block")
    if verdict not in ("block", "ask"):
        raise SettingsError("verdict must be block or ask")
    label = DESCRIBE[kind](pattern)
    reason = spec.get("reason")
    reason = reason.strip()[:300] if isinstance(reason, str) and reason.strip() else f"Disallowed by the operator: {label}."
    return {"kind": kind, "pattern": pattern, "verdict": verdict, "reason": reason, "label": label,
            "by": str(spec.get("by") or "dashboard")[:80]}


DESCRIBE = {
    "command": lambda p: f"shell command containing “{p}”",
    "read": lambda p: f"reading {p}",
    "write": lambda p: f"editing {p}",
    "tool": lambda p: f"any {p} call",
    "host": lambda p: f"reaching {p}",
}


def to_rule(r):
    """A custom rule as a policy Rule. A host rule matches WebFetch URLs here; the proxy checks deny_hosts."""
    kind, pat = r["kind"], r["pattern"]
    tools = frozenset(KINDS[kind] or [pat])
    paths, commands = (), ()
    if kind == "command":
        commands = (re.compile(re.escape(pat), re.IGNORECASE),)
    elif kind in ("read", "write"):
        p = pat.lower()
        while p.startswith("./"):
            p = p[2:]
        paths = (p,) if p.startswith("/") or p.startswith("*") else (p, "*/" + p)
    elif kind == "host":
        return P.Rule(r["id"], tools, (), (), r["verdict"], r["reason"], hosts=(pat,))
    return P.Rule(r["id"], tools, paths, commands, r["verdict"], r["reason"])
