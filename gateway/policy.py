"""Policy: decide whether a tool call the model proposed may reach the agent.

The rules are data, not code: they live in a TOML file outside the runner
(policy/default.toml), so they can change without touching the gateway, and the agent
can't read or edit them.

judge() never raises. If the policy file can't be loaded, or a tool call can't be read,
the answer is "block" (fail closed: threat model category 0).
"""
import fnmatch
import posixpath
import re
import shlex
import tomllib
import unicodedata
from dataclasses import dataclass

# Where Claude Code's tools put the file (or URL) they touch.
PATH_FIELDS = ("file_path", "notebook_path", "path")
SOURCE_FIELDS = ("file_path", "notebook_path", "path", "url")
RULE_KEYS = {"id", "tools", "paths", "commands", "verdict", "reason"}
TAINT_KEYS = {"id", "tools", "paths", "commands", "tag"}
EGRESS_KEYS = {"allow", "block_when_tainted"}
SHELL_TOOLS = {"Bash"}  # tools whose input is a shell command rather than a single path
VERDICTS = {"block", "ask"}  # "ask" pauses the call for a human approval
LEVELS = {"block": "red", "ask": "yellow"}
TAGS = {"untrusted", "sensitive"}  # the two session properties (threat model §4, category 1)


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    verdict: str            # "allow", "ask" or "block"
    level: str              # traffic light for the dashboard: "green", "yellow" or "red"
    rule: str | None = None
    reason: str = ""
    advisory: bool = False  # matched on shell text: a match blocks, a miss proves nothing

    @property
    def blocked(self):
        return self.verdict == "block"

    @property
    def asks(self):
        return self.verdict == "ask"


ALLOW = Decision("allow", "green")


@dataclass(frozen=True)
class Rule:
    id: str
    tools: frozenset
    paths: tuple       # lowercased glob patterns
    commands: tuple    # compiled regular expressions
    verdict: str
    reason: str
    hosts: tuple = ()  # host patterns for a URL-taking tool (WebFetch); set by dashboard rules

    @property
    def advisory(self):
        return bool(self.commands)


@dataclass(frozen=True)
class TaintRule:
    """Reading a source matched here marks the session. Nothing is blocked; a later egress
    decision (M3 step 3) reads the marks. Source-based: the tag is from WHERE content comes
    from, not from scanning it."""
    id: str
    tools: frozenset
    paths: tuple       # lowercased glob patterns; for a shell tool, matched against paths the command mentions
    commands: tuple    # compiled regular expressions searched in a shell command
    tag: str           # "untrusted" or "sensitive"


@dataclass(frozen=True)
class TaintHit:
    tag: str
    source: str        # the file, URL or command that brought the content in
    rule: str          # the [[taint]] id
    advisory: bool     # True when it came from shell text: a miss would have proved nothing


@dataclass(frozen=True)
class EgressDecision:
    verdict: str                # "allow" or "block"
    rule: str                   # "allowlist" / "unknown_destination" / "lethal_trifecta"
    reason: str
    category: str               # dest_category for the event: "allowlist" or "unknown"
    trifecta: bool = False      # a tainted session sending out: the block that marks the session

    @property
    def blocked(self):
        return self.verdict == "block"

    @property
    def level(self):
        return "green" if self.verdict == "allow" else "red"


class Policy:
    # Run-time switches (gateway/settings.py). Defaults = everything on, as the file says.
    deny_unknown = True      # egress: a host off the allowlist is denied
    check_canaries = True    # flag canary markers in request bodies
    budget = True            # enforce the model-request budget and session lifetime
    deny_hosts = ()          # operator rules: (rule id, host pattern, reason, verdict) denied at egress

    def __init__(self, rules=(), taint=(), egress_allow=(), block_when_tainted=True, canaries=(),
                 version="", root="/workspace", home="/home/node", source="", error=None):
        self.rules = list(rules)
        self.taint = list(taint)
        self.egress_allow = tuple(egress_allow)       # hosts a clean session may reach through the proxy
        self.block_when_tainted = block_when_tainted  # a tainted session may reach none (lethal trifecta)
        self.canaries = tuple(canaries)               # markers to watch for in request bodies
        self.version = version
        self.root = root.rstrip("/") or "/"
        self.home = home.rstrip("/") or "/"
        self.source = source
        self.error = error  # set when the file couldn't be loaded: every call is then blocked

    def judge(self, call):
        try:
            return self._judge(call)
        except Exception as exc:  # a bug here must not let the call through
            return Decision("block", "red", "policy_error", f"The gateway couldn't evaluate this call ({exc}).")

    def _judge(self, call):
        if self.error:
            return Decision("block", "red", "policy_unavailable",
                            f"No policy is loaded ({self.error}), so every tool call is blocked.")
        if not getattr(call, "readable", True) or not isinstance(call.input, dict):
            return Decision("block", "red", "unreadable_tool_call",
                            "The gateway couldn't read this tool call's arguments, so it can't be checked.")
        for rule in self.rules:
            advisory = self._matches(rule, call)
            if advisory is not None:
                return Decision(rule.verdict, LEVELS[rule.verdict], rule.id, rule.reason,
                                rule.advisory or advisory)
        return ALLOW

    def _matches(self, rule, call):
        """None if the rule doesn't match; otherwise True/False for whether the match was advisory
        (a path a shell command merely MENTIONS — shell text, so the same caveat as taint)."""
        if not tool_matches(call.name, rule.tools):
            return None
        advisory = False
        if rule.paths:
            command = call.input.get("command")
            if call.name in SHELL_TOOLS and isinstance(command, str):
                # A shell tool has no single path field: match against the paths it mentions,
                # exactly like taint does (cat/grep .env). Advisory — shell text can hide a path.
                if not any(self._raw_path_matches(rule.paths, p) for p in mentioned_paths(command)):
                    return None
                advisory = True
            elif not self._path_matches(rule.paths, call):
                return None
        if rule.hosts:
            url = call.input.get("url")
            if not isinstance(url, str) or not host_matches(url_host(url), rule.hosts):
                return None
        if rule.commands:
            command = call.input.get("command")
            if not isinstance(command, str) or not any(r.search(command) for r in rule.commands):
                return None
        return advisory

    def _path_matches(self, paths, call):
        raw = next((call.input[f] for f in PATH_FIELDS if isinstance(call.input.get(f), str)), None)
        return raw is not None and self._raw_path_matches(paths, raw)

    def _raw_path_matches(self, paths, raw):
        absolute = canonical(raw, self.root, self.home)
        relative = inside(absolute, self.root)  # None outside the workspace
        return any(fnmatch.fnmatchcase(absolute, pat) if pat.startswith("/")
                   else relative is not None and fnmatch.fnmatchcase(relative, pat)
                   for pat in paths)

    def classify_taint(self, call):
        """The marks an ALLOWED call brings in: a list of TaintHit, at most one per tag, in policy order.

        Call this only for calls judge() allowed: a blocked read never produces content, so it
        never taints. Source-based, so it never scans the content the agent read. For a shell
        command, `paths` are matched against the paths the command mentions: that is shell text,
        so those hits are advisory. A false positive only marks the session (later egress gets
        stricter); a miss (an obfuscated path) is why egress must deny unknown destinations anyway.
        """
        if self.error or not getattr(call, "readable", True) or not isinstance(call.input, dict):
            return []
        hits, tags = [], set()
        for t in self.taint:
            if t.tag in tags or not tool_matches(call.name, t.tools):
                continue
            hit = self._taint_hit(t, call)
            if hit:
                hits.append(hit)
                tags.add(t.tag)
        return hits

    def judge_egress(self, host, tainted):
        """Whether the runner may reach `host` through the gateway proxy. Deny by default.

        `tainted` = the session has read untrusted content AND holds sensitive data. Such a
        session making any outbound request is the lethal trifecta (threat model §4, category 2),
        so it is denied even to an allowed host — an allowed service can still be an exfil channel.
        An unknown host is denied regardless: that backstop does not depend on the taint marks
        being complete, which is why a missed mark can never by itself open a door.
        """
        if self.error:
            return EgressDecision("block", "policy_unavailable",
                                  f"No policy is loaded ({self.error}), so all egress is denied.", "unknown")
        allowed = host_matches(host, self.egress_allow)
        category = "allowlist" if allowed else "unknown"
        for rid, pattern, reason, _verdict in self.deny_hosts:  # operator rules: an "ask" can't pause a socket, so it denies
            if host_matches(host, (pattern,)):
                return EgressDecision("block", rid, reason, category)
        if tainted and self.block_when_tainted:
            return EgressDecision("block", "lethal_trifecta",
                                  "Session has read untrusted content and holds sensitive data; "
                                  "an outbound request could exfiltrate it.", category, trifecta=True)
        if allowed:
            return EgressDecision("allow", "allowlist", f"{host} is on the egress allowlist.", category)
        if not self.deny_unknown:
            return EgressDecision("allow", "allowlist_off",
                                  f"{host} is not on the allowlist, but unknown-host denial is switched off.", category)
        return EgressDecision("block", "unknown_destination",
                              f"{host} is not on the egress allowlist.", category)

    def _taint_hit(self, t, call):
        command = call.input.get("command")
        shell = call.name in SHELL_TOOLS and isinstance(command, str)
        source, advisory = None, False
        if t.paths:
            if shell:
                source = next((p for p in mentioned_paths(command) if self._raw_path_matches(t.paths, p)), None)
                advisory = True
            elif self._path_matches(t.paths, call):
                source = taint_source(call)
            if source is None:
                return None
        if t.commands:
            if not isinstance(command, str) or not any(r.search(command) for r in t.commands):
                return None
            from .describe import key_detail
            source, advisory = source or key_detail(call), True
        return TaintHit(t.tag, source or taint_source(call), t.id, advisory)


def canonical(raw, root, home):
    """The absolute path a tool will touch, compared the way the workspace's filesystem would.

    Resolves "..", ".", repeated slashes, "~" and relative paths. Lowercased and in Unicode
    NFC form, because a macOS workspace treats "CLAUDE.md" and "claude.md" (and composed vs.
    decomposed accents) as the same file. Symlinks aren't resolved here: the gateway doesn't
    see the runner's filesystem. Read-only mounts (a later step) cover those.
    """
    p = unicodedata.normalize("NFC", raw)
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    if not p.startswith("/"):
        p = posixpath.join(root, p)
    p = posixpath.normpath(p)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    return p.lower()


def inside(absolute, root):
    """The path relative to the workspace root, or None if it's outside."""
    root = root.lower()
    if absolute.startswith(root + "/"):
        return absolute[len(root) + 1:]
    return None


def tool_matches(name, patterns):
    """A tool name matches a pattern set: exact, or a `prefix*` wildcard (for `mcp__*` etc.)."""
    for pat in patterns:
        if pat.endswith("*") and name.startswith(pat[:-1]):
            return True
        if name == pat:
            return True
    return False


def url_host(url):
    from urllib.parse import urlsplit
    try:
        return urlsplit(url if "//" in url else "//" + url).hostname or ""
    except ValueError:
        return ""


def host_matches(host, patterns):
    """True if `host` matches any pattern. `*.example.com` matches any subdomain and the apex."""
    host = host.strip().strip(".").lower()
    for pat in patterns:
        pat = pat.strip().strip(".").lower()
        if pat.startswith("*."):
            if host == pat[2:] or host.endswith("." + pat[2:]):
                return True
        elif host == pat:
            return True
    return False


def notice(call, decision):
    """What the agent receives instead of a blocked call."""
    from .describe import describe
    return (f"[FlowControl gateway] Blocked {describe(call)}\n"
            f"{decision.reason} (rule: {decision.rule})")


_SHELL_FALLBACK = re.compile(r"[\s;|&<>()`]+")


def mentioned_paths(command):
    """Path-like words in a shell command: anything containing "/" or ".", minus options.

    Handles quoting and operators (`cat "a b.md"&&grep x .env>out`), `--opt=value`, curl's
    `@file`, and `$(...)`. It reads text, so a path built at run time (`$(printf .%s env)`) or a
    directory-wide read (`grep -r .`) isn't seen: callers treat the result as advisory.
    """
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        words = list(lex)
    except ValueError:  # unbalanced quotes: fall back to a plain split
        words = _SHELL_FALLBACK.split(command)
    out = []
    for word in words:
        for part in word.split("="):
            part = part.strip("'\"").lstrip("@")
            if part and not part.startswith("-") and ("/" in part or "." in part):
                out.append(part)
    return out


def taint_source(call):
    """The file or URL a tainting call read, for the taint event's `source`."""
    for f in SOURCE_FIELDS:
        v = call.input.get(f)
        if isinstance(v, str) and v:
            return v
    from .describe import key_detail
    return key_detail(call)


# ---- loading ---------------------------------------------------------------------------

def load(path):
    """Load a policy file. Never raises: a broken or missing file gives a policy that blocks everything."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return from_dict(data, source=path)
    except (OSError, tomllib.TOMLDecodeError, PolicyError) as exc:
        return Policy(source=path, error=f"{type(exc).__name__}: {exc}")


def from_text(text, source="<text>"):
    return from_dict(tomllib.loads(text), source=source)


def from_dict(data, source=""):
    unknown = set(data) - {"version", "workspace", "rules", "taint", "egress", "canaries"}
    if unknown:
        raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise PolicyError("'version' must be a non-empty string")
    ws = data.get("workspace", {})
    rules = _unique(data.get("rules", []), _rule, "rule")
    taint = _unique(data.get("taint", []), _taint, "taint")
    allow, block_when_tainted = _egress(data.get("egress", {}))
    canaries = data.get("canaries", [])
    if not isinstance(canaries, list) or not all(isinstance(c, str) and c for c in canaries):
        raise PolicyError("'canaries' must be a list of non-empty strings")
    return Policy(rules=rules, taint=taint, egress_allow=allow, block_when_tainted=block_when_tainted,
                  canaries=tuple(canaries), version=version,
                  root=ws.get("root", "/workspace"), home=ws.get("home", "/home/node"), source=source)


def body_has_canary(body, canaries):
    """True if any canary marker appears in the request body (bytes or str)."""
    if not canaries:
        return False
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return any(c in body for c in canaries)


def _egress(e):
    if not isinstance(e, dict):
        raise PolicyError("'egress' must be a table")
    unknown = set(e) - EGRESS_KEYS
    if unknown:
        raise PolicyError(f"egress: unknown keys {sorted(unknown)}")
    allow = e.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(h, str) and h for h in allow):
        raise PolicyError("egress.allow must be a list of non-empty host patterns")
    block = e.get("block_when_tainted", True)
    if not isinstance(block, bool):
        raise PolicyError("egress.block_when_tainted must be true or false")
    return tuple(allow), block


def _unique(entries, parse, kind):
    out, seen = [], set()
    for i, e in enumerate(entries):
        item = parse(e, i)
        if item.id in seen:
            raise PolicyError(f"duplicate {kind} id {item.id!r}")
        seen.add(item.id)
        out.append(item)
    return out


def _rule(r, i):
    where = f"rule #{i + 1}"
    unknown = set(r) - RULE_KEYS
    if unknown:  # catches typos like "path" for "paths", which would otherwise match every call
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
    rid = r.get("id")
    if not isinstance(rid, str) or not rid:
        raise PolicyError(f"{where}: 'id' must be a non-empty string")
    where = f"rule {rid!r}"
    tools = r.get("tools")
    if not isinstance(tools, list) or not tools or not all(isinstance(t, str) for t in tools):
        raise PolicyError(f"{where}: 'tools' must be a non-empty list of names")
    if r.get("verdict") not in VERDICTS:
        raise PolicyError(f"{where}: 'verdict' must be one of {sorted(VERDICTS)}")
    if not isinstance(r.get("reason"), str) or not r["reason"]:
        raise PolicyError(f"{where}: 'reason' must be a non-empty string")
    paths = tuple(unicodedata.normalize("NFC", p).lower() for p in _strings(r, "paths", where))
    try:
        commands = tuple(re.compile(c) for c in _strings(r, "commands", where))
    except re.error as exc:
        raise PolicyError(f"{where}: bad regular expression: {exc}") from None
    return Rule(rid, frozenset(tools), paths, commands, r["verdict"], r["reason"])


def _taint(t, i):
    where = f"taint #{i + 1}"
    unknown = set(t) - TAINT_KEYS
    if unknown:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
    tid = t.get("id")
    if not isinstance(tid, str) or not tid:
        raise PolicyError(f"{where}: 'id' must be a non-empty string")
    where = f"taint {tid!r}"
    tools = t.get("tools")
    if not isinstance(tools, list) or not tools or not all(isinstance(x, str) for x in tools):
        raise PolicyError(f"{where}: 'tools' must be a non-empty list of names")
    if t.get("tag") not in TAGS:
        raise PolicyError(f"{where}: 'tag' must be one of {sorted(TAGS)}")
    paths = tuple(unicodedata.normalize("NFC", p).lower() for p in _strings(t, "paths", where))
    try:
        commands = tuple(re.compile(c) for c in _strings(t, "commands", where))
    except re.error as exc:
        raise PolicyError(f"{where}: bad regular expression: {exc}") from None
    return TaintRule(tid, frozenset(tools), paths, commands, t["tag"])


def _strings(r, key, where):
    value = r.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError(f"{where}: '{key}' must be a list of non-empty strings")
    return value
