/* Protections panel: the gateway's protections grouped by the eight threat categories, plus the
   operator's own disallowed actions. Live, every change is a command to the gateway, and the
   gateway answers with a `settings` event (protocol/EVENTS.md). In ?demo there is no gateway:
   the same panel works on a local copy, and app.js applies the operator's rules to the replay. */
(function () {
  // Mirror of gateway/settings.py PROTECTIONS, for demo mode only (live mode uses the gateway's list).
  const DEFAULTS = [
    ["isolated_runner", 0, "Gateway bypass", "Isolated runner", "The agent's only way out is through FlowControl.", true],
    ["fail_closed", 0, "Gateway bypass", "Fail closed", "Anything that can't be checked is blocked.", true],
    ["untrusted_sources", 1, "Prompt injection", "Flag outside content", "Web pages, MCP results and downloads mark the session untrusted.", false],
    ["quarantine", 1, "Prompt injection", "Quarantine", "Poisoned files are hidden from the model.", true],
    ["trifecta", 2, "Data exfiltration", "Lethal trifecta lock", "No outbound requests once the session is both untrusted and holding secrets.", false],
    ["egress_allowlist", 2, "Data exfiltration", "Allowlist only", "Outbound requests may only reach approved hosts.", false],
    ["shell_upload", 2, "Data exfiltration", "Block curl / wget uploads", "Stops shell commands that send data out.", false],
    ["canaries", 2, "Data exfiltration", "Canary keys", "Flags planted fake keys if they show up in traffic.", false],
    ["protected_config", 3, "Dangerous actions", "Protect config and CI", "The agent can't edit its own settings, git hooks or CI workflows.", false],
    ["third_party_untrusted", 4, "Supply chain", "Flag vendored code", "vendor/, node_modules/ and third_party/ count as untrusted.", false],
    ["credential_broker", 5, "Credentials", "Key broker", "The real API key never enters the agent's sandbox.", true],
    ["secrets_sensitive", 5, "Credentials", "Flag secret files", ".env, keys and credential files mark the session as holding secrets.", false],
    ["budget", 6, "Runaway resources", "Budget and time limit", "Stops the run when it makes too many requests or runs too long.", false],
    ["bound_approvals", 7, "Approval abuse", "Exact-action approvals", "Approving one action never approves a different one; no answer means no.", true],
    ["feed_isolation", 7, "Approval abuse", "Private control panel", "The agent can't reach this dashboard or press its buttons.", true],
    ["audit_chain", 7, "Approval abuse", "Tamper-evident log", "Every event is hash-chained, so edits are detectable.", true],
  ];

  const KINDS = {
    command: { label: "Shell command containing", placeholder: "e.g. setup.sh  or  rm -rf" },
    read: { label: "Reading a file", placeholder: "e.g. .env  or  secrets/*" },
    write: { label: "Editing a file", placeholder: "e.g. package.json  or  src/auth/*" },
    tool: { label: "Any call of tool", placeholder: "e.g. WebFetch  or  mcp__*" },
    host: { label: "Reaching host", placeholder: "e.g. pastebin.com  or  *.ngrok.io" },
  };
  const DESCRIBE = {
    command: (p) => `shell command containing “${p}”`, read: (p) => `reading ${p}`,
    write: (p) => `editing ${p}`, tool: (p) => `any ${p} call`, host: (p) => `reaching ${p}`,
  };

  function defaults() {
    return {
      protections: DEFAULTS.map(([id, category, category_title, label, detail, locked]) =>
        ({ id, category, category_title, label, detail, locked, available: true, enabled: true })),
      custom_rules: [], policy_version: "demo", revision: 0,
    };
  }

  /* The newest settings snapshot in the event list, or null. */
  function latest(events) {
    for (let i = events.length - 1; i >= 0; i--) if (events[i].type === "settings") return events[i].data;
    return null;
  }

  // ---- demo-only: the gateway's matching, simplified, so the replay honours your rules -------
  const TOOLS = { command: ["Bash"], read: ["Read", "Grep", "Glob", "NotebookRead"], write: ["Write", "Edit", "MultiEdit", "NotebookEdit"] };
  function glob(pat, path) {
    const re = new RegExp("^" + pat.toLowerCase().replace(/^(\.\/)+/, "").replace(/[.+^${}()|[\]\\?]/g, "\\$&").replace(/\*/g, ".*") + "$");
    const p = String(path || "").toLowerCase().replace(/^\/workspace\//, "").replace(/^(\.\/)+/, "");
    return re.test(p) || (!pat.startsWith("/") && !pat.startsWith("*") && p.split("/").some((_, i, a) => re.test(a.slice(i).join("/"))));
  }
  function hostMatch(pat, host) {
    host = String(host || "").toLowerCase();
    return pat.startsWith("*.") ? host === pat.slice(2) || host.endsWith(pat.slice(1)) : host === pat;
  }
  function matches(rule, ev) {
    const d = ev.data || {};
    if (ev.type === "network_request") return rule.kind === "host" && hostMatch(rule.pattern, d.destination);
    if (ev.type !== "tool_call") return false;
    const tool = d.tool || "";
    switch (rule.kind) {
      case "command": return tool === "Bash" && String(d.input || "").toLowerCase().includes(rule.pattern.toLowerCase());
      case "read": case "write": {
        if (tool === "Bash") {  // like the gateway: a command that mentions the file
          const bare = rule.pattern.replace(/^(\.\/)+/, "").replace(/\*/g, "").toLowerCase();
          return !!bare && String(d.input || "").toLowerCase().includes(bare);
        }
        return TOOLS[rule.kind].includes(tool) && glob(rule.pattern, d.path || d.input);
      }
      case "tool": return rule.pattern.endsWith("*") ? tool.startsWith(rule.pattern.slice(0, -1)) : tool === rule.pattern;
      case "host": try { return tool === "WebFetch" && hostMatch(rule.pattern, new URL(d.input).hostname); } catch (e) { return false; }
    }
    return false;
  }
  function clean(spec) {  // same checks as the gateway, so demo and live refuse the same input
    const kind = spec.kind, verdict = spec.verdict === "ask" ? "ask" : "block";
    let pattern = String(spec.pattern || "").trim();
    if (!KINDS[kind]) throw new Error("Pick what to disallow.");
    if (!pattern) throw new Error("Type what to match.");
    if (pattern.length > 200) throw new Error("Keep it under 200 characters.");
    if (kind === "tool" && !/^[A-Za-z0-9_-]+\*?$/.test(pattern)) throw new Error("A tool name like Bash, WebFetch or mcp__*.");
    if (kind === "host") {
      pattern = pattern.toLowerCase();
      if (!/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(pattern)) throw new Error("A host like example.com or *.example.com.");
    }
    const label = DESCRIBE[kind](pattern);
    return { kind, pattern, verdict, label, reason: `Disallowed by the operator: ${label}.` };
  }

  // ---- the settings window -----------------------------------------------------------------
  // Switchable protections, grouped by what they do (the category number stays as a tag).
  const GROUPS = [
    ["Spot risky input", "Mark the session when the agent reads something it shouldn't trust or something secret.",
      ["untrusted_sources", "third_party_untrusted", "secrets_sensitive", "canaries"]],
    ["Stop data leaving", "Decide what may go out of the sandbox.", ["trifecta", "egress_allowlist", "shell_upload"]],
    ["Stop dangerous changes", "Files the agent must never touch.", ["protected_config"]],
    ["Limits", "Keep a runaway agent from burning time and money.", ["budget"]],
  ];
  const CATS = ["Gateway bypass", "Prompt injection", "Data exfiltration", "Dangerous actions", "Supply chain", "Credentials", "Runaway resources", "Approval abuse"];
  const PAGES = [["overview", "Overview"], ["rules", "Disallowed actions"], ["protections", "Protections"], ["always", "Always on"]];
  const EXAMPLES = [["command", "setup.sh", "a script"], ["read", ".env", "secrets"], ["host", "*.ngrok.io", "a host"], ["command", "rm -rf", "deletes"]];

  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const svg = (d) => { const s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("viewBox", "0 0 16 16"); s.setAttribute("aria-hidden", "true"); s.innerHTML = d; return s; };
  const ICONS = {
    overview: '<rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/>',
    rules: '<circle cx="8" cy="8" r="6"/><path d="M3.8 12.2l8.4-8.4"/>',
    protections: '<path d="M8 1.5l5.5 2v4.2c0 3.2-2.3 5.6-5.5 6.8-3.2-1.2-5.5-3.6-5.5-6.8V3.5z"/>',
    always: '<rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 015 0v2"/>',
  };

  function toggle(on, disabled, onchange, label) {
    const b = el("input", "switch");
    b.type = "checkbox"; b.role = "switch"; b.checked = on; b.disabled = disabled;
    b.setAttribute("aria-label", label);
    b.onchange = () => onchange(b.checked);
    return b;
  }

  function render(root, snap, opts) {
    const s = snap || defaults();
    const prots = s.protections || [];
    const byId = Object.fromEntries(prots.map((p) => [p.id, p]));
    const page = opts.page || "rules";
    root.textContent = "";
    const modal = el("div", "set-modal");

    // sidebar
    const side = el("nav", "set-side");
    side.append(el("div", "set-side-title", "Protections"));
    PAGES.forEach(([id, label]) => {
      const b = el("button", "set-nav" + (page === id ? " on" : ""));
      b.type = "button";
      b.append(svg(ICONS[id]), el("span", null, label));
      const n = id === "rules" ? (s.custom_rules || []).length : id === "protections" ? prots.filter((p) => !p.locked && !p.enabled).length : 0;
      if (n) b.append(el("span", "set-nav-n" + (id === "protections" ? " warn" : ""), id === "protections" ? `${n} off` : n));
      b.onclick = () => opts.onPage(id);
      side.append(b);
    });
    const meta = el("div", "set-side-meta");
    meta.append(el("div", null, "Policy"), el("div", "mono", s.policy_version || "—"));
    if (opts.demo) meta.append(el("div", "set-demo", "Demo mode"));
    side.append(meta);

    // content
    const main = el("section", "set-main");
    const close = el("button", "icon set-close", "×");
    close.type = "button"; close.title = "Close (Esc)"; close.setAttribute("aria-label", "Close");
    close.onclick = opts.onClose;
    main.append(close);
    const body = el("div", "set-body");
    ({ overview, rules, protections, always })[page](body, s, prots, byId, opts);
    main.append(body);
    modal.append(side, main);
    root.append(modal);
  }

  function header(body, title, sub) {
    body.append(el("h2", "set-h", title));
    if (sub) body.append(el("p", "set-lede", sub));
  }

  function overview(body, s, prots, byId, opts) {
    const off = prots.filter((p) => !p.enabled);
    header(body, "Overview", off.length
      ? `${off.length} protection${off.length > 1 ? "s are" : " is"} switched off. Everything else is on.`
      : "Every protection is on. The agent is covered in all eight threat categories.");
    const grid = el("div", "set-cats");
    CATS.forEach((name, i) => {
      const mine = prots.filter((p) => p.category === i);
      const offHere = mine.filter((p) => !p.enabled);
      const tile = el("button", "set-cat" + (offHere.length ? " off" : ""));
      tile.type = "button";
      tile.append(el("span", "set-cat-num", i));
      const t = el("span", "set-cat-txt");
      t.append(el("span", "set-cat-name", name),
        el("span", "set-cat-sub", offHere.length ? `${offHere.length} off: ${offHere.map((p) => p.label).join(", ")}` : mine.map((p) => p.label).join(" · ")));
      tile.append(t, el("span", "set-cat-state", offHere.length ? "Reduced" : "On"));
      tile.onclick = () => opts.onPage(mine.every((p) => p.locked) ? "always" : "protections");
      grid.append(tile);
    });
    body.append(grid);
    const n = (s.custom_rules || []).length;
    const cta = el("div", "set-cta");
    cta.append(el("span", null, n ? `Plus ${n} disallowed action${n > 1 ? "s" : ""} of your own.` : "Want to stop something specific?"));
    const b = el("button", "btn btn-outline", n ? "View rules" : "Disallow an action");
    b.type = "button"; b.onclick = () => opts.onPage("rules");
    cta.append(b);
    body.append(cta);
  }

  function rules(body, s, prots, byId, opts) {
    header(body, "Disallowed actions", "Stop the agent from doing something specific. A new rule applies to its very next action.");
    const form = el("form", "set-form");
    const kind = el("select", "set-kind");
    kind.setAttribute("aria-label", "What to disallow");
    Object.entries(KINDS).forEach(([k, v]) => { const o = el("option", null, v.label); o.value = k; kind.append(o); });
    kind.value = opts.draft.kind || "command";
    const pat = el("input", "set-pattern");
    pat.type = "text"; pat.autocomplete = "off"; pat.spellcheck = false;
    pat.setAttribute("aria-label", "Pattern");
    pat.placeholder = KINDS[kind.value].placeholder; pat.value = opts.draft.pattern || "";
    kind.onchange = () => { opts.draft.kind = kind.value; pat.placeholder = KINDS[kind.value].placeholder; pat.focus(); };
    pat.oninput = () => (opts.draft.pattern = pat.value);
    const l1 = el("label", "set-field"); l1.append(el("span", "set-label", "When the agent tries"), kind);
    const l2 = el("label", "set-field grow"); l2.append(el("span", "set-label", "Matching"), pat);
    const row = el("div", "set-row"); row.append(l1, l2);
    const seg = el("div", "seg");
    seg.setAttribute("role", "radiogroup");
    [["block", "Block it"], ["ask", "Ask me first"]].forEach(([v, label]) => {
      const b = el("button", (opts.draft.verdict || "block") === v ? "on" : "", label);
      b.type = "button"; b.setAttribute("role", "radio"); b.setAttribute("aria-checked", String((opts.draft.verdict || "block") === v));
      b.onclick = () => { opts.draft.verdict = v; [...seg.children].forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-checked", String(x === b)); }); };
      seg.append(b);
    });
    const go = el("button", "btn btn-solid", "Add rule"); go.type = "submit";
    const l3 = el("div", "set-field"); l3.append(el("span", "set-label", "Then"), seg);
    const row2 = el("div", "set-row end"); row2.append(l3, go);
    form.append(row, row2);
    const ex = el("div", "set-examples");
    ex.append(el("span", null, "Try"));
    EXAMPLES.forEach(([k, p]) => {
      const c = el("button", "chip", p); c.type = "button";
      c.title = `${KINDS[k].label} ${p}`;
      c.onclick = () => { opts.draft.kind = k; opts.draft.pattern = p; kind.value = k; pat.value = p; pat.placeholder = KINDS[k].placeholder; pat.focus(); };
      ex.append(c);
    });
    form.append(ex);
    if (opts.error) form.append(el("div", "set-error", opts.error));
    form.onsubmit = (e) => {
      e.preventDefault();
      try { opts.onAdd(clean({ kind: kind.value, pattern: pat.value, verdict: opts.draft.verdict || "block" })); opts.draft.pattern = ""; }
      catch (x) { opts.onError(x.message); }
    };
    body.append(form);

    const custom = s.custom_rules || [];
    body.append(el("div", "set-sub-h", custom.length ? `Your rules (${custom.length})` : "Your rules"));
    if (!custom.length) { body.append(el("p", "set-empty", "None yet. Rules you add show up here and in the story when they stop something.")); return; }
    const list = el("ul", "set-list");
    custom.forEach((r) => {
      const li = el("li", "set-li");
      const t = el("span", "set-li-txt");
      t.append(el("span", "set-li-title", r.label), el("span", "set-li-sub", `${r.id} · by ${r.by || "dashboard"}`));
      const rm = el("button", "btn btn-ghost", "Remove"); rm.type = "button";
      rm.setAttribute("aria-label", `Remove ${r.label}`);
      rm.onclick = () => opts.onRemove(r.id);
      li.append(el("span", `tag ${r.verdict}`, r.verdict === "ask" ? "Ask" : "Block"), t, rm);
      list.append(li);
    });
    body.append(list);
  }

  function protections(body, s, prots, byId, opts) {
    header(body, "Protections", "All on by default. Turning one off applies to the agent's next action and is logged.");
    if (opts.error) body.append(el("div", "set-error", opts.error));
    GROUPS.forEach(([title, sub, ids]) => {
      const items = ids.map((id) => byId[id]).filter(Boolean);
      if (!items.length) return;
      body.append(el("div", "set-sub-h", title), el("p", "set-group-sub", sub));
      const list = el("ul", "set-list");
      items.forEach((p) => {
        const li = el("li", "set-li" + (p.enabled ? "" : " off"));
        const t = el("span", "set-li-txt");
        const ttl = el("span", "set-li-title", p.label);
        ttl.append(el("span", "cat-tag", `Cat ${p.category}`));
        t.append(ttl, el("span", "set-li-sub", p.available ? p.detail : "Not in the loaded policy file."));
        li.append(t, toggle(p.enabled, !p.available, (on) => opts.onToggle(p.id, on, p.label), p.label));
        list.append(li);
      });
      body.append(list);
    });
  }

  function always(body, s, prots) {
    header(body, "Always on", "Enforced by how FlowControl is deployed, not by a setting. They can't be switched off from here.");
    const list = el("ul", "set-list");
    prots.filter((p) => p.locked).forEach((p) => {
      const li = el("li", "set-li");
      const t = el("span", "set-li-txt");
      const ttl = el("span", "set-li-title", p.label);
      ttl.append(el("span", "cat-tag", `Cat ${p.category}`));
      t.append(ttl, el("span", "set-li-sub", p.detail));
      li.append(t, el("span", "set-locked", "On"));
      list.append(li);
    });
    body.append(list);
  }

  window.FCSettings = { defaults, latest, render, matches, clean };
})();
