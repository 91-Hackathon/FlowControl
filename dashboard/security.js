/* Security events: Cloudflare style. Action summary + timeline, top rules, and an event log
   where each event expands into a field list: action, rule, reason, what matched, cause. */
(function () {
  const M = () => window.FCModel;
  const ACTION = { block: "Block", ask: "Challenge", allow: "Allow" };

  /* The expanded detail for one decision (also used in the Network detail pane). */
  function card(dec, byId) {
    const d = dec.data || {};
    const target = byId[d.target_event];
    const td = (target && target.data) || {};
    const wrap = document.createElement("div");
    wrap.className = "sec-card";
    const fields = [
      ["Action taken", ACTION[d.verdict] || d.verdict, d.verdict === "block" ? "st-bad" : d.verdict === "ask" ? "st-warn" : ""],
      ["Rule ID", d.rule, "mono"],
      ["Rule message", d.reason],
      ["Decided by", d.decided_by === "llm" ? "LLM (can only escalate)" : "Rule (deterministic)"],
      ["Match type", d.advisory ? "Advisory: shell text pattern (a match blocks, a miss proves nothing)" : "Structured: tool and path / destination"],
      ["Policy version", d.policy_version, "mono"],
      ["Event", `${dec.event_id} → judged ${d.target_event}`, "mono"],
    ];
    if (target) {
      fields.push(["Request", target.type === "network_request" ? `${td.method} ${td.destination}` : td.summary || target.type, "mono"]);
      if (td.tool) fields.push(["Tool", td.tool, "mono"]);
      if (td.path) fields.push(["Path", td.path, "mono"]);
      if (td.input && td.input !== td.path) fields.push(["Input", td.input, "mono"]);
      if (td.preview) fields.push(["Payload", td.preview, "mono payload"]);
    }
    const grid = document.createElement("div");
    grid.className = "kv";
    fields.filter(([, v]) => v != null && v !== "").forEach(([k, v, cls]) => {
      const a = document.createElement("span"); a.className = "k"; a.textContent = k;
      const b = document.createElement("span"); b.className = "v " + (cls || "");
      if ((cls || "").includes("payload")) b.appendChild(highlightCanary(String(v)));
      else b.textContent = String(v);
      grid.append(a, b);
    });
    wrap.appendChild(grid);

    // what led here
    const causes = [];
    (function walk(id, seen) {
      if (!id || seen.has(id) || !byId[id]) return;
      seen.add(id);
      (byId[id].caused_by || []).forEach((c) => walk(c, seen));
      if (id !== dec.event_id) causes.push(byId[id]);
    })(dec.event_id, new Set());
    if (causes.length) {
      const chain = document.createElement("div");
      chain.className = "chain";
      const label = document.createElement("span"); label.className = "chain-label"; label.textContent = "Caused by";
      chain.appendChild(label);
      causes.sort((a, b) => a.seq - b.seq).forEach((e, i) => {
        if (i) { const s = document.createElement("span"); s.className = "arr"; s.textContent = "→"; chain.appendChild(s); }
        const p = document.createElement("span");
        p.className = "pill" + (M().isBlock(e) ? " red" : e.type === "taint" ? " amber" : "");
        p.textContent = label_(e);
        chain.appendChild(p);
      });
      wrap.appendChild(chain);
    }
    return wrap;
  }

  function label_(e) {
    const d = e.data || {};
    if (e.type === "tool_call") return d.summary || d.tool;
    if (e.type === "network_request") return `${d.method} ${d.destination}`;
    if (e.type === "taint") return `marked ${d.tag}`;
    if (e.type === "heal") return "healed";
    return e.type;
  }

  function highlightCanary(text) {
    const frag = document.createDocumentFragment();
    const re = /\[CANARY\][^&\s"]*/g;
    let last = 0, m;
    while ((m = re.exec(text))) {
      frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      const s = document.createElement("span"); s.className = "canary"; s.textContent = m[0];
      frag.appendChild(s);
      last = m.index + m[0].length;
    }
    frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
  }

  /* ---- the Security view ---- */
  const open = new Set(); // expanded decision ids survive re-renders

  function render(root, events, byId) {
    const judged = events.filter((e) => e.type === "tool_call" || e.type === "network_request");
    const decisions = events.filter((e) => e.type === "decision");
    const blocked = judged.filter((e) => M().isBlock(e));
    const asked = decisions.filter((e) => e.data.verdict === "ask");

    // summary numbers
    root.querySelector(".sec-total").textContent = judged.length;
    root.querySelector(".sec-allow").textContent = judged.length - blocked.length;
    root.querySelector(".sec-ask").textContent = asked.length;
    root.querySelector(".sec-block").textContent = blocked.length;

    // timeline: allowed vs blocked per bucket
    const n = 40;
    const all = M().buckets(judged, n, () => 1);
    const bad = M().buckets(judged, n, (e) => (M().isBlock(e) ? 1 : 0));
    const max = Math.max(1, ...all);
    const svg = root.querySelector(".sec-chart");
    svg.innerHTML = all.map((v, i) => {
      const x = i * (100 / n), w = 100 / n - 0.6, h = (v / max) * 46, hb = (bad[i] / max) * 46;
      return `<rect class="ok" x="${x}" y="${48 - h}" width="${w}" height="${h - hb}"/><rect class="bad" x="${x}" y="${48 - hb}" width="${w}" height="${hb}"/>`;
    }).join("");

    // top rules / top blocked tools
    topTable(root.querySelector(".sec-rules tbody"), count(decisions.filter((e) => e.data.verdict !== "allow"), (e) => e.data.rule));
    topTable(root.querySelector(".sec-tools tbody"), count(blocked, (e) => (e.type === "tool_call" ? e.data.tool : e.data.destination)));

    // event log, newest first
    const log = root.querySelector(".sec-log");
    log.textContent = "";
    const rows = decisions.slice().sort((a, b) => b.seq - a.seq);
    root.querySelector(".sec-empty").hidden = rows.length > 0;
    rows.forEach((dec) => {
      const d = dec.data, target = byId[d.target_event], td = (target && target.data) || {};
      const item = document.createElement("div");
      item.className = "sec-item" + (open.has(dec.event_id) ? " open" : "");
      const head = document.createElement("div");
      head.className = "sec-head";
      const cells = [
        ["chev", "▸"],
        ["time", new Date(dec.time).toLocaleTimeString([], { hour12: false })],
        ["badge " + d.verdict, ACTION[d.verdict] || d.verdict],
        ["rule mono", d.rule],
        ["what", target ? (target.type === "network_request" ? `${td.method} ${td.destination}` : td.summary || td.tool) : d.target_event],
      ];
      cells.forEach(([cls, text]) => { const s = document.createElement("span"); s.className = cls; s.textContent = text; s.title = text; head.appendChild(s); });
      head.addEventListener("click", () => {
        if (open.has(dec.event_id)) open.delete(dec.event_id); else open.add(dec.event_id);
        render(root, events, byId);
      });
      item.appendChild(head);
      if (open.has(dec.event_id)) item.appendChild(card(dec, byId));
      log.appendChild(item);
    });
  }

  function count(list, keyFn) {
    const m = {};
    list.forEach((e) => { const k = keyFn(e) || "(none)"; m[k] = (m[k] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }

  function topTable(tbody, pairs) {
    tbody.textContent = "";
    if (!pairs.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td class="muted">None yet</td><td></td>';
      tbody.appendChild(tr);
      return;
    }
    const max = pairs[0][1];
    pairs.forEach(([k, v]) => {
      const tr = document.createElement("tr");
      const a = document.createElement("td");
      a.className = "mono"; a.textContent = k; a.title = k;
      const b = document.createElement("td");
      b.className = "num";
      b.innerHTML = `<span class="meter"><span style="width:${(v / max) * 100}%"></span></span>`;
      b.append(String(v));
      tr.append(a, b);
      tbody.appendChild(tr);
    });
  }

  window.FCSecurity = { render, card };
})();
