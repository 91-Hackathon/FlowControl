/* Traffic map: Little Snitch style. Agent -> gateway -> destinations; allowed links in ink,
   blocked ones stopped at the gateway in red; a connection list beside it. */
(function () {
  const M = () => window.FCModel;
  const ORDER = ["LLM API", "Files: read", "Files: write", "Shell", "Web", "MCP", "Subagents", "Other tools", "Unknown hosts"];
  const SVGNS = "http://www.w3.org/2000/svg";

  function aggregate(events) {
    const groups = {};
    events.forEach((ev) => {
      const dst = M().destination(ev);
      if (!dst) return;
      const g = (groups[dst.group] ||= { name: dst.group, count: 0, blocked: 0, last: 0, keys: {} });
      const k = (g.keys[dst.key] ||= { key: dst.key, group: dst.group, count: 0, blocked: 0, last: 0, lastId: null });
      const t = Date.parse(ev.time) || 0;
      g.count++; k.count++;
      if (dst.blocked) { g.blocked++; k.blocked++; }
      g.last = Math.max(g.last, t);
      if (t >= k.last) { k.last = t; k.lastId = ev.event_id; }
    });
    return ORDER.filter((n) => groups[n]).map((n) => groups[n]);
  }

  function el(tag, attrs, text) {
    const e = document.createElementNS(SVGNS, tag);
    Object.entries(attrs || {}).forEach(([k, v]) => e.setAttribute(k, v));
    if (text != null) e.textContent = text;
    return e;
  }

  function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  const GLYPH = { "LLM API": "AI", "Files: read": "R", "Files: write": "W", "Shell": ">_", "Web": "↗", "MCP": "M", "Subagents": "S", "Other tools": "T", "Unknown hosts": "?" };
  const REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Agent -> one gateway "gate" -> a card per destination group. Allowed traffic leaves the gate
     as an ink line (thicker = more requests); blocked traffic stops at a red marker right at the
     gate, with the path it tried to take drawn faint and dashed. A dot travels along links that
     carried traffic in the last few seconds. */
  function drawGraph(svg, groups) {
    svg.textContent = "";
    const W = 760, cardW = 300, cardH = 58, gap = 12, padY = 34;
    const n = Math.max(groups.length, 1);
    const stackH = n * cardH + (n - 1) * gap;
    const H = Math.max(260, stackH + padY * 2 + 30);
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const top = (H - 30 - stackH) / 2 + 6, cy = top + stackH / 2;
    const now = Math.max(0, ...groups.map((g) => g.last));
    const total = groups.reduce((a, g) => a + g.count, 0);
    const blocked = groups.reduce((a, g) => a + g.blocked, 0);
    const gateX = 262, gateW = 22, outX = gateX + gateW, cardX = W - cardW - 14;
    const gateTop = Math.min(top, cy - 40) - 6, gateBot = Math.max(top + stackH, cy + 40) + 6;
    const lw = (c) => (1.2 + Math.log2(c + 1) * 1.1).toFixed(1);
    const traveller = (d, cls, dur) => {
      if (REDUCED) return;
      const dot = el("circle", { r: 3.2, class: `traveller ${cls}` });
      const anim = el("animateMotion", { dur: `${dur}s`, repeatCount: "indefinite", path: d });
      dot.append(anim);
      svg.append(dot);
    };

    // agent -> gate
    const inD = `M168,${cy} L${gateX},${cy}`;
    svg.append(el("path", { d: inD, class: "link in", "stroke-width": lw(total) }));
    if (now && Date.now() - now < 4000) traveller(inD, "ink", 1.1);
    const agent = el("g", { class: "node agent" });
    agent.append(el("rect", { x: 20, y: cy - 34, width: 148, height: 68, rx: 12 }));
    agent.append(el("rect", { x: 34, y: cy - 14, width: 28, height: 28, rx: 7, class: "glyph-bg" }));
    agent.append(el("text", { x: 48, y: cy + 4.5, class: "glyph", "text-anchor": "middle" }, "▸_"));
    agent.append(el("text", { x: 72, y: cy - 3, class: "n-title" }, "Agent"));
    agent.append(el("text", { x: 72, y: cy + 14, class: "n-sub" }, "Claude Code"));
    svg.append(agent);

    // the gate
    const gate = el("g", { class: "gate" });
    gate.append(el("rect", { x: gateX, y: gateTop, width: gateW, height: gateBot - gateTop, rx: gateW / 2 }));
    gate.append(el("text", { x: gateX + gateW / 2, y: gateTop - 12, class: "n-title", "text-anchor": "middle" }, "Gateway"));
    gate.append(el("text", { x: gateX + gateW / 2, y: gateBot + 20, class: "n-sub", "text-anchor": "middle" },
      total ? `${total - blocked} through · ${blocked} stopped` : "policy + broker"));
    svg.append(gate);

    if (!groups.length) {
      svg.append(el("text", { x: cardX + cardW / 2, y: cy + 4, class: "n-sub", "text-anchor": "middle" }, "No traffic yet"));
      return;
    }

    groups.forEach((g, i) => {
      const y = top + i * (cardH + gap), ny = y + cardH / 2;
      const allowed = g.count - g.blocked;
      const d = `M${outX},${ny} L${cardX},${ny}`;
      const recent = now - g.last < 2500;
      if (allowed > 0) {
        svg.append(el("path", { d, class: "link ok", "stroke-width": lw(allowed) }));
        if (recent) traveller(d, "ink", 1.3);
      }
      if (g.blocked > 0) {
        const ty = allowed > 0 ? ny + 9 : ny; // a mixed group: the stopped path runs just below the allowed one
        svg.append(el("path", { d: `M${outX + 26},${ty} L${cardX},${ty}`, class: "link tried" }));
        svg.append(el("path", { d: `M${outX},${ty} L${outX + 18},${ty}`, class: "link stopped", "stroke-width": lw(g.blocked) }));
        const sx = outX + 24;
        svg.append(el("circle", { cx: sx, cy: ty, r: 7, class: "stop" }));
        svg.append(el("path", { d: `M${sx - 2.6},${ty - 2.6} L${sx + 2.6},${ty + 2.6} M${sx + 2.6},${ty - 2.6} L${sx - 2.6},${ty + 2.6}`, class: "stop-x" }));
      }
      const keys = Object.values(g.keys).sort((a, b) => b.count - a.count);
      const more = keys.length > 1 ? ` +${keys.length - 1}` : "";
      const sub = trunc(keys[0].key, (g.blocked ? 26 : 30) - more.length) + more; // fits the card in 11px mono
      const state = g.blocked && !allowed ? " all-denied" : g.blocked ? " some-denied" : "";
      const node = el("g", { class: `node dest${state}` });
      const title = el("title", null, `${g.name}: ${g.count} request${g.count > 1 ? "s" : ""}${g.blocked ? `, ${g.blocked} stopped` : ""}\n${keys.map((k) => k.key).join("\n")}`);
      node.append(title);
      node.append(el("rect", { x: cardX, y, width: cardW, height: cardH, rx: 10 }));
      node.append(el("rect", { x: cardX + 12, y: y + 15, width: 28, height: 28, rx: 7, class: "glyph-bg" }));
      node.append(el("text", { x: cardX + 26, y: y + 33.5, class: "glyph", "text-anchor": "middle" }, GLYPH[g.name] || "•"));
      node.append(el("text", { x: cardX + 52, y: y + 25, class: "n-title" }, g.name));
      node.append(el("text", { x: cardX + 52, y: y + 42, class: "n-sub" }, sub));
      if (g.blocked) {
        const label = `${g.blocked} stopped`, bw = 8 + label.length * 6.2;
        node.append(el("rect", { x: cardX + cardW - 12 - bw, y: y + 12, width: bw, height: 18, rx: 9, class: "pill-bad" }));
        node.append(el("text", { x: cardX + cardW - 12 - bw / 2, y: y + 25, class: "pill-bad-t", "text-anchor": "middle" }, label));
        node.append(el("text", { x: cardX + cardW - 14, y: y + 45, class: "n-count", "text-anchor": "end" }, `${g.count} total`));
      } else {
        node.append(el("text", { x: cardX + cardW - 14, y: y + 34, class: "n-big", "text-anchor": "end" }, g.count));
      }
      svg.append(node);
    });
  }

  function drawList(tbody, groups, onPick) {
    tbody.textContent = "";
    const keys = groups.flatMap((g) => Object.values(g.keys)).sort((a, b) => b.last - a.last);
    keys.forEach((k) => {
      const tr = document.createElement("tr");
      if (k.blocked && k.blocked === k.count) tr.className = "blocked";
      const state = k.blocked === 0 ? "allow" : k.blocked === k.count ? "deny" : "mixed";
      const cells = [
        ["ls-state " + state, state === "allow" ? "●" : state === "deny" ? "⊘" : "◐"],
        ["", k.key], ["muted", k.group], ["num", k.count], ["num" + (k.blocked ? " st-bad" : ""), k.blocked || ""],
        ["muted", k.last ? new Date(k.last).toLocaleTimeString([], { hour12: false }) : ""],
      ];
      cells.forEach(([cls, text]) => {
        const td = document.createElement("td");
        td.className = cls;
        td.textContent = text;
        td.title = String(text);
        tr.appendChild(td);
      });
      tr.addEventListener("click", () => onPick(k.key));
      tbody.appendChild(tr);
    });
  }

  function render(root, events, onPick) {
    const groups = aggregate(events);
    drawGraph(root.querySelector("svg"), groups);
    drawList(root.querySelector("tbody"), groups, onPick);
  }

  window.FCMap = { render };
})();
