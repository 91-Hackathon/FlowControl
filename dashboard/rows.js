/* Rows: turn a gateway event into a table row, and draw the table (incl. waterfall).
   Knows nothing about where events come from. */
(function () {
  const ICON = { llm: "AI", tool: "T", net: "↗", gateway: "G", blocked: "✕", session: "S" };

  /* Event -> row model. Returns null for events that don't belong in the list. */
  function fromEvent(ev) {
    const d = ev.data || {};
    const end = Date.parse(ev.time) || Date.now();
    const row = {
      id: ev.event_id, seq: ev.seq, ev, end, start: end,
      kind: "gateway", name: ev.type, sub: "", status: "", statusClass: "st-ok",
      type: ev.type, initiator: "", size: "", time: null, blocked: false, search: "",
    };
    switch (ev.type) {
      case "llm_call":
        Object.assign(row, {
          kind: "llm", name: "messages", sub: d.destination || "",
          status: "200", type: "llm", initiator: "agent",
          size: `${k(d.input_tokens)} / ${k(d.output_tokens)} tok`,
          time: d.duration_ms != null ? d.duration_ms : null,
        });
        if (row.time != null) row.start = end - row.time;
        break;
      case "tool_call":
        Object.assign(row, {
          kind: "tool", name: d.summary || d.tool, sub: "",
          status: verdict(ev, d.blocked), type: d.tool, initiator: "model",
          size: d.target === "network" ? "network" : "local", blocked: !!d.blocked,
        });
        break;
      case "network_request":
        Object.assign(row, {
          kind: d.blocked ? "blocked" : "net", name: `${d.method} ${d.destination}`, sub: d.dest_category,
          status: d.blocked ? "(blocked)" : "200", type: "fetch", initiator: "script",
          size: d.bytes != null ? bytes(d.bytes) : "", time: d.latency_ms, blocked: !!d.blocked,
        });
        break;
      case "decision":
        Object.assign(row, {
          kind: d.verdict === "block" ? "blocked" : "gateway", name: `decision: ${d.verdict}`, sub: d.rule,
          status: d.verdict, type: "decision", initiator: d.decided_by, blocked: d.verdict === "block",
        });
        break;
      case "taint":
        Object.assign(row, { name: `marked ${d.tag}`, sub: d.source, status: d.to_state, statusClass: "st-warn", type: "taint", initiator: "gateway" });
        break;
      case "approval_request":
        Object.assign(row, { name: "approval requested", sub: d.summary, status: "pending", statusClass: "st-warn", type: "approval", initiator: "gateway" });
        break;
      case "approval_result":
        Object.assign(row, { name: `approval ${d.result}`, sub: d.by, status: d.result, statusClass: d.result === "approved" ? "st-ok" : "st-bad", type: "approval", initiator: "user" });
        break;
      case "heal":
        Object.assign(row, { name: "healed", sub: d.quarantined_source, status: d.status, statusClass: "st-heal", type: "heal", initiator: "gateway" });
        break;
      case "quarantine":
        Object.assign(row, { name: "quarantined source", sub: d.source, status: "withheld", statusClass: "st-heal", type: "quarantine", initiator: "gateway" });
        break;
      case "settings":
        if (!d.change && !d.error) return null; // the initial snapshot isn't activity
        Object.assign(row, { name: d.error ? "settings refused" : "policy changed", sub: d.error || d.change,
          status: d.error ? "refused" : `rev ${d.revision}`, statusClass: d.error || ev.level === "yellow" ? "st-warn" : "st-ok",
          type: "settings", initiator: d.by || "dashboard" });
        break;
      case "session_start":
        Object.assign(row, { kind: "session", name: "session start", sub: d.task, status: "", type: "session", initiator: d.agent });
        break;
      case "session_end":
        Object.assign(row, { kind: "session", name: `session ${d.result}`, sub: d.summary, status: d.result, type: "session", initiator: "gateway" });
        break;
      default:
        return null; // stats and unknown types
    }
    if (row.blocked) { row.kind = "blocked"; row.statusClass = "st-bad"; }
    else if (row.statusClass === "st-ok" && /^(ask|yellow|pending)$/.test(row.status)) row.statusClass = "st-warn";
    row.search = [row.name, row.sub, row.status, row.type, row.initiator].join(" ").toLowerCase();
    return row;
  }

  function verdict(ev, blocked) {
    if (blocked) return "(blocked)";
    if (ev.level === "red") return "block";
    if (ev.level === "yellow") return "ask";
    if (ev.level === "green") return "allow";
    return "—"; // no level: watched, not judged
  }

  /* Which type chip a row belongs to. */
  function group(row) {
    if (row.blocked) return ["blocked", groupOf(row)];
    return [groupOf(row)];
  }
  function groupOf(row) {
    return { llm: "llm", tool: "tool", net: "net", blocked: "net", session: "gateway", gateway: "gateway" }[row.kind] || "gateway";
  }

  /* ---- table ---------------------------------------------------------------- */
  function renderRow(row) {
    const tr = document.createElement("tr");
    tr.dataset.id = row.id;
    if (row.blocked) tr.classList.add("blocked");
    const cells = [
      ["name", null],
      [row.statusClass, row.status],
      ["muted", row.type],
      ["muted", row.initiator],
      ["num", row.size],
      ["num", row.time != null ? ms(row.time) : ""],
      ["wf", null],
    ];
    cells.forEach(([cls, text], i) => {
      const td = document.createElement("td");
      td.className = cls;
      if (i === 0) {
        const nm = document.createElement("div");
        nm.className = "nm";
        const ico = document.createElement("span");
        ico.className = `ico ${row.kind}`;
        ico.textContent = ICON[row.kind] || "";
        const txt = document.createElement("span");
        txt.className = "txt";
        txt.textContent = row.name;
        if (row.sub) {
          const sub = document.createElement("span");
          sub.className = "sub";
          sub.textContent = row.sub;
          txt.appendChild(sub);
        }
        nm.append(ico, txt);
        td.appendChild(nm);
        td.title = row.sub ? `${row.name}\n${row.sub}` : row.name;
      } else if (cls === "wf") {
        const bar = document.createElement("div");
        bar.className = `bar ${row.kind}`;
        td.appendChild(bar);
      } else {
        td.textContent = text || "";
        td.title = text || "";
      }
      tr.appendChild(td);
    });
    return tr;
  }

  /* Position every waterfall bar on a shared timeline from the first to the last event. */
  function layoutWaterfall(tbody, rows) {
    if (!rows.length) return;
    let t0 = Infinity, t1 = -Infinity;
    rows.forEach((r) => { t0 = Math.min(t0, r.start); t1 = Math.max(t1, r.end); });
    const span = Math.max(1000, t1 - t0) * 1.04;
    for (const tr of tbody.children) {
      const r = rows.byId[tr.dataset.id];
      const bar = tr.querySelector(".bar");
      if (!r || !bar) continue;
      const left = ((r.start - t0) / span) * 100;
      const width = ((r.end - r.start) / span) * 100;
      bar.style.left = `${left}%`;
      bar.style.width = width > 0.2 ? `${width}%` : "";
      bar.classList.toggle("point", !(width > 0.2));
    }
  }

  // ---- formatting ----
  function k(n) { return n == null ? "—" : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n); }
  function ms(v) { return v >= 1000 ? `${(v / 1000).toFixed(2)} s` : `${Math.round(v * 10) / 10} ms`; }
  function bytes(b) { return b >= 1024 ? `${(b / 1024).toFixed(1)} kB` : `${b} B`; }

  window.FCRows = { fromEvent, group, renderRow, layoutWaterfall, fmt: { k, ms, bytes } };
})();
