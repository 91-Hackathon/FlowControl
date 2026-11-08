/* Model: derived facts the views share. Pure functions of the event list; no DOM. */
(function () {
  /* Where an event "goes", for the traffic map (Little Snitch style).
     Returns { group, key, blocked } or null for events that aren't traffic. */
  function destination(ev) {
    const d = ev.data || {};
    if (ev.type === "llm_call") return { group: "LLM API", key: d.destination || "llm", blocked: false };
    if (ev.type === "network_request") {
      const group = d.dest_category === "llm" ? "LLM API" : d.dest_category === "allowlist" ? "Web" : "Unknown hosts";
      return { group, key: d.destination, blocked: !!d.blocked };
    }
    if (ev.type !== "tool_call") return null;
    const blocked = !!d.blocked || ev.level === "red";
    const tool = d.tool || "";
    if (["Read", "Glob", "Grep", "NotebookRead"].includes(tool)) return { group: "Files: read", key: shortPath(d.path || d.input), blocked };
    if (["Write", "Edit", "MultiEdit", "NotebookEdit"].includes(tool)) return { group: "Files: write", key: shortPath(d.path || d.input), blocked };
    if (tool === "Bash") return { group: "Shell", key: shellProgram(d.input), blocked };
    if (tool === "WebFetch") return { group: "Web", key: host(d.input), blocked };
    if (tool === "WebSearch") return { group: "Web", key: "web search", blocked };
    if (tool === "Task" || tool === "Agent") return { group: "Subagents", key: tool, blocked };
    if (tool.startsWith("mcp__")) return { group: "MCP", key: tool.split("__")[1] || tool, blocked };
    return { group: "Other tools", key: tool, blocked };
  }

  function shortPath(p) {
    if (!p) return "(unknown)";
    const s = String(p).replace(/^\/workspace\//, "").replace(/^\/Users\/[^/]+\//, "~/");
    return s.length > 48 ? "…" + s.slice(-47) : s;
  }

  /* The program a shell command runs: skip "cd x &&" and env assignments. */
  function shellProgram(cmd) {
    if (!cmd) return "(shell)";
    const parts = String(cmd).split(/&&|;|\|\|/).map((s) => s.trim()).filter(Boolean);
    const main = parts.find((p) => !/^cd\s/.test(p)) || parts[0] || "";
    const words = main.split(/\s+/).filter((w) => !/^[A-Z_][A-Z0-9_]*=/.test(w));
    return (words[0] || "(shell)").replace(/^.*\//, "");
  }

  function host(url) {
    try { return new URL(String(url)).host || String(url); } catch (e) { return String(url || "(url)"); }
  }

  /* decision events keyed by the event they judged */
  function decisionsByTarget(events) {
    const out = {};
    events.forEach((ev) => { if (ev.type === "decision" && ev.data) out[ev.data.target_event] = ev; });
    return out;
  }

  function isBlock(ev) {
    const d = ev.data || {};
    return (ev.type === "decision" && d.verdict === "block") || (ev.type !== "decision" && (d.blocked === true || ev.level === "red"));
  }

  /* Attack chains: for each block decision, every earlier event that led to it (via
     caused_by), the block itself, and any heal that followed from it. Sorted by seq. */
  function attackChains(events, byId) {
    const chains = [];
    events.filter((e) => e.type === "decision" && e.data && e.data.verdict === "block").forEach((dec) => {
      const seen = new Set();
      (function walk(id) {
        if (!id || seen.has(id) || !byId[id]) return;
        seen.add(id);
        (byId[id].caused_by || []).forEach(walk);
      })(dec.event_id);
      events.forEach((e) => {
        if (e.type === "heal" && (e.caused_by || []).some((c) => seen.has(c))) seen.add(e.event_id);
      });
      const ids = [...seen].sort((a, b) => byId[a].seq - byId[b].seq);
      chains.push({ decision: dec, ids, healed: ids.some((id) => byId[id].type === "heal") });
    });
    return chains;
  }

  /* Split [t0, t1] into n buckets and aggregate a value per bucket (for sparklines). */
  function buckets(events, n, pick, mode) {
    const timed = events.map((e) => ({ t: Date.parse(e.time), v: pick(e) })).filter((x) => x.v != null && !isNaN(x.t));
    const out = new Array(n).fill(0), cnt = new Array(n).fill(0);
    if (!timed.length) return out;
    const t0 = Math.min(...timed.map((x) => x.t)), t1 = Math.max(...timed.map((x) => x.t));
    const span = Math.max(1, t1 - t0);
    timed.forEach(({ t, v }) => {
      const i = Math.min(n - 1, Math.floor(((t - t0) / span) * n));
      out[i] += v; cnt[i]++;
    });
    if (mode === "avg") return out.map((v, i) => (cnt[i] ? v / cnt[i] : 0));
    return out;
  }

  window.FCModel = { destination, decisionsByTarget, isBlock, attackChains, buckets, shortPath };
})();
