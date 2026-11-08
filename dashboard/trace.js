/* Session replay: LangSmith-style trace tree with a playback bar and the attack chain on top.

   Tree: session -> each LLM call -> the tool calls it proposed -> what the gateway did about
   them (decisions, marks). Tool calls stream in before their LLM call finishes, so tool calls
   seen since the previous LLM call belong to the next one. */
(function () {
  const M = () => window.FCModel, R = () => window.FCRows, D = () => window.FCDetail;

  const st = { cursor: 0, follow: true, playing: false, speed: 1, selected: null, timer: null };
  let last = { root: null, events: [], byId: {}, rowsById: {} };

  // ---- tree -------------------------------------------------------------------------
  function buildTree(events, byId) {
    const root = { ev: null, children: [] };
    const nodes = {};
    let pending = []; // nodes waiting for the LLM call that proposed them
    // The gateway emits a tool call *before* its LLM call ends ("before"); hand-written
    // feeds such as events.example.json list it after ("after"). Decided at the first LLM
    // call that proposed tools: if none were waiting, tool calls follow their LLM call.
    let order = null, lastLlm = null;
    const attach = (node, parentId) => {
      const parent = parentId && nodes[parentId];
      if (parent) parent.children.push(node);
      else if (order === "after" && lastLlm) lastLlm.children.push(node);
      else pending.push(node);
    };
    events.forEach((ev) => {
      const node = { ev, children: [] };
      nodes[ev.event_id] = node;
      switch (ev.type) {
        case "session_start": root.ev = ev; break;
        case "llm_call":
          if (!order && (ev.data.tool_calls_proposed || 0) > 0) order = pending.some((n) => n.ev.type === "tool_call") ? "before" : "after";
          node.children = pending; pending = []; root.children.push(node); lastLlm = node;
          break;
        case "tool_call": if (order === "after" && lastLlm) lastLlm.children.push(node); else pending.push(node); break;
        case "decision": attach(node, ev.data && ev.data.target_event); break;
        case "network_request": {
          const tool = (ev.caused_by || []).map((id) => byId[id]).filter((e) => e && e.type === "tool_call").pop();
          attach(node, tool && tool.event_id);
          break;
        }
        case "taint": case "approval_request": case "approval_result":
          attach(node, (ev.caused_by || []).find((id) => nodes[id] && nodes[id].ev.type !== "taint"));
          break;
        case "stats": break;
        default: root.children.push(node); // heal, session_end
      }
    });
    if (pending.length) root.children.push({ ev: null, streaming: true, children: pending });
    return root;
  }

  function flatten(node, depth, out) {
    node.children.forEach((c) => { out.push({ node: c, depth }); flatten(c, depth + 1, out); });
    return out;
  }

  // ---- rendering ----------------------------------------------------------------------
  function render(root, events, byId, rowsById) {
    last = { root, events, byId, rowsById };
    const n = events.length;
    if (st.follow || st.cursor > n) st.cursor = n;
    const visible = events.slice(0, st.cursor);
    const vById = {};
    visible.forEach((e) => (vById[e.event_id] = e));

    // playback bar
    const slider = root.querySelector(".pb-slider");
    slider.max = String(n);
    slider.value = String(st.cursor);
    const at = visible[visible.length - 1];
    root.querySelector(".pb-pos").textContent = n
      ? `${st.cursor} / ${n}${at ? " · " + new Date(at.time).toLocaleTimeString([], { hour12: false }) : ""}${st.follow ? " · live" : ""}`
      : "No events yet";
    root.querySelector(".pb-play").textContent = st.playing ? "❚❚" : "▶";
    root.querySelector(".pb-play").title = st.playing ? "Pause" : "Play";

    // attack chain strip
    const chains = M().attackChains(visible, vById);
    const chainIds = new Set(chains.flatMap((c) => c.ids));
    const strip = root.querySelector(".chain-strip");
    strip.textContent = "";
    strip.hidden = !chains.length;
    chains.slice(-1).forEach((c) => {
      const label = document.createElement("span");
      label.className = "chain-label";
      label.textContent = chains.length > 1 ? `Attack chain (latest of ${chains.length})` : "Attack chain";
      strip.appendChild(label);
      c.ids.forEach((id, i) => {
        const e = vById[id];
        if (i) { const a = document.createElement("span"); a.className = "arr"; a.textContent = "→"; strip.appendChild(a); }
        const p = document.createElement("button");
        p.type = "button";
        p.className = "pill" + (M().isBlock(e) ? " red" : e.type === "heal" ? " green" : e.type === "taint" ? " amber" : "");
        p.textContent = pillText(e);
        p.addEventListener("click", () => { st.selected = id; render(root, events, byId, rowsById); });
        strip.appendChild(p);
      });
    });

    // tree
    const tree = buildTree(visible, vById);
    const list = root.querySelector(".trace-tree");
    list.textContent = "";
    const head = document.createElement("div");
    head.className = "tr-row tr-root";
    head.innerHTML = '<span class="ico session">S</span><span class="tr-name"></span>';
    head.querySelector(".tr-name").textContent = tree.ev ? `Session · ${tree.ev.data.task}` : "Session";
    list.appendChild(head);
    const rows = flatten(tree, 1, []);
    const current = at && at.event_id;
    if (!st.selected || !vById[st.selected]) st.selected = null;
    rows.forEach(({ node, depth }) => list.appendChild(treeRow(node, depth, chainIds, current, () => {
      st.selected = node.ev ? node.ev.event_id : null;
      render(root, events, byId, rowsById);
    })));
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "tr-empty";
      empty.textContent = n ? "Move the slider or press play to replay the session." : "Waiting for agent activity…";
      list.appendChild(empty);
    }
    const selRow = list.querySelector(".tr-row.sel");
    if (selRow && st.playing) selRow.scrollIntoView({ block: "nearest" });

    // detail for the selected (or current) event
    const showId = st.selected || current;
    const detail = root.querySelector(".trace-detail");
    detail.textContent = "";
    const row = showId && rowsById[showId];
    if (row) {
      const title = document.createElement("div");
      title.className = "td-title";
      title.textContent = row.name;
      detail.appendChild(title);
      const ev = vById[showId];
      const dec = ev.type === "decision" ? ev : visible.find((e) => e.type === "decision" && e.data.target_event === showId);
      if (dec && window.FCSecurity) detail.appendChild(window.FCSecurity.card(dec, vById));
      const body = document.createElement("div");
      D().render(body, row, "overview", rowsById);
      detail.appendChild(body);
    } else {
      detail.innerHTML = '<div class="tr-empty">Select a step to see what happened.</div>';
    }
  }

  function treeRow(node, depth, chainIds, current, onClick) {
    const div = document.createElement("div");
    const ev = node.ev;
    div.className = "tr-row";
    div.style.paddingLeft = `${8 + depth * 16}px`;
    if (!ev) {
      div.classList.add("muted");
      div.innerHTML = '<span class="ico llm">AI</span><span class="tr-name">LLM call (streaming…)</span>';
      return div;
    }
    const row = R().fromEvent(ev) || { kind: "gateway", name: ev.type };
    if (chainIds.has(ev.event_id)) div.classList.add("chain");
    if (M().isBlock(ev)) div.classList.add("blocked");
    if (ev.event_id === (st.selected || current)) div.classList.add("sel");
    const ico = document.createElement("span");
    ico.className = `ico ${row.kind}`;
    ico.textContent = { llm: "AI", tool: "T", net: "↗", gateway: "G", blocked: "✕", session: "S" }[row.kind] || "";
    const name = document.createElement("span");
    name.className = "tr-name";
    name.textContent = ev.type === "llm_call" ? `${ev.data.model || "LLM"} · ${ev.data.tool_calls_proposed || 0} tool calls` : row.name;
    name.title = row.name;
    const meta = document.createElement("span");
    meta.className = "tr-meta";
    if (ev.type === "llm_call") {
      const d = ev.data;
      meta.textContent = `${R().fmt.k((d.input_tokens || 0) + (d.output_tokens || 0))} tok  ${d.duration_ms != null ? R().fmt.ms(d.duration_ms) : ""}`;
    } else if (row.status) {
      meta.textContent = row.status;
      meta.className += " " + row.statusClass;
    }
    div.append(ico, name, meta);
    div.addEventListener("click", onClick);
    return div;
  }

  function pillText(e) {
    const d = e.data || {};
    if (e.type === "tool_call") return d.summary || d.tool;
    if (e.type === "network_request") return `${d.method} ${d.destination}${d.blocked ? " (blocked)" : ""}`;
    if (e.type === "taint") return `marked ${d.tag}`;
    if (e.type === "decision") return `${d.verdict}: ${d.rule}`;
    if (e.type === "heal") return "healed, task continues";
    return e.type;
  }

  // ---- playback --------------------------------------------------------------------
  function rerender() { if (last.root) render(last.root, last.events, last.byId, last.rowsById); }

  function step() {
    const n = last.events.length;
    if (st.cursor >= n) { st.playing = false; st.follow = true; rerender(); return; }
    st.cursor++;
    st.selected = null;
    rerender();
    const a = last.events[st.cursor - 1], b = last.events[st.cursor];
    const gap = a && b ? Date.parse(b.time) - Date.parse(a.time) : 400;
    st.timer = setTimeout(step, Math.min(1200, Math.max(150, gap)) / st.speed);
  }

  function wire(root) {
    root.querySelector(".pb-play").addEventListener("click", () => {
      clearTimeout(st.timer);
      if (st.playing) { st.playing = false; rerender(); return; }
      st.playing = true; st.follow = false;
      if (st.cursor >= last.events.length) st.cursor = 0;
      step();
    });
    root.querySelector(".pb-start").addEventListener("click", () => {
      clearTimeout(st.timer); st.playing = false; st.follow = false; st.cursor = 0; st.selected = null; rerender();
    });
    root.querySelector(".pb-end").addEventListener("click", () => {
      clearTimeout(st.timer); st.playing = false; st.follow = true; st.selected = null; rerender();
    });
    root.querySelector(".pb-slider").addEventListener("input", (e) => {
      clearTimeout(st.timer); st.playing = false;
      st.cursor = Number(e.target.value);
      st.follow = st.cursor >= last.events.length;
      st.selected = null;
      rerender();
    });
    root.querySelector(".pb-speed").addEventListener("change", (e) => { st.speed = Number(e.target.value) || 1; });
  }

  function reset() { clearTimeout(st.timer); Object.assign(st, { cursor: 0, follow: true, playing: false, selected: null }); }

  window.FCTrace = { render, wire, reset };
})();
