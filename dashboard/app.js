/* App: get events (gateway WebSocket or demo replay), keep the event list, run the views.

   ?ws=URL   connect to another feed (default ws://localhost:8080/events)
   ?demo     replay protocol/events.example.json, no gateway needed
   #map / #security / #replay   open on that view
*/
(function () {
  const R = window.FCRows, D = window.FCDetail, M = window.FCModel;
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  // Served by the gateway (/dashboard/): connect back to the same host and port. Opened some
  // other way (file, dev server): fall back to the default feed address.
  const SAME_ORIGIN = location.protocol.startsWith("http") && location.pathname.startsWith("/dashboard");
  const WS_URL = params.get("ws") || (SAME_ORIGIN ? `ws://${location.host}/events` : "ws://localhost:8080/events");
  const DEMO = params.has("demo");

  const state = {
    events: [], byId: {},           // raw events, in seq order
    rows: [], recording: true, filter: "", type: "all",
    selected: null, tab: "overview", task: null, sessionId: null,
    view: "network", socket: null, ended: false,
    pinned: null,                   // story moment whose rows are highlighted
    settingsOpen: false, draft: {}, setError: "", setKey: "", setPage: "rules",
    demoSettings: null,             // ?demo: local copy of the protections (no gateway to ask)
  };
  state.rows.byId = {};

  function resetData() {
    state.events = []; state.byId = {};
    state.rows = []; state.rows.byId = {};
    state.task = null;
    state.ended = false;
    state.pinned = null;
    window.FCTrace.reset();
    select(null);
    rebuild();
  }

  // ---- adding events -----------------------------------------------------------
  function onEvent(ev) {
    if (!state.recording) return;
    if (ev.type === "session_start") { state.task = ev.data && ev.data.task; }
    if (ev.type === "session_end") state.ended = true;
    if (ev.session_id) state.sessionId = ev.session_id;
    if (ev.type === "settings" && ev.data) state.setError = ev.data.error || "";
    state.events.push(ev);
    state.byId[ev.event_id] = ev;
    const row = R.fromEvent(ev);
    if (row) {
      state.rows.push(row);
      state.rows.byId[row.id] = row;
      appendRow(row);
    }
    scheduleRefresh();
  }

  function visible(row) {
    if (state.type !== "all" && !R.group(row).includes(state.type)) return false;
    return !state.filter || row.search.includes(state.filter);
  }

  function appendRow(row) {
    const wrap = $("tableWrap");
    const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 30;
    const tr = R.renderRow(row);
    tr.hidden = !visible(row);
    if (state.pinned && state.pinned.related.includes(row.id)) tr.classList.add("related");
    $("rows").appendChild(tr);
    if (atBottom) wrap.scrollTop = wrap.scrollHeight; // follow new rows unless the user scrolled up
  }

  function rebuild() {
    const body = $("rows");
    body.textContent = "";
    state.rows.forEach((r) => {
      const tr = R.renderRow(r);
      tr.hidden = !visible(r);
      if (r.id === state.selected) tr.classList.add("sel");
      body.appendChild(tr);
    });
    scheduleRefresh();
  }

  // ---- refresh: shared parts every time, the open view only -------------------------------
  let pending = false;
  function scheduleRefresh() {
    if (pending) return;
    pending = true;
    setTimeout(() => { pending = false; refresh(); }, 40); // timer, not rAF: keeps working in background tabs
  }

  function refresh() {
    if (typeof updateControls === "function") updateControls();
    const ev = state.events;
    const blocks = ev.filter((e) => e.type !== "decision" && M.isBlock(e));
    window.FCKpis.render($("kpis"), {
      llm: ev.filter((e) => e.type === "llm_call"),
      tools: ev.filter((e) => e.type === "tool_call"),
      judged: ev.filter((e) => e.type === "tool_call" || e.type === "network_request"),
      blocks,
    });
    $("secCount").hidden = !blocks.length;
    $("secCount").textContent = blocks.length;
    renderTask();
    renderStatus(blocks.length);
    renderStory();
    renderSettings();

    if (state.view === "network") {
      const shown = state.rows.filter(visible);
      shown.byId = state.rows.byId;
      R.layoutWaterfall($("rows"), shown.length ? shown : state.rows);
      $("empty").hidden = state.rows.length > 0;
    } else if (state.view === "map") {
      window.FCMap.render($("view-map"), ev, (key) => { openView("network"); setFilter(key); });
    } else if (state.view === "security") {
      window.FCSecurity.render($("view-security"), ev, state.byId);
    } else if (state.view === "replay") {
      window.FCTrace.render($("view-replay"), ev, state.byId, state.rows.byId);
    }
  }

  function renderTask() {
    const bar = $("session");
    bar.textContent = "";
    if (state.task) {
      const b = document.createElement("b"); b.textContent = state.task;
      bar.append(`${state.sessionId || "session"} · task: `, b);
    } else {
      bar.textContent = "Waiting for an agent session…";
    }
  }

  // ---- story pane and header status line --------------------------------------------------
  function renderStory() {
    const st = window.FCStory.status(state.events);
    const line = $("statusLine");
    line.textContent = "";
    if (state.events.length) {
      const o = document.createElement("span");
      o.className = st.outcome.tone;
      o.textContent = (st.outcome.tone === "bad" ? "■ " : st.outcome.tone === "warn" ? "● " : "✓ ") + st.outcome.text;
      const sep = document.createElement("span"); sep.className = "sl-sep";
      const t = document.createElement("span"); t.textContent = st.task.text;
      line.append(o, sep, t);
      if (st.task.note) { const n = document.createElement("span"); n.className = "sl-note"; n.textContent = st.task.note; line.append(n); }
    }

    $("storyTitle").textContent = st.outcome.text;
    $("storyTitle").className = "story-title " + (st.outcome.tone === "bad" ? "bad" : "");
    const sub = $("storySub");
    sub.textContent = "";
    if (st.task.text) { const b = document.createElement("b"); b.textContent = st.task.text; sub.append(b); }
    if (st.task.note) sub.append(` — ${st.task.note}`);

    const moments = window.FCStory.build(state.events, state.byId);
    if (state.pinned) state.pinned = moments.find((m) => m.id === state.pinned.id) || null;
    const list = $("moments");
    list.replaceChildren(...moments.map((m, i) => {
      const li = document.createElement("li");
      li.className = `moment ${m.tone}${i === moments.length - 1 ? " latest" : ""}${state.pinned && state.pinned.id === m.id ? " pinned" : ""}`;
      li.dataset.id = m.id;
      const time = document.createElement("span"); time.className = "m-time";
      time.textContent = new Date(m.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      const title = document.createElement("div"); title.className = "m-title"; title.textContent = m.title;
      li.append(time, title);
      if (m.detail) { const d = document.createElement("div"); d.className = "m-detail"; d.textContent = m.detail; li.append(d); }
      if (m.chain && m.chain.length > 1) {
        const c = document.createElement("div"); c.className = "m-chain";
        c.textContent = "Chain: " + m.chain.map((id) => (state.rows.byId[id] ? state.rows.byId[id].name : id)).join(" → ");
        li.append(c);
      }
      return li;
    }));
    $("storyHint").hidden = !moments.length;
    applyFocus();
  }

  function applyFocus() {
    const rel = new Set(state.pinned ? state.pinned.related : []);
    $("tableWrap").classList.toggle("focusing", rel.size > 0);
    for (const tr of $("rows").children) tr.classList.toggle("related", rel.has(tr.dataset.id));
  }

  $("moments").addEventListener("click", (e) => {
    const li = e.target.closest(".moment");
    if (!li) return;
    const moments = window.FCStory.build(state.events, state.byId);
    const m = moments.find((x) => x.id === li.dataset.id);
    if (!m || (state.pinned && state.pinned.id === m.id)) { state.pinned = null; scheduleRefresh(); return; }
    state.pinned = m;
    if (state.view !== "network") openView("network");
    if (state.filter || state.type !== "all") { setFilter(""); $("types").querySelector('[data-type="all"]').click(); }
    scheduleRefresh();
    setTimeout(() => {
      const first = [...$("rows").children].find((tr) => m.related.includes(tr.dataset.id));
      if (first) first.scrollIntoView({ block: "center", behavior: "smooth" });
    }, 60);
  });

  // ---- protections panel ------------------------------------------------------------------
  const S = window.FCSettings;
  function currentSettings() {
    return DEMO ? (state.demoSettings = state.demoSettings || S.defaults()) : S.latest(state.events);
  }

  function renderSettings(force) {
    const snap = currentSettings();
    const n = snap ? (snap.custom_rules || []).length : 0;
    $("ruleCount").hidden = !n;
    $("ruleCount").textContent = n;
    const off = snap ? snap.protections.filter((p) => !p.enabled).length : 0;
    $("openSettings").classList.toggle("weakened", off > 0);
    $("openSettings").title = off ? `${off} protection${off > 1 ? "s" : ""} switched off` : "Protections and disallowed actions";
    if (!state.settingsOpen) return;
    const key = JSON.stringify([state.setPage, snap && snap.revision, snap && snap.custom_rules, snap && snap.protections.map((p) => p.enabled), state.setError, !!snap]);
    if (!force && key === state.setKey) return; // don't rebuild under the user's cursor
    const pop = $("settingsPop");
    const prev = pop.querySelector(".set-body");
    const keepScroll = prev && JSON.parse(state.setKey || "[]")[0] === state.setPage ? prev.scrollTop : 0;
    state.setKey = key;
    S.render(pop, snap, {
      demo: DEMO, draft: state.draft, page: state.setPage,
      onPage: (page) => { state.setPage = page; state.setError = ""; renderSettings(true); focusSettings(); },
      error: state.setError || (!snap && !DEMO ? "Not connected to a gateway yet: showing the defaults." : ""),
      onClose: () => toggleSettings(false),
      onError: (msg) => { state.setError = msg; renderSettings(true); },
      onToggle: (id, enabled, label) => {
        if (!enabled && !confirm(`Switch off “${label}”? The agent's next actions won't be checked by it.`)) return renderSettings(true);
        settingsCommand({ command: "set_protection", id, enabled });
      },
      onAdd: (rule) => settingsCommand({ command: "add_rule", rule }),
      onRemove: (id) => settingsCommand({ command: "remove_rule", id }),
    });
    const body = pop.querySelector(".set-body");
    if (body) body.scrollTop = keepScroll; // a toggle on the same page doesn't jump back to the top
  }

  function settingsCommand(cmd) {
    state.setError = "";
    if (DEMO) { demoSettingsChange(cmd); return; }
    if (!send(cmd)) { state.setError = "The gateway isn't connected, so nothing was changed."; renderSettings(true); return; }
    renderSettings(true); // the gateway answers with a settings event, which re-renders
  }

  function toggleSettings(open) {
    state.settingsOpen = open == null ? !state.settingsOpen : open;
    $("settingsPop").hidden = !state.settingsOpen;
    $("openSettings").setAttribute("aria-expanded", String(state.settingsOpen));
    $("openSettings").classList.toggle("on", state.settingsOpen);
    document.body.classList.toggle("modal-open", state.settingsOpen);
    if (state.settingsOpen) {
      state.setError = "";
      const pop = $("settingsPop");
      pop.classList.add("opening");
      setTimeout(() => pop.classList.remove("opening"), 250);
      renderSettings(true);
      focusSettings();
    } else {
      $("openSettings").focus();
    }
  }
  function focusSettings() {
    const pop = $("settingsPop");
    const target = pop.querySelector(".set-pattern") || pop.querySelector(".set-nav.on");
    if (target) target.focus();
  }
  $("openSettings").addEventListener("click", (e) => { e.stopPropagation(); toggleSettings(); });
  document.addEventListener("mousedown", (e) => {
    if (state.settingsOpen && e.target === $("settingsPop")) toggleSettings(false); // click on the backdrop
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.settingsOpen) { e.stopImmediatePropagation(); toggleSettings(false); } }, true);

  // ---- presenter mode ----------------------------------------------------------------------
  function togglePresent() {
    document.body.classList.toggle("present");
    $("present").textContent = document.body.classList.contains("present") ? "Exit present" : "Present";
  }
  $("present").addEventListener("click", togglePresent);
  document.addEventListener("keydown", (e) => {
    if (e.target.closest("input, select, textarea") || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "p" || e.key === "P") togglePresent();
  });

  function renderStatus(blocked) {
    const rows = state.rows;
    const shown = rows.filter(visible).length;
    const llm = state.events.filter((e) => e.type === "llm_call");
    const tools = state.events.filter((e) => e.type === "tool_call").length;
    const tokens = llm.reduce((s, e) => s + (e.data.input_tokens || 0) + (e.data.output_tokens || 0), 0);
    const overhead = llm.map((e) => e.data.latency_ms).filter((v) => v != null);
    const parts = [
      shown === rows.length || state.view !== "network" ? `${rows.length} events` : `${shown} / ${rows.length} events`,
      `${llm.length} LLM calls`,
      `${tools} tool calls`,
      `${R.fmt.k(tokens)} tokens`,
      overhead.length ? `gateway +${(overhead.reduce((a, b) => a + b, 0) / overhead.length).toFixed(1)} ms avg` : "gateway —",
    ];
    if (blocked) parts.push(`${blocked} blocked`);
    const bar = $("status");
    bar.textContent = "";
    parts.forEach((p) => { const s = document.createElement("span"); s.textContent = p; bar.appendChild(s); });
  }

  // ---- views ---------------------------------------------------------------------------
  function openView(name) {
    state.view = name;
    document.querySelectorAll("#panels button[data-view]").forEach((b) => b.classList.toggle("on", b.dataset.view === name));
    ["network", "map", "security", "replay"].forEach((v) => ($(`view-${v}`).hidden = v !== name));
    document.querySelector(".net-only").hidden = name !== "network";
    document.title = `FlowControl · ${name[0].toUpperCase()}${name.slice(1)}`;
    if (location.hash.slice(1) !== name) history.replaceState(null, "", name === "network" ? location.pathname + location.search : `#${name}`);
    scheduleRefresh();
  }
  $("panels").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-view]");
    if (b) openView(b.dataset.view);
  });

  // ---- Network: selection and detail pane -------------------------------------------------
  function decisionFor(id) {
    return state.events.find((e) => e.type === "decision" && e.data && e.data.target_event === id) || (state.byId[id] && state.byId[id].type === "decision" ? state.byId[id] : null);
  }

  function showDetail(row) {
    const dec = decisionFor(row.id);
    $("secTab").hidden = !dec;
    if (state.tab === "security" && !dec) setTab("overview");
    const body = $("detailBody");
    if (state.tab === "security" && dec) {
      body.textContent = "";
      body.appendChild(window.FCSecurity.card(dec, state.byId));
    } else {
      D.render(body, row, state.tab, state.rows.byId);
    }
  }

  function setTab(tab) {
    state.tab = tab;
    document.querySelectorAll(".tabs button[data-tab]").forEach((x) => x.classList.toggle("on", x.dataset.tab === tab));
  }

  function select(id) {
    state.selected = id;
    for (const tr of $("rows").children) tr.classList.toggle("sel", tr.dataset.id === id);
    const row = id && state.rows.byId[id];
    $("detail").hidden = !row;
    $("view-network").classList.toggle("with-detail", !!row);
    if (row) {
      if (decisionFor(row.id) && M.isBlock(row.ev)) setTab("security"); // blocked rows open on the reason
      showDetail(row);
    }
    scheduleRefresh();
  }

  $("rows").addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (tr) select(tr.dataset.id);
  });
  $("closeDetail").addEventListener("click", () => select(null));
  document.querySelectorAll(".tabs button[data-tab]").forEach((b) => b.addEventListener("click", () => {
    setTab(b.dataset.tab);
    if (state.selected) showDetail(state.rows.byId[state.selected]);
  }));
  document.addEventListener("keydown", (e) => {
    if (state.view !== "network" || e.target.closest("input, select")) return;
    if (e.key === "Escape") { if (state.pinned && !state.selected) { state.pinned = null; scheduleRefresh(); } return select(null); }
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const shown = [...$("rows").children].filter((tr) => !tr.hidden);
    if (!shown.length) return;
    e.preventDefault();
    const i = shown.findIndex((tr) => tr.dataset.id === state.selected);
    const next = shown[Math.max(0, Math.min(shown.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    select(next.dataset.id);
    next.scrollIntoView({ block: "nearest" });
  });

  // ---- toolbar -----------------------------------------------------------------------
  $("rec").addEventListener("click", () => {
    state.recording = !state.recording;
    $("rec").classList.toggle("on", state.recording);
    $("rec").title = state.recording ? "Pause recording" : "Record";
  });
  $("clear").addEventListener("click", resetData);

  function setFilter(text) {
    $("filter").value = text;
    state.filter = text.trim().toLowerCase();
    for (const tr of $("rows").children) tr.hidden = !visible(state.rows.byId[tr.dataset.id]);
    scheduleRefresh();
  }
  $("filter").addEventListener("input", (e) => setFilter(e.target.value));
  $("types").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    state.type = b.dataset.type;
    [...$("types").children].forEach((x) => x.classList.toggle("on", x === b));
    for (const tr of $("rows").children) tr.hidden = !visible(state.rows.byId[tr.dataset.id]);
    scheduleRefresh();
  });


  // ---- operator controls: commands to the gateway (protocol/EVENTS.md §5) ------------------
  function send(cmd) {
    if (DEMO) return demoCommand({ ...cmd, by: "operator@dashboard" });
    const s = state.socket;
    if (!s || s.readyState !== 1) return false;
    s.send(JSON.stringify({ ...cmd, by: "operator@dashboard" }));
    return true;
  }

  function updateControls() {
    const live = DEMO || (state.socket && state.socket.readyState === 1);
    $("stopRun").disabled = !live || state.ended;
    $("stopRun").textContent = state.ended ? "Run ended" : "Stop run";
    renderApprovals();
  }

  $("stopRun").addEventListener("click", () => {
    if (!confirm("Stop the run? The gateway will deny every further request from the agent.")) return;
    send({ command: "stop", session_id: state.sessionId });
  });

  function pendingApprovals() {
    const answered = new Set(state.events.filter((e) => e.type === "approval_result").map((e) => e.data.target_event));
    return state.events.filter((e) => e.type === "approval_request" && !answered.has(e.data.target_event));
  }

  /* Pending approvals: a card at the top of the story pane, right under the headline, so the
     question sits next to the story that explains it. Built once per request; the timer only
     ticks the countdown (rebuilding would swallow clicks). */
  function secondsLeft(e) { return Math.max(0, (Date.parse(e.time) + e.data.timeout_s * 1000 - Date.now()) / 1000); }

  function renderApprovals() {
    const box = $("approvals");
    const pending = state.ended ? [] : pendingApprovals();
    const key = pending.map((e) => e.event_id).join(",");
    if (box.dataset.key === key) {
      pending.forEach((e, i) => {
        const card = box.children[i];
        if (!card) return;
        const left = secondsLeft(e);
        card.querySelector(".ap-left").textContent = `${Math.round(left)}s`;
        card.querySelector(".ap-bar span").style.width = `${(100 * left) / e.data.timeout_s}%`;
        card.classList.toggle("urgent", left < 15);
      });
      return;
    }
    box.dataset.key = key;
    const mk = (tag, cls, text) => { const x = document.createElement(tag); x.className = cls; if (text != null) x.textContent = text; return x; };
    box.replaceChildren(...pending.map((e) => {
      const d = e.data, target = state.byId[d.target_event], td = (target && target.data) || {};
      const card = mk("div", "approval");
      card.setAttribute("role", "group");
      card.setAttribute("aria-label", "Approval needed");
      const top = mk("div", "ap-top");
      top.append(mk("span", "ap-eyebrow", "Needs your OK"), mk("span", "ap-left", `${Math.round(secondsLeft(e))}s`));
      const action = td.tool ? `${td.tool} ${td.input || td.path || ""}`.trim() : td.destination ? `${td.method || ""} ${td.destination}`.trim() : "";
      card.append(top, mk("div", "ap-what", d.summary));
      if (action) card.append(mk("div", "ap-action", action));
      if (d.reason) card.append(mk("div", "ap-why", d.reason));
      const bar = mk("div", "ap-bar"); const fill = mk("span", ""); fill.style.width = `${(100 * secondsLeft(e)) / d.timeout_s}%`; bar.append(fill);
      card.append(bar);
      const acts = mk("div", "ap-actions");
      const no = mk("button", "btn btn-outline no", "Deny"); no.type = "button";
      const yes = mk("button", "btn btn-solid yes", "Approve"); yes.type = "button";
      no.onclick = () => send({ command: "deny", target_event: d.target_event });
      yes.onclick = () => send({ command: "approve", target_event: d.target_event });
      acts.append(no, yes);
      card.append(acts, mk("div", "ap-note", "Approves this one action only. No answer in time means deny."));
      return card;
    }));
    if (pending.length && state.view === "network" && !state.selected) {
      const tr = [...$("rows").children].find((r) => r.dataset.id === pending[0].data.target_event);
      if (tr) tr.scrollIntoView({ block: "nearest" });
    }
  }
  setInterval(renderApprovals, 1000); // countdowns

  // ---- data sources ------------------------------------------------------------------------
  function setConn(text, cls, link) {  // text only: WS_URL comes from the page URL
    const el = $("conn");
    el.className = "conn " + (cls || "");
    el.textContent = text;
    if (link) {
      const a = document.createElement("a");
      a.href = link.href; a.textContent = link.text;
      el.append(a);
    }
  }

  function connect() {
    setConn("Connecting");
    let socket;
    try { socket = new WebSocket(WS_URL); } catch (e) { return retry(); }
    state.socket = socket;
    socket.onopen = () => {
      resetData(); // the gateway replays the whole run on connect
      setConn(`Live · ${WS_URL.replace(/^ws:\/\//, "")}`, "live");
      updateControls();
    };
    socket.onmessage = (m) => {
      try { onEvent(JSON.parse(m.data)); } catch (e) { console.warn("bad event", e); }
    };
    socket.onclose = retry;
  }

  function retry() {
    updateControls();
    setConn("Gateway offline · retrying · ", "off", { href: "?demo", text: "demo" });
    setTimeout(connect, 2000);
  }

  /* Demo: replay protocol/events.example.json with its original spacing. It pauses at an
     approval request until you press Approve (the run continues) or Deny (the run stops). */
  const demo = { i: 0, base: 0, timer: null, waiting: null, seq: 0, dropped: new Set(), customBlocks: 0 };

  function demoEmit(src) {
    const events = window.FC_DEMO_EVENTS;
    const offset = Date.parse(src.time) - Date.parse(events[0].time);
    onEvent({ ...src, time: new Date(demo.base + offset).toISOString() });
  }

  function demoNext() {
    const events = window.FC_DEMO_EVENTS || [];
    if (demo.i >= events.length) { $("replayDemo").hidden = false; return; }
    let src = events[demo.i++];
    if ((src.caused_by || []).some((id) => demo.dropped.has(id))) { // it followed from an action your rule stopped
      demo.dropped.add(src.event_id);
      return demoNext();
    }
    if (src.type === "session_end" && demo.customBlocks) {
      src = { ...src, data: { ...src.data, summary: `Task finished. ${demo.customBlocks} action${demo.customBlocks > 1 ? "s" : ""} stopped by your rules.` } };
    }
    if (src.type === "stats") return demoNext();
    const rule = (src.type === "tool_call" || src.type === "network_request") && demoRuleFor(src);
    if (rule && demoEnforce(src, rule)) return;
    if (rule) {
      const nextEv = events[demo.i];
      demo.timer = setTimeout(demoNext, Math.min(1500, Math.max(300, nextEv ? Date.parse(nextEv.time) - Date.parse(src.time) : 0)));
      return;
    }
    if (src.type === "approval_result" && demo.waiting) {  // the user answers this one
      demo.held = src;
      return;
    }
    demoEmit(src);
    if (src.type === "approval_request") demo.waiting = src;
    const nextEv = events[demo.i];
    const gap = nextEv ? Date.parse(nextEv.time) - Date.parse(src.time) : 0;
    demo.timer = setTimeout(demoNext, Math.min(1500, Math.max(300, gap)));
  }

  /* Demo: apply a settings command locally and announce it like the gateway would. */
  function demoSettingsChange(cmd) {
    const s = currentSettings();
    let change = null;
    if (cmd.command === "set_protection") {
      const p = s.protections.find((x) => x.id === cmd.id);
      if (!p || p.locked || p.enabled === cmd.enabled) return renderSettings(true);
      p.enabled = cmd.enabled;
      change = `${cmd.enabled ? "Turned on" : "Turned OFF"}: ${p.label}`;
    } else if (cmd.command === "add_rule") {
      const rule = { ...cmd.rule, id: `custom_${(demo.ruleSeq = (demo.ruleSeq || 0) + 1)}`, by: "operator@dashboard" };
      s.custom_rules.push(rule);
      change = `Disallowed: ${rule.label} (${rule.verdict === "ask" ? "ask first" : "block"})`;
    } else if (cmd.command === "remove_rule") {
      const r = s.custom_rules.find((x) => x.id === cmd.id);
      if (!r) return;
      s.custom_rules = s.custom_rules.filter((x) => x !== r);
      change = `Removed rule: ${r.label}`;
    }
    s.revision += 1;
    s.policy_version = `demo+dash.${s.revision}`;
    const last = state.events[state.events.length - 1];
    onEvent({ event_id: `evt_set_${s.revision}`, session_id: last ? last.session_id : "sess_demo", seq: (last ? last.seq : 0) + 0.01,
      time: new Date().toISOString(), type: "settings", level: /^Turned OFF/.test(change) ? "yellow" : null,
      session_state: last ? last.session_state : "clean", caused_by: [],
      data: { ...JSON.parse(JSON.stringify(s)), change, by: "operator@dashboard" } });
  }

  /* Demo: does one of your rules catch this replayed event? Returns the rule or null. */
  function demoRuleFor(src) {
    const s = state.demoSettings;
    if (!s || !s.custom_rules.length) return null;
    const rules = [...s.custom_rules.filter((r) => r.verdict === "block"), ...s.custom_rules.filter((r) => r.verdict === "ask")];
    return rules.find((r) => S.matches(r, src)) || null;
  }

  function demoEnforce(src, rule) {
    const d = src.data || {};
    const at = (k, extra) => ({ session_id: src.session_id, time: src.time, session_state: src.session_state, ...extra, seq: src.seq + k });
    if (rule.verdict === "block") {
      demo.dropped.add(src.event_id);
      demo.customBlocks += 1;
      demoEmit({ ...src, level: "red", data: { ...d, blocked: true } });
      demoEmit(at(0.1, { event_id: src.event_id + "_d", type: "decision", level: "red", caused_by: [src.event_id],
        data: { target_event: src.event_id, verdict: "block", rule: rule.id, reason: rule.reason, decided_by: "rule", policy_version: state.demoSettings.policy_version } }));
      return false; // keep playing
    }
    demoEmit({ ...src, level: "yellow" });
    demoEmit(at(0.1, { event_id: src.event_id + "_d", type: "decision", level: "yellow", caused_by: [src.event_id],
      data: { target_event: src.event_id, verdict: "ask", rule: rule.id, reason: rule.reason, decided_by: "rule", policy_version: state.demoSettings.policy_version } }));
    const req = at(0.2, { event_id: src.event_id + "_a", type: "approval_request", level: "yellow", caused_by: [src.event_id + "_d"],
      data: { target_event: src.event_id, summary: `Agent wants to: ${d.summary || d.destination || src.type}`, reason: rule.label, timeout_s: 60 } });
    demoEmit(req);
    demo.waiting = req;
    demo.custom = { src, rule };
    return true; // pause for the human
  }

  function demoCommand(cmd) {
    if (cmd.command === "stop") { demoStop("stopped", "Run stopped from the dashboard."); return true; }
    if (demo.custom && demo.waiting && cmd.target_event === demo.waiting.data.target_event) {
      const { src } = demo.custom, req = demo.waiting;
      demo.custom = null; demo.waiting = null;
      demo.base += Date.now() - Date.parse(state.byId[req.event_id].time);
      const ok = cmd.command === "approve";
      if (!ok) { demo.dropped.add(src.event_id); demo.customBlocks += 1; }
      demoEmit({ ...req, event_id: src.event_id + "_r", type: "approval_result", level: ok ? "green" : "red", seq: src.seq + 0.3,
        caused_by: [req.event_id], data: { target_event: src.event_id, result: ok ? "approved" : "denied", by: cmd.by } });
      clearTimeout(demo.timer);
      demo.timer = setTimeout(demoNext, 500);
      return true;
    }
    if (!demo.waiting || cmd.target_event !== demo.waiting.data.target_event) return false;
    const req = demo.waiting;
    demo.waiting = null;
    const shift = Date.now() - Date.parse(state.byId[req.event_id].time); // later events keep their spacing
    demo.base += shift;
    if (cmd.command === "approve") {
      demoEmit({ ...(demo.held || {}), data: { ...((demo.held || {}).data || {}), result: "approved", by: cmd.by } });
      demo.held = null;
      clearTimeout(demo.timer);
      demo.timer = setTimeout(demoNext, 500);
    } else {
      const held = demo.held || req;
      demoEmit({ ...held, type: "approval_result", event_id: held.event_id + "_d", data: { target_event: req.data.target_event, result: "denied", by: cmd.by } });
      demoStop("stopped", "The secrets read was denied, so the agent stopped.");
    }
    return true;
  }

  function demoStop(result, summary) {
    clearTimeout(demo.timer);
    demo.waiting = null;
    const last = state.events[state.events.length - 1];
    if (!last || state.ended) return;
    onEvent({ event_id: "evt_demo_end", session_id: last.session_id, seq: last.seq + 1, time: new Date().toISOString(),
      type: "session_end", level: null, session_state: "ended", caused_by: [], data: { result, summary } });
    $("replayDemo").hidden = false;
  }

  function runDemo() {
    clearTimeout(demo.timer);
    Object.assign(demo, { i: 0, base: Date.now(), waiting: null, held: null, custom: null, dropped: new Set(), customBlocks: 0 });
    $("replayDemo").hidden = true;
    resetData();
    setConn("Demo replay", "demo");
    demoNext();
  }
  $("replayDemo").addEventListener("click", runDemo);

  // ---- start ---------------------------------------------------------------------------------
  window.FCKpis.build($("kpis"));
  window.FCTrace.wire($("view-replay"));
  const startView = location.hash.slice(1);
  openView(["map", "security", "replay"].includes(startView) ? startView : "network");
  refresh();
  if (DEMO) runDemo(); else connect();
})();
