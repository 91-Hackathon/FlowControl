/* Detail pane: what you see after clicking a row (like DevTools' Headers / Preview / Response tabs). */
(function () {
  const F = () => window.FCRows.fmt;

  /* Key/value sections per event type. Each entry: [label, value, extraClass]. */
  function overview(row, byId) {
    const ev = row.ev, d = ev.data || {};
    const general = [
      ["Event", `${ev.type} · ${ev.event_id} · seq ${ev.seq}`],
      ["Time", new Date(ev.time).toLocaleString()],
      ["Session", `${ev.session_id} · state ${ev.session_state}`],
      ["Level", ev.level == null ? "not judged (informational)" : ev.level, ev.level === "red" ? "red" : ""],
    ];
    let specific = [], title = "Details";
    switch (ev.type) {
      case "llm_call":
        title = "Model call";
        specific = [
          ["Destination", d.destination], ["Provider", d.provider], ["Model", d.model],
          ["Input tokens", `${d.input_tokens}${d.cached_input_tokens ? ` (${d.cached_input_tokens} from cache)` : ""}`],
          ["Output tokens", d.output_tokens], ["Tool calls proposed", d.tool_calls_proposed],
          ["Round trip", d.duration_ms != null ? F().ms(d.duration_ms) : "—"],
          ["Gateway overhead", d.latency_ms != null ? F().ms(d.latency_ms) : "—"],
          ["Canary in body", d.canary_hit ? "yes" : "no"],
        ];
        break;
      case "tool_call":
        title = "Tool call";
        specific = [["Tool", d.tool], ["Input", d.input], ["Path", d.path], ["Target", d.target], ["tool_use_id", d.tool_use_id], ["Blocked", d.blocked ? "yes" : "no", d.blocked ? "red" : ""]];
        break;
      case "network_request":
        title = "Request";
        specific = [
          ["Method", d.method], ["Destination", d.destination], ["Category", d.dest_category],
          ["Size", d.bytes != null ? F().bytes(d.bytes) : "—"], ["Canary in body", d.canary_hit ? "yes" : "no", d.canary_hit ? "red" : ""],
          ["Blocked", d.blocked ? "yes" : "no", d.blocked ? "red" : ""], ["Payload preview", d.preview, "payload"],
        ];
        break;
      case "decision": {
        title = "Gateway decision";
        const target = byId[d.target_event];
        specific = [
          ["Verdict", d.verdict, d.verdict === "block" ? "red" : ""], ["Rule", d.rule], ["Reason", d.reason],
          ["Decided by", d.decided_by], ["Applies to", target ? `${target.name} (${d.target_event})` : d.target_event],
        ];
        break;
      }
      case "taint":
        title = "Session marked";
        specific = [["Tag", d.tag], ["Source", d.source], ["State", `${d.from_state} → ${d.to_state}`]];
        break;
      case "heal":
        title = "Self-heal";
        specific = [["Status", d.status], ["Quarantined", d.quarantined_source], ["Rolled back to", d.rolled_back_to], ["Removed events", (d.removed_events || []).join(", ")], ["Told the agent", d.message_to_agent]];
        break;
      default:
        specific = Object.entries(d).map(([kk, v]) => [kk, typeof v === "object" ? JSON.stringify(v) : v]);
    }
    const causes = (ev.caused_by || []).map((id) => (byId[id] ? `${byId[id].name} (${id})` : id));
    if (causes.length) specific.push(["Caused by", causes.join("\n")]);
    return [["General", general], [title, specific.filter(([, v]) => v !== undefined && v !== null && v !== "")]];
  }

  function render(container, row, tab, byId) {
    container.textContent = "";
    if (tab === "data" || tab === "event") {
      const pre = document.createElement("pre");
      pre.textContent = JSON.stringify(tab === "data" ? row.ev.data : row.ev, null, 2);
      container.appendChild(pre);
      return;
    }
    const sentence = explain(row.ev, byId);
    if (sentence) {
      const p = document.createElement("p");
      p.className = "explain" + (window.FCModel.isBlock(row.ev) ? " bad" : "");
      p.textContent = sentence;
      container.appendChild(p);
    }
    for (const [title, pairs] of overview(row, byId)) {
      const sec = document.createElement("details");
      sec.className = "section";
      sec.open = true;
      const sum = document.createElement("summary");
      sum.textContent = title;
      const kv = document.createElement("div");
      kv.className = "kv";
      for (const [label, value, cls] of pairs) {
        const kEl = document.createElement("span"); kEl.className = "k"; kEl.textContent = label;
        const vEl = document.createElement("span"); vEl.className = "v" + (cls === "red" ? " red" : "");
        if (cls === "payload") vEl.appendChild(highlightCanary(String(value)));
        else vEl.textContent = String(value);
        vEl.style.whiteSpace = "pre-wrap";
        kv.append(kEl, vEl);
      }
      sec.append(sum, kv);
      container.appendChild(sec);
    }
  }

  /* One plain sentence about the event, shown above the fields. */
  function explain(ev, byId) {
    const d = ev.data || {};
    const target = d.target_event && byId[d.target_event];
    const what = target ? (target.ev.data.summary || target.name) : "the action";
    switch (ev.type) {
      case "session_start": return `The agent started a session${d.task ? ` to: ${d.task}` : ""}.`;
      case "llm_call": return `The agent sent the conversation to ${d.model || "the model"} and got back ${d.tool_calls_proposed || 0} proposed tool call${d.tool_calls_proposed === 1 ? "" : "s"}.`;
      case "tool_call":
        if (d.blocked) return `The gateway stopped this ${d.tool} call before it ran.`;
        if (ev.level === "yellow") return `The model asked to run ${d.tool}${d.input ? ` on ${d.input}` : ""}; the gateway held it until a person answered.`;
        return `The model asked to run ${d.tool}${d.input ? ` on ${d.input}` : ""}; the gateway let it through.`;
      case "network_request":
        if (d.blocked) return `An outbound ${d.method} to ${d.destination} was blocked${d.canary_hit ? " — it carried a canary key, so secrets were leaving" : ""}.`;
        return `The agent made an outbound ${d.method} request to ${d.destination}.`;
      case "decision":
        if (d.verdict === "block") return `Blocked: ${d.reason || d.rule}.`;
        if (d.verdict === "ask") return `The gateway paused ${what} and asked a person: ${d.reason || d.rule}.`;
        return `The gateway allowed ${what}.`;
      case "taint":
        return d.tag === "untrusted"
          ? `${d.source} is outside content. Anything it says is now treated as possibly hostile.`
          : `${d.source} contains secrets. The session is now marked as holding them.`;
      case "approval_request": return `Waiting for a person to approve: ${d.summary}.`;
      case "approval_result": return `${d.by || "Someone"} ${d.result === "approved" ? "approved" : "denied"} the request.`;
      case "heal": return `The gateway removed ${d.quarantined_source} from the conversation and told the agent why, so it can carry on safely.`;
      case "quarantine": return `${d.source} is quarantined: the model sees a placeholder instead of its content.`;
      case "session_end": return d.summary || `The session ended (${d.result}).`;
    }
    return "";
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

  window.FCDetail = { render };
})();
