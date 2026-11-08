/* Story: the run told in plain English, so nobody has to read the traffic table to follow it.
   status(events)        -> { outcome: {text, tone}, task: {text, note} }  (the header line)
   build(events, byId)   -> [{ id, time, title, detail, tone, related: [event ids] }]
   Pure functions of the event list; no DOM. tone: "bad" | "warn" | "ok" | "" */
(function () {
  const M = () => window.FCModel;

  function lastOf(events, type) {
    for (let i = events.length - 1; i >= 0; i--) if (events[i].type === type) return events[i];
    return null;
  }

  /* A short name for whatever was stopped. */
  function blockedLabel(target) {
    if (!target) return "Action blocked";
    const d = target.data || {};
    if (target.type === "network_request") return d.canary_hit ? "Secret upload blocked" : "Outbound request blocked";
    if (d.target === "network") return "Outbound request blocked";
    return `${d.tool || "Tool"} action blocked`;
  }

  function pendingApprovals(events) {
    const answered = new Set(events.filter((e) => e.type === "approval_result").map((e) => e.data.target_event));
    return events.filter((e) => e.type === "approval_request" && !answered.has(e.data.target_event));
  }

  function status(allEvents) {
    const events = allEvents.filter((e) => e.type !== "settings"); // a policy change isn't agent activity
    const byId = {};
    events.forEach((e) => (byId[e.event_id] = e));
    const blocks = events.filter((e) => e.type !== "decision" && M().isBlock(e));
    const pending = pendingApprovals(events);
    const end = lastOf(events, "session_end");
    const heal = lastOf(events, "heal");

    let outcome;
    if (blocks.length) {
      const last = blocks[blocks.length - 1];
      const dec = allEvents.find((e) => e.type === "decision" && e.data && e.data.target_event === last.event_id);
      const text = dec && /^custom_/.test(dec.data.rule || "") ? "Blocked by your rule" : blockedLabel(last);
      outcome = { text: blocks.length > 1 ? `${text} (+${blocks.length - 1} more)` : text, tone: "bad" };
    } else if (pending.length) outcome = { text: "Approval needed", tone: "warn" };
    else if (events.some((e) => e.type === "approval_result" && e.data.result !== "approved")) outcome = { text: "Action denied by you", tone: "bad" };
    else if (events.length) outcome = { text: "No actions blocked", tone: "ok" };
    else outcome = { text: "Waiting for an agent", tone: "" };

    let task;
    if (end) {
      const r = end.data.result;
      task = { text: r === "completed" ? "Task completed" : r === "stopped" ? "Run stopped" : "Run failed", note: end.data.summary || "" };
    } else if (pending.length) task = { text: "Agent waiting for your approval", note: pending[0].data.summary || "" };
    else if (heal && blocks.length && Date.parse(heal.time) >= Date.parse(blocks[blocks.length - 1].time)) task = { text: "Agent recovering", note: "Unsafe context was removed; the agent continues without it" };
    else if (events.length) task = { text: "Agent running", note: "" };
    else task = { text: "", note: "" };
    return { outcome, task };
  }

  function build(events, byId) {
    const out = [];
    const add = (ev, title, detail, tone, related) =>
      out.push({ id: ev.event_id, time: ev.time, title, detail: detail || "", tone: tone || "", related: related || [ev.event_id] });
    const approvalMoment = {}; // target_event -> moment, so the answer updates it

    events.forEach((ev) => {
      const d = ev.data || {};
      switch (ev.type) {
        case "session_start":
          add(ev, "Agent started", d.task ? `Task: ${d.task}` : "");
          break;
        case "taint":
          if (d.tag === "untrusted") {
            add(ev, "Untrusted content read", `${d.source} came from outside the project. From here on its text could try to steer the agent.`, "warn", [ev.event_id, ...(ev.caused_by || [])]);
          } else if (d.tag === "sensitive") {
            const asked = Object.values(approvalMoment).find((m) => m.source === d.source || (ev.caused_by || []).includes(m.target));
            if (asked) {
              asked.title = asked.answer === "approved" ? "Secrets read, with your approval" : asked.title;
              asked.related.push(ev.event_id);
            } else {
              add(ev, "Sensitive data read", `${d.source} holds secrets. The session now carries them.`, "warn", [ev.event_id, ...(ev.caused_by || [])]);
            }
          }
          break;
        case "approval_request": {
          const tgt = byId[d.target_event];
          add(ev, "Approval needed", `${d.summary}${d.reason ? ` — ${d.reason}` : ""}`, "warn", [ev.event_id, d.target_event]);
          const m = out[out.length - 1];
          m.target = d.target_event;
          m.source = tgt && tgt.data && (tgt.data.path || tgt.data.input);
          approvalMoment[d.target_event] = m;
          break;
        }
        case "approval_result": {
          const m = approvalMoment[d.target_event];
          const label = d.result === "approved" ? "Approved" : d.result === "denied" ? "Denied" : "No answer, denied";
          if (m) {
            m.answer = d.result;
            m.title = `${label}: ${m.detail.split(" — ")[0]}`;
            m.detail = `${d.by ? `By ${d.by}. ` : ""}${m.detail.split(" — ")[1] || ""}`.trim();
            m.tone = d.result === "approved" ? "" : "bad";
            m.related.push(ev.event_id);
          } else {
            add(ev, label, d.by || "", d.result === "approved" ? "" : "bad");
          }
          break;
        }
        case "decision":
          if (d.verdict === "block") {
            const target = byId[d.target_event];
            const chain = (M().attackChains([...events], byId).find((c) => c.decision === ev) || { ids: [ev.event_id] }).ids;
            const mine = /^custom_/.test(d.rule || "");
            const what = target && target.data ? target.data.summary || target.data.destination || "" : "";
            add(ev, mine ? `Your rule blocked: ${what}` : blockedLabel(target), d.reason || d.rule || "", "bad", [...new Set([...chain, d.target_event])]);
            out[out.length - 1].chain = chain;
          }
          break;
        case "network_request":
        case "tool_call":
          // blocked without a separate decision event: still worth a moment
          if (M().isBlock(ev) && !events.some((e) => e.type === "decision" && e.data && e.data.target_event === ev.event_id)) {
            add(ev, blockedLabel(ev), d.summary || d.destination || "", "bad");
          }
          break;
        case "heal":
          add(ev, "Unsafe context removed", `${d.quarantined_source || "The bad source"} was taken out of the conversation and the agent was told why.`, "ok", [ev.event_id, ...(d.removed_events || [])]);
          break;
        case "quarantine":
          add(ev, "Source withheld", `${d.source} is quarantined; the model gets a placeholder instead of its content.`, "ok", [ev.event_id, ...(ev.caused_by || [])]);
          break;
        case "settings":
          if (d.change) {
            const off = /^Turned OFF/.test(d.change);
            add(ev, d.change.replace(/^Disallowed: /, "New rule: "), `${d.by ? `By ${d.by}. ` : ""}Takes effect on the agent's next action.`, off ? "warn" : "");
          }
          break;
        case "session_end": {
          const r = d.result;
          add(ev, r === "completed" ? "Task completed" : r === "stopped" ? "Run stopped" : "Run failed", d.summary || "", r === "completed" ? "ok" : "bad");
          break;
        }
      }
    });
    return out;
  }

  window.FCStory = { status, build };
})();
