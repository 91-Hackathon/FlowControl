# Gateway ↔ Dashboard event protocol

This document is the contract between the gateway and the dashboard. The gateway sends
events in this format; the dashboard reads them in this format. As long as both sides
follow it, each can be built separately and they will plug together.

Related files:

| File | What it is | Who uses it |
|---|---|---|
| `events.schema.json` | The formal definition (JSON Schema); tools can check events against it automatically | Gateway development, tests |
| `events.example.json` | 21 example events that tell the demo story | **Dashboard development: use it as mock data** |
| `EVENTS.md` | This document: the two files above in plain words | Everyone |

---

## 1. The one rule

> **Fields can be added. Never rename or remove them.**

Add new fields whenever you need to; the dashboard simply ignores fields it doesn't know.
If something really has to be renamed or removed, tell the team first and update all three
files together.

---

## 2. Transport

- Channel: WebSocket at `ws://localhost:8080/events`
- One WebSocket message = one JSON object
- **Gateway → dashboard**: **events**, telling the dashboard what happened
- **Dashboard → gateway**: **commands**, e.g. the user clicked "approve" or "stop"
- **Joining late loses nothing**: when a dashboard connects, the gateway first sends every
  event of the current run in order, then keeps streaming new ones. A page refresh
  therefore receives the full history again, so **clear your list when the connection
  opens** to avoid duplicates
- **Reconnect**: if the gateway restarts, the dashboard should retry every 1–2 seconds
- **Debug page**: open `http://localhost:8080/` for a bare-bones live event list
  (`gateway/viewer.html`, under 100 lines; a good reference for connecting)
- **Current status**: the gateway acts on `stop` (it revokes the run — see below); the other
  commands (`approve`, `deny`, `rollback_files`) are received but only printed for now
- **Not reachable from the agent**: in the container setup, connections to the feed from the
  agent's network are refused (403). Commands such as `approve` and `stop` can therefore only
  come from the dashboard side, never from the agent itself

### What the gateway sends today

`session_start`, `tool_call`, `taint`, `network_request`, `decision`, `llm_call`,
`session_end`, `approval_request`, `approval_result` and `quarantine`.

- Every `tool_call` is judged before the agent receives it: `"level": "green"` (allowed) or
  `"red"` (blocked, with `"blocked": true`).
- An allowed read of an untrusted source (third-party code, web content) or a sensitive one
  (`.env`, keys) is followed by a `taint` event, the first time each kind is read. `caused_by`
  points at the read; `from_state` / `to_state` show the change. `session_state` moves
  `clean` → `untrusted` / `sensitive` → `tainted`.
- Each outbound request (npm, pip, git, curl — not the model route) is a `network_request`
  event: `dest_category` is `allowlist` or `unknown`, and `blocked` says whether the gateway
  proxy denied it. A denied one is followed by a `decision` event.
- Each block (a tool call or an egress request) is followed by a `decision` event
  (`verdict: "block"`) whose `target_event` and `caused_by` point at the blocked event. A block
  of an outbound request from a tainted session (`lethal_trifecta`) sets `session_state` to
  `"blocked"`; a routine `unknown_destination` denial does not.
- `session_start`, `llm_call`, `taint` and `decision` events have `"level": null`, except a
  `decision` for a block, which is `"red"`.
- The `stop` command (dashboard → gateway) revokes the run: the gateway denies every further
  model and egress request, cuts any in-flight response, and sends one `session_end`
  (`result: "stopped"`, `session_state: "ended"`, `"level": "red"`). It is idempotent. The
  gateway also auto-stops on a request budget or token-lifetime limit.
- A policy `ask` verdict holds the tool call and sends an `approval_request` (yellow). The
  dashboard answers with `approve` / `deny` (bound to the request's `action_digest`); the
  gateway sends an `approval_result` and either releases or replaces the call.
- The `quarantine` command marks a source; from then on the gateway replaces that source's
  tool-result content before the model sees it and sends a `quarantine` event the first time.
- Every event carries a `prev_hash`/`hash` chain so the log is tamper-evident.

The other event types come in later steps; use `events.example.json` to build for them now.

### Extra fields the gateway sends

These were added during implementation, following the "add, never rename" rule:

| Event | Field | Meaning |
|---|---|---|
| `llm_call` | `duration_ms` | Whole round trip, mostly the model thinking (`latency_ms` counts only the time the gateway itself adds) |
| `llm_call` | `cached_input_tokens` | The part of `input_tokens` served from the prompt cache |
| `tool_call` | `tool_use_id` | The model's ID for this tool call, used later to match a tool call with its result |
| `llm_call` | `tool_calls_blocked` | How many of `tool_calls_proposed` the gateway replaced before the agent got them |
| `decision` | `policy_version` | The `version` of the policy file that made the decision |
| `decision` | `advisory` | `true` when the rule matched on shell text (such rules can be dodged by rewording; a miss proves nothing) |
| `session_start` | `policy` | Policy file and version in effect (field was already in the spec, now filled in) |
| every event (envelope) | `untrusted_input_seen`, `sensitive_data_seen` | The two booleans `session_state` is derived from. Still accurate after the state becomes `blocked`, which would otherwise hide them |
| `taint` | `rule` | The `[[taint]]` entry in the policy file that matched |
| `taint` | `advisory` | `true` when the mark came from a shell command's text (the paths it mentions); `false` for the `Read` / web tools |

---

## 3. The common envelope

Every event has these fields; `data` holds the type-specific content.

```json
{
  "event_id": "evt_0014",
  "session_id": "sess_01",
  "seq": 14,
  "time": "2026-11-04T10:30:15.870Z",
  "type": "network_request",
  "level": "red",
  "session_state": "tainted",
  "caused_by": ["evt_0005", "evt_0011", "evt_0013"],
  "data": { }
}
```

| Field | Meaning | How the dashboard uses it |
|---|---|---|
| `event_id` | Event ID: `evt_` plus at least 4 digits | Find the row when it's clicked |
| `session_id` | Which agent run | Separate several agents running at once |
| `seq` | Order number, counting up from 1 | **Sort by this**, not by arrival order |
| `time` | When it happened (UTC, ISO 8601) | Shown in the traffic list |
| `type` | Event type, see section 4 | Decides what the row looks like |
| `level` | Risk level: `green` / `yellow` / `red` / `null` | Traffic-light colour; `null` means informational, no light |
| `session_state` | The session's state **after** this event | Read directly by a status bar |
| `caused_by` | Earlier events that led to this one | **Draws the attack chain.** Empty array `[]` if none |
| `data` | The content; differs per type | See section 4 |

### `session_state` values

The state only moves forward: once it gets worse, it doesn't go back to clean on its own.

| Value | Meaning | Suggested colour | When it's entered |
|---|---|---|---|
| `clean` | Clean | Green | At the start |
| `untrusted` | Has read untrusted content | Yellow | Read an external README, web page, etc. |
| `sensitive` | Holds sensitive data | Yellow | Read `.env`, keys, etc. |
| `tainted` | Tainted (both of the above) | Orange | Both conditions hold |
| `blocked` | Blocking | Red | A dangerous action was just blocked |
| `healed` | Healed | Blue | Self-heal succeeded and the task continues |
| `ended` | Ended | Grey | The session is over |

---

## 4. Event types

| type | Sent when | Priority |
|---|---|---|
| `session_start` | The agent starts | P0 |
| `llm_call` | One round trip between the agent and the LLM | P0 |
| `tool_call` | The agent reads a file, edits a file, runs a command | P0 |
| `network_request` | Any outbound network request | P0 |
| `taint` | The session becomes riskier | P0 |
| `decision` | The gateway decides: allow / ask / block | P0 |
| `heal` | After a block: clear the contamination and let the task continue | P0 |
| `session_end` | The task finished or was stopped | P0 |
| `approval_request` | A yellow action needs a human's OK | P1 |
| `approval_result` | The human approved / denied, or it timed out | P1 |
| `stats` | Summary numbers, sent every few seconds | P1 |
| `settings` | The current protections and operator rules: once at start, then after every change | P1 |

The fields inside `data` for each type follow. **Bold fields are required.**

### session_start
| Field | Meaning |
|---|---|
| **`agent`** | Which agent, e.g. `claude-code` |
| **`task`** | What the user asked it to do, e.g. "Fix the failing test" |
| `user` | Who started it |
| `policy` | Which policy file is in effect |

### llm_call
| Field | Meaning |
|---|---|
| **`provider`** | `anthropic`, `openai`, etc. |
| **`destination`** | e.g. `api.anthropic.com` |
| `model` | Model name |
| `input_tokens` / `output_tokens` | Input / output token counts (input includes cached tokens) |
| `cached_input_tokens` | How much of the input came from the prompt cache |
| `tool_calls_proposed` | How many tools the model asked to run this time |
| `canary_hit` | Whether a canary key appeared in the request (see note 3 in section 7) |
| **`latency_ms`** | Latency **added by the gateway**, not the LLM's total time |
| `duration_ms` | The whole round trip |

### tool_call
| Field | Meaning |
|---|---|
| **`tool`** | `Read`, `Write`, `Edit`, `Bash`, `WebFetch`, or an MCP tool name |
| **`summary`** | One-line description, shown directly in the list |
| `input` | The key argument, **truncated to ~200 characters and redacted** |
| **`target`** | `local` (this machine) or `network` (goes online) |
| `path` | The file it touches, if any |
| `blocked` | Whether it was blocked; default `false` |
| `tool_use_id` | The model's ID for this call |

### network_request
| Field | Meaning |
|---|---|
| **`method`** | `GET`, `POST`, etc. |
| **`destination`** | Target host |
| **`dest_category`** | `llm` (LLM API) / `allowlist` (trusted, e.g. GitHub, npm) / `unknown` (never seen). Good for grouping destinations |
| `bytes` | How many bytes were sent |
| `preview` | First ~200 characters of the body. Real secrets appear as `***`; canary keys as `[CANARY]...` so they can be highlighted |
| `canary_hit` | Whether a canary key was in the body |
| **`blocked`** | Whether it was blocked. **Show blocked requests in red** |
| `latency_ms` | Gateway latency; `null` when blocked |

### taint
| Field | Meaning |
|---|---|
| **`tag`** | `sensitive` (touched sensitive data) or `untrusted` (touched untrusted content) |
| **`source`** | The file or URL that caused it |
| **`from_state`** / **`to_state`** | The state before and after; a status bar can animate the change |

### decision
| Field | Meaning |
|---|---|
| **`target_event`** | Which event was judged |
| **`verdict`** | `allow` / `ask` (needs approval) / `block` |
| **`rule`** | The rule that matched, e.g. `lethal_trifecta`, `canary_hit` |
| **`reason`** | A human-readable reason, **shown directly on the dashboard** |
| **`decided_by`** | `rule` or `llm`. A red light is always `rule` |

### approval_request
| Field | Meaning |
|---|---|
| **`target_event`** | The action awaiting approval |
| **`summary`** | Title for the approval card |
| **`reason`** | Why approval is needed |
| **`timeout_s`** | Auto-deny after this many seconds without an answer |

### approval_result
| Field | Meaning |
|---|---|
| **`target_event`** | Which action |
| **`result`** | `approved` / `denied` / `timeout` |
| **`by`** | Who decided, e.g. `alice@phone` |

### heal (the most important one)
| Field | Meaning |
|---|---|
| **`quarantined_source`** | The quarantined source of contamination, e.g. the malicious README |
| **`rolled_back_to`** | The event the context was rolled back to (the last clean moment) |
| **`removed_events`** | Events whose content was quarantined. **The dashboard can strike these rows through or grey them out** |
| **`message_to_agent`** | The replacement text the gateway gave the agent |
| **`status`** | `success` / `failed` |

### session_end
| Field | Meaning |
|---|---|
| **`result`** | `completed` / `stopped` / `failed` |
| `summary` | One-line summary |
| `attacks_blocked` | How many attacks were blocked |
| `heals` | How many self-heals happened |

### stats
| Field | Meaning |
|---|---|
| **`total_events`** | Total number of events |
| **`auto_allowed`** | How many were allowed automatically |
| **`asked`** | How many needed approval |
| **`blocked`** | How many were blocked |
| `heals` | How many self-heals |
| **`avg_latency_ms`** | Average gateway latency. **Put it somewhere visible: the A10 judges will look at it** |

### settings
Sent once when the gateway starts (so a dashboard that connects later learns the current
protections from the replayed history), and again after every change made from the dashboard.
`level` is `yellow` when the change switched a protection OFF, otherwise null.

| Field | Meaning |
|---|---|
| **`protections`** | List of `{id, category, category_title, label, detail, locked, available, enabled}`. `category` is the threat category 0–7 (docs/threat-model.md §4). `locked` = enforced by the deployment, always on. `available` = false when the policy file lacks the rule it switches |
| **`custom_rules`** | Operator rules: `{id, kind, pattern, verdict, reason, label, by}`. `id` is `custom_N`; a `decision` made by one has `rule: "custom_N"` |
| **`policy_version`** | The file's version plus `+dash.N` after N changes. Every later `decision` carries this version |
| **`revision`** | Number of changes so far |
| `change` | One line on what changed, e.g. `Disallowed: shell command containing “setup.sh” (block)` or `Turned OFF: Deny unknown hosts`. Absent on the startup snapshot |
| `by` | Who made the change |
| `error` | Present instead of `change` when a command was refused (bad rule, locked protection) |

---

## 5. Commands (dashboard → gateway)

Sent when the user clicks a button on the dashboard.

```json
{ "command": "approve",        "target_event": "evt_0007", "by": "alice@dashboard" }
{ "command": "deny",           "target_event": "evt_0007", "by": "alice@dashboard" }
{ "command": "stop",           "session_id": "sess_01" }
{ "command": "rollback_files", "session_id": "sess_01" }
{ "command": "set_protection", "id": "egress_allowlist", "enabled": false, "by": "alice@dashboard" }
{ "command": "add_rule", "rule": { "kind": "command", "pattern": "setup.sh", "verdict": "block" }, "by": "alice@dashboard" }
{ "command": "remove_rule", "id": "custom_1", "by": "alice@dashboard" }
```

| Command | Effect | Required |
|---|---|---|
| `approve` | Approve a yellow action | `target_event` |
| `deny` | Deny a yellow action | `target_event` |
| `stop` | Stop the whole session: **the "stop the run" step the challenge asks for** | `session_id` |
| `rollback_files` | Undo every file change the agent made | `session_id` |
| `set_protection` | Switch a built-in protection on or off (locked ones refuse). Applies to the agent's next action | `id`, `enabled` |
| `add_rule` | Disallow an action. `kind`: `command` (Bash command containing the text, case-insensitive, literal), `read` / `write` (file glob; a bare name matches in any folder), `tool` (tool name or `prefix*`), `host` (host or `*.suffix`: proxy egress and WebFetch URLs). `verdict`: `block` (default) or `ask`. Operator blocks are checked before the policy file's rules and operator asks after them, so adding a rule never loosens anything | `rule.kind`, `rule.pattern` |
| `remove_rule` | Remove an operator rule | `id` |

The gateway answers every settings command with a `settings` event (with `change`, or `error`).

---

## 6. The example story (`events.example.json`)

A bank engineer asks the agent to fix a bug; along the way it's attacked through a
poisoned README:

| # | What happens | Light | State |
|---|---|---|---|
| 1 | Start: fix the test for `src/trade.py` | | clean |
| 2–3 | Ask the LLM, read `src/trade.py` | 🟢 | clean |
| 4–5 | Read a third-party library's README (**with hidden malicious instructions**); marked untrusted | 🟢 | untrusted |
| 6–10 | Wants to read `.env`; the gateway asks for approval; the user approves on their phone | 🟡 | untrusted |
| 11 | Reads `.env`; marked sensitive | | **tainted** |
| 12–13 | Runs `setup.sh` as the README says | 🟢 | tainted |
| 14 | The script secretly POSTs `.env` to an outside host, **carrying a canary key** | 🔴 blocked | tainted |
| 15 | Gateway decision: lethal trifecta + canary hit | 🔴 | blocked |
| 16 | **Self-heal**: quarantine the README, roll back to just after step 3 | | **healed** |
| 17–19 | The agent carries on: edits the code, runs the tests | 🟢 | healed |
| 20–21 | Summary numbers, task completed ✅ | | ended |

**Tip for dashboard work**: `dashboard/?demo` already replays this file. To simulate it over
the real WebSocket instead, send one event every 0.5–1 seconds, pausing longer around
event 14 (block) and event 16 (heal) when rehearsing the demo.

Event 14's `caused_by` is `["evt_0005", "evt_0011", "evt_0013"]`: "read the malicious
README", "read `.env`", "ran setup.sh". Following those IDs backwards gives the attack chain.

---

## 7. Notes

1. **Truncate `preview` and `input`**: about 200 characters at most, or the dashboard slows down.
2. **Always redact real secrets**: show them as `***`. Only canary keys are shown
   (`[CANARY]...`), so nothing real leaks when the demo is on a projector.
3. **A canary key inside an LLM request is not a red light**: once the agent has read
   `.env`, its contents naturally appear in the conversation sent to the LLM (see event 12:
   `canary_hit: true`, still green). It's only red when a canary key goes somewhere
   **other than** the LLM.
4. **Enum values are always lowercase**: `red` not `Red`, `tool_call` not `toolCall`.
5. **Sort by `seq`**: messages can arrive out of order.
6. **P0 first**: the 8 P0 types carry the whole demo; add P1 if there's time.

---

## 8. Checking the format

With Python installed:

```bash
pip install jsonschema
```

Then, from the `protocol/` folder:

```bash
python3 -c "import json,jsonschema; s=json.load(open('events.schema.json')); v=jsonschema.Draft202012Validator(s); [v.validate(e) for e in json.load(open('events.example.json'))]; print('OK')"
```

`OK` means the example file matches the format exactly. The gateway's own events can be
checked the same way (the test suite in `tests/` already does this).
