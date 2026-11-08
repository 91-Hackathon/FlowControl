# FlowControl dashboard

Everything the AI agent does through the gateway: the traffic in detail on the left, and
the same run told in plain English on the right, so a viewer can follow it without
reading the table. Plain HTML, CSS and JavaScript: no build, no installs.

Look: "quiet clarity". Black ink on white and warm cream; **red only for blocked**,
amber only for "waiting on a person"; Inter for text, IBM Plex Mono where the machine
speaks (hosts, paths, times). Light only.

## Open it

```bash
python3 -m http.server 5173 --directory dashboard
```

| URL | What it shows |
|---|---|
| http://localhost:5173/ | Live: connects to the gateway at `ws://localhost:8080/events`, retries every 2s |
| http://localhost:5173/?demo | Demo: replays `protocol/events.example.json` (the bank repo attack), no gateway needed. It pauses at the approval request: **Approve** lets the run continue to the blocked upload and the heal; **Deny** stops it. **Replay demo** starts over |
| http://localhost:8080/dashboard/ | Served by the gateway itself (same port as the live feed) |
| `?ws=ws://host:port/events` | Live, from another address |
| `#map`, `#security`, `#replay` | Open on that view (e.g. `/?demo#replay`) |

A page that connects late still gets every event of the run so far.

## Layout

```
┌ FlowControl │ task · ■ outcome │ task state │ ● conn  [Stop run] [Replay demo] [Present] ── header
├──────────────────────────────────────────────────────────┬──────────────────────┐
│ Network | Map | Security (n) | Replay     filter · chips │ WHAT HAPPENED        │
│ [LLM][Tools][Allowed][Blocked][Overhead][Tokens]         │ Headline (outcome)   │
│ the open view                                            │ task state — note    │
│                                                          │ ┌ Needs your OK ───┐ │
│                                                          │ │ action  [Deny][✓]│ │ only while waiting
│                                                          │ └──────────────────┘ │
│                                                          │ ○ moment             │
│ status bar                                               │ ● moment (blocked)   │
└──────────────────────────────────────────────────────────┴──────────────────────┘
```

The story pane is about a quarter of the width (`clamp(300px, 27vw, 400px)`). Press **P**
(or Present) for presenter mode: the story grows to ~38% with bigger type and the KPI row
and status bar hide. On narrow screens the story moves below the workspace.

### Approvals

When the gateway holds an action for a person, a card appears at the top of the story pane,
right under the headline: what the agent wants to do, the exact action (tool and input),
why it needs approval, a countdown bar (turns red in the last 15 s), and **Deny** /
**Approve**. It approves that one action only; no answer in time means deny. The card goes
away once answered and the story records the answer.

### Header status line and story

`story.js` turns the event list into words:

- **Outcome**: `Secret upload blocked` / `Outbound request blocked` / `<Tool> action blocked`
  (red), `Approval needed` (amber), `Action denied by you`, or `No actions blocked`.
- **Task state**: `Agent running`, `Agent waiting for your approval`, `Agent recovering`
  (after a heal), `Task completed`, `Run stopped`, `Run failed`.
- **Moments**: agent started, untrusted content read, sensitive data read (folded into the
  approval when you approved it), approval needed / approved / denied, blocked (with the
  chain of steps that led to it), unsafe context removed (heal), source withheld
  (quarantine), and how the run ended.

Click a moment to highlight its events in Network (the others dim); click it again or press
Esc to clear. The Network detail pane also starts with one plain sentence about the event.

### Protections (the shield button)

Opens a settings window in the middle of the screen (Esc or a click outside closes it):

| Page | What's there |
|---|---|
| Overview | The eight threat categories as tiles, each "On" or "Reduced" with what's switched off |
| Disallowed actions | Add your own rule: *When the agent tries* (shell command containing / reading a file / editing a file / any call of a tool / reaching a host) *matching* (pattern) *then* Block it or Ask me first. Example chips fill the form. Your rules are listed below with Remove |
| Protections | The switchable protections, grouped by what they do (spot risky input, stop data leaving, stop dangerous changes, limits), each with a switch and its category tag. All on by default; switching one off asks first, turns the shield button amber and is logged |
| Always on | What the deployment itself enforces (isolated runner, key broker, exact-action approvals, …): shown, never switchable |

A new rule applies to the agent's very next action; it shows as a "New rule" moment in the
story, and a block by it reads "Your rule blocked: …". An **Ask me first** rule is the
easiest way to show a live approval card: the default policy has no "ask" rules of its own.
Live, these are commands to the gateway (protocol/EVENTS.md §5). In `?demo` the window works
on a local copy and the replay honours your rules: add "Reading a file `.env`" and press
Replay demo — the read is blocked and the whole exfiltration chain after it never happens.

### Stat panels

A big number with a faint sparkline of the same number over the session. All ink, except
**Blocked**, which turns red (with a red background) once anything is blocked.

### Network (Chrome DevTools)

One row per event, with a waterfall. Click a row (↑ ↓ to move, Esc to close) for the detail
pane: Overview, Data, Event, and **Security** when the gateway made a decision about it.
A blocked row opens straight on Security.

### Map (Little Snitch)

Agent → the gateway (drawn as a gate) → a card per destination group: LLM API, Files: read,
Files: write, Shell (by program), Web (by host), MCP (by server), Subagents, Unknown hosts.
Traffic that went through leaves the gate as an ink line (thicker = more requests); traffic
that was stopped ends at a red ✕ right at the gate, with the path it tried drawn faint and
dashed, and its card turns red. A dot travels along links with traffic in the last few
seconds. The list beside it has every destination with requests, denied and last seen;
click one to see its requests in Network.

### Security (Cloudflare security events)

Totals by action (allowed, challenged = needs approval, blocked), a timeline of allowed
vs blocked, top rules, top blocked destinations, and the event log. Expand an event for
the action taken, rule ID, rule message, decided by (rule or LLM), match type (structured,
or advisory for shell-text rules), policy version, the request with its payload (canary
keys highlighted), and the chain of events that caused it.

### Replay (LangSmith traces)

A trace tree: session → each LLM call → the tool calls it proposed → what the gateway did
(decisions, marks, approvals). Click a step for its details. The playback bar replays the
session: ⏮ back to start, ▶ play / pause, ⏭ back to live, the slider to scrub, 1× 2× 4×.
When a block happens, the **attack chain** bar shows every step that led to it, the block,
and the heal if there was one; steps in the chain have a red edge in the tree.

The gateway sends a tool call before the LLM call that proposed it finishes; hand-written
feeds (like the example) list it after. The tree detects which order the feed uses.

## Files

| File | Job |
|---|---|
| `index.html` | Page structure |
| `style.css` | "Quiet clarity" theme (light only) |
| `story.js` | Header status line and story moments, in plain English. No DOM |
| `settings.js` | Protections panel; in demo, also matches your rules against the replay |
| `model.js` | Shared facts: where an event goes, attack chains, time buckets. No DOM |
| `rows.js` | Event → table row, waterfall layout |
| `detail.js` | Network detail pane tabs, with a plain-English sentence on top |
| `kpis.js` | Stat panels |
| `map.js` | Traffic map and connection list |
| `security.js` | Security events view, and the block card reused by Network and Replay |
| `trace.js` | Replay: trace tree, playback, attack chain |
| `app.js` | Live feed / demo replay, panel tabs, toolbar, selection, story pane, approvals, presenter mode |
| `demo-data.js` | Copy of `protocol/events.example.json` for `?demo` |

After editing a file, bump its `?v=` number in `index.html` so browsers don't use a cached copy.

Refresh the demo data after changing `protocol/events.example.json`:

```bash
python3 -c "import json; ev=json.load(open('protocol/events.example.json')); open('dashboard/demo-data.js','w').write('window.FC_DEMO_EVENTS = ' + json.dumps(ev, indent=1) + ';\n')"
```
