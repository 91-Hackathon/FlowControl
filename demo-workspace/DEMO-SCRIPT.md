# FlowControl — Demo Script (screen recording)

Two short recordings:

- **Part 1 (~2 min)** — the main demo: launch, traffic, a blocked action, a human approval, stop.
- **Part 2 (~40 sec)** — egress control: the agent tries to reach a host that isn't allowed.

`[brackets]` = what you do. The rest is what you say out loud.

---

## 0. Setup (before you record — do this once)

1. Docker Desktop running; the real API key in your shell.
2. Start the run (the demo policy turns on the approval step):

   ```bash
   cd /Users/evanyu/Desktop/Hackathon/FlowControl && FC_WORKSPACE=./demo-workspace FC_POLICY_FILE=policy/demo.toml ./flowcontrol run
   ```

3. Wait for `gateway ready`. The **FlowControl desktop app opens automatically**, and you're dropped into the agent (Claude Code).
   - If the desktop app isn't built, it falls back to the browser at **http://localhost:8080/dashboard/**.
4. Put the terminal and the desktop app side by side. Start recording.

---

# Part 1 — main demo

## 1. Opening (~15 sec)

> "AI agents are powerful, but they run commands, touch files, and reach the internet — mostly unsupervised. FlowControl is a control layer between the agent and the world. It shows you everything the agent does, blocks the actions it shouldn't take, pauses for a human on the gray areas, and lets you kill the run. Let me show you."

## 2. Launch

> "I've launched a real coding agent — Claude Code — inside an isolated sandbox. Its only way out is through our gateway. On the right is the live dashboard."

## 3. Display traffic  **[type: `Do step 1 in TASK.md.`]**

> "I give it a normal engineering task. Watch the dashboard — every step shows up live: the files it reads, the model calls it makes. Full visibility, nothing hidden."

## 4. Block — a dangerous action  **[a red row appears — pause, point]**

> "Its task was to change our deploy pipeline. But editing CI from inside a run is off-limits — so the gateway blocks it. Red line: *blocked, protected config*. The agent simply cannot touch it."

## 5. Zoom out — the 8 threat categories (~25 sec)

> "That block is one of **eight categories of risk** we cover — the eight ways an agent can go wrong:
>
> 1. **Bypassing the control layer** — the sandbox has no way out except our gateway.
> 2. **Prompt injection** — untrusted files or web pages trying to hijack the agent; we track what it reads and mark it tainted.
> 3. **Data exfiltration** — secrets leaving the box.
> 4. **Dangerous actions** — tampering with CI, settings, deploy — what you just saw.
> 5. **Supply chain** — malicious dependencies; we disable package install scripts.
> 6. **Credential abuse** — the agent never gets the real API key, only a short-lived token the gateway swaps in.
> 7. **Runaway resources** — CPU, memory, and process count are capped, with a budget and a time limit that auto-stop it.
> 8. **Tampering** — the audit log is tamper-evident, and the agent can't reach the control channel to approve or stop itself.
>
> In a live run you only see a few of these fire — a well-behaved model refuses a lot on its own. So to prove the **gateway itself** covers all eight, we test each category with a scripted agent that always attempts the attack. The gateway blocks every one. The model is the first layer; the gateway is the guaranteed backstop."

## 6. Human approval  **[type: `Now do step 2 in TASK.md.`]**

> "Next it needs to check our runtime config — which means opening the secrets file."

**[A yellow card appears on the dashboard: Approve / Deny. The agent is paused.]**

> "Reading secrets is a judgment call, so the gateway doesn't decide alone — it pauses the agent and asks a human. That's this card. The approval is tied to this exact action, and if nobody answers, it's denied."

**[Click Approve.]**

> "It has a legitimate reason, so I approve. The agent continues — and notice the session is now flagged as holding secrets. From here on, the gateway treats anything it sends out much more strictly. **Hard rules for the clear cases, a human for the gray ones.**"

## 7. Stop the run  **[click "Stop run" on the dashboard]**

> "Now say I don't like where this run is going. One click, and the run is revoked."

**[type anything, e.g. `try again`]**

> "Every further request is denied. The agent is dead. Done."

## 8. Closing (~15 sec)

> "So: we launched an agent, watched everything it did, blocked a dangerous action, paused for a human where it mattered, and killed the run — across eight categories of risk. None of it relied on the model behaving well. The gateway enforces the rules either way. That's FlowControl."

---

# Part 2 — egress control (separate short recording)

**Setup:** `Ctrl-C` out of the agent, then start a fresh run:

```bash
./flowcontrol stop
```

```bash
FC_WORKSPACE=./demo-workspace FC_POLICY_FILE=policy/demo.toml ./flowcontrol run
```

## 1. Intro  **[type: `Read TASK-EGRESS.md and complete it.`]**

> "One more control: where the agent is allowed to go on the network. I'm asking it to fetch a deploy checklist from an internal docs site."

## 2. Block  **[a red row appears — pause, point]**

> "The agent runs the request — and the gateway stops it at the network level. Red line: *blocked, unknown destination* — that host isn't on the allowlist. The request never reaches the server. The agent just gets a 403."

## 3. Why it matters

> "The agent can only talk to hosts we've approved — the model API, package registries, GitHub. Everything else is denied by default. That's what stops a hijacked agent from sending your data somewhere it shouldn't: there's simply no road out. And once a session has touched secrets, the gateway goes further and cuts outbound traffic completely."

**[Teardown:]**

```bash
./flowcontrol stop
```

---

## Notes

- Pause ~2 sec after each red row and on the yellow card so viewers can read them.
- You have **120 seconds** to click **Approve** before it auto-denies (fail-closed).
- `demo.toml` = the default policy **plus** the approval-on-secret-read rule. The real default keeps approval off (it's a usability cost).
- The agent runs with Claude Code's own permission prompts off, so FlowControl is the single control plane (disable with `FC_AGENT_SKIP_PERMISSIONS=0`).
- All values in `.env` are fake — safe on screen.
- If something hangs: `Ctrl-C` the agent, `./flowcontrol stop`, then restart from Setup step 2.
