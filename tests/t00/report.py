"""T00 report: compare probe results with expectations, check independent evidence, write a report.

usage: python3 report.py OUT_DIR REPORT_PATH
Exit code 0 only if every check passes.
"""
import json
import pathlib
import sys

out, report_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
cfg = json.loads((out / "config.json").read_text())


def jsonl(name):
    p = out / name
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def by_id(rows):
    return {r["id"]: r for r in rows}


runner, control = by_id(jsonl("runner.jsonl")), by_id(jsonl("control.jsonl"))
down, recovered = by_id(jsonl("down.jsonl")), by_id(jsonl("recovered.jsonl"))
sniff = [r for r in jsonl("sniff.log") if "marker" in r]
sinks = {name: jsonl(f"{name}.log") for name in ("host_sink", "egress_sink")}
claude_down = json.loads((out / "claude_down.json").read_text()) if (out / "claude_down.json").exists() else {}

RM, CM = cfg["runner_marker"], cfg["control_marker"]
# Probes where a container with a normal network should succeed: proof the probe itself works.
CONTROL_POSITIVE = {
    "tcp_public_ip", "tcp_public_name", "tcp_host_sink", "tcp_egress_sink", "tcp_metadata", "udp_public",
    "dns_resolver_public", "dns_resolver_marker", "dns_direct_google", "dns_direct_cloudflare",
    "dns_direct_tcp", "ipv6_public", "ipv6_global_address", "child_curl", "child_node", "child_proxy_env",
}

failures, rows = [], []
for pid, r in runner.items():
    expected = "reached" if pid == "gateway_model_route" else "blocked"
    ok = r["outcome"] == expected
    c = control.get(pid)
    if not ok:
        verdict = "**FAIL**"
        failures.append(f"{pid}: expected {expected}, got {r['outcome']} ({r['detail']})")
    elif pid in CONTROL_POSITIVE and (not c or c["outcome"] != "open"):
        verdict = "pass (not proven: control also blocked)"
    else:
        verdict = "pass"
    rows.append((pid, r["what"], expected, r["outcome"], c["outcome"] if (c and pid in CONTROL_POSITIVE) else "—", verdict, r["detail"]))

# Independent evidence -------------------------------------------------------------------
evidence = []
for name, lines in sinks.items():
    hit_r = [l for l in lines if RM in l.get("data", "")]
    hit_c = [l for l in lines if CM in l.get("data", "")]
    if hit_r:
        failures.append(f"{name} received data from the runner: {hit_r[:2]}")
    evidence.append((f"{name}: runner data received", len(hit_r), "0", "**FAIL**" if hit_r else "pass"))
    evidence.append((f"{name}: control data received (sink works)", len(hit_c), "≥1", "ok" if hit_c else "not proven"))

def describe(s):
    port = f":{s['dport']}" if "dport" in s else ""
    return f"{s['iface']} {s.get('proto', '?')} {s.get('src', '?')}→{s.get('dst', '?')}{port}"


agent_bridge = cfg.get("agent_bridge", "")
r_seen = [s for s in sniff if s["marker"] == RM]
r_leaks = [s for s in r_seen if s["iface"] != agent_bridge]
c_seen = [s for s in sniff if s["marker"] == CM]
c_dns = [s for s in c_seen if s.get("dport") == 53 or s.get("sport") == 53]
if r_leaks:
    failures.append(f"runner marker seen outside the agent network: {sorted({describe(s) for s in r_leaks})[:5]}")
evidence.append(("sniffer: runner marker outside the agent network", len(r_leaks), "0", "**FAIL**" if r_leaks else "pass"))
evidence.append(("sniffer: runner marker on the agent network bridge (never left it)", len(r_seen) - len(r_leaks), "any", "info"))
evidence.append(("sniffer: control marker seen (sniffer works)", len(c_seen), "≥1", "ok" if c_seen else "not proven"))
evidence.append(("sniffer: control DNS packets carrying its marker (sniffer catches DNS)", len(c_dns), "≥1",
                 "ok" if c_dns else "not proven"))

# Gateway down: everything must fail, including the model route -----------------------------
down_open = [pid for pid, r in down.items() if r["outcome"] != "blocked"]
if down_open:
    failures.append(f"with the gateway stopped, still open: {down_open}")
rec = recovered.get("gateway_model_route", {}).get("outcome")
if rec != "reached":
    failures.append(f"after restarting the gateway, model route is {rec}")

lines = [
    "# T00 — gateway bypass and fail-closed",
    "",
    f"Run: {cfg['started_utc']} · result: **{'PASS' if not failures else 'FAIL'}**",
    "",
    "Threat model §7, T00: direct egress, DNS, IPv6, subprocess bypass; gateway unavailable.",
    "Expected evidence: independent capture confirms denied transfers; failure is closed.",
    "",
    "## Configuration",
    "",
    f"- Docker: {cfg['docker_version']}",
    f"- Claude Code: {cfg['claude_version']}",
    f"- Runner image: `{cfg['runner_image']}`",
    f"- Gateway image: `{cfg['gateway_image']}`",
    f"- compose.yaml (resolved) sha256: `{cfg['compose_sha256']}`",
    f"- Agent network bridge: `{agent_bridge}`",
    f"- Markers: runner `{RM}`, control `{CM}`",
    "",
    "## Probes from inside the runner",
    "",
    "Control = the same probe from a container with a normal network; `open` there proves the probe can succeed.",
    "",
    "| Probe | What | Expected | Runner | Control | Verdict | Detail |",
    "|---|---|---|---|---|---|---|",
]
for pid, what, exp, got, ctl, verdict, detail in rows:
    lines.append(f"| `{pid}` | {what} | {exp} | {got} | {ctl} | {verdict} | {detail.replace('|', '/')} |")
lines += ["", "## Independent evidence", "", "| Check | Count | Expected | Verdict |", "|---|---|---|---|"]
lines += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in evidence]
lines += [
    "",
    "## Gateway stopped (fail closed)",
    "",
    f"- Probes still open with the gateway stopped: {down_open or 'none'}",
    f"- Claude Code with the gateway stopped: exit {claude_down.get('exit')}, after {claude_down.get('seconds')}s"
    f" — {claude_down.get('output', '').strip()[:160] or 'no output'}",
    f"- Model route after restarting the gateway: {rec}",
    "",
    "## Failures",
    "",
]
lines += [f"- {f}" for f in failures] or ["None."]
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text("\n".join(lines) + "\n")
print("\n".join(lines))
sys.exit(1 if failures else 0)
