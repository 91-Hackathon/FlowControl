#!/usr/bin/env bash
# Does the real Claude Code accept what the gate sends it, and does a blocked call stay unrun?
# Runs the pinned Claude Code (runner image) against a scripted fake model (fake_model.py),
# through a gateway on this machine. No real API key needed; takes about a minute.
#
# Usage: tests/claude_gate/run.sh        (needs Docker running)
#
# Cases (Claude Code runs with --dangerously-skip-permissions, so its own permission checks
# are off and only the gateway stands in the way):
#   blocked   the model asks to Write a CI workflow           -> gateway blocks; file never written
#   no_gate   the same with an empty policy                    -> file IS written (the block above is the gateway's)
#   mixed     one allowed Bash call + one blocked Write        -> Bash runs, Write doesn't, conversation continues
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=tests/claude_gate
OUT="$(mktemp -d)"
FAKE_PORT=18700 GW_PORT=18787 LIVE_PORT=18081
PROTECTED=.github/workflows/release.yml
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

fails=0
check() {  # check DESCRIPTION COMMAND...
  if "${@:2}" >/dev/null 2>&1; then printf '  pass  %s\n' "$1"; else printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); fi
}
wait_port() { python3 -I -c 'import socket,sys,time
for _ in range(100):
    try: socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close(); sys.exit(0)
    except OSError: time.sleep(0.1)
sys.exit(1)' "$1"; }

docker image inspect flowcontrol-runner >/dev/null 2>&1 || docker build -q -t flowcontrol-runner runner >/dev/null

# Policies: the repository's default, and an empty one (nothing blocked).
printf 'version = "empty"\n' > "$OUT/empty.toml"
WRITE_PROTECTED='{"name": "Write", "input": {"file_path": "/workspace/'"$PROTECTED"'", "content": "on: push  # planted\n"}}'
cat > "$OUT/one_write.json" <<EOF
{"text": "I'll add the release workflow.", "calls": [$WRITE_PROTECTED]}
EOF
cat > "$OUT/mixed.json" <<EOF
{"text": "Two things at once.", "calls": [
  {"name": "Bash", "input": {"command": "echo allowed > /workspace/allowed.txt", "description": "write a file"}},
  $WRITE_PROTECTED]}
EOF

run_case() {  # run_case NAME POLICY SCENARIO
  local dir="$OUT/$1"
  mkdir -p "$dir/ws"
  python3 -I "$HERE/fake_model.py" "$FAKE_PORT" "$3" "$dir/requests.jsonl" & PIDS+=($!)
  FC_PORT=$GW_PORT FC_LIVE_PORT=$LIVE_PORT FC_UPSTREAM="127.0.0.1:$FAKE_PORT" FC_UPSTREAM_SCHEME=http \
    FC_POLICY_FILE="$2" FC_EVENTS_FILE="$dir/events.jsonl" python3 -m gateway > "$dir/gateway.log" 2>&1 & PIDS+=($!)
  wait_port "$FAKE_PORT" && wait_port "$GW_PORT"
  local status=0
  docker run --rm --user 1000:1000 \
    -e ANTHROPIC_BASE_URL="http://host.docker.internal:$GW_PORT" \
    -e ANTHROPIC_API_KEY=sk-ant-fake-claude-gate-test -e CLAUDE_CODE_MAX_RETRIES=1 \
    -v "$dir/ws:/workspace" flowcontrol-runner \
    claude -p "Do the task." --dangerously-skip-permissions < /dev/null > "$dir/claude.out" 2>&1 || status=$?
  echo "$status" > "$dir/exit"
  kill "${PIDS[@]}" 2>/dev/null || true; wait 2>/dev/null || true; PIDS=()
  printf '\n%s  (Claude Code exit %s) said:\n' "$1" "$status"; sed 's/^/    | /' "$dir/claude.out"
}

echo "Claude Code: $(docker run --rm --network none flowcontrol-runner claude --version)"

run_case blocked policy/default.toml "$OUT/one_write.json"
D="$OUT/blocked"
check "Claude Code exited normally" grep -qx 0 "$D/exit"
check "protected file was never written" test ! -e "$D/ws/$PROTECTED"
check "Claude Code showed the gateway's notice" grep -q "FlowControl gateway\] Blocked Write" "$D/claude.out"
check "gateway logged the block" grep -q "BLOCKED Write" "$D/gateway.log"
check "decision event: protected_config" grep -q '"rule": "protected_config"' "$D/events.jsonl"

run_case no_gate "$OUT/empty.toml" "$OUT/one_write.json"
D="$OUT/no_gate"
check "without the rule, the same call DOES write the file" test -e "$D/ws/$PROTECTED"

run_case mixed policy/default.toml "$OUT/mixed.json"
D="$OUT/mixed"
check "Claude Code exited normally" grep -qx 0 "$D/exit"
check "allowed Bash call ran" test -e "$D/ws/allowed.txt"
check "blocked Write didn't" test ! -e "$D/ws/$PROTECTED"
check "conversation continued to the model's last answer" grep -q "done\." "$D/claude.out"
check "what Claude Code sent back is consistent (notice kept, blocked call absent, one tool result)" \
  python3 -I - "$D/requests.jsonl" <<'PY'
import json, sys
reqs = [json.loads(l)["body"] for l in open(sys.argv[1]) if l.strip()]
follow = [b for b in reqs if b.get("tools") and any(
    isinstance(m.get("content"), list) and any(c.get("type") == "tool_result" for c in m["content"])
    for m in b.get("messages", []))]
assert follow, "no follow-up request with a tool result"
msgs = follow[-1]["messages"]
assistant = [m for m in msgs if m["role"] == "assistant"][-1]["content"]
text = " ".join(c.get("text", "") for c in assistant if c.get("type") == "text")
tool_ids = [c["id"] for c in assistant if c.get("type") == "tool_use"]
results = [c["tool_use_id"] for c in msgs[-1]["content"] if c.get("type") == "tool_result"]
assert "[FlowControl gateway] Blocked Write" in text, text
assert tool_ids == ["toolu_fake0"], tool_ids
assert results == ["toolu_fake0"], results
PY

echo
if [ "$fails" -eq 0 ]; then echo "claude_gate: PASS"; else echo "claude_gate: FAIL ($fails)  logs: $OUT"; fi
[ "$fails" -eq 0 ]
