#!/usr/bin/env bash
# T06: stop the run. A scripted model keeps the agent working (up to MAX steps). A dashboard
# client watches the live feed and, the moment the agent becomes active, sends the `stop`
# command — the dashboard button. The gateway must then deny every further request, end the
# session, and the agent must stop well before MAX. No real key.
#
# Usage: tests/t06/run.sh     (needs Docker running; ~30s). Report in reports/.
set -euo pipefail
cd "$(dirname "$0")/../.."
T06=tests/t06
OUT="$(mktemp -d)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MODEL_PORT=19166
MAX_STEPS=6

export ANTHROPIC_API_KEY="sk-ant-t06-fake-key"
export FC_SESSION_TOKEN="$(openssl rand -hex 16)"
export FC_LIVE_HOST_PORT="${FC_LIVE_HOST_PORT:-18080}"
export FC_UPSTREAM="fc-t06-model:${MODEL_PORT}" FC_UPSTREAM_SCHEME=http

say() { printf '\033[2m[t06]\033[0m %s\n' "$*"; }
DASH_PID=""
cleanup() {
  [ -n "$DASH_PID" ] && kill "$DASH_PID" 2>/dev/null || true
  docker rm -f fc-t06-model >/dev/null 2>&1 || true
  docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

export FC_WORKSPACE="$OUT/ws"; mkdir -p "$FC_WORKSPACE"

say "building and starting the gateway"
docker compose up -d --wait --build gateway >/dev/null 2>&1
docker compose build -q runner >/dev/null 2>&1

say "starting the scripted model (keeps the agent working up to $MAX_STEPS steps)"
docker run -d --name fc-t06-model --network flowcontrol_egress -v "$PWD/$T06:/t06:ro" \
  flowcontrol-gateway python3 -I /t06/fake_model.py "$MODEL_PORT" "$MAX_STEPS" >/dev/null
for _ in $(seq 1 40); do docker logs fc-t06-model 2>&1 | grep -q ready && break; sleep 0.25; done

say "starting the dashboard client: it watches the feed and sends STOP when the agent is active"
PYTHONPATH="$PWD" python3 "$T06/dashboard.py" 127.0.0.1 "$FC_LIVE_HOST_PORT" tool_call >"$OUT/dashboard.out" 2>&1 &
DASH_PID=$!
sleep 1  # let it connect before the agent starts

say "running the agent (it would do $MAX_STEPS steps if nothing stopped it)"
docker compose run --rm --no-deps -T runner claude -p "Do a long multi-step task." --dangerously-skip-permissions \
  </dev/null >"$OUT/agent.out" 2>&1 || true
sleep 1

LOG="$(docker logs flowcontrol-gateway-1 2>&1)"
steps_run=$(printf '%s\n' "$LOG" | grep -c "Bash: sleep 1; echo step" || true)
stop_seen=$(printf '%s\n' "$LOG" | grep -c "STOP from t06@dashboard" || true)
refused=$(printf '%s\n' "$LOG" | grep -c "session was stopped by the operator" || true)
# session_end is a structured event, written to events.jsonl (mounted to ./logs), not to stdout.
ended=$(grep -c '"result": "stopped"' logs/events.jsonl 2>/dev/null || true)

pass=0; fail=0
check() { if eval "$2"; then printf '    pass  %s\n' "$1"; pass=$((pass+1)); else printf '    FAIL  %s\n' "$1"; fail=$((fail+1)); fi; }
echo
say "dashboard: $(cat "$OUT/dashboard.out" | tr '\n' ' ')"
check "the dashboard sent STOP and the gateway received it"          "[ $stop_seen -ge 1 ]"
check "the run ended (session_end: stopped)"                         "[ $ended -ge 1 ]"
check "the gateway refused at least one request after the stop"      "[ $refused -ge 1 ]"
check "the agent was cut short (ran fewer than $MAX_STEPS steps)"     "[ $steps_run -lt $MAX_STEPS ]"

mkdir -p "$T06/reports"
REPORT="$T06/reports/t06-${STAMP}.md"
{
  echo "# T06 — stop the run (revocation)"
  echo
  echo "Run: $STAMP · result: **$([ $fail -eq 0 ] && echo PASS || echo FAIL)**"
  echo
  echo "A scripted model would have the agent do $MAX_STEPS steps. The dashboard client sent STOP"
  echo "the moment the agent became active (first tool_call). The gateway then denied everything."
  echo
  echo "- Steps the agent actually ran before the stop: $steps_run / $MAX_STEPS"
  echo "- Dashboard STOP received by the gateway: $stop_seen"
  echo "- Requests refused after the stop (session stopped): $refused"
  echo "- session_end (stopped) recorded: $ended"
  echo
  echo "## Gateway log around the stop"
  echo '```'
  printf '%s\n' "$LOG" | grep -E "STOP from|session was stopped|Bash: sleep|session started" | sed -E 's/^\[[0-9:]+\] //' | head -20
  echo '```'
} > "$REPORT"
say "report: $REPORT"

echo
if [ "$fail" -eq 0 ]; then echo "T06: PASS ($pass checks)"; else echo "T06: FAIL ($fail of $((pass+fail)))  logs: $OUT"; fi
[ "$fail" -eq 0 ]
