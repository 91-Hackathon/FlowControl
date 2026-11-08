# Shared helpers for the container harnesses (T02, T05, T07, T08, T11). Source it from a run.sh
# after setting T (e.g. T=t05). Needs Docker running. Uses a fake key unless a test says otherwise.
#
#   fc_setup POLICY_TOML [extra env...]   copy the policy under ./policy, set env, start the gateway
#   fc_model SCRIPT_JSON                  start the scripted model on the egress network
#   fc_agent PROMPT                       run one Claude Code turn in the runner; output on stdout
#   fc_gateway_log                        the gateway's stdout
#   fc_events                             path of a file with this run's events (JSON lines)
#   check NAME CONDITION                  print pass / FAIL and count
#   fc_finish                             print the summary line; exit status = result

FC_TDIR="tests/$T"
FC_OUT="$(mktemp -d)"
FC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FC_ACTIVE_POLICY="policy/_${T}-active.toml"   # under ./policy: the only folder mounted into the gateway
FC_MODEL_NAME="fc-${T}-model"
FC_MODEL_PORT="${FC_MODEL_PORT:-19200}"
FC_EXTRA_CONTAINERS=""
pass=0; fail=0

export ANTHROPIC_API_KEY="${FC_TEST_KEY:-sk-ant-${T}-fake-key}"
export FC_SESSION_TOKEN="$(openssl rand -hex 16)"
export FC_LIVE_HOST_PORT="${FC_LIVE_HOST_PORT:-18080}"
export FC_WORKSPACE="$FC_OUT/ws"; mkdir -p "$FC_WORKSPACE"

say() { printf '\033[2m[%s]\033[0m %s\n' "$T" "$*"; }

fc_cleanup() {
  # shellcheck disable=SC2086
  docker rm -f "$FC_MODEL_NAME" $FC_EXTRA_CONTAINERS >/dev/null 2>&1 || true
  docker compose down >/dev/null 2>&1 || true
  rm -f "$FC_ACTIVE_POLICY"
}
trap fc_cleanup EXIT

fc_setup() {  # fc_setup POLICY_TOML
  cp "$1" "$FC_ACTIVE_POLICY"
  export FC_POLICY_FILE="$FC_ACTIVE_POLICY"
  docker compose up -d --wait --build gateway >/dev/null 2>&1
  docker compose build -q runner >/dev/null 2>&1
}

fc_model() {  # fc_model SCRIPT_JSON  (the gateway must already point FC_UPSTREAM at it)
  cp "$1" "$FC_OUT/script.json"
  docker run -d --name "$FC_MODEL_NAME" --network flowcontrol_egress -v "$PWD/tests/lib:/fclib:ro" -v "$FC_OUT:/out" \
    flowcontrol-gateway python3 -I /fclib/scripted_model.py "$FC_MODEL_PORT" /out/script.json /out/model.log >/dev/null
  for _ in $(seq 1 40); do docker logs "$FC_MODEL_NAME" 2>&1 | grep -q ready && return 0; sleep 0.25; done
  echo "scripted model did not start" >&2; return 1
}

fc_use_model() {  # point the gateway at the scripted model; call BEFORE fc_setup
  export FC_UPSTREAM="${FC_MODEL_NAME}:${FC_MODEL_PORT}" FC_UPSTREAM_SCHEME=http
}

fc_agent() {  # fc_agent PROMPT
  docker compose run --rm --no-deps -T runner claude -p "$1" --dangerously-skip-permissions </dev/null 2>&1 \
    | grep -v -E '^ ?Container ' || true
}

fc_runner() {  # fc_runner SHELL_COMMAND: a plain command in the runner (no agent)
  docker compose run --rm --no-deps -T runner sh -c "$1" </dev/null 2>&1 | grep -v -E '^ ?Container ' || true
}

fc_gateway_log() { docker logs flowcontrol-gateway-1 2>&1; }
fc_events() {  # a copy of this gateway run's events (the gateway starts a fresh file on every start/restart)
  cp logs/events.jsonl "$FC_OUT/events.jsonl" 2>/dev/null || : > "$FC_OUT/events.jsonl"
  echo "$FC_OUT/events.jsonl"
}

fc_restart_gateway() {  # a clean session, same config (the events file starts over)
  docker restart flowcontrol-gateway-1 >/dev/null
  for _ in $(seq 1 40); do
    docker exec flowcontrol-gateway-1 python3 -c "import socket; socket.create_connection(('127.0.0.1',8787),1)" 2>/dev/null && return 0
    sleep 0.25
  done
  echo "gateway did not come back" >&2; return 1
}

check() {
  if eval "$2"; then printf '    pass  %s\n' "$1"; pass=$((pass+1)); else printf '    FAIL  %s\n' "$1"; fail=$((fail+1)); fi
}

fc_report_path() { mkdir -p "$FC_TDIR/reports"; echo "$FC_TDIR/reports/${T}-${FC_STAMP}.md"; }

fc_finish() {
  local name; name="$(echo "$T" | tr '[:lower:]' '[:upper:]')"
  echo
  if [ "$fail" -eq 0 ]; then echo "$name: PASS ($pass checks)"; else echo "$name: FAIL ($fail of $((pass+fail)))  logs kept: $FC_OUT"; fi
  [ "$fail" -eq 0 ]
}
