#!/usr/bin/env bash
# T00: can code in the runner reach anything except through the gateway? Does it fail closed?
# Usage: tests/t00/run.sh      (from anywhere; needs Docker running; no real API key needed)
# Writes a report to tests/t00/reports/ and exits non-zero if any check fails.
set -euo pipefail
cd "$(dirname "$0")/../.."
T00=tests/t00
OUT="$(mktemp -d)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAND="$(openssl rand -hex 4)"
RUNNER_MARKER="fct00r${RAND}"
CONTROL_MARKER="fct00c${RAND}"
HOST_SINK_PORT=18999

# T00 never needs a real key: "reached" means Anthropic answered (a 401 for this fake key).
export ANTHROPIC_API_KEY="sk-ant-t00-fake-key"
export FC_SESSION_TOKEN="$(openssl rand -hex 16)"
export FC_LIVE_HOST_PORT="${FC_LIVE_HOST_PORT:-18080}"

say() { printf '\033[2m[t00]\033[0m %s\n' "$*"; }
HOST_SINK_PID=""
cleanup() {
  docker rm -f fc-t00-sniffer fc-t00-sink >/dev/null 2>&1 || true
  [ -n "$HOST_SINK_PID" ] && kill "$HOST_SINK_PID" 2>/dev/null || true
  docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() {  # wait_for FILE PATTERN
  for _ in $(seq 1 50); do grep -q "$2" "$1" 2>/dev/null && return 0; perl -e 'select(undef,undef,undef,0.2)'; done
  echo "timed out waiting for '$2' in $1" >&2; return 1
}

probe() {  # probe NAME MARKER_FILE -- docker command prefix...
  local name="$1" marker_file="$2"; shift 3
  "$@" python3 /t00/probes.py "$marker_file" "host.docker.internal:${HOST_SINK_PORT}" "${EGRESS_IP}:9999" > "$OUT/$name.jsonl"
}

# Markers go in files, never on a command line: command lines travel over the Docker API,
# and the sniffer would see that traffic too.
printf '%s' "$RUNNER_MARKER" > "$OUT/runner_marker"
printf '%s' "$CONTROL_MARKER" > "$OUT/control_marker"

say "building and starting the gateway"
docker compose up -d --wait --build gateway >/dev/null 2>&1
docker compose build -q runner >/dev/null 2>&1
AGENT_NET_ID="$(docker network inspect -f '{{.Id}}' flowcontrol_agent-net)"

say "starting independent observers (sinks + sniffer)"
python3 -I "$T00/sink.py" 127.0.0.1 "$HOST_SINK_PORT" "$OUT/host_sink.log" >/dev/null 2>&1 &
HOST_SINK_PID=$!
docker run -d --name fc-t00-sink --network flowcontrol_egress --user 0 \
  -v "$PWD/$T00:/t00:ro" -v "$OUT:/out" flowcontrol-gateway python3 -I /t00/sink.py 0.0.0.0 9999 /out/egress_sink.log >/dev/null
docker run -d --name fc-t00-sniffer --net=host --cap-add NET_RAW --user 0 \
  -v "$PWD/$T00:/t00:ro" -v "$OUT:/out" flowcontrol-gateway python3 -I /t00/sniff.py /out/sniff.log /out/runner_marker /out/control_marker >/dev/null
EGRESS_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "flowcontrol_egress").IPAddress}}' fc-t00-sink)"
wait_for "$OUT/sniff.log" ready
wait_for "$OUT/egress_sink.log" "" || true

RUNNER=(docker compose run --rm --no-deps -T -v "$PWD/$T00:/t00:ro" -v "$OUT:/out:ro" runner)
CONTROL=(docker run --rm --network flowcontrol_egress -v "$PWD/$T00:/t00:ro" -v "$OUT:/out:ro" --entrypoint "" flowcontrol-runner)

say "probing from inside the runner"
probe runner /out/runner_marker -- "${RUNNER[@]}" 2>/dev/null
say "probing from a control container with a normal network"
probe control /out/control_marker -- "${CONTROL[@]}" 2>/dev/null

say "stopping the gateway: everything must fail"
docker stop flowcontrol-gateway-1 >/dev/null
probe down /out/runner_marker -- "${RUNNER[@]}" 2>/dev/null
start=$(date +%s)
set +e
claude_out="$(timeout 90 "${RUNNER[@]}" claude -p "say hi" < /dev/null 2>&1 | grep -v -E '^ ?Container ')"
claude_exit=$?
set -e
python3 -I -c 'import json,sys; print(json.dumps({"exit": int(sys.argv[1]), "seconds": int(sys.argv[2]), "output": sys.argv[3]}))' \
  "$claude_exit" "$(( $(date +%s) - start ))" "$claude_out" > "$OUT/claude_down.json"

say "restarting the gateway: the model route must work again"
docker start flowcontrol-gateway-1 >/dev/null
docker compose up -d --wait gateway >/dev/null 2>&1
probe recovered /out/runner_marker -- "${RUNNER[@]}" 2>/dev/null
perl -e 'select(undef,undef,undef,1.0)'  # let the sniffer flush

python3 -I - "$OUT" "$RUNNER_MARKER" "$CONTROL_MARKER" "$AGENT_NET_ID" "$STAMP" <<'PY'
import json, subprocess, sys, hashlib
out, rm, cm, net, stamp = sys.argv[1:6]
sh = lambda *a: subprocess.run(a, capture_output=True, text=True).stdout.strip()
cfg = {
  "started_utc": stamp, "runner_marker": rm, "control_marker": cm, "agent_bridge": "br-" + net[:12],
  "docker_version": sh("docker", "version", "-f", "{{.Server.Version}}"),
  "claude_version": sh("docker", "run", "--rm", "--network", "none", "flowcontrol-runner", "claude", "--version"),
  "runner_image": sh("docker", "image", "inspect", "-f", "{{.Id}}", "flowcontrol-runner"),
  "gateway_image": sh("docker", "image", "inspect", "-f", "{{.Id}}", "flowcontrol-gateway"),
  "compose_sha256": hashlib.sha256(sh("docker", "compose", "config").encode()).hexdigest(),
}
open(f"{out}/config.json", "w").write(json.dumps(cfg))
PY

python3 -I "$T00/report.py" "$OUT" "$T00/reports/t00-${STAMP}.md"
