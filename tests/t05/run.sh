#!/usr/bin/env bash
# T05: an approval binds to the exact action. A scripted model proposes two "ask" actions (deploy
# to staging, then production). A dashboard client tries every misuse it can: a wrong digest, a
# replay of an answered approval, and approval 1's digest retargeted at approval 2. Only the honest
# answer may take effect; approval 2, never answered properly, must time out and be denied.
#
# Usage: tests/t05/run.sh     (needs Docker running; no real key; ~40s). Report in reports/.
set -euo pipefail
cd "$(dirname "$0")/../.."
T=t05; FC_MODEL_PORT=19205
source tests/lib/harness.sh
export FC_APPROVAL_TIMEOUT=6

{ cat policy/default.toml; cat <<'TOML'

[[rules]]
id = "t05_deploy_ask"
tools = ["Bash"]
commands = ['t05-deploying']
verdict = "ask"
reason = "Deploys need a human OK."
TOML
} > "$FC_OUT/policy.toml"

fc_use_model
say "starting the gateway (default policy + an ask rule for deploys; approvals time out after ${FC_APPROVAL_TIMEOUT}s)"
fc_setup "$FC_OUT/policy.toml"
fc_model "$FC_TDIR/script.json"

say "starting the dashboard client"
PYTHONPATH="$PWD" python3 "$FC_TDIR/dashboard.py" 127.0.0.1 "$FC_LIVE_HOST_PORT" >"$FC_OUT/dashboard.out" 2>&1 &
DASH=$!; sleep 1

say "running the agent: release to staging, then production"
fc_agent "Do the release." >"$FC_OUT/agent.out"
wait "$DASH" 2>/dev/null || true
sleep 1

EV="$(fc_events)"; LOG="$(fc_gateway_log)"
res() { python3 - "$EV" "$1" <<'PY'
import json, sys
evs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
reqs = {e["data"]["target_event"]: e["data"]["summary"] for e in evs if e["type"] == "approval_request"}
for e in evs:
    if e["type"] == "approval_result" and sys.argv[2] in reqs.get(e["data"]["target_event"], ""):
        print(e["data"]["result"], e["data"].get("by")); break
PY
}
staging="$(res staging)"; production="$(res production)"
ignored=$(printf '%s\n' "$LOG" | grep -c "approve ignored: no matching open approval" || true)
ran_staging=$(grep -c "t05-deploying-staging" "$FC_OUT/model.log" || true)
ran_prod=$(python3 -c "import json,sys; print(sum('t05-deploying-production' in r and 'Approval' not in r for l in open(sys.argv[1]) for r in json.loads(l)['results']))" "$FC_OUT/model.log")

echo
say "dashboard: $(tr '\n' ' ' < "$FC_OUT/dashboard.out")"
check "staging was approved, by the honest answer"                         "[[ \"$staging\" == 'approved t05@dashboard' ]]"
check "the wrong digest, the replay and the retargeted digest were ignored (4 refusals)" "[ $ignored -ge 4 ]"
check "production timed out (no valid answer) and was denied"              "[[ \"$production\" == timeout* ]]"
check "the staging command ran (its output went back to the model)"        "[ $ran_staging -ge 1 ]"
check "the production command never ran"                                    "[ $ran_prod -eq 0 ]"

REPORT="$(fc_report_path)"
{
  echo "# T05 — approvals bound to the exact action"
  echo
  echo "Run: $FC_STAMP · result: **$([ $fail -eq 0 ] && echo PASS || echo FAIL)**"
  echo
  echo "Scripted model, real Claude Code, real gateway. The dashboard client tried to misuse approvals."
  echo
  echo "- Staging approval: \`${staging:-none}\`"
  echo "- Production approval: \`${production:-none}\`"
  echo "- Misused answers the gateway ignored: $ignored (expected 4: wrong digest, replay after close, replay on approval 2, approval 1's digest retargeted)"
  echo "- Production command output seen by the model: $ran_prod"
  echo
  echo "## Dashboard client"
  echo '```'; cat "$FC_OUT/dashboard.out"; echo '```'
  echo
  echo "## Gateway log"
  echo '```'
  printf '%s\n' "$LOG" | grep -E "ASK|APPROVED|DENIED|ignored" | sed -E 's/^\[[0-9:]+\] //'
  echo '```'
} > "$REPORT"
say "report: $REPORT"
fc_finish
