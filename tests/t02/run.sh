#!/usr/bin/env bash
# T02: an allowed host is not a blank cheque. Egress edge cases through the gateway proxy, run as
# plain commands in the runner (no agent needed: the proxy is what's under test). Two sinks on
# the egress network are the ground truth: "allowed" is on the allowlist, "other" is not.
#
#   A  allowlisted host reachable                                  -> reaches "allowed"
#   B  unknown host                                                -> denied, "other" sees nothing
#   C  redirect from the allowed host to the unknown one (curl -L) -> the hop is judged again, denied
#   D  cloud metadata address, even when the policy allowlists it  -> refused (unsafe_address)
#   E  link-local address, same                                    -> refused
#   F  data in the query string of an allowed host                 -> REACHES it. Known gap, recorded,
#                                                                     not claimed: hostname-level policy
#                                                                     can't see what a request carries.
#
# Usage: tests/t02/run.sh     (needs Docker running; no real key; ~30s). Report in reports/.
set -euo pipefail
cd "$(dirname "$0")/../.."
T=t02
source tests/lib/harness.sh
PORT=9102
FC_EXTRA_CONTAINERS="fc-t02-allowed fc-t02-other"

{ sed -E 's/^allow = \[/allow = [\n  "fc-t02-allowed", "169.254.169.254", "169.254.10.10",/' policy/default.toml; } > "$FC_OUT/policy.toml"
grep -q '"fc-t02-allowed"' "$FC_OUT/policy.toml" || { echo "could not add the test hosts to the allowlist" >&2; exit 1; }

say "starting the gateway (allowlist + the test sink + two link-local addresses on purpose)"
fc_setup "$FC_OUT/policy.toml"
for s in allowed other; do
  docker run -d --name "fc-t02-$s" --network flowcontrol_egress -v "$PWD/$FC_TDIR:/t02:ro" -v "$FC_OUT:/out" \
    flowcontrol-gateway python3 -I /t02/sink.py "$PORT" "/out/$s.log" "http://fc-t02-other:$PORT/stolen?via=redirect" >/dev/null
done
for _ in $(seq 1 40); do docker logs fc-t02-allowed 2>&1 | grep -q ready && docker logs fc-t02-other 2>&1 | grep -q ready && break; sleep 0.25; done
touch "$FC_OUT/allowed.log" "$FC_OUT/other.log"

code() { fc_runner "curl -s -o /dev/null -w '%{http_code}' --max-time 15 $1 || true" | tail -1; }
a=$(code "http://fc-t02-allowed:$PORT/hello")
b=$(code "http://fc-t02-other:$PORT/direct")
c=$(code "-L http://fc-t02-allowed:$PORT/redirect")
d=$(code "http://169.254.169.254/latest/meta-data/")
e=$(code "http://169.254.10.10/")
f=$(code "'http://fc-t02-allowed:$PORT/q?secret=T02-DATA-IN-QUERY'")
sleep 1
LOG="$(fc_gateway_log)"
other_hits=$(wc -l < "$FC_OUT/other.log" | tr -d ' ')
hello=$(grep -c '"/hello"' "$FC_OUT/allowed.log" || true)
query=$(grep -c 'T02-DATA-IN-QUERY' "$FC_OUT/allowed.log" || true)
redirect_judged=$(printf '%s\n' "$LOG" | grep -c "egress GET fc-t02-other:$PORT -> BLOCKED \[unknown_destination\]" || true)

echo
check "A: allowlisted host reached (HTTP $a, sink saw it: $hello)"                       "[ \"$a\" = 200 ] && [ $hello -ge 1 ]"
check "B: unknown host denied by the proxy (HTTP $b)"                                     "[ \"$b\" = 403 ]"
check "C: the redirect hop to the unknown host was judged again and denied (HTTP $c)"     "[ \"$c\" = 403 ] && [ $redirect_judged -ge 2 ]"
check "B+C: the unknown host received nothing ($other_hits requests)"                     "[ $other_hits -eq 0 ]"
check "D: metadata address refused although allowlisted (HTTP $d)"                        "[ \"$d\" = 403 ]"
check "E: link-local address refused although allowlisted (HTTP $e)"                      "[ \"$e\" = 403 ]"
unsafe=$(printf '%s\n' "$LOG" | grep -c "169.254" || true)

REPORT="$(fc_report_path)"
{
  echo "# T02 — allowed host, unapproved use"
  echo
  echo "Run: $FC_STAMP · result: **$([ $fail -eq 0 ] && echo PASS || echo FAIL)**"
  echo
  echo "| Case | Expected | HTTP | Ground truth |"
  echo "|---|---|---|---|"
  echo "| A · allowlisted host | reach | $a | allowed sink saw /hello: $hello |"
  echo "| B · unknown host | deny | $b | other sink requests: $other_hits |"
  echo "| C · redirect allowed → unknown | deny the hop | $c | other sink requests: $other_hits |"
  echo "| D · 169.254.169.254 (allowlisted on purpose) | deny | $d | proxy refused by address |"
  echo "| E · 169.254.10.10 (allowlisted on purpose) | deny | $e | proxy refused by address |"
  echo "| F · data in an allowed host's query | **known gap** | $f | allowed sink saw the data: $query |"
  echo
  echo "F is the documented limit of hostname-level egress (threat model §4.2, T02 \"partial\"): an"
  echo "allowed host still receives what a request carries. In a tainted session the lethal-trifecta"
  echo "lock denies even allowed hosts (T01); in a clean session, resource- and query-level rules are roadmap."
  echo
  echo "## Gateway egress decisions"
  echo '```'
  printf '%s\n' "$LOG" | grep -E "^\[.*\] egress" | sed -E 's/^\[[0-9:]+\] //'
  echo '```'
} > "$REPORT"
say "report: $REPORT"
fc_finish
