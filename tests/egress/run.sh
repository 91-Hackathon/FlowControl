#!/usr/bin/env bash
# Egress policy in the real container (M3 step 3). The runner's HTTP(S) proxy is the gateway,
# which allows or denies each destination by policy. No real key needed (the proxy doesn't use
# one); uses a FAKE key so the gateway starts in brokered mode. Makes a real call to npmjs.
#
#   A  an allowlisted host (registry.npmjs.org) is reachable through the proxy
#   B  an unknown host (example.com) is denied (the proxy 403s the CONNECT)
#   C  the model route (gateway:8787) still works with HTTP_PROXY set (NO_PROXY excludes it)
#
# Usage: tests/egress/run.sh     (needs Docker running and outbound internet; ~30s)
set -euo pipefail
cd "$(dirname "$0")/../.."
export ANTHROPIC_API_KEY="sk-ant-fake-egress-check"
export FC_SESSION_TOKEN="$(openssl rand -hex 16)"
export FC_LIVE_HOST_PORT="${FC_LIVE_HOST_PORT:-18080}"

fails=0
ok()  { printf '  pass  %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
trap 'docker compose down >/dev/null 2>&1 || true' EXIT

echo "== build + start gateway =="
docker compose up -d --wait --build gateway >/dev/null 2>&1
docker compose build -q runner >/dev/null 2>&1
docker logs flowcontrol-gateway-1 2>&1 | grep -E "^(policy|egress)" || true

run() { docker compose run --rm --no-deps -T runner sh -c "$1" 2>/dev/null; }

echo
echo "Checks:"
a=$(run 'curl -s -o /dev/null -w "%{http_code}" --max-time 25 https://registry.npmjs.org/left-pad || echo 000')
[ "$a" = "200" ] && ok "allowlisted registry.npmjs.org reachable through the proxy (200)" \
                  || bad "registry.npmjs.org returned $a (expected 200)"

code=$(run 'curl -s -o /dev/null --max-time 25 https://example.com/; echo $?')
[ "$code" != "0" ] && ok "unknown host example.com denied by the proxy (curl exit $code)" \
                   || bad "example.com was NOT denied (curl succeeded)"

m=$(run 'curl -s -o /dev/null -w "%{http_code}" --max-time 25 http://gateway:8787/v1/messages -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d "{\"model\":\"claude-haiku-5-5\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" || echo 000')
[ "$m" = "401" ] && ok "model route still works with HTTP_PROXY set (reached Anthropic: 401 on the fake key)" \
                 || bad "model route returned $m (expected 401 = reached; 000 would mean the proxy broke it)"

echo
echo "Gateway egress decisions logged:"
docker logs flowcontrol-gateway-1 2>&1 | grep -aoE "egress (CONNECT|GET|POST) [^ ]+ -> (allowed|BLOCKED) \[[a-z_]+\]" | sort -u | sed 's/^/  /' || true

echo
if [ "$fails" -eq 0 ]; then echo "egress: PASS"; else echo "egress: FAIL ($fails)"; fi
[ "$fails" -eq 0 ]
