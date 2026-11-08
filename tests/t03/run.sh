#!/usr/bin/env bash
# T03: config the agent must not change is read-only at the OS level. A script tries to modify
# it through alternate tools, path tricks and replacement; the OS denies every one, and the
# protected bytes are unchanged. Legitimate work still succeeds. Also checks the launcher
# refuses a workspace that would expose the FlowControl project itself.
#
# Usage: tests/t03/run.sh     (needs Docker running; no API key; ~20s)
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"
T03=tests/t03
OUT="$(mktemp -d)"
WS="$OUT/ws"

# The protected paths, mirroring the launcher (flowcontrol: PROTECTED_DIRS / PROTECTED_FILES).
PROTECTED_DIRS=(.claude .github/workflows)
GUARD='{"guard":"ORIGINAL"}'

fails=0
ok()   { printf '  pass  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
same() { [ "$(cat "$2" 2>/dev/null || true)" = "$3" ] && ok "$1" || bad "$1 (changed to: $(cat "$2" 2>/dev/null))"; }
gone() { [ ! -e "$2" ] && ok "$1" || bad "$1 ($2 exists)"; }
have() { [ -e "$2" ] && ok "$1" || bad "$1 ($2 missing)"; }

docker image inspect flowcontrol-runner >/dev/null 2>&1 || docker build -q -t flowcontrol-runner runner >/dev/null

# A workspace that is a git repo and has a top-level CLAUDE.md, so every protected kind is covered.
mkdir -p "$WS/.claude" "$WS/.github/workflows" "$WS/.git/hooks"
printf '%s' "$GUARD" > "$WS/.claude/settings.json"
printf 'ORIGINAL' > "$WS/.git/hooks/pre-commit"
printf 'ORIGINAL' > "$WS/.git/config"
printf 'ORIGINAL' > "$WS/CLAUDE.md"

# The read-only mounts the launcher would add for this workspace.
RO=(-v "$WS/.claude:/workspace/.claude:ro"
    -v "$WS/.github/workflows:/workspace/.github/workflows:ro"
    -v "$WS/CLAUDE.md:/workspace/CLAUDE.md:ro"
    -v "$WS/.git/hooks:/workspace/.git/hooks:ro"
    -v "$WS/.git/config:/workspace/.git/config:ro")

echo "runner: $(docker run --rm --network none flowcontrol-runner claude --version)"
echo
echo "Attacker script inside the runner (every line should fail):"
docker run --rm --user 1000:1000 --network none \
  -v "$WS:/workspace" "${RO[@]}" \
  -v "$PWD/$T03:/t03:ro" \
  --entrypoint "" flowcontrol-runner sh /t03/attack.sh | sed 's/^/  | /'

echo
echo "Checks:"
same "protected .claude/settings.json unchanged"   "$WS/.claude/settings.json" "$GUARD"
same ".git/hooks/pre-commit unchanged"             "$WS/.git/hooks/pre-commit" "ORIGINAL"
same ".git/config unchanged"                       "$WS/.git/config"           "ORIGINAL"
same "CLAUDE.md unchanged"                          "$WS/CLAUDE.md"             "ORIGINAL"
gone "no evil.json created in .claude"             "$WS/.claude/evil.json"
gone "no CI workflow created"                       "$WS/.github/workflows/ci.yml"
gone "protected dir not renamed away"              "$WS/.claude.bak"
have "the protected dir still exists"              "$WS/.claude"
have "legitimate src/app.py was written"           "$WS/src/app.py"
[ "$(cat "$WS/src/app.py" 2>/dev/null || true)" = "ok" ] && ok "src/app.py has the right content" \
  || bad "src/app.py content wrong"

# The launcher must refuse a workspace that contains the FlowControl project (the agent could
# otherwise rewrite the policy). preflight runs first, so give it a satisfiable environment;
# the refusal must come before any gateway container starts.
echo
echo "Launcher refuses an unsafe workspace:"
set +e
msg="$(FC_WORKSPACE="$REPO" ANTHROPIC_API_KEY="sk-ant-t03-dummy" FC_LIVE_HOST_PORT=18083 \
  ./flowcontrol run -p hi 2>&1)"
code=$?
set -e
if [ "$code" -ne 0 ] && printf '%s' "$msg" | grep -q "contains the FlowControl project"; then
  ok "workspace = project root is refused"
else
  bad "workspace = project root was NOT refused (exit $code): $msg"
fi
if docker ps -a --filter "name=^flowcontrol-gateway-1$" -q | grep -q .; then
  bad "a gateway container was started despite the refusal"; docker rm -f flowcontrol-gateway-1 >/dev/null 2>&1 || true
else
  ok "no gateway container was started"
fi

echo
if [ "$fails" -eq 0 ]; then echo "T03: PASS"; else echo "T03: FAIL ($fails)  workspace kept at: $WS"; fi
[ "$fails" -eq 0 ]
