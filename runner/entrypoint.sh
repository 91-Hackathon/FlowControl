#!/bin/sh
# Runner entrypoint: prepare Claude Code's state, then run the command (default: claude).
#
# The runner's home directory is temporary (wiped every run), so Claude Code would ask its
# first-run setup questions every time. Seed just enough state to skip them:
#   - onboarding done
#   - the API key it was given is approved. That "key" is the FlowControl session token,
#     not a real key: Claude Code stores the last 20 characters to remember the approval.
# Folder trust is NOT pre-accepted: Claude Code still asks once about /workspace.
set -e

if [ -n "$ANTHROPIC_API_KEY" ] && [ ! -f "$HOME/.claude.json" ]; then
  suffix=$(printf %s "$ANTHROPIC_API_KEY" | tail -c 20)
  cat > "$HOME/.claude.json" <<EOF
{"hasCompletedOnboarding": true, "customApiKeyResponses": {"approved": ["$suffix"], "rejected": []}}
EOF
fi

exec "$@"
