#!/bin/sh
# Runs inside the runner as the agent's user. Every write below targets a protected path and
# must be refused by the OS (the paths are read-only mounts). This script always exits 0; the
# host side (run.sh) decides pass/fail by checking the files afterward. The last step is
# ordinary work in a writable folder and must succeed.
set +e
try() { desc="$1"; shift; "$@" >/dev/null 2>&1; printf '  exit=%s  %s\n' "$?" "$desc"; }

# --- alternate tools writing the same protected file (gateway rule only covers Write/Edit) ---
try "cat > overwrite .claude/settings.json"   sh -c 'cat > /workspace/.claude/settings.json <<E
{"guard":"HACKED"}
E'
try "tee new file in .claude"                 sh -c 'echo x | tee /workspace/.claude/evil.json'
try "python open(w) .claude/settings.json"    python3 -c 'open("/workspace/.claude/settings.json","w").write("HACKED")'
try "sed -i in place"                         sed -i 's/ORIGINAL/HACKED/' /workspace/.claude/settings.json
try "append >>"                               sh -c 'echo HACKED >> /workspace/.claude/settings.json'
try "create CI workflow via cat"              sh -c 'mkdir -p /workspace/.github/workflows && cat > /workspace/.github/workflows/ci.yml <<E
on: push
E'
try "write git hook"                          sh -c 'echo evil > /workspace/.git/hooks/pre-commit'
try "append git config"                       sh -c 'echo "[evil]" >> /workspace/.git/config'

# --- replacement / rename, from the writable workspace root (threat model: file replacement) ---
try "rm the protected file"                   rm -f /workspace/.claude/settings.json
try "rm -rf the protected dir"                rm -rf /workspace/.claude
try "mv the protected dir aside"              mv /workspace/.claude /workspace/.claude.bak
try "replace file by mv over it"              sh -c 'echo HACKED > /tmp/x && mv /tmp/x /workspace/.claude/settings.json'
try "write through a symlink to it"           sh -c 'ln -s /workspace/.claude /workspace/link && echo HACKED > /workspace/link/settings.json'
try "climb .. back into .claude"              sh -c 'echo HACKED > /workspace/src/../.claude/settings.json'
try "rm -rf .github (holds a mountpoint)"     rm -rf /workspace/.github

# --- legitimate work must still succeed ---
try "normal write in src/"                    sh -c 'mkdir -p /workspace/src && echo ok > /workspace/src/app.py'
exit 0
