#!/usr/bin/env bash
# Run every acceptance test (threat model §7) one after another, then the unit tests, and print
# one line per test. Each harness starts and stops its own containers, so they can't run in
# parallel. Needs Docker running and outbound internet (T00, T11, egress). No real key needed.
#
# Usage: tests/run-all.sh [t00 t01 ...]     (default: all; ~6 min)
cd "$(dirname "$0")/.."
TESTS=("$@"); [ ${#TESTS[@]} -eq 0 ] && TESTS=(t00 t01 t02 t03 t05 t06 t07 t08 t11)
results=(); failed=0
for t in "${TESTS[@]}"; do
  printf '\n\033[1m== %s ==\033[0m\n' "$t"
  start=$(date +%s)
  if bash "tests/$t/run.sh"; then r=PASS; else r=FAIL; failed=$((failed+1)); fi
  results+=("$(printf '%-4s %s  (%ss)' "$t" "$r" $(( $(date +%s) - start )))")
done
printf '\n\033[1m== unit tests ==\033[0m\n'
if python3 -m unittest discover -t . -s tests 2>&1 | tail -3; then :; fi
python3 -m unittest discover -t . -s tests >/dev/null 2>&1 && unit=PASS || { unit=FAIL; failed=$((failed+1)); }

printf '\n\033[1mSummary\033[0m\n'
printf '  %s\n' "${results[@]}"
printf '  unit %s\n' "$unit"
[ "$failed" -eq 0 ]
