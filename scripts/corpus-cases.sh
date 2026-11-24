#!/bin/bash
# scripts/corpus-cases.sh — runs the cases of the conformance corpus through the C check (against recorded caps) and compares
# the result with want.json.
#
#   scripts/corpus-cases.sh [TOOLS_DIR]     # default build/tools
#
# The number of cases is checked too. A case in the PENDING table is one for which part of the check is not yet in C (the
# reason is named); its differences are counted and reported separately, and a difference outside the table is a failure.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="${1:-$HERE/build/tools}"
CORPUS="$HERE/third_party/bpf-mlir/conformance/requirements/cases"
[ -x "$TOOLS/check_case" ] || { echo "corpus-cases: $TOOLS/check_case is missing (scripts/build-tools.sh)" >&2; exit 1; }
# The table of cases that are known not to match yet, as case name: reason. (The uprobe DWARF reading, which was the last
# such gap, has been implemented.)
declare -A PENDING=(
  # (empty: the 6 uprobe DWARF cases were closed when the DWARF reading was implemented)
)
total=0 same=0 fail=0 pending=0
for d in "$CORPUS"/*/; do
  name=$(basename "$d")
  total=$((total + 1))
  want=$(jq -c . "$d/want.json")
  got=$("$TOOLS/check_case" "$d" | jq -c .) || { echo "FAIL $name: check_case rc"; fail=$((fail + 1)); continue; }
  if [ "$got" = "$want" ]; then
    same=$((same + 1))
    [ -z "${PENDING[$name]:-}" ] || echo "note: $name is in the PENDING table but matched (review the table)"
  elif [ -n "${PENDING[$name]:-}" ]; then
    # Check the direction of the difference. C may only be stricter: the result must be target_rejected; the only Unmet kind
    # that C has and want does not may be the blocking uprobearg_unknown; and the only Unmet kinds that want has and C does
    # not may be uprobearg, uprobearg_abi and uprobearg_abi_unknown (the checks that need DWARF, including the check of the
    # target's source language that decision-policy version 4 added). A looser direction (C accepts, or C reports a
    # non-blocking Unknown) is a failure.
    dir_ok=$(jq -n --argjson w "$want" --argjson g "$got" '
      ($g.result == "target_rejected")
      and ([$g.unmet[] | select(. as $u | ($w.unmet | index([$u])) == null)] | all(.kind == "uprobearg_unknown" and .blocks_load))
      and ([$w.unmet[] | select(. as $u | ($g.unmet | index([$u])) == null)] | all(.kind == "uprobearg" or .kind == "uprobearg_abi" or .kind == "uprobearg_abi_unknown"))')
    if [ "$dir_ok" != true ]; then
      echo "DIFF $name: the PENDING difference is not on the stopping side (${PENDING[$name]}): want $want got $got"
      fail=$((fail + 1))
      continue
    fi
    echo "PENDING $name (${PENDING[$name]}; C is on the stopping side): want $(jq -r .result <<< "$want") got $(jq -r .result <<< "$got")"
    pending=$((pending + 1))
  else
    echo "DIFF $name: want $want"
    echo "          got  $got"
    fail=$((fail + 1))
  fi
done
echo "cases: $same / $total same, pending $pending, fail $fail"
[ "$total" -gt 0 ] || { echo "corpus-cases: no cases" >&2; exit 1; }
[ "$fail" -eq 0 ] && [ $((same + pending)) -eq "$total" ]
