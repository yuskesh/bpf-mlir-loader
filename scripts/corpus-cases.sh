#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="${1:-$HERE/build/tools}"
CORPUS="$HERE/third_party/bpf-mlir/conformance/requirements/cases"
[ -x "$TOOLS/check_case" ] || { echo "corpus-cases: $TOOLS/check_case is missing (scripts/build-tools.sh)" >&2; exit 1; }
declare -A PENDING=(
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
