#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="${1:-$HERE/build/tools}"
CORPUS="$HERE/third_party/bpf-mlir/conformance/requirements/parse"
[ -x "$TOOLS/parse_case" ] || { echo "corpus-parse: $TOOLS/parse_case is missing (scripts/build-tools.sh)" >&2; exit 1; }
total=0 same=0 fail=0
for d in "$CORPUS"/*/; do
  name=$(basename "$d")
  total=$((total + 1))
  want=$(jq -c . "$d/want.json")
  got=$("$TOOLS/parse_case" "$d/requirements.txt") || { echo "FAIL $name: parse_case rc=$?"; fail=$((fail + 1)); continue; }
  if [ "$got" = "$want" ]; then
    same=$((same + 1))
  else
    echo "DIFF $name: want $want got $got"
    fail=$((fail + 1))
  fi
done
echo "parse: $same / $total same"
[ "$total" -gt 0 ] || { echo "corpus-parse: no cases" >&2; exit 1; }
[ "$fail" -eq 0 ] && [ "$same" -eq "$total" ]
