#!/bin/bash
# scripts/corpus-parse.sh — runs the parse cases of the conformance corpus through the C implementation and compares the
# result with want.json.
#
#   scripts/corpus-parse.sh [TOOLS_DIR]     # default build/tools (scripts/build-tools.sh)
#
# The number of cases is checked too: the number of cases and the number of comparisons must be equal and not zero (a
# comparison of zero cases would pass diff).
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
