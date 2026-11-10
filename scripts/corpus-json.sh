#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="${1:-$HERE/build/tools}"
CORPUS="$HERE/third_party/bpf-mlir/conformance/requirements/json"
[ -x "$TOOLS/json_case" ] || { echo "corpus-json: $TOOLS/json_case is missing (scripts/build-tools.sh)" >&2; exit 1; }
total=0 same=0 fail=0
for d in "$CORPUS"/*/; do
  name=$(basename "$d")
  total=$((total + 1))
  kind=$(jq -r .kind "$d/case.json")
  want=$(jq -c . "$d/want.json")
  line=$("$TOOLS/json_case" "$kind" "$d/input.json")
  res=$(cut -f2 <<< "$line"); rule=$(cut -f3 -s <<< "$line")
  if [ "$res" = ok ]; then got='{"result":"ok"}'; else got=$(jq -cn --arg r "$rule" '{"result":"invalid","rule":$r}'); fi
  if [ "$got" = "$want" ]; then same=$((same + 1)); else echo "DIFF $name ($kind): want $want got $got"; fail=$((fail + 1)); fi
done
echo "json: $same / $total same"
[ "$total" -gt 0 ] && [ "$fail" -eq 0 ] && [ "$same" -eq "$total" ]
