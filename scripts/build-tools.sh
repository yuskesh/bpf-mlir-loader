#!/bin/bash
# Build bml-precheck and the self-contained tests against build/libs.
#
#   scripts/build-tools.sh
#
# Run scripts/build-libs.sh first. The output goes to build/tools.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
L="$HERE/build/libs"
OUT="$HERE/build/tools"
export TMPDIR="$HERE/build/tmp"
mkdir -p "$TMPDIR" "$OUT"
[ -f "$L/lib/libbml.a" ] || { echo "build-tools: $L/lib/libbml.a is missing (run scripts/build-libs.sh)" >&2; exit 1; }
CC=(gcc -O2 -g -std=gnu11 -Wall -Wextra -Werror -I"$HERE/src" -I"$HERE/cmd" -I"$L/include")
LIB=("$L/lib/libbml.a" "$L/lib/libbpf.a" "$L/lib/libelf.a" "$L/lib/libz.a")
for t in netkit_finish_unit own_ids_unit live_target_rows_unit kernel_values_unit json_test parse_case check_case json_case maps_case; do
  "${CC[@]}" -o "$OUT/$t" "$("$HERE/scripts/srcs.sh" test "$t")" "${LIB[@]}"
done
# shellcheck disable=SC2046
"${CC[@]}" -o "$OUT/bml-precheck" $("$HERE/scripts/srcs.sh" cmd bml-precheck) "${LIB[@]}"
echo "$OUT"
