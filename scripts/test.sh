#!/bin/bash
# Build the libraries and run the self-contained tests and the conformance corpus.
# Root, Go and LLVM are not needed. The corpus comes from third_party/bpf-mlir.
#
#   git submodule update --init third_party/libbpf third_party/elfutils third_party/zlib third_party/bpf-mlir
#   scripts/test.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ -d "$HERE/third_party/bpf-mlir/conformance/requirements" ] || {
  echo "test: third_party/bpf-mlir is not checked out (git submodule update --init third_party/bpf-mlir)" >&2; exit 1; }
[ -f "$HERE/build/libs/lib/libbml.a" ] || "$HERE/scripts/build-libs.sh" "$HERE/build/libs"
"$HERE/scripts/libbpf-pin.sh" --check
"$HERE/scripts/build-tools.sh"
for t in netkit_finish_unit own_ids_unit live_target_rows_unit kernel_values_unit json_test; do
  "$HERE/build/tools/$t" > /dev/null
  echo "unit $t: ok"
done
# sentinel_unit takes Go's texts for errno 0 and 1. With no Go here they come from the committed table of Go's texts
# (src/util/go_errno.tsv; a number not in it is "errno N", as in Go). It prints one line per case and always exits 0:
# all 10 lines must end in "ok".
go1=$(awk -F'\t' '$1 == "1" { print $2 }' "$HERE/src/util/go_errno.tsv")
go0=$(awk -F'\t' '$1 == "0" { print $2 }' "$HERE/src/util/go_errno.tsv"); go0=${go0:-errno 0}
s=$("$HERE/build/tools/sentinel_unit" "$go0" "$go1")
[ "$(grep -c '	ok$' <<< "$s")" = 10 ] && [ "$(grep -c . <<< "$s")" = 10 ] ||
  { printf '%s\n' "$s" >&2; echo "unit sentinel_unit: FAIL" >&2; exit 1; }
echo "unit sentinel_unit: ok"
"$HERE/scripts/gen-errno-tables.sh" --check
for s in cases json maps parse; do
  "$HERE/scripts/corpus-$s.sh"
done
echo "test: ok"
