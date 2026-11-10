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
for s in cases json maps parse; do
  "$HERE/scripts/corpus-$s.sh"
done
echo "test: ok"
