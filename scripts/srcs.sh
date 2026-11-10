#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-}" in
src) find "$HERE/src" -name '*.c' | LC_ALL=C sort ;;
cmd) find "$HERE/cmd/$2" -name '*.c' | LC_ALL=C sort ;;
test)
  m=$(find "$HERE/test" -path "$HERE/test/oracle" -prune -o -name "$2.c" -print)
  [ "$(printf '%s\n' "$m" | grep -c .)" = 1 ] || { echo "srcs: test/*/$2.c is not exactly one file: $m" >&2; exit 1; }
  echo "$m" ;;
*) echo "srcs: src | cmd <name> | test <name>" >&2; exit 2 ;;
esac
