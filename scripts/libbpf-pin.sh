#!/bin/bash
# scripts/libbpf-pin.sh — pins the hash of the libbpf sources that the load guard (src/load/) depends on. Upgrading libbpf
# makes the gate fail and forces a new audit of the guard's assumptions: how libbpf decides to sanitize and rewrites
# the object, that libbpf throws the whole BTF away when the kernel rejects it, that libbpf strips the BTF of a typed map
# (a devmap), that libbpf replaces some helper calls, the values of feat_supported and kern_feature_id, and the memlock and
# token options. The hash covers whole files, which is stricter than the ranges the guard relies on, so every libbpf
# upgrade is audited again.
#
#   scripts/libbpf-pin.sh [--check] [LIBBPF_SRC_DIR]     # default third_party/libbpf/src. --check compares with the table; without it the table is written
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TABLE="$HERE/scripts/libbpf-pin.tsv"
CHECK=0
[ "${1:-}" != "--check" ] || { CHECK=1; shift; }
SRC="${1:-$HERE/third_party/libbpf/src}"
FILES="libbpf.c features.c libbpf_internal.h bpf.c btf.c"
gen() {
  echo "# libbpf-pin.tsv — written by scripts/libbpf-pin.sh (libbpf v1.7.0 f5dcbae7). file and sha256. Guard preconditions: libbpf.c (btf_needs_sanitization, sanitize_btf, "BTF is optional", dropping map BTF, helper substitution, kernel_supports), features.c (feat_supported and the probes), libbpf_internal.h (enum kern_feature_id values, LBF_* in src/load/internal.h), bpf.c (libbpf_set_memlock_rlim, bump_rlimit_memlock), btf.c (BTF parsing and raw bytes)"
  for f in $FILES; do printf '%s\t%s\n' "$f" "$(sha256sum < "$SRC/$f" | cut -d' ' -f1)"; done
}
if [ "$CHECK" = 1 ]; then
  cmp -s <(gen) "$TABLE" || { echo "libbpf-pin: the libbpf source the guard depends on differs from the pinned table ($SRC); re-audit the guard preconditions and rewrite the table" >&2; diff <(gen) "$TABLE" >&2 || true; exit 1; }
  echo "ok: the libbpf source matches the pinned table ($(echo $FILES | wc -w) files)"
else
  gen > "$TABLE"
fi
