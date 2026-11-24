#!/bin/bash
# scripts/stamp-facts.sh — print the version facts of a bml tree (the rules are in scripts/stamp-lib.sh)
#
#   scripts/stamp-facts.sh [TREE]     # default TREE is this repository
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=stamp-lib.sh
. "$HERE/scripts/stamp-lib.sh"
bml_stamp_facts "${1:-$HERE}"
