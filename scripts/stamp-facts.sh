#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/scripts/stamp-lib.sh"
bml_stamp_facts "${1:-$HERE}"
