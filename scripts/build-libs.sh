#!/bin/bash
# scripts/build-libs.sh — builds the static libraries of the product: zlib (third_party/zlib) → libelf (third_party/elfutils,
# without zstd, bzip2, lzma and debuginfod) → libbpf (third_party/libbpf, built against that libelf's headers) → libbml.a
# (src/). The trees of the submodules are never modified.
#
#   scripts/build-libs.sh [OUT]        # the default OUT is build/libs
#
# Output: OUT/lib/{libz.a,libelf.a,libbpf.a,libbml.a,libbml_spinel.a,libbml_build.a}, OUT/include/ (the headers of zlib, libelf,
# libbpf and bml), and OUT/LICENSES and OUT/NOTICE.
# Reproducibility: the same source should give the same .a files. Paths are removed with -ffile-prefix-map, ar runs in
# deterministic mode (D), and SOURCE_DATE_EPOCH is fixed.
# Version facts: libbml.a's util_stamp.o carries the source form, commit, dirty flag and the bpf-mlir commit
# this tree pins (scripts/stamp-lib.sh), read before and after the build; a change in between stops the build.
set -euo pipefail
if [ -n "${BML_STAMP_MUT+x}" ]; then
  echo "build-libs: BML_STAMP_MUT is set (a test hook; unset it)" >&2
  exit 1
fi
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/scripts/stamp-lib.sh"
OUT="${1:-$HERE/build/libs}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
JOBS="$(nproc)"
export TMPDIR="$HERE/build/tmp"
mkdir -p "$TMPDIR"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$HERE" log -1 --format=%ct -- third_party src include shim)}"
export LC_ALL=C TZ=UTC
export ARFLAGS=crD

rm -rf "$OUT/zlib" "$OUT/elfutils" "$OUT/libbpf" "$OUT/bml" "$OUT/bml_spinel" "$OUT/bml_build" "$OUT/lib" "$OUT/include" "$OUT/log" "$OUT/stamp"
mkdir -p "$OUT/lib" "$OUT/include" "$OUT/log"

# The output of a step goes to OUT/log/<step>.log. On failure the step name and the tail of its output go to stderr and the
# build stops (it never exits silently with status 1).
step() {
  local name="$1" log="$OUT/log/$1.log"
  shift
  if ! "$@" >"$log" 2>&1; then
    echo "build-libs: step '$name' failed: $*" >&2
    echo "build-libs: last 40 lines of $log:" >&2
    tail -n 40 "$log" >&2
    exit 1
  fi
}

# The whole build (zlib → libelf → libbpf → libbml → libbml_spinel) runs inside bml_stamp_guarded.
build_body() {
# ---- zlib (third_party/zlib) ----
# Compile the library sources directly, without running configure (so zconf.h is not generated). _LARGEFILE64_SOURCE is
# defined because libbpf uses gzopen64.
Z="$OUT/zlib"
mkdir -p "$Z"
Z_CFLAGS="-O2 -g -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -ffile-prefix-map=$HERE/third_party/zlib=zlib -ffunction-sections -fdata-sections"
for s in adler32 crc32 deflate infback inffast inflate inftrees trees zutil compress uncompr gzclose gzlib gzread gzwrite; do
  gcc $Z_CFLAGS -c "$HERE/third_party/zlib/$s.c" -o "$Z/$s.o"
done
ar crD "$OUT/lib/libz.a" $(ls "$Z"/*.o | LC_ALL=C sort)
cp "$HERE/third_party/zlib/zlib.h" "$HERE/third_party/zlib/zconf.h" "$OUT/include/"

# ---- libelf (elfutils) ----
# The git tree has no libdw/known-dwarf.h (it is generated with gawk), and a configure that is not in maintainer mode
# needs it. The generating awk script is specific to gawk (it uses match with an array, and asorti). libelf and libeu do not
# use this header, which is checked after the build through the .deps files. So a placeholder containing #error is put in
# the build-side copy, and building libdw would fail loudly.
EU="$OUT/elfutils"
mkdir -p "$EU/src" "$EU/obj"
git -C "$HERE/third_party/elfutils" archive --format=tar HEAD | tar -x -C "$EU/src"
printf '#error "placeholder: libdw is not built by bpf-mlir-loader (scripts/build-libs.sh)"\n' > "$EU/src/libdw/known-dwarf.h"
# autoreconf needs autopoint (from gettext)
(cd "$EU/src" && step elfutils-autoreconf autoreconf -fi)
EU_CFLAGS="-O2 -g -ffile-prefix-map=$EU/src=elfutils -ffile-prefix-map=$EU/obj=elfutils -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections"
# zlib is the third_party/zlib built above (the system zlib headers and library are not used)
(cd "$EU/obj" && step elfutils-configure "$EU/src/configure" --quiet \
   --without-zstd --without-bzlib --without-lzma \
   --disable-debuginfod --disable-libdebuginfod --disable-nls --disable-demangler \
   --disable-textrelcheck --disable-symbol-versioning \
   CFLAGS="$EU_CFLAGS" CPPFLAGS="-I$OUT/include" LDFLAGS="-L$OUT/lib")
step elfutils-libeu make -C "$EU/obj/lib" -j"$JOBS" libeu.a
step elfutils-libelf make -C "$EU/obj/libelf" -j"$JOBS" libelf.a
if grep -rl known-dwarf "$EU/obj/lib/.deps" "$EU/obj/libelf/.deps" >/dev/null 2>&1; then
  echo "build-libs: libelf / libeu included known-dwarf.h (the placeholder)" >&2; exit 1
fi
if grep -rlE "/usr/include/(zlib|zconf)\.h" "$EU/obj/libelf/.deps" >/dev/null 2>&1; then
  echo "build-libs: libelf included the system zlib headers" >&2; exit 1
fi
cp "$EU/obj/libelf/libelf.a" "$OUT/lib/"
cp "$EU/src/libelf/libelf.h" "$EU/src/libelf/gelf.h" "$EU/src/libelf/nlist.h" "$EU/src/libelf/elf.h" "$OUT/include/"

# ---- libbpf ----
LB="$OUT/libbpf"
mkdir -p "$LB/obj"
step libbpf make -C "$HERE/third_party/libbpf/src" -j"$JOBS" BUILD_STATIC_ONLY=y NO_PKG_CONFIG=1 \
  EXTRA_CFLAGS="-I$OUT/include -ffile-prefix-map=$HERE/third_party/libbpf=libbpf -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections" \
  ARFLAGS=rcsD OBJDIR="$LB/obj" DESTDIR="$LB" PREFIX= LIBDIR=/lib INCLUDEDIR=/include install
cp "$LB/lib/libbpf.a" "$OUT/lib/"
cp -r "$LB/include/bpf" "$OUT/include/"
if [ -n "$(git -C "$HERE/third_party/libbpf" status --porcelain)" ]; then
  echo "build-libs: third_party/libbpf has uncommitted changes after the build" >&2; exit 1
fi

# ---- libbml ----
B="$OUT/bml"
mkdir -p "$B"
# With -ffile-prefix-map the later map wins, so $OUT (which is inside $HERE) comes last. This matters for the include
# directory recorded in the debug information of objects that include libelf's elf.h.
BML_CFLAGS="-O2 -g -std=gnu11 -Wall -Wextra -Werror -ffile-prefix-map=$HERE=bml -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections -I$HERE/src -I$HERE/include -I$HERE/third_party/libbpf/include/uapi -I$OUT/include -I$OUT/stamp"
rm -f "$B"/*.o
# Every .c file of the layer directories of src (util, json, elf, btf, req, caps, maps, ...). The object name is derived
# from the path, so two layers can have a file of the same name without a collision.
for c in $("$HERE/scripts/srcs.sh" src); do
  obj=$(printf '%s' "${c#"$HERE"/src/}" | tr / _)
  gcc $BML_CFLAGS -c "$c" -o "$B/${obj%.c}.o"
done
ar crD "$OUT/lib/libbml.a" $(ls "$B"/*.o | LC_ALL=C sort)
cp -r "$HERE/include/bml" "$OUT/include/"
rm -f "$OUT/include/bml/bml_testonly.h" # the test-only interface exists only in test builds, not in the product library, so its header is not shipped either

# ---- libbml_spinel (the C ABI shim of spinel-bpf-mlir's spinelbpf_* functions; a separate archive that is linked together with libbml.a) ----
S="$OUT/bml_spinel"
rm -rf "$S"; mkdir -p "$S"
for c in $(find "$HERE/shim/spinel" -name '*.c' | LC_ALL=C sort); do
  gcc $BML_CFLAGS -I"$HERE" -c "$c" -o "$S/spinel_$(basename "${c%.c}").o"
done
ar crD "$OUT/lib/libbml_spinel.a" $(ls "$S"/*.o | LC_ALL=C sort)
cp "$HERE/shim/spinel/spinelbpf.h" "$OUT/include/bml/"

# ---- libbml_build (the build-time exports bml_build_*, include/bml/build.h; linked together with libbml.a) ----
S="$OUT/bml_build"
rm -rf "$S"; mkdir -p "$S"
for c in $(find "$HERE/shim/build" -name '*.c' | LC_ALL=C sort); do
  gcc $BML_CFLAGS -I"$HERE" -c "$c" -o "$S/build_$(basename "${c%.c}").o"
done
ar crD "$OUT/lib/libbml_build.a" $(ls "$S"/*.o | LC_ALL=C sort)
cp "$HERE/shim/build/build.h" "$OUT/include/bml/"

if [ -n "$(git -C "$HERE/third_party/elfutils" status --porcelain)$(git -C "$HERE/third_party/zlib" status --porcelain)" ]; then
  echo "build-libs: third_party/elfutils or zlib has uncommitted changes after the build" >&2; exit 1
fi
}
bml_stamp_guarded "$HERE" "$OUT/stamp" build_body

# ---- License texts and NOTICE (generated every time from the pinned sources, so they never disagree with the versions) ----
# Whether to distribute, and which license to choose, is the user's decision. This only collects the texts of the components
# that are statically linked into downstream executables.
L="$OUT/LICENSES"
rm -rf "$L"
mkdir -p "$L"
cp "$HERE/third_party/libbpf/LICENSE" "$L/libbpf.LICENSE"
cp "$HERE/third_party/libbpf/LICENSE.BSD-2-Clause" "$L/libbpf.BSD-2-Clause"
cp "$HERE/third_party/libbpf/LICENSE.LGPL-2.1" "$L/libbpf.LGPL-2.1"
cp "$HERE/third_party/elfutils/COPYING-LGPLV3" "$L/elfutils-libelf.LGPL-3.0"
cp "$HERE/third_party/elfutils/COPYING-GPLV2" "$L/elfutils-libelf.GPL-2.0"
cp "$HERE/third_party/elfutils/COPYING" "$L/elfutils-libelf.GPL-3.0"
cp "$HERE/third_party/zlib/LICENSE" "$L/zlib.LICENSE"
ZH="$HERE/third_party/zlib/zlib.h"
eu_ver=$(git -C "$HERE/third_party/elfutils" describe --tags --exact-match 2>/dev/null || git -C "$HERE/third_party/elfutils" rev-parse HEAD)
lb_ver=$(git -C "$HERE/third_party/libbpf" describe --tags --exact-match 2>/dev/null || git -C "$HERE/third_party/libbpf" rev-parse HEAD)
z_ver=$(sed -n 's/^#define ZLIB_VERSION "\(.*\)"/\1/p' "$ZH")
cat > "$OUT/NOTICE" <<EOF
bpf-mlir-loader — statically linked components (generated by build-libs.sh; license texts are in LICENSES/)

- libbpf $lb_ver ($(git -C "$HERE/third_party/libbpf" rev-parse HEAD)) — LGPL-2.1 OR BSD-2-Clause
  (recommended: choose BSD-2-Clause — show LICENSES/libbpf.BSD-2-Clause in the documentation of distributed binaries)
- elfutils libelf $eu_ver ($(git -C "$HERE/third_party/elfutils" rev-parse HEAD)) — GPL-2.0-or-later OR LGPL-3.0-or-later
  (choosing LGPL-3.0 with static linking requires giving recipients a way to replace libelf and relink — the executable's object files or source, plus instructions)
  build: --without-zstd --without-bzlib --without-lzma --disable-debuginfod --disable-libdebuginfod --disable-nls
- zlib $z_ver ($(git -C "$HERE/third_party/zlib" rev-parse HEAD)) — zlib license
- bpf-mlir-loader itself — Apache-2.0 WITH LLVM-exception
EOF
ls -l "$OUT/lib" | awk 'NR>1{print $5, $9}'
