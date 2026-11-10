#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HERE/build/libs}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
JOBS="$(nproc)"
export TMPDIR="$HERE/build/tmp"
mkdir -p "$TMPDIR"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$HERE" log -1 --format=%ct -- third_party src include shim)}"
export LC_ALL=C TZ=UTC
export ARFLAGS=crD

rm -rf "$OUT/zlib" "$OUT/elfutils" "$OUT/libbpf" "$OUT/bml" "$OUT/bml_spinel" "$OUT/lib" "$OUT/include" "$OUT/log"
mkdir -p "$OUT/lib" "$OUT/include" "$OUT/log"

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

Z="$OUT/zlib"
mkdir -p "$Z"
Z_CFLAGS="-O2 -g -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -ffile-prefix-map=$HERE/third_party/zlib=zlib -ffunction-sections -fdata-sections"
for s in adler32 crc32 deflate infback inffast inflate inftrees trees zutil compress uncompr gzclose gzlib gzread gzwrite; do
  gcc $Z_CFLAGS -c "$HERE/third_party/zlib/$s.c" -o "$Z/$s.o"
done
ar crD "$OUT/lib/libz.a" $(ls "$Z"/*.o | LC_ALL=C sort)
cp "$HERE/third_party/zlib/zlib.h" "$HERE/third_party/zlib/zconf.h" "$OUT/include/"

EU="$OUT/elfutils"
mkdir -p "$EU/src" "$EU/obj"
git -C "$HERE/third_party/elfutils" archive --format=tar HEAD | tar -x -C "$EU/src"
printf '#error "placeholder: libdw is not built by bpf-mlir-loader (scripts/build-libs.sh)"\n' > "$EU/src/libdw/known-dwarf.h"
(cd "$EU/src" && step elfutils-autoreconf autoreconf -fi)
EU_CFLAGS="-O2 -g -ffile-prefix-map=$EU/src=elfutils -ffile-prefix-map=$EU/obj=elfutils -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections"
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

B="$OUT/bml"
mkdir -p "$B"
BML_CFLAGS="-O2 -g -std=gnu11 -Wall -Wextra -Werror -ffile-prefix-map=$HERE=bml -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections -I$HERE/src -I$HERE/include -I$HERE/third_party/libbpf/include/uapi -I$OUT/include"
rm -f "$B"/*.o
for c in $("$HERE/scripts/srcs.sh" src); do
  obj=$(printf '%s' "${c#"$HERE"/src/}" | tr / _)
  gcc $BML_CFLAGS -c "$c" -o "$B/${obj%.c}.o"
done
ar crD "$OUT/lib/libbml.a" $(ls "$B"/*.o | LC_ALL=C sort)
cp -r "$HERE/include/bml" "$OUT/include/"
rm -f "$OUT/include/bml/bml_testonly.h"

S="$OUT/bml_spinel"
rm -rf "$S"; mkdir -p "$S"
for c in $(find "$HERE/shim/spinel" -name '*.c' | LC_ALL=C sort); do
  gcc $BML_CFLAGS -I"$HERE" -c "$c" -o "$S/spinel_$(basename "${c%.c}").o"
done
ar crD "$OUT/lib/libbml_spinel.a" $(ls "$S"/*.o | LC_ALL=C sort)
cp "$HERE/shim/spinel/spinelbpf.h" "$OUT/include/bml/"

if [ -n "$(git -C "$HERE/third_party/elfutils" status --porcelain)$(git -C "$HERE/third_party/zlib" status --porcelain)" ]; then
  echo "build-libs: third_party/elfutils or zlib has uncommitted changes after the build" >&2; exit 1
fi

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
