# bpf-mlir-loader

A C loader for BPF objects produced by [bpf-mlir](https://github.com/yuskesh/bpf-mlir).
It enforces the bpf-mlir load contract (the requirements section, the schema hash,
map declarations and record members, and the kernel's capabilities) before a
program is loaded, and needs no Go runtime. It is built on libbpf.

Linux x86_64 only. The C API is documented in `include/bml/bml.h`.

## Build

Requires gcc, make, autoconf, automake, libtool, gettext (for `autopoint`), gawk,
flex, bison and git.

```sh
git submodule update --init third_party/libbpf third_party/elfutils third_party/zlib
scripts/build-libs.sh
```

`build/libs` then holds `lib/libbml.a`, `lib/libbml_spinel.a`, `lib/libbpf.a`,
`lib/libelf.a`, `lib/libz.a`, the headers in `include/`, and `LICENSES/` and
`NOTICE` for the statically linked components.

Link order: `libbml.a libbpf.a libelf.a libz.a`.

## Test

The tests need `jq` as well. They do not need root, Go or LLVM, and they do not
load programs into the kernel.

```sh
git submodule update --init third_party/bpf-mlir
scripts/test.sh
```

`third_party/bpf-mlir` supplies the conformance corpus only. The product build
does not use it.

## License

bpf-mlir-loader is licensed under Apache-2.0 WITH LLVM-exception. See `LICENSE`
and `NOTICE`.

The dependencies are fetched as git submodules and are not included in this source
tree. `scripts/build-libs.sh` links libelf statically. If you distribute a binary
that contains libelf and choose LGPL-3.0 for it, the license asks you to:

- provide the corresponding source of libelf (elfutils 0.196) and its license texts;
- accompany the binary with copies of the GNU GPL version 3 and the GNU LGPL
  version 3 (`LICENSES/elfutils-libelf.GPL-3.0` and
  `LICENSES/elfutils-libelf.LGPL-3.0`);
- let the recipient replace libelf with a modified version and relink, for example
  by providing the object files of your program.

If you use libbpf under BSD-2-Clause, its copyright notice and conditions
(`LICENSES/libbpf.BSD-2-Clause`) must appear in the documentation of a distributed
binary. Shipping the `NOTICE` and `LICENSES/` that `scripts/build-libs.sh` writes to
`build/libs` with that documentation covers this notice and the zlib notice.

This is a summary and not legal advice. The authoritative text is `COPYING-LGPLV3`
in the elfutils source and each license text in `LICENSES/`.
