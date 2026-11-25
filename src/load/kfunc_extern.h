/* The shape guard's proof for the kfunc externs other than the two arena kfuncs (which arena_extern.h decides). */
#ifndef BML_LOAD_KFUNC_EXTERN_H
#define BML_LOAD_KFUNC_EXTERN_H
#include "elf/elf.h"
#include "load/load.h"

struct bml_live;

/* Returns 1 if the name is one that lb_arena_extern decides, 0 otherwise. */
int lb_kfunc_is_arena_name(const char *name);

/* Proves every undefined symbol in syms (in symbol-table order) that is not an arena name, and returns 0 when all of them
 * are kfunc externs that libbpf resolves from vmlinux BTF only. Otherwise returns -1 with a BML_LOAD_SHAPE failure in r
 * whose message starts "kfunc extern <name>: ". The target's vmlinux BTF is read from /sys/kernel/btf/vmlinux, the file
 * libbpf is given; vmlinux is a test seam that replaces that view (NULL in the load path). */
int lb_kfunc_externs(const struct bml_elf *e, const struct bml_elf_sym *syms, size_t ns, struct bml_live *vmlinux,
		     struct bml_load_result *r);
#endif
