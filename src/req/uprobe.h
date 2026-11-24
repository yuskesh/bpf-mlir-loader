/* uprobe.h — parts of the uprobe check (a port of bpf-mlir's go/requirements/uprobe.go): the binary's SHA-256, the symbol, and the DWARF argument types
 * (the latter are in dwarf/dwarf.h). */
#ifndef BML_UPROBE_H
#define BML_UPROBE_H

#include <stddef.h>
#include <stdint.h>

#include "dwarf/dwarf.h"
#include "elf/elf.h"

/* SHA-256 as lowercase hexadecimal (64 characters + NUL) */
void bml_sha256_hex(const uint8_t *data, size_t len, char out[65]);

/* uprobeSymbol: returns NULL if the symbol is exactly one FUNC (counting only entries with different values) inside an executable PT_LOAD
 * segment; otherwise a malloc-ed text describing the mismatch. */
char *bml_uprobe_symbol(const struct bml_elf *elf, const char *name);
/* The file offset of a uprobe attach. It uses the same symbol rules as the check (bml_uprobe_symbol), and the offset is computed as in
 * cilium/ebpf: v - p_vaddr + p_offset. Returns 0 with *off (and, if not NULL, the symbol value in *value and the p_vaddr of the containing
 * segment in *seg_vaddr), or -1 with *why (the same text as the check; malloc-ed). */
int bml_uprobe_file_offset(const struct bml_elf *elf, const char *name, uint64_t *off, uint64_t *value, uint64_t *seg_vaddr, char **why);

/* dwarfSubprogramFromData: if uprobeSymbol fails on body the result is `cannot resolve DWARF address: <text>`; otherwise the subprogram is chosen
 * from d (the DWARF embedded in the body or in a split file) by the address of the first STT_FUNC whose name matches, looking in .symtab and
 * then .dynsym. Returns 0 with *out, or -1 with *err. */
int bml_uprobe_dwarf_at(const struct bml_elf *body, struct bml_dwarf *d, const char *name, int parameters, const uint8_t *raw, size_t n_raw,
			struct bml_dwarf_sub *out, char **err); /* raw: the number of the formal parameter that needs a format-18 ptr (NULL if there is none) */

#endif
