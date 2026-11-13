#ifndef BML_UPROBE_H
#define BML_UPROBE_H

#include <stddef.h>
#include <stdint.h>

#include "dwarf/dwarf.h"
#include "elf/elf.h"


void bml_sha256_hex(const uint8_t *data, size_t len, char out[65]);


char *bml_uprobe_symbol(const struct bml_elf *elf, const char *name);


int bml_uprobe_file_offset(const struct bml_elf *elf, const char *name, uint64_t *off, uint64_t *value, uint64_t *seg_vaddr, char **why);



int bml_uprobe_dwarf_at(const struct bml_elf *body, struct bml_dwarf *d, const char *name, int parameters, const uint8_t *raw, size_t n_raw,
			struct bml_dwarf_sub *out, char **err);

#endif
