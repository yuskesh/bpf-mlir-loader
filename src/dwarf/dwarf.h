#ifndef BML_DWARF_H
#define BML_DWARF_H

#include <stddef.h>
#include <stdint.h>

#include "elf/elf.h"


#define BML_DEBUG_RAW_LIMIT 268435456
#define BML_DEBUG_EXPANDED_LIMIT 536870912

struct bml_dwarf_param {
	char *name;
	char *type;
	char *pointer;
};


struct bml_dwarf_sub {
	int64_t lang;
	char *producer;
	int64_t cc;
	struct bml_dwarf_param *params;
	size_t n;
};


struct bml_dwarf;
int bml_dwarf_open(const struct bml_elf *elf, struct bml_dwarf **out, char **err);
void bml_dwarf_close(struct bml_dwarf *d);




int bml_dwarf_subprogram_at(struct bml_dwarf *d, uint64_t address, const char *name, int parameters, struct bml_dwarf_sub *out, char **err);

int bml_dwarf_subprogram_at_ptr(struct bml_dwarf *d, uint64_t address, const char *name, int parameters, const uint8_t *raw_ptr, size_t n_raw,
				struct bml_dwarf_sub *out, char **err);
void bml_dwarf_sub_free(struct bml_dwarf_sub *s);


int bml_dwarf_subprogram_names(const struct bml_elf *elf, char ***names, size_t *n, char **err);

#endif
