#ifndef BML_ELF_MAPS_SYMBOLS_H
#define BML_ELF_MAPS_SYMBOLS_H

#include <stddef.h>

#include "elf/elf.h"

/* CONTRACT: 0 with *out (malloc'd names, sorted, without duplicates; free with bml_elf_names_free) — an empty list when the ELF has
 * no `.maps` section; -1 with *err (malloc — bml_elf_symbols's text) when the symbol table cannot be read. */
int bml_elf_maps_symbols(const struct bml_elf *elf, char ***out, size_t *n, char **err);
void bml_elf_names_free(char **v, size_t n);

#endif
