
#ifndef BML_DWARF_SPLIT_H
#define BML_DWARF_SPLIT_H

#include <stddef.h>
#include <stdint.h>

#include "dwarf/dwarf.h"
#include "elf/elf.h"


int bml_debug_build_id(const struct bml_elf *e, const char *owner, uint8_t **id, size_t *n, char **why);

int bml_debug_link_crc(const struct bml_elf *e, uint32_t *crc, int *has, char **why);

uint32_t bml_crc32_ieee(const uint8_t *p, size_t n);

int bml_debug_has_info(const struct bml_elf *e);

int bml_debug_open_checks(const struct bml_elf *f, char **why);

int bml_debug_split_checks(const struct bml_elf *f, char **why);

#endif
