/* dwarf/split.h — the binding of separate DWARF and the checks made before reading it (from bpf-mlir's split-DWARF
 * support). Failure is -1 with *why set to a fixed ASCII message (malloc'd). */
#ifndef BML_DWARF_SPLIT_H
#define BML_DWARF_SPLIT_H

#include <stddef.h>
#include <stdint.h>

#include "dwarf/dwarf.h"
#include "elf/elf.h"

/* debugBuildID: owner is "the binary" or "separate DWARF". *id is malloc'd. */
int bml_debug_build_id(const struct bml_elf *e, const char *owner, uint8_t **id, size_t *n, char **why);
/* debugLinkCRC: if there is none, the result is 0 with *has = 0 */
int bml_debug_link_crc(const struct bml_elf *e, uint32_t *crc, int *has, char **why);
/* crc32.ChecksumIEEE */
uint32_t bml_crc32_ieee(const uint8_t *p, size_t n);
/* hasDebugInfo: a .debug_info or .zdebug_info section exists (NOBITS and size 0 count too) */
int bml_debug_has_info(const struct bml_elf *e);
/* The reading of the compression header that elf.NewFile does (part of the "unreadable" check of step 6; call it after bml_elf_open) */
int bml_debug_open_checks(const struct bml_elf *f, char **why);
/* The first half of steps 9 to 11: altlink, REL / RELA sections aimed at debug sections, type units, the per-section limit, and whether info exists */
int bml_debug_split_checks(const struct bml_elf *f, char **why);

#endif
