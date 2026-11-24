/* dwarf/dwarf.h — reading the formal parameters from the DWARF of a uprobe target. This is a C copy of dwarfParams in
 * bpf-mlir's go/requirements/uprobe.go, together with the parts of the behavior of Go's debug/elf File.DWARF() and of
 * the Reader and Type in debug/dwarf that dwarfParams uses. */
#ifndef BML_DWARF_H
#define BML_DWARF_H

#include <stddef.h>
#include <stdint.h>

#include "elf/elf.h"

/* Limits for separate DWARF (from bpf-mlir's split-DWARF support): the size of the file in bytes, and the total size
 * of the debug sections after decompression. */
#define BML_DEBUG_RAW_LIMIT 268435456
#define BML_DEBUG_EXPANDED_LIMIT 536870912

struct bml_dwarf_param {
	char *name;
	char *type;    /* i8 ... u64, ptr or strptr; "" if it cannot be read (dwarfSpelling); not produced for an argument that needs ptr ("") */
	char *pointer; /* from bpf-mlir's ptr parameter type: only for an argument that needs ptr; one of ptr, non-pointer or ptr(depth=...,width=...); "" means Unknown (NULL for other arguments) */
};

/* dwarfSubprogram: the chosen DW_TAG_subprogram and the compile unit that contains it */
struct bml_dwarf_sub {
	int64_t lang;   /* DW_AT_language (-1 if absent) */
	char *producer; /* DW_AT_producer ("" if absent) */
	int64_t cc;     /* DW_AT_calling_convention (-1 if absent) */
	struct bml_dwarf_param *params;
	size_t n;
};

/* An opened DWARF (Go's *dwarf.Data); the ELF's bytes must stay alive until it is closed. If it cannot be opened or
 * read, the result is -1 with *err set to a malloc'd message (`no DWARF: ...`). */
struct bml_dwarf;
int bml_dwarf_open(const struct bml_elf *elf, struct bml_dwarf **out, char **err);
void bml_dwarf_close(struct bml_dwarf *d);
/* dwarfSubprogramFromData (bpf-mlir's address-based subprogram lookup, used by split-DWARF support from policy version 16):
 * exactly one DW_TAG_subprogram over all CUs must be a non-declaration whose direct DW_AT_low_pc is address (the
 * st_value of the body's FUNC symbol, which the caller decides). The result carries the language, producer and
 * calling convention of that CU and, if parameters is set, the direct formal_parameter children (the result is
 * excluded). The name is used only in messages. Zero matches, or two or more, give `DWARF has N non-declaration
 * DW_TAG_subprogram definitions at <name> (0x<address>), want exactly one`; a read error gives Go's DecodeError
 * message. Failure is -1 with *err set to a malloc'd message. */
int bml_dwarf_subprogram_at(struct bml_dwarf *d, uint64_t address, const char *name, int parameters, struct bml_dwarf_sub *out, char **err);
/* The same, but for each argument i with raw_ptr[i] true (i is the 1-based parameter number, up to n_raw) it also
 * produces the pointer spelling (the ptr parameter type of requirements format 18). */
int bml_dwarf_subprogram_at_ptr(struct bml_dwarf *d, uint64_t address, const char *name, int parameters, const uint8_t *raw_ptr, size_t n_raw,
				struct bml_dwarf_sub *out, char **err);
void bml_dwarf_sub_free(struct bml_dwarf_sub *s);

/* For tests (the differential against Go) and fuzzing: the names of the subprograms that have a name and have
 * children, in order of appearance (duplicates included). Failure is -1 with *err set. */
int bml_dwarf_subprogram_names(const struct bml_elf *elf, char ***names, size_t *n, char **err);

#endif
