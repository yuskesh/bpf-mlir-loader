/* btf/globals.h — the check of global variables: ELF symbols, the BTF DATASEC and the declaration. It is a copy of
 * GlobalSymbols, GlobalProblems, checkGlobal and btfRelocs in go/layout (from bpf-mlir's global-variable checks). The
 * messages are byte-identical to Go's (they become part of the maps.json problem messages). */
#ifndef BML_BTF_GLOBALS_H
#define BML_BTF_GLOBALS_H

#include <stddef.h>
#include <stdint.h>

/* GLOBAL OBJECT symbols of .rodata and .bss (a Go map: for the same name the last one wins), in ascending name order */
struct btf_gsym {
	const char *name;    /* inside the ELF string table */
	const char *section; /* ".rodata" / ".bss" */
};

/* CONTRACT: *out is malloc'd (release with free). Each name points into the elf data, so it is valid only while elf is alive. Failure returns -1 and sets *err (malloc'd text) */
int btf_global_symbols(const void *elf, size_t len, struct btf_gsym **out, size_t *n, char **err);

/* CONTRACT: returns the problems joined with "; " (malloc'd; an empty string means a match). section is ".rodata" or ".bss"; size is in bytes.
 * An unreadable ELF or BTF returns NULL and sets *err (malloc'd). Out of memory returns NULL with *err = NULL */
char *btf_global_problems(const void *elf, size_t len, const char *name, const char *section, uint32_t size, int is_signed, char **err);

/* Go's GlobalOffset: the st_value and st_size of the first OBJECT symbol with the name (an offset inside the section;
 * use it after the globals check has confirmed that it agrees with the DATASEC). -1 if there is none or it cannot be read. */
int btf_global_offset(const void *elf, size_t len, const char *name, uint64_t *off, uint64_t *size);

#endif
