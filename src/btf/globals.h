#ifndef BML_BTF_GLOBALS_H
#define BML_BTF_GLOBALS_H

#include <stddef.h>
#include <stdint.h>


struct btf_gsym {
	const char *name;
	const char *section;
};

/* CONTRACT: *out is malloc'd (release with free). Each name points into the elf data, so it is valid only while elf is alive. Failure returns -1 and sets *err (malloc'd text) */
int btf_global_symbols(const void *elf, size_t len, struct btf_gsym **out, size_t *n, char **err);

/* CONTRACT: returns the problems joined with "; " (malloc'd; an empty string means a match). section is ".rodata" or ".bss"; size is in bytes.
 * An unreadable ELF or BTF returns NULL and sets *err (malloc'd). Out of memory returns NULL with *err = NULL */
char *btf_global_problems(const void *elf, size_t len, const char *name, const char *section, uint32_t size, int is_signed, char **err);



int btf_global_offset(const void *elf, size_t len, const char *name, uint64_t *off, uint64_t *size);

#endif
