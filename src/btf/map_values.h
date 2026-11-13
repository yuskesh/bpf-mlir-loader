#ifndef BML_BTF_MAP_VALUES_H
#define BML_BTF_MAP_VALUES_H

#include <stddef.h>

#include "elf/elf.h"

struct mapfields {
	const char *map;
	const char *fields[64];
	size_t n;
};


int btf_map_value_fields(const struct bml_elf *e, const char **needed, size_t n_needed, struct mapfields **out, size_t *n_out,
			 char **err);

#endif
