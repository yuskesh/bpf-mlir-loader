/* btf/map_values.h — the bpf_timer / bpf_spin_lock members directly inside a map value's STRUCT: the minimal .BTF
 * reading of Go's mapValueFields. Split out of mapfield.c. As in Go, .BTF is always read as little endian. */
#ifndef BML_BTF_MAP_VALUES_H
#define BML_BTF_MAP_VALUES_H

#include <stddef.h>

#include "elf/elf.h"

struct mapfields {
	const char *map;
	const char *fields[64]; /* "bpf_spin_lock" or "bpf_timer" (static strings), in name order */
	size_t n;
};

/* The fields of each needed map. *out is malloc'd (map names point into needed). Failure is -1 with *err set to Go's message (malloc'd). */
int btf_map_value_fields(const struct bml_elf *e, const char **needed, size_t n_needed, struct mapfields **out, size_t *n_out,
			 char **err);

#endif
