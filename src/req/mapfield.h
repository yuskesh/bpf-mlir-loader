

#ifndef BML_MAPFIELD_H
#define BML_MAPFIELD_H

#include <stddef.h>

#include "elf/elf.h"

enum bml_mf_state { BML_MF_NOT_DERIVED, BML_MF_DERIVED, BML_MF_FAILED };

struct bml_mf_use {
	char *map;
	const char *field;
};

struct bml_mf_prog {
	char *program;
	struct bml_mf_use *uses;
	size_t n_uses;
};

struct bml_map_fields {
	enum bml_mf_state state;
	char *reason;
	struct bml_mf_prog *progs;
	size_t n_progs;
};


void bml_map_fields_derive(const struct bml_elf *elf, struct bml_map_fields *out);
void bml_map_fields_free(struct bml_map_fields *mf);
const struct bml_mf_prog *bml_map_fields_uses(const struct bml_map_fields *mf, const char *program);

#endif
