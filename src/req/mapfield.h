/* mapfield.h — deriving which map fields a program uses (section 7 of bpf-mlir's docs/requirements_format.md). A port of
 * go/requirements/mapfield.go and of scanFuncs in requirements.go. Three states: not derived, derived, and failed (with a reason). */
#ifndef BML_MAPFIELD_H
#define BML_MAPFIELD_H

#include <stddef.h>

#include "elf/elf.h"

enum bml_mf_state { BML_MF_NOT_DERIVED, BML_MF_DERIVED, BML_MF_FAILED };

struct bml_mf_use {
	char *map;
	const char *field; /* "bpf_spin_lock" or "bpf_timer" (a static string) */
};

struct bml_mf_prog {
	char *program; /* the name of the FUNC symbol */
	struct bml_mf_use *uses; /* in map-name order, and within a map in field-name order (as in Go) */
	size_t n_uses;
};

struct bml_map_fields {
	enum bml_mf_state state;
	char *reason; /* the reason for FAILED */
	struct bml_mf_prog *progs; /* only programs that have at least one use */
	size_t n_progs;
};

/* Go's deriveMapFields (part of FromELF). The caller zero-initialises out. */
void bml_map_fields_derive(const struct bml_elf *elf, struct bml_map_fields *out);
void bml_map_fields_free(struct bml_map_fields *mf);
const struct bml_mf_prog *bml_map_fields_uses(const struct bml_map_fields *mf, const char *program);

#endif
