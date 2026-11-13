#include "shim/build/elf_internal.h"

#include <stdlib.h>
#include <string.h>

#include "elf/elf.h"
#include "elf/maps_symbols.h"
#include "util/gostr.h"

int bml_build_schema_sha256(const void *elf, size_t len, char out[65], struct bml_build_error *err)
{
	bb_init(err);
	out[0] = 0;
	struct bml_requirements *req;
	if (bb_read_requirements(elf, len, &req, err))
		return err->code;
	const char *s = req->schema_sha256.p ? req->schema_sha256.p : "";
	if (strlen(s) > 64)
		bb_unsupported(err, "schema-sha256", "the schema hash is longer than 64 characters");
	else
		memcpy(out, s, strlen(s) + 1);
	bml_requirements_free(req);
	return err->code;
}

int bml_build_map_symbols(const void *elf, size_t len, char ***names, size_t *n, struct bml_build_error *err)
{
	bb_init(err);
	*names = NULL;
	*n = 0;
	struct bml_elf e;
	char *m = NULL;
	if (bml_elf_open(elf ? elf : "", len, &e, &m)) {
		if (!m)
			return bb_nomem(err);
		bb_unsupported(err, "elf-header", m);
		free(m);
		return err->code;
	}
	if (bml_elf_maps_symbols(&e, names, n, &m)) {
		if (!m) {
			bb_nomem(err);
		} else if (!strcmp(m, "no symbol section")) {
			bb_fail(err, "cannot read ELF symbols: no symbol section");
		} else if (!strcmp(m, "out of memory")) {
			bb_nomem(err);
		} else {
			bb_unsupported(err, "elf-symbols", m);
		}
		free(m);
	}
	bml_elf_close(&e);
	return err->code;
}
