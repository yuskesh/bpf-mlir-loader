/* CONTRACT: record table of the ELF BTF.
 *
 * Parse applies the boundary checks (header ranges in uint64, string table ending in NUL, type records inside the range by kind and vlen)
 * and the stable English error text byte for byte. The recursion in spell (array elements) has no limit in Go,
 * where a cyclic BTF overflows the stack; C stops at depth 64 with "?btf_kind_0" (a known difference). */
#ifndef BML_BTF_LAYOUT_H
#define BML_BTF_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

struct lmember {
	const char *name;
	uint32_t type_id, offset;
};


struct lsecinfo {
	uint32_t type_id, offset, size, pos;
};

struct ltype {
	uint32_t kind;
	const char *name;
	int is_signed;
	uint32_t size, type_id, nelems;
	struct lmember *members;
	uint32_t n_members;
	int bitfield;
	struct lsecinfo *secinfo;
	uint32_t n_secinfo;
};

struct lbtf {
	struct ltype *t;
	size_t n;
};


struct btf_indexed {
	struct {
		const char *name;
		uint32_t offset;
		char *type;
	} m;
	size_t idx;
};


int btf_layout_parse(const void *elf_data, size_t elf_len, struct lbtf *b, char **err);
void btf_layout_free(struct lbtf *b);

const struct ltype *btf_layout_resolve(const struct lbtf *b, uint32_t id);

char *btf_layout_record(const struct lbtf *b, const char *name, int *missing);

char *btf_shape_string(uint32_t size, struct btf_indexed *ms, size_t n);

#endif
