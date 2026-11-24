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
	const char *name; /* inside raw (NUL-terminated) */
	uint32_t type_id, offset;
};

/* A DATASEC var_secinfo (Go's varSecinfo, used by the globals check). pos is the byte position of the offset field inside the .BTF section (compare it with r_offset in .rel.BTF). */
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

/* One member of the table string (sorted by offset; members with the same offset keep their original order, idx) */
struct btf_indexed {
	struct {
		const char *name;
		uint32_t offset;
		char *type;
	} m;
	size_t idx;
};

/* Read the ELF's .BTF (go/layout's parseBTF). Failure is -1 with *err set (malloc'd: Go's message, or the C code's message for a corrupt BTF). */
int btf_layout_parse(const void *elf_data, size_t elf_len, struct lbtf *b, char **err);
void btf_layout_free(struct lbtf *b);
/* Strip typedef, const, volatile, restrict and type_tag (Go's resolve: depth 32; an out-of-range id or exceeding the limit gives an empty type of kind 0) */
const struct ltype *btf_layout_resolve(const struct lbtf *b, uint32_t id);
/* The table string of the STRUCT with the name (a BTFRecords lookup; malloc'd). NULL with *missing set if there is none. */
char *btf_layout_record(const struct lbtf *b, const char *name, int *missing);
/* size=N;name:off:type;... (ms is stably sorted by offset; malloc'd) */
char *btf_shape_string(uint32_t size, struct btf_indexed *ms, size_t n);

#endif
