/* load/struct_ops.h — the guards for struct_ops link tables (.struct_ops.link): G2 (tables, slots, programs and the
 * binding to the requirements rows) and G3 (the members that the ELF sets, against the target kernel's struct). G1 (only
 * the link-table form is accepted) is in pre.c. Internal to the load
 * layer and its tests. */
#ifndef BML_LOAD_STRUCT_OPS_H
#define BML_LOAD_STRUCT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "load/load.h"
#include "req/req.h"

struct btf;
struct bpf_map;
struct bpf_map_info;
struct bpf_object;

struct lb_sop_member {
	char *name;
	uint32_t off, size; /* bytes, inside the table */
	int slot;           /* a function-pointer member */
	int set;            /* a slot with a relocation, or a data member with a non-zero byte in its own range */
};

struct lb_sop_slot {
	char *prog;         /* the program the relocation names */
	uint32_t off;       /* inside the table */
	const char *member; /* the member at off (set by lb_sop_table_members; NULL until then) */
};

struct lb_sop_table {
	char *name, *type;  /* the map (VAR) name and its STRUCT name */
	uint64_t off, size; /* inside .struct_ops.link */
	struct lb_sop_member *m;
	size_t n_m;
	struct lb_sop_slot *slots;
	size_t n_slots;
};

struct lb_sop_tables {
	struct lb_sop_table *t;
	size_t n;
};

/* The members of one table from the local BTF (struct_id, a STRUCT of `size` bytes) and the table's bytes. The slots
 * (t->slots, set by the caller) must each be at the start of a function-pointer member, 8-byte aligned, and their 8
 * bytes must be zero (REL: no addend). Member forms and ranges are checked before any byte is read. Fails with SHAPE.
 * On entry t->name and t->slots are the caller's; the function fills type, size and the members. */
int lb_sop_table_members(const struct btf *local, uint32_t struct_id, const uint8_t *bytes, uint64_t size, struct lb_sop_table *t,
			 struct bml_load_result *r);
/* G2 on the ELF and its parsed requirements. No table and no struct_ops program is 0 with zero tables. */
int lb_sop_slots(const uint8_t *elf, size_t len, const struct bml_requirements *req, struct lb_sop_tables *out, struct bml_load_result *r);
/* G3 against a kernel BTF (vmlinux). Fails with BML_LOAD_STRUCT_OPS_TARGET. */
int lb_sop_members(const struct lb_sop_tables *t, const struct btf *kern, struct bml_load_result *r);
void lb_sop_tables_free(struct lb_sop_tables *t);
/* G2, then G3 against btf__load_vmlinux_btf() if the ELF has a table (the load path; called before libbpf opens the ELF). */
int lb_check_struct_ops(const uint8_t *elf, size_t len, const struct bml_requirements *req, struct bml_load_result *r);
/* After load: a struct_ops map is created by libbpf with key / value BTF ids 0 and the vmlinux value type
 * bpf_struct_ops_<T> (T is the local value type's name). Anything else stops with MAP_BTF. */
int lb_sop_check_loaded_map(struct bpf_object *obj, struct bpf_map *m, uint32_t local_value_id, const struct bpf_map_info *mi,
			    struct bml_load_result *r);

#endif
