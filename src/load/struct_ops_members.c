/* load/struct_ops_members.c — struct_ops: the members of a struct_ops table (forms, ranges, which are set, the slot positions
 * of G2) and G3 (the set members against the kernel's struct, by name, never by offset). Also the post-load rule for the
 * BTF ids of a struct_ops map. The lookup of the kernel types is libbpf's own (find_struct_ops_kern_types):
 * bpf_struct_ops_<T> with a member `data` of type T, in the vmlinux BTF only (module BTF is not searched). */
#include "load/struct_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "load/internal.h"
#include "util/mutation.h"

/* typedef / const / volatile / restrict / type_tag are skipped (depth 32); -1 for an unreadable id */
static int skip_mods(const struct btf *b, uint32_t id, uint32_t *out)
{
	for (int d = 0; d < 32; d++) {
		const struct btf_type *t = btf__type_by_id(b, id);
		if (!t)
			return -1;
		switch (btf_kind(t)) {
		case BTF_KIND_TYPEDEF: case BTF_KIND_CONST: case BTF_KIND_VOLATILE: case BTF_KIND_RESTRICT: case BTF_KIND_TYPE_TAG:
			id = t->type;
			continue;
		default:
			*out = id;
			return 0;
		}
	}
	return -1;
}

static int is_func_ptr(const struct btf *b, uint32_t id)
{
	uint32_t p, f;
	if (skip_mods(b, id, &p) || !btf_is_ptr(btf__type_by_id(b, p)) || skip_mods(b, btf__type_by_id(b, p)->type, &f))
		return 0;
	return btf_is_func_proto(btf__type_by_id(b, f));
}

int lb_sop_table_members(const struct btf *local, uint32_t struct_id, const uint8_t *bytes, uint64_t size, struct lb_sop_table *t,
			 struct bml_load_result *r)
{
	const struct btf_type *st = btf__type_by_id(local, struct_id);
	if (!st || !btf_is_struct(st))
		return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: the table's BTF type is not a struct", t->name);
	t->type = strdup(btf__name_by_offset(local, st->name_off) ? btf__name_by_offset(local, st->name_off) : "");
	t->size = size;
	if (!t->type)
		return lb_fail(r, BML_LOAD_ENV, "out of memory");
	if (st->size != size)
		return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: the struct %s has %u bytes, the table %llu", t->name, t->type, st->size,
			       (unsigned long long)size);
	uint16_t n = btf_vlen(st);
	t->m = calloc(n ? n : 1, sizeof *t->m);
	if (!t->m)
		return lb_fail(r, BML_LOAD_ENV, "out of memory");
	const struct btf_member *mb = btf_members(st);
	/* forms and ranges of every member, before any byte of the table is read */
	for (uint16_t i = 0; i < n; i++) {
		const char *mn = btf__name_by_offset(local, mb[i].name_off);
		uint32_t boff = btf_member_bit_offset(st, i), mt;
		if (btf_member_bitfield_size(st, i) || boff % 8)
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: member %s is a bitfield (outside the bpf-mlir ELF form)", t->name, mn);
		if (skip_mods(local, mb[i].type, &mt))
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: member %s has an unreadable type", t->name, mn);
		const struct btf_type *ty = btf__type_by_id(local, mt);
		long long msz = -1;
		int slot = is_func_ptr(local, mb[i].type);
		uint32_t et;
		if (slot)
			msz = 8;
		else if (btf_is_int(ty) || btf_is_enum(ty) || btf_is_enum64(ty))
			msz = ty->size;
		else if (btf_is_array(ty) && !skip_mods(local, btf_array(ty)->type, &et) && btf_is_int(btf__type_by_id(local, et)))
			msz = btf__resolve_size(local, mt);
		else
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: member %s has a form outside the bpf-mlir ELF form (BTF kind %u)", t->name,
				       mn, btf_kind(ty));
		if (msz < 0 || boff / 8 + (uint64_t)msz > size)
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: member %s at %u (%lld bytes) is outside the %llu-byte table", t->name, mn,
				       boff / 8, msz, (unsigned long long)size);
		t->m[i] = (struct lb_sop_member){strdup(mn ? mn : ""), boff / 8, (uint32_t)msz, slot, 0};
		t->n_m = i + 1u;
		if (!t->m[i].name)
			return lb_fail(r, BML_LOAD_ENV, "out of memory");
	}
	/* the slots (G2): each at the start of a function-pointer member, 8-byte aligned (so its 8 bytes are inside the member and
	 * the table); only then are its bytes read, and they must be zero */
	for (size_t s = 0; s < t->n_slots; s++) {
		struct lb_sop_slot *sl = &t->slots[s];
		struct lb_sop_member *m = NULL;
		for (size_t i = 0; i < t->n_m && sl->off % 8 == 0; i++)
			if (t->m[i].slot && t->m[i].off == sl->off)
				m = &t->m[i];
		if (!m) {
			if (BML_MUT("load.struct_ops_slots_ok"))
				continue;
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: program %s at table offset %u is not at the start of a function-pointer member%s",
				       t->name, sl->prog, sl->off, sl->off % 8 ? " (not 8-byte aligned)" : "");
		}
		uint64_t v = 0;
		memcpy(&v, bytes + sl->off, 8);
		if (v && !BML_MUT("load.struct_ops_slots_ok"))
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: slot %s (program %s) holds a non-zero addend", t->name, m->name, sl->prog);
		m->set = 1;
		sl->member = m->name;
	}
	/* data members: set if a byte of their own range is not zero (padding is not counted) */
	for (size_t i = 0; i < t->n_m; i++)
		for (uint32_t k = 0; !t->m[i].slot && k < t->m[i].size && !t->m[i].set; k++)
			t->m[i].set = bytes[t->m[i].off + k] != 0;
	return 0;
}

/* The kernel's T, if bpf_struct_ops_<T> has a member data of type T (libbpf's find_struct_ops_kern_types); -1 if not */
static int kern_types(const struct btf *kern, const char *type, uint32_t *value_id)
{
	char vname[256];
	if (snprintf(vname, sizeof vname, "bpf_struct_ops_%s", type) >= (int)sizeof vname)
		return -1;
	int kt = btf__find_by_name_kind(kern, type, BTF_KIND_STRUCT), vt = btf__find_by_name_kind(kern, vname, BTF_KIND_STRUCT);
	if (kt <= 0 || vt <= 0)
		return -1;
	const struct btf_type *v = btf__type_by_id(kern, (uint32_t)vt);
	const struct btf_member *mb = btf_members(v);
	for (uint16_t i = 0; i < btf_vlen(v); i++)
		if (!strcmp(btf__name_by_offset(kern, mb[i].name_off), "data") && mb[i].type == (uint32_t)kt) {
			if (value_id)
				*value_id = (uint32_t)vt;
			return kt;
		}
	return -1;
}

#define G3_STOP(...)                                                                                                               \
	do {                                                                                                                       \
		if (!BML_MUT("load.struct_ops_members_ok"))                                                                       \
			return lb_fail(r, BML_LOAD_STRUCT_OPS_TARGET, __VA_ARGS__);                                                \
	} while (0)

int lb_sop_members(const struct lb_sop_tables *ts, const struct btf *kern, struct bml_load_result *r)
{
	for (size_t ti = 0; ti < ts->n; ti++) {
		const struct lb_sop_table *t = &ts->t[ti];
		int kt = kern_types(kern, t->type, NULL);
		if (kt < 0) {
			G3_STOP("struct_ops type %s is not in the vmlinux BTF (no bpf_struct_ops_%s with a member data of type %s; map %s)", t->type,
				t->type, t->type, t->name);
			continue;
		}
		const struct btf_type *k = btf__type_by_id(kern, (uint32_t)kt);
		const struct btf_member *km = btf_members(k);
		for (size_t i = 0; i < t->n_m; i++) {
			const struct lb_sop_member *m = &t->m[i];
			if (!m->set)
				continue; /* libbpf skips a zero member the kernel lacks; nothing is set */
			int j = -1;
			for (uint16_t x = 0; x < btf_vlen(k) && j < 0; x++)
				if (!strcmp(btf__name_by_offset(kern, km[x].name_off), m->name))
					j = x;
			if (j < 0) {
				G3_STOP("struct_ops map %s: member %s is set, but the kernel's %s has no member %s", t->name, m->name, t->type, m->name);
				continue;
			}
			if (m->slot) {
				if (!is_func_ptr(kern, km[j].type))
					G3_STOP("struct_ops map %s: member %s is a program slot, but not a function pointer in the kernel's %s", t->name, m->name,
						t->type);
				continue;
			}
			long long ks = btf__resolve_size(kern, km[j].type);
			if (btf_member_bitfield_size(k, (uint32_t)j))
				G3_STOP("struct_ops map %s: member %s is a bitfield in the kernel's %s", t->name, m->name, t->type);
			else if (ks != (long long)m->size)
				G3_STOP("struct_ops map %s: member %s has %lld bytes in the kernel's %s and %u in the ELF", t->name, m->name, ks, t->type,
					m->size);
		}
	}
	return 0;
}

int lb_sop_check_loaded_map(struct bpf_object *obj, struct bpf_map *m, uint32_t local_value_id, const struct bpf_map_info *mi,
			    struct bml_load_result *r)
{
	const struct btf *local = bpf_object__btf(obj);
	const struct btf_type *lt = local ? btf__type_by_id(local, local_value_id) : NULL;
	const char *type = lt ? btf__name_by_offset(local, lt->name_off) : NULL;
	struct btf *vm = btf__load_vmlinux_btf();
	uint32_t want = 0;
	int ok = type && vm && kern_types(vm, type, &want) >= 0;
	btf__free(vm);
	if (!ok || mi->btf_key_type_id || mi->btf_value_type_id || mi->btf_vmlinux_value_type_id != want)
		return lb_fail(r, BML_LOAD_MAP_BTF, "struct_ops map %s: the kernel has key %u / value %u / vmlinux value %u, expected 0 / 0 / %u (bpf_struct_ops_%s)",
			       bpf_map__name(m), mi->btf_key_type_id, mi->btf_value_type_id, mi->btf_vmlinux_value_type_id, want, type ? type : "?");
	return 0;
}
