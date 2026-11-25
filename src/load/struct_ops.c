/* load/struct_ops.c — the struct_ops guard G2 on an ELF: the tables of .struct_ops.link (the DATASEC VARs, each bound to its GLOBAL
 * OBJECT symbol and its bytes by bpf-mlir's globals rule), the relocations (each to exactly one table and one
 * function-pointer member, no duplicate offset, a FUNC symbol of a struct_ops / struct_ops.s section), every program in
 * exactly one slot (libbpf would silently not load an unreferenced one), and the binding of each slot to the program's
 * `attach … trace_struct_ops <map>` and `structop <p> <struct> <member>` rows. Also the load-path entry G2 + G3. */
#include "load/struct_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>

#include "btf/globals.h"
#include "elf/elf.h"
#include "load/internal.h"
#include "util/mutation.h"

#define LINK ".struct_ops.link"
#define SLOTS_OK BML_MUT("load.struct_ops_slots_ok") /* mutant: G2's stops off (a broken slot is skipped) */

void lb_sop_tables_free(struct lb_sop_tables *ts)
{
	for (size_t i = 0; ts && i < ts->n; i++) {
		struct lb_sop_table *t = &ts->t[i];
		for (size_t k = 0; k < t->n_m; k++)
			free(t->m[k].name);
		for (size_t k = 0; k < t->n_slots; k++)
			free(t->slots[k].prog);
		free(t->m), free(t->slots), free(t->name), free(t->type);
	}
	if (ts) {
		free(ts->t);
		ts->t = NULL, ts->n = 0;
	}
}

static int is_prog_sec(const struct bml_elf *e, uint16_t shndx)
{
	return shndx < e->n_sections && (!strcmp(e->sections[shndx].name, "struct_ops") || !strcmp(e->sections[shndx].name, "struct_ops.s"));
}

static const struct bml_attach *attach_of(const struct bml_requirements *req, const char *prog)
{
	for (size_t i = 0; req && i < req->n_attaches; i++)
		if (!strcmp(req->attaches[i].program.p, prog) && !strcmp(req->attaches[i].attach_type.p, "trace_struct_ops"))
			return &req->attaches[i];
	return NULL;
}

static int add_slot(struct lb_sop_table *t, const char *prog, uint32_t off)
{
	struct lb_sop_slot *ns = realloc(t->slots, (t->n_slots + 1) * sizeof *ns);
	if (!ns)
		return -1;
	t->slots = ns;
	t->slots[t->n_slots] = (struct lb_sop_slot){strdup(prog), off, NULL};
	return t->slots[t->n_slots++].prog ? 0 : -1;
}

/* The tables: the VARs of the .struct_ops.link DATASEC, bound to their symbols; sorted by offset, no overlap */
static int read_tables(const uint8_t *elf, size_t len, const struct btf *b, const struct bml_elf_shdr *sec, struct lb_sop_tables *out,
		       struct bml_load_result *r)
{
	int ds = btf__find_by_name_kind(b, LINK, BTF_KIND_DATASEC);
	if (ds <= 0)
		return lb_fail(r, BML_LOAD_SHAPE, "the ELF has a %s section but no DATASEC %s in its BTF", LINK, LINK);
	const struct btf_type *d = btf__type_by_id(b, (uint32_t)ds);
	const struct btf_var_secinfo *vs = btf_var_secinfos(d);
	out->t = calloc(btf_vlen(d) ? btf_vlen(d) : 1, sizeof *out->t);
	if (!out->t)
		return lb_fail(r, BML_LOAD_ENV, "out of memory");
	for (uint16_t i = 0; i < btf_vlen(d); i++) {
		const struct btf_type *v = btf__type_by_id(b, vs[i].type);
		const char *name = v && btf_is_var(v) ? btf__name_by_offset(b, v->name_off) : NULL;
		long long size = v ? btf__resolve_size(b, v->type) : -1;
		struct lb_sop_table *t = &out->t[out->n];
		if (!name || size <= 0 || !(t->name = strdup(name)))
			return lb_fail(r, BML_LOAD_SHAPE, "DATASEC %s entry %u is not a sized VAR", LINK, i);
		out->n++;
		char *err = NULL, *probs = btf_global_problems(elf, len, name, LINK, (uint32_t)size, -1, &err);
		if (!probs || *probs) {
			lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: %s", name, probs ? probs : err ? err : "out of memory");
			free(probs), free(err);
			return -1;
		}
		free(probs);
		uint64_t off = 0, sz = 0;
		if (btf_global_offset(elf, len, name, &off, &sz) || off > sec->size || sec->size - off < (uint64_t)size)
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops map %s: the table is outside the %llu-byte %s", name,
				       (unsigned long long)sec->size, LINK);
		t->off = off, t->size = (uint64_t)size;
	}
	for (size_t i = 1; i < out->n; i++) /* insertion sort by offset (a few tables) */
		for (size_t j = i; j > 0 && out->t[j - 1].off > out->t[j].off; j--) {
			struct lb_sop_table x = out->t[j];
			out->t[j] = out->t[j - 1], out->t[j - 1] = x;
		}
	for (size_t i = 1; i < out->n; i++)
		if (out->t[i - 1].off + out->t[i - 1].size > out->t[i].off)
			return lb_fail(r, BML_LOAD_SHAPE, "struct_ops maps %s and %s overlap in %s", out->t[i - 1].name, out->t[i].name, LINK);
	return 0;
}

/* The relocations of .struct_ops.link, each to one table */
static int read_slots(const struct bml_elf *e, size_t li, const struct bml_elf_sym *syms, size_t ns, struct lb_sop_tables *ts,
		      struct bml_load_result *r)
{
	for (size_t ri = 0; ri < e->n_sections; ri++) {
		const struct bml_elf_shdr *rs = &e->sections[ri];
		if (rs->type != BML_SHT_REL || rs->info != li)
			continue;
		const uint8_t *rd;
		size_t rl;
		char *err = NULL;
		if (bml_elf_section_data(e, rs, &rd, &rl, &err) || rl % 16) {
			free(err);
			return lb_fail(r, BML_LOAD_SHAPE, "relocation section %s cannot be read", rs->name);
		}
		for (size_t k = 0; k < rl; k += 16) {
			uint64_t off = bml_elf_u64(e, rd + k), si = bml_elf_u64(e, rd + k + 8) >> 32;
			if (si < 1 || si > ns)
				return lb_fail(r, BML_LOAD_SHAPE, "the relocation at %s offset %llu names symbol %llu outside the symbol table", LINK,
					       (unsigned long long)off, (unsigned long long)si);
			const struct bml_elf_sym *s = &syms[si - 1];
			if (BML_ST_TYPE(s->info) != BML_STT_FUNC || !is_prog_sec(e, s->shndx)) {
				if (SLOTS_OK)
					continue;
				return lb_fail(r, BML_LOAD_SHAPE, "the relocation at %s offset %llu names %s, which is not a struct_ops program", LINK,
					       (unsigned long long)off, s->name);
			}
			struct lb_sop_table *t = NULL;
			for (size_t i = 0; i < ts->n; i++)
				if (ts->t[i].off <= off && off < ts->t[i].off + ts->t[i].size)
					t = &ts->t[i];
			if (!t) {
				if (SLOTS_OK)
					continue;
				return lb_fail(r, BML_LOAD_SHAPE, "the relocation of program %s at %s offset %llu is outside every struct_ops table", s->name,
					       LINK, (unsigned long long)off);
			}
			const char *dup = NULL;
			for (size_t i = 0; i < t->n_slots && !dup; i++)
				if (t->slots[i].off == off - t->off)
					dup = t->slots[i].prog;
			if (dup) {
				if (SLOTS_OK)
					continue;
				return lb_fail(r, BML_LOAD_SHAPE, "programs %s and %s are both at %s offset %llu of struct_ops map %s (a duplicate slot)", dup,
					       s->name, LINK, (unsigned long long)off, t->name);
			}
			if (add_slot(t, s->name, (uint32_t)(off - t->off)))
				return lb_fail(r, BML_LOAD_ENV, "out of memory");
		}
	}
	return 0;
}

/* Every program in exactly one slot, and each slot bound to its program's attach and structop rows. All problems are
 * named in one message. */
static int bind(const struct bml_elf *e, const struct bml_elf_sym *syms, size_t ns, const struct bml_requirements *req,
		const struct lb_sop_tables *ts, struct bml_load_result *r)
{
	struct bml_buf b = {0};
	for (size_t i = 0; i < ns; i++) {
		if (BML_ST_TYPE(syms[i].info) != BML_STT_FUNC || !is_prog_sec(e, syms[i].shndx))
			continue;
		size_t c = 0;
		for (size_t t = 0; t < ts->n; t++)
			for (size_t k = 0; k < ts->t[t].n_slots; k++)
				c += !strcmp(ts->t[t].slots[k].prog, syms[i].name);
		if (c != 1)
			bml_buf_addf(&b, "%sprogram %s is in %zu slots%s", b.len ? "; " : "", syms[i].name, c, c ? "" : " (libbpf would not load it)");
	}
	for (size_t t = 0; t < ts->n; t++)
		for (size_t k = 0; k < ts->t[t].n_slots; k++) {
			const struct lb_sop_table *tb = &ts->t[t];
			const struct lb_sop_slot *s = &tb->slots[k];
			const struct bml_attach *a = attach_of(req, s->prog);
			const char *sep = b.len ? "; " : "";
			if (!s->member)
				continue; /* a slot skipped by the mutant */
			if (!a)
				bml_buf_addf(&b, "%sprogram %s has no trace_struct_ops attach row", sep, s->prog);
			else if (strcmp(a->target.p, tb->name))
				bml_buf_addf(&b, "%sprogram %s is in a slot of struct_ops map %s, but its attach row names %s", sep, s->prog, tb->name, a->target.p);
			else if (strcmp(a->sop_member.p, s->member) || strcmp(a->sop_struct.p, tb->type))
				bml_buf_addf(&b, "%sprogram %s is in member %s.%s of struct_ops map %s, but its structop row names %s.%s", sep, s->prog, tb->type,
					     s->member, tb->name, a->sop_struct.p, a->sop_member.p);
		}
	if (!b.len || SLOTS_OK) {
		free(bml_buf_take(&b));
		return 0;
	}
	char *m = bml_buf_take(&b);
	int rc = lb_fail(r, BML_LOAD_SHAPE, "struct_ops slots: %s", m ? m : "out of memory");
	free(m);
	return rc;
}

int lb_sop_slots(const uint8_t *elf, size_t len, const struct bml_requirements *req, struct lb_sop_tables *out, struct bml_load_result *r)
{
	memset(out, 0, sizeof *out);
	struct bml_elf e;
	char *err = NULL;
	if (bml_elf_open(elf, len, &e, &err)) {
		free(err);
		return lb_fail(r, BML_LOAD_SHAPE, "the ELF cannot be read");
	}
	struct bml_elf_sym *syms = NULL;
	size_t ns = 0, li = 0, nl = 0;
	struct btf *b = NULL;
	int rc = -1;
	for (size_t i = 0; i < e.n_sections; i++)
		if (!strcmp(e.sections[i].name, LINK))
			li = i, nl++;
	if (bml_elf_symbols(&e, BML_SHT_SYMTAB, &syms, &ns, &err)) {
		lb_fail(r, BML_LOAD_SHAPE, "the ELF has no symbol table");
		goto out;
	}
	if (nl > 1) {
		lb_fail(r, BML_LOAD_SHAPE, "the ELF has %zu %s sections", nl, LINK);
		goto out;
	}
	if (nl == 1) {
		const struct bml_elf_shdr *bs = bml_elf_section(&e, ".BTF");
		const uint8_t *bd, *sd;
		size_t bl, sl;
		if (!bs || bml_elf_section_data(&e, bs, &bd, &bl, &err) || !(b = btf__new(bd, (uint32_t)bl))) {
			b = NULL;
			lb_fail(r, BML_LOAD_SHAPE, "the ELF .BTF cannot be read for the struct_ops tables");
			goto out;
		}
		if (bml_elf_section_data(&e, &e.sections[li], &sd, &sl, &err)) {
			lb_fail(r, BML_LOAD_SHAPE, "%s cannot be read", LINK);
			goto out;
		}
		if (read_tables(elf, len, b, &e.sections[li], out, r))
			goto out;
		for (size_t i = 0; i < ns; i++) { /* every symbol in the section is a table */
			int ok = BML_ST_TYPE(syms[i].info) == 3 /* STT_SECTION */ || syms[i].shndx != li;
			for (size_t t = 0; t < out->n && !ok; t++)
				ok = BML_ST_TYPE(syms[i].info) == BML_STT_OBJECT && !strcmp(out->t[t].name, syms[i].name);
			if (!ok) {
				lb_fail(r, BML_LOAD_SHAPE, "symbol %s in %s is not a struct_ops table", syms[i].name, LINK);
				goto out;
			}
		}
		if (read_slots(&e, li, syms, ns, out, r))
			goto out;
		const struct btf_type *d = btf__type_by_id(b, (uint32_t)btf__find_by_name_kind(b, LINK, BTF_KIND_DATASEC));
		const struct btf_var_secinfo *vs = btf_var_secinfos(d);
		for (size_t t = 0; t < out->n; t++) {
			uint32_t sid = 0; /* the VAR's type, typedefs and modifiers skipped (0 if unreadable: a SHAPE stop below) */
			for (uint16_t i = 0; i < btf_vlen(d); i++) {
				const struct btf_type *v = btf__type_by_id(b, vs[i].type);
				int id = btf__resolve_type(b, v->type);
				if (!strcmp(btf__name_by_offset(b, v->name_off), out->t[t].name) && id > 0)
					sid = (uint32_t)id;
			}
			if (lb_sop_table_members(b, sid, sd + out->t[t].off, out->t[t].size, &out->t[t], r))
				goto out;
		}
	}
	rc = bind(&e, syms, ns, req, out, r);
out:
	free(err);
	free(syms);
	btf__free(b);
	bml_elf_close(&e);
	if (rc)
		lb_sop_tables_free(out);
	return rc;
}

int lb_check_struct_ops(const uint8_t *elf, size_t len, const struct bml_requirements *req, struct bml_load_result *r)
{
	struct lb_sop_tables ts;
	if (lb_sop_slots(elf, len, req, &ts, r))
		return -1;
	if (!ts.n)
		return 0;
	struct btf *kern = btf__load_vmlinux_btf();
	int rc = kern ? lb_sop_members(&ts, kern, r) : lb_fail(r, BML_LOAD_ENV, "the vmlinux BTF cannot be read for the struct_ops check");
	btf__free(kern);
	lb_sop_tables_free(&ts);
	return rc;
}
