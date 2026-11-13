#include "btf/globals.h"

#include <stdlib.h>
#include <string.h>

#include "btf/layout.h"
#include "elf/elf.h"
#include "util/gostr.h"

#define STB_GLOBAL 1
#define ST_BIND(i) ((i) >> 4)
#define R_BPF_64_ABS32 3
#define R_BPF_64_NODYLD32 4

static char *dupe(const char *s)
{
	return strdup(s);
}


static int read_symbols(const struct bml_elf *e, struct bml_elf_sym **syms, size_t *n, char **err)
{
	char *serr = NULL;
	if (bml_elf_symbols(e, BML_SHT_SYMTAB, syms, n, &serr)) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "the ELF symbol table cannot be read: ");
		bml_buf_adds(&b, serr ? serr : "");
		free(serr);
		*err = bml_buf_take(&b);
		return -1;
	}
	return 0;
}

static int cmp_gsym(const void *a, const void *b)
{
	return strcmp(((const struct btf_gsym *)a)->name, ((const struct btf_gsym *)b)->name);
}

int btf_global_symbols(const void *data, size_t len, struct btf_gsym **out, size_t *n, char **err)
{
	*out = NULL;
	*n = 0;
	*err = NULL;
	struct bml_elf e;
	if (bml_elf_open(data, len, &e, err))
		return -1;
	struct bml_elf_sym *syms = NULL;
	size_t ns = 0;
	int rc = -1;
	if (read_symbols(&e, &syms, &ns, err))
		goto done;
	struct btf_gsym *g = calloc(ns + 1, sizeof(*g));
	if (!g) {
		*err = dupe("out of memory");
		goto done;
	}
	size_t k = 0;
	for (size_t i = 0; i < ns; i++) {
		const struct bml_elf_sym *s = &syms[i];
		if (BML_ST_TYPE(s->info) != BML_STT_OBJECT || ST_BIND(s->info) != STB_GLOBAL || s->shndx >= e.n_sections)
			continue;
		const char *sn = e.sections[s->shndx].name;
		const char *sec = !strcmp(sn, ".rodata") ? ".rodata" : !strcmp(sn, ".bss") ? ".bss" : NULL;
		if (!sec)
			continue;
		size_t j = 0;
		while (j < k && strcmp(g[j].name, s->name))
			j++;
		g[j].name = s->name;
		g[j].section = sec;
		if (j == k)
			k++;
	}
	qsort(g, k, sizeof(*g), cmp_gsym);
	*out = g;
	*n = k;
	rc = 0;
done:
	free(syms);
	bml_elf_close(&e);
	return rc;
}

struct brel {
	uint32_t off, sym, rtype;
};


static int btf_relocs(const struct bml_elf *e, struct brel **out, size_t *n, char **err)
{
	*out = NULL;
	*n = 0;
	size_t btf = 0;
	int have = 0;
	for (size_t i = 0; i < e->n_sections && !have; i++)
		if (!strcmp(e->sections[i].name, ".BTF"))
			btf = i, have = 1;
	size_t cap = 0;
	for (size_t i = 0; i < e->n_sections; i++) {
		const struct bml_elf_shdr *s = &e->sections[i];
		if (s->type != BML_SHT_REL || !have || s->info >= e->n_sections || s->info != btf)
			continue;
		if (!e->is64) {
			struct bml_buf b = {0};
			bml_buf_addf(&b, "%s: not ELF64", s->name);
			*err = bml_buf_take(&b);
			return -1;
		}
		const uint8_t *d;
		size_t len;
		char *derr = NULL;
		if (bml_elf_section_data(e, s, &d, &len, &derr)) {
			struct bml_buf b = {0};
			bml_buf_addf(&b, "cannot read %s: %s", s->name, derr ? derr : "");
			free(derr);
			*err = bml_buf_take(&b);
			return -1;
		}
		for (size_t k = 0; k + 16 <= len; k += 16) {
			uint64_t off = bml_elf_u64(e, d + k), info = bml_elf_u64(e, d + k + 8);
			struct brel r = {(uint32_t)off, (uint32_t)(info >> 32), (uint32_t)info};
			size_t j = 0;
			while (j < *n && (*out)[j].off != r.off)
				j++;
			if (j == *n) {
				if (*n == cap) {
					size_t nc = cap ? cap * 2 : 16;
					struct brel *np = realloc(*out, nc * sizeof(*np));
					if (!np) {
						*err = dupe("out of memory");
						return -1;
					}
					*out = np;
					cap = nc;
				}
				(*n)++;
			}
			(*out)[j] = r;
		}
	}
	return 0;
}


static void add_bind(struct bml_buf *b, unsigned v)
{
	static const struct {
		unsigned i;
		const char *s;
	} names[] = {{0, "STB_LOCAL"}, {1, "STB_GLOBAL"}, {2, "STB_WEAK"}, {10, "STB_LOOS"}, {12, "STB_HIOS"}, {13, "STB_LOPROC"}, {15, "STB_HIPROC"}};
	size_t nn = sizeof(names) / sizeof(names[0]);
	for (size_t i = 0; i < nn; i++)
		if (names[i].i == v) {
			bml_buf_adds(b, names[i].s);
			return;
		}
	for (size_t j = nn; j-- > 0;)
		if (names[j].i < v) {
			bml_buf_addf(b, "%s+%u", names[j].s, v - names[j].i);
			return;
		}
	bml_buf_addf(b, "%u", v);
}


#define PROB(...)                                                                                                                  \
	do {                                                                                                                       \
		if (o->len)                                                                                                        \
			bml_buf_adds(o, "; ");                                                                                     \
		bml_buf_addf(o, __VA_ARGS__);                                                                                      \
	} while (0)


static void check_global(const struct bml_elf *e, const struct bml_elf_sym *syms, size_t ns, const struct lbtf *b, const struct brel *rels,
			 size_t nr, const char *name, const char *section, uint32_t size, int is_signed, struct bml_buf *o)
{
	const struct bml_elf_sym *sym = NULL;
	for (size_t i = 0; i < ns; i++) {
		if (!strcmp(syms[i].name, name) && BML_ST_TYPE(syms[i].info) == BML_STT_OBJECT) {
			if (sym) {
				PROB("global %s: the ELF has two symbols of that name", name);
				return;
			}
			sym = &syms[i];
		}
	}
	if (!sym) {
		PROB("global %s: the ELF has no OBJECT symbol of that name", name);
		return;
	}
	if (ST_BIND(sym->info) != STB_GLOBAL) {
		PROB("global %s: the symbol binding is ", name);
		add_bind(o, ST_BIND(sym->info));
		bml_buf_adds(o, " (not GLOBAL)");
	}
	const struct bml_elf_shdr *sec = sym->shndx < e->n_sections ? &e->sections[sym->shndx] : NULL;
	if (!sec || strcmp(sec->name, section))
		PROB("global %s: the symbol is in section %s (declared %s)", name, sec ? sec->name : "?", section);
	if (sym->size != (uint64_t)size)
		PROB("global %s: the symbol size is %llu (declared %u)", name, (unsigned long long)sym->size, size);

	const struct ltype *ds = NULL;
	for (size_t i = 0; i < b->n; i++) {
		if (b->t[i].kind == 15 && !strcmp(b->t[i].name, section)) {
			if (ds) {
				PROB("global %s: the BTF has two DATASECs %s", name, section);
				return;
			}
			ds = &b->t[i];
		}
	}
	if (!ds) {
		PROB("global %s: the BTF has no DATASEC %s", name, section);
		return;
	}
	if (sec && ds->size != 0 && (uint64_t)ds->size != sec->size)
		PROB("global %s: DATASEC %s has size %u (neither 0 nor the ELF section size %llu)", name, section, ds->size,
		     (unsigned long long)sec->size);
	const struct lsecinfo *vsi = NULL;
	for (uint32_t i = 0; i < ds->n_secinfo; i++) {
		uint32_t id = ds->secinfo[i].type_id;
		if (id < b->n && b->t[id].kind == 14 && !strcmp(b->t[id].name, name))
			vsi = &ds->secinfo[i];
	}
	if (!vsi) {
		PROB("global %s: DATASEC %s has no VAR %s", name, section, name);
		return;
	}
	uint64_t off = vsi->offset;
	const struct brel *r = NULL;
	for (size_t i = 0; i < nr; i++)
		if (rels[i].off == vsi->pos)
			r = &rels[i];
	if (r) {
		if (r->rtype != R_BPF_64_ABS32 && r->rtype != R_BPF_64_NODYLD32)
			PROB("global %s: the DATASEC offset relocation has type %u (not R_BPF_64_ABS32 / R_BPF_64_NODYLD32)", name, r->rtype);
		else if (r->sym == 0 || r->sym > ns || strcmp(syms[r->sym - 1].name, name))
			PROB("global %s: the DATASEC offset relocation refers to symbol %s", name,
			     (r->sym != 0 && r->sym <= ns) ? syms[r->sym - 1].name : "?");
		else
			off += syms[r->sym - 1].value;
	}
	if (off != sym->value)
		PROB("global %s: the DATASEC offset is %llu (raw %u + .rel.BTF; the ELF symbol is at %llu)", name, (unsigned long long)off,
		     vsi->offset, (unsigned long long)sym->value);
	if ((uint64_t)vsi->size != sym->size)
		PROB("global %s: the DATASEC size is %u (the ELF symbol has %llu)", name, vsi->size, (unsigned long long)sym->size);
	if (sec && (uint64_t)vsi->offset + vsi->size > sec->size)
		PROB("global %s: the DATASEC range [%u, %u) exceeds the ELF section size %llu", name, vsi->offset,
		     (uint32_t)(vsi->offset + vsi->size), (unsigned long long)sec->size);
	const struct ltype *vt = btf_layout_resolve(b, b->t[vsi->type_id].type_id);
	if (vt->kind != 1) {
		PROB("global %s: the VAR type (kind %u) is not INT", name, vt->kind);
	} else {
		if (vt->size != size)
			PROB("global %s: the VAR type %s has size %u (declared %u)", name, vt->name, vt->size, size);
		if (!!vt->is_signed != !!is_signed)
			PROB("global %s: the VAR type %s has signed=%s (declared %s)", name, vt->name, vt->is_signed ? "true" : "false",
			     is_signed ? "true" : "false");
	}
}

char *btf_global_problems(const void *data, size_t len, const char *name, const char *section, uint32_t size, int is_signed, char **err)
{
	*err = NULL;
	struct bml_elf e;
	if (bml_elf_open(data, len, &e, err))
		return NULL;
	struct bml_elf_sym *syms = NULL;
	size_t ns = 0;
	struct lbtf b = {0};
	int have_btf = 0;
	struct brel *rels = NULL;
	size_t nr = 0;
	char *res = NULL;
	if (read_symbols(&e, &syms, &ns, err))
		goto done;
	if (btf_layout_parse(data, len, &b, err))
		goto done;
	have_btf = 1;
	if (btf_relocs(&e, &rels, &nr, err))
		goto done;
	struct bml_buf o = {0};
	check_global(&e, syms, ns, &b, rels, nr, name, section, size, is_signed, &o);
	res = bml_buf_take(&o);
done:
	free(rels);
	if (have_btf)
		btf_layout_free(&b);
	free(syms);
	bml_elf_close(&e);
	return res;
}

int btf_global_offset(const void *data, size_t len, const char *name, uint64_t *off, uint64_t *size)
{
	struct bml_elf e;
	char *err = NULL;
	if (bml_elf_open(data, len, &e, &err)) {
		free(err);
		return -1;
	}
	struct bml_elf_sym *syms = NULL;
	size_t ns = 0;
	int rc = -1;
	if (bml_elf_symbols(&e, BML_SHT_SYMTAB, &syms, &ns, &err) == 0) {
		for (size_t i = 0; i < ns && rc; i++)
			if (!strcmp(syms[i].name, name) && BML_ST_TYPE(syms[i].info) == BML_STT_OBJECT) {
				*off = syms[i].value;
				*size = syms[i].size;
				rc = 0;
			}
	}
	free(err);
	free(syms);
	bml_elf_close(&e);
	return rc;
}
