


#include "btf/structops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/layout.h"
#include "elf/elf.h"
#include "util/gostr.h"

struct kv {
	const char *k;
	char *v;
};

static int put(struct kv **a, size_t *n, const char *k, char *v)
{
	for (size_t i = 0; i < *n; i++)
		if (!strcmp((*a)[i].k, k)) {
			free((*a)[i].v);
			(*a)[i].v = v;
			return 0;
		}
	struct kv *na = realloc(*a, (*n + 1) * sizeof **a);
	if (!na) {
		free(v);
		return -1;
	}
	*a = na;
	(*a)[(*n)++] = (struct kv){k, v};
	return 0;
}

static int cmp_kv(const void *x, const void *y)
{
	return strcmp(((const struct kv *)x)->k, ((const struct kv *)y)->k);
}

static void kv_free(struct kv *a, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(a[i].v);
	free(a);
}


static uint32_t size_of(const struct lbtf *b, uint32_t id, int d)
{
	if (d > 64)
		return 0;
	const struct ltype *t = btf_layout_resolve(b, id);
	if (t->kind == 2)
		return 8;
	if (t->kind == 3)
		return size_of(b, t->type_id, d + 1) * t->nelems;
	return t->size;
}

static char *fmt(const char *f, const char *a, const char *b, const char *c)
{
	struct bml_buf o = {0};
	bml_buf_addf(&o, f, a, b ? b : "", c ? c : "");
	return bml_buf_take(&o);
}

void bml_struct_ops_tables_free(struct bml_struct_ops_table *t, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free(t[i].var), free(t[i].spelling);
	free(t);
}

static int add_table(struct bml_struct_ops_table **out, size_t *n, const char *var, char *sp)
{
	for (size_t i = 0; i < *n; i++)
		if (!strcmp((*out)[i].var, var)) {
			free((*out)[i].spelling);
			(*out)[i].spelling = sp;
			return 0;
		}
	struct bml_struct_ops_table *na = realloc(*out, (*n + 1) * sizeof **out);
	if (!na) {
		free(sp);
		return -1;
	}
	*out = na;
	(*out)[*n].var = strdup(var);
	(*out)[*n].spelling = sp;
	return (*out)[(*n)++].var ? 0 : -1;
}

int bml_struct_ops_tables(const void *data, size_t len, struct bml_struct_ops_table **out, size_t *n, char **err)
{
	*out = NULL, *n = 0, *err = NULL;
	struct bml_elf e;
	if (bml_elf_open(data, len, &e, err))
		return -1;
	int rc = -1, any = 0;
	struct lbtf b = {0};
	struct bml_elf_sym *syms = NULL;
	size_t nsyms = 0;
	for (size_t i = 0; i < e.n_sections; i++)
		any |= !strcmp(e.sections[i].name, ".struct_ops.link") || !strcmp(e.sections[i].name, ".struct_ops");
	if (!any) {
		bml_elf_close(&e);
		return 0;
	}
	if (btf_layout_parse(data, len, &b, err))
		goto out;
	char *serr = NULL;
	if (bml_elf_symbols(&e, BML_SHT_SYMTAB, &syms, &nsyms, &serr)) {
		*err = fmt("the ELF symbol table cannot be read: %s", serr, NULL, NULL);
		free(serr);
		goto out;
	}
	for (size_t idx = 0; idx < e.n_sections; idx++) {
		const struct bml_elf_shdr *sec = &e.sections[idx];
		if (strcmp(sec->name, ".struct_ops.link") != 0 && strcmp(sec->name, ".struct_ops") != 0)
			continue;
		const uint8_t *sd;
		size_t sl;
		char *de = NULL;
		if (bml_elf_section_data(&e, sec, &sd, &sl, &de)) {
			*err = fmt("%s cannot be read: %s", sec->name, de, NULL);
			free(de);
			goto out;
		}
		struct kv *rels = NULL;
		size_t nrel = 0;
		char **keys = NULL;
		size_t nkeys = 0;
		int fail = 0;
		for (size_t r = 0; r < e.n_sections && !fail; r++) {
			const struct bml_elf_shdr *rs = &e.sections[r];
			if (rs->type != BML_SHT_REL || rs->info != idx)
				continue;
			const uint8_t *rd;
			size_t rl;
			if (bml_elf_section_data(&e, rs, &rd, &rl, &de)) {
				*err = fmt("%s cannot be read: %s", rs->name, de, NULL);
				free(de);
				fail = 1;
				break;
			}
			for (size_t i = 0; i + 16 <= rl; i += 16) {
				uint64_t off = bml_elf_u64(&e, rd + i), info = bml_elf_u64(&e, rd + i + 8);
				uint64_t si = info >> 32;
				char ks[32];
				snprintf(ks, sizeof ks, "%llu", (unsigned long long)off);
				if (si < 1 || si > nsyms) {
					char ss[32];
					snprintf(ss, sizeof ss, "%llu", (unsigned long long)si);
					*err = fmt("%s: relocation at %s names symbol %s outside the symbol table", rs->name, ks, ss);
					fail = 1;
					break;
				}
				char **nk = realloc(keys, (nkeys + 1) * sizeof *keys);
				if (!nk) {
					fail = 1;
					break;
				}
				keys = nk;
				keys[nkeys] = strdup(ks);
				char *v = strdup(syms[si - 1].name);
				if (!keys[nkeys] || !v || put(&rels, &nrel, keys[nkeys++], v)) {
					free(v);
					fail = 1;
					break;
				}
			}
		}
		for (size_t s = 0; s < nsyms && !fail; s++) {
			const struct bml_elf_sym *sy = &syms[s];
			if (sy->shndx != idx || BML_ST_TYPE(sy->info) != BML_STT_OBJECT)
				continue;
			long vt = -1;
			for (size_t t = 0; t < b.n; t++)
				if (b.t[t].kind == 14 && !strcmp(b.t[t].name, sy->name))
					vt = (long)b.t[t].type_id;
			if (vt < 0) {
				*err = fmt("%s: variable %s has no BTF VAR", sec->name, sy->name, NULL);
				fail = 1;
				break;
			}
			const struct ltype *st = btf_layout_resolve(&b, (uint32_t)vt);
			if (st->kind != 4) {
				*err = fmt("%s: variable %s is not a struct in the BTF", sec->name, sy->name, NULL);
				fail = 1;
				break;
			}
			struct kv *dat = NULL, *ops = NULL;
			size_t nd = 0, no = 0;
			for (uint32_t m = 0; m < st->n_members && !fail; m++) {
				const struct lmember *mb = &st->members[m];
				const struct ltype *mt = btf_layout_resolve(&b, mb->type_id);
				uint64_t pos = sy->value + mb->offset;
				char ks[32];
				snprintf(ks, sizeof ks, "%llu", (unsigned long long)pos);
				if (mt->kind == 2) {
					for (size_t i = nrel; i-- > 0;)
						if (!strcmp(rels[i].k, ks)) {
							char *v = strdup(rels[i].v);
							if (!v || put(&ops, &no, mb->name, v))
								fail = 1;
							break;
						}
				} else if (mt->kind == 3) {
					uint64_t sz = size_of(&b, mb->type_id, 0);
					if (pos + sz > sl) {
						*err = fmt("%s: member %s.%s is outside the section", sec->name, sy->name, mb->name);
						fail = 1;
						break;
					}
					const uint8_t *raw = sd + pos;
					size_t k = 0;
					while (k < sz && raw[k])
						k++;
					char *v = strndup((const char *)raw, k);
					if (!v || put(&dat, &nd, mb->name, v))
						fail = 1;
				}
			}
			if (!fail) {
				if (nd)
					qsort(dat, nd, sizeof *dat, cmp_kv);
				if (no)
					qsort(ops, no, sizeof *ops, cmp_kv);
				struct bml_buf o = {0};
				bml_buf_addf(&o, "type=%s;", st->name);
				for (size_t i = 0; i < nd; i++)
					bml_buf_addf(&o, "%s=%s;", dat[i].k, dat[i].v);
				for (size_t i = 0; i < no; i++)
					bml_buf_addf(&o, "%s=%s;", ops[i].k, ops[i].v);
				char *sp = bml_buf_take(&o);
				if (!sp || add_table(out, n, sy->name, sp))
					fail = 1;
			}
			kv_free(dat, nd);
			kv_free(ops, no);
		}
		kv_free(rels, nrel);
		for (size_t i = 0; i < nkeys; i++)
			free(keys[i]);
		free(keys);
		if (fail) {
			if (!*err)
				*err = strdup("out of memory");
			goto out;
		}
	}
	rc = 0;
out:
	free(syms);
	btf_layout_free(&b);
	bml_elf_close(&e);
	if (rc) {
		bml_struct_ops_tables_free(*out, *n);
		*out = NULL, *n = 0;
	}
	return rc;
}
