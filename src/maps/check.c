#include "maps/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/layout.h"
#include "btf/structops.h"
#include "json/json.h"
#include "util/gostr.h"
#include "util/mutation.h"

char *md_xstrdup(const char *s)
{
	return strdup(s ? s : "");
}

char *md_fmts(const char *f, ...) __attribute__((format(printf, 1, 2)));
char *md_fmts(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	int k = vsnprintf(NULL, 0, f, ap);
	va_end(ap);
	char *p = k >= 0 ? malloc((size_t)k + 1) : NULL;
	if (!p)
		return NULL;
	va_start(ap, f);
	vsnprintf(p, (size_t)k + 1, f, ap);
	va_end(ap);
	return p;
}


void bml_map_problems_free(struct bml_map_problems *v)
{
	for (size_t i = 0; i < v->n; i++) {
		free(v->p[i].map);
		free(v->p[i].declared);
		free(v->p[i].elf);
	}
	free(v->p);
	memset(v, 0, sizeof(*v));
}


int md_add(struct bml_map_problems *v, char *map, const char *field, char *declared, char *elf)
{
	if (v->n == v->cap) {
		size_t nc = v->cap ? v->cap * 2 : 8;
		struct bml_map_problem *np = realloc(v->p, nc * sizeof(*np));
		if (!np) {
			free(map), free(declared), free(elf);
			return -1;
		}
		v->p = np;
		v->cap = nc;
	}
	struct bml_map_problem *p = &v->p[v->n++];
	p->map = map ? map : md_xstrdup("");
	p->field = field;
	p->declared = declared ? declared : md_xstrdup("");
	p->elf = elf ? elf : md_xstrdup("");
	return (p->map && p->declared && p->elf) ? 0 : -1;
}

char *bml_map_problem_string(const struct bml_map_problem *p)
{
	const char *f = p->field;
	if (!strcmp(f, "missing_in_elf"))
		return md_fmts("map %s: declared (%s), but the ELF has no such map", p->map, p->declared);
	if (!strcmp(f, "undeclared"))
		return md_fmts("map %s: the ELF holds it (%s), but it is not declared", p->map, p->elf);
	if (!strcmp(f, "flags_undeclared"))
		return md_fmts("map %s: flags are not declared, but the ELF map has flags %s (omit flags only for maps whose flags are 0)", p->map, p->elf);
	if (!strcmp(f, "decl") || !strcmp(f, "format"))
		return md_fmts("map %s: %s", p->map, p->declared);
	if (!strcmp(f, "struct_ops"))
		return md_fmts("map %s: struct_ops table declared %s, but the ELF has %s", p->map, p->declared, p->elf);
	if (!strcmp(f, "inner"))
		return md_fmts("map %s: inner map template declared %s, but the ELF has %s", p->map, p->declared, p->elf);
	if (!strcmp(f, "record"))
		return md_fmts("%s: the same name with a different layout — declared %s, but the ELF BTF has %s", p->map, p->declared, p->elf);
	if (!strcmp(f, "record_missing"))
		return md_fmts("%s: declared (%s), but the ELF BTF has no such struct", p->map, p->declared);
	if (!strcmp(f, "global"))
		return md_fmts("global %s: declared %s, but the ELF differs: %s", p->map, p->declared, p->elf);
	if (!strcmp(f, "global_missing_in_elf"))
		return md_fmts("global %s: declared (%s), but the ELF has no such global in .rodata / .bss", p->map, p->declared);
	if (!strcmp(f, "global_undeclared"))
		return md_fmts("global %s: the ELF holds it (%s), but it is not declared", p->map, p->elf);
	return md_fmts("map %s: %s is %s in the declaration, but %s in the ELF", p->map, f, p->declared, p->elf);
}
static int streq_str(const char *a, const struct bml_str *s)
{
	size_t n = strlen(a);
	return s->len == n && (n == 0 || memcmp(s->p, a, n) == 0);
}


static int check_struct_ops(const struct bml_map_decl *m, const void *elf, size_t elf_len, struct bml_map_problems *out)
{
	if (!elf)
		return md_add(out, md_xstrdup(m->name), "format",
			      md_xstrdup("struct_ops is declared, but only the requirements section was given (the struct_ops check needs the ELF)"), NULL);
	struct bml_struct_ops_table *t;
	size_t n;
	char *err = NULL;
	if (bml_struct_ops_tables(elf, elf_len, &t, &n, &err)) {
		if (!err)
			return -1;
		int rc = md_add(out, md_xstrdup(m->name), "format", md_fmts("the ELF cannot be read for the struct_ops check: %s", err), NULL);
		free(err);
		return rc;
	}
	const char *got = "-";
	for (size_t i = 0; i < n; i++)
		if (!strcmp(t[i].var, m->name))
			got = t[i].spelling;
	int rc = 0;
	if (strcmp(m->struct_ops, got) != 0)
		rc = md_add(out, md_xstrdup(m->name), "struct_ops", md_xstrdup(m->struct_ops), md_xstrdup(got));
	bml_struct_ops_tables_free(t, n);
	return rc;
}

int bml_check_map_decls(const struct bml_requirements *req, const void *elf, size_t elf_len, const struct bml_map_decls *d,
			struct bml_map_problems *out)
{
	memset(out, 0, sizeof(*out));
	if (req->version < 2) {
		if (md_add(out, NULL, "format", md_fmts("requirements version %d has no map definitions (rebuild the object)", req->version), NULL))
			return -1;
		return 1;
	}
	char *seen = calloc(d->n_maps + 1, 1);
	if (!seen)
		return -1;
#define SEEN(name) seen_name(d, seen, (name))
	for (size_t i = 0; i < d->n_maps; i++) {
		const struct bml_map_decl *m = &d->maps[i];
		int already = 0;
		for (size_t j = 0; j < i; j++)
			if (seen[j] && !strcmp(d->maps[j].name, m->name))
				already = 1;
		int rc = 0;
		if (!m->name[0]) {
			rc = md_add(out, NULL, "decl", md_xstrdup("a declaration without a name"), NULL);
		} else if (already) {
			rc = md_add(out, md_xstrdup(m->name), "decl", md_xstrdup("declared twice"), NULL);
		} else if (!m->kind[0]) {
			seen[i] = 1;
			rc = md_add(out, md_xstrdup(m->name), "decl",
				 md_xstrdup("declared without a kind (the kind is required — the key and value spellings alone do not tell an array from a per-CPU array)"),
				 NULL);
		} else {
			seen[i] = 1;
			const struct bml_map *row = NULL;
			for (size_t k = 0; k < req->n_maps; k++)
				if (streq_str(m->name, &req->maps[k].symbol))
					row = &req->maps[k];
			if (!row) {
				rc = md_add(out, md_xstrdup(m->name), "missing_in_elf", md_xstrdup(m->kind), NULL);
			} else if (!streq_str(m->kind, &row->map_type) && !BML_MUT("maps.kind_continue")) {
				rc = md_add(out, md_xstrdup(m->name), "kind", md_xstrdup(m->kind), md_xstrdup(row->map_type.p));
			} else {
				if (!streq_str(m->kind, &row->map_type))
					rc = md_add(out, md_xstrdup(m->name), "kind", md_xstrdup(m->kind), md_xstrdup(row->map_type.p));
				if (!rc && !streq_str(m->key, &row->key))
					rc = md_add(out, md_xstrdup(m->name), "key", md_xstrdup(m->key), md_xstrdup(row->key.p));
				if (!rc && !streq_str(m->value, &row->value))
					rc = md_add(out, md_xstrdup(m->name), "value", md_xstrdup(m->value), md_xstrdup(row->value.p));
				if (!rc && m->max_entries != row->max_entries)
					rc = md_add(out, md_xstrdup(m->name), "max_entries", md_fmts("%llu", (unsigned long long)m->max_entries),
						 md_fmts("%llu", (unsigned long long)row->max_entries));
				if (!rc && (m->has_flags || BML_MUT("maps.flags_always")) && m->flags != row->flags)
					rc = md_add(out, md_xstrdup(m->name), "flags", md_fmts("%llu", (unsigned long long)m->flags),
						 md_fmts("%llu", (unsigned long long)row->flags));

				if (!rc && !m->has_flags && !BML_MUT("maps.flags_always") && !BML_MUT("maps.flags_omit_unchecked") && row->flags != 0)
					rc = md_add(out, md_xstrdup(m->name), "flags_undeclared", NULL, md_fmts("%llu", (unsigned long long)row->flags));

				if (!rc && m->has_inner) {
					char *decl = md_fmts("kind=%s key=%s value=%s max_entries=%llu flags=%llu", m->inner_kind, m->inner_key, m->inner_value,
							     (unsigned long long)m->inner_max_entries, (unsigned long long)m->inner_flags);
					char *ein = md_xstrdup("-");
					for (size_t k = 0; k < req->n_innermaps; k++) {
						const struct bml_innermap *im = &req->innermaps[k];
						if (streq_str(m->name, &im->outer)) {
							free(ein);
							ein = md_fmts("kind=%s key=%s value=%s max_entries=%llu flags=%llu", im->map_type.p, im->key.p, im->value.p,
								      (unsigned long long)im->max_entries, (unsigned long long)im->flags);
						}
					}
					if (decl && ein && strcmp(decl, ein) != 0)
						rc = md_add(out, md_xstrdup(m->name), "inner", decl, ein);
					else {
						free(decl);
						free(ein);
					}
				}
				if (!rc && m->struct_ops)
					rc = check_struct_ops(m, elf, elf_len, out);
			}
		}
		if (rc) {
			free(seen);
			return -1;
		}
	}
	if (md_check_records(elf, elf_len, d, out) || md_check_globals(elf, elf_len, d, out)) {
		free(seen);
		return -1;
	}
	if (!d->allow_undeclared || BML_MUT("maps.always_bidirectional")) {
		for (size_t k = 0; k < req->n_maps; k++) {
			int s = 0;
			for (size_t i = 0; i < d->n_maps; i++)
				if (seen[i] && streq_str(d->maps[i].name, &req->maps[k].symbol))
					s = 1;
			if (!s && md_add(out, md_xstrdup(req->maps[k].symbol.p), "undeclared", NULL, md_xstrdup(req->maps[k].map_type.p))) {
				free(seen);
				return -1;
			}
		}
	}
	free(seen);
	return out->n ? 1 : 0;
}
