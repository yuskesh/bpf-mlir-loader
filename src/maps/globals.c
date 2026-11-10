
#include "maps/internal.h"

#include <stdlib.h>
#include <string.h>

#include "btf/globals.h"
#include "util/gostr.h"
#include "util/mutation.h"


static int global_type(const char *s, int *is_signed)
{
	if (s[0] != 'u' && s[0] != 'i')
		return 0;
	*is_signed = s[0] == 'i';
	int bits = 0;
	const char *p = s + 1;
	if (p[0] == '8')
		bits = 8, p += 1;
	else if (p[0] == '1' && p[1] == '6')
		bits = 16, p += 2;
	else if (p[0] == '3' && p[1] == '2')
		bits = 32, p += 2;
	else if (p[0] == '6' && p[1] == '4')
		bits = 64, p += 2;
	else
		return 0;
	if (p[0] == 'b' && p[1] == 'e')
		p += 2;
	return *p ? 0 : bits;
}

struct gidx {
	const struct bml_global_decl *d;
	size_t idx;
};

static int cmp_gidx(const void *a, const void *b)
{
	const struct gidx *x = a, *y = b;
	int c = strcmp(x->d->name, y->d->name);
	if (c)
		return c;
	return x->idx < y->idx ? -1 : (x->idx > y->idx);
}

int md_check_globals(const void *elf, size_t elf_len, const struct bml_map_decls *d, struct bml_map_problems *out)
{
	if (!d->has_globals || (d->n_globals == 0 && BML_MUT("maps.globals_empty_is_nil")))
		return 0;
	if (!elf)
		return md_add(out, NULL, "format",
			      md_xstrdup("globals are declared, but only the requirements section was given (the global check needs the ELF)"), NULL);
	struct btf_gsym *eg = NULL;
	size_t neg = 0;
	char *err = NULL;
	if (btf_global_symbols(elf, elf_len, &eg, &neg, &err)) {
		char *m = md_fmts("the ELF cannot be read for the global check: %s", err ? err : "");
		free(err);
		return md_add(out, NULL, "format", m, NULL);
	}
	int rc = 0;
	struct gidx *s = calloc(d->n_globals + 1, sizeof(*s));
	char *seen = calloc(d->n_globals + 1, 1);
	if (!s || !seen) {
		rc = -1;
		goto done;
	}
	for (size_t i = 0; i < d->n_globals; i++)
		s[i] = (struct gidx){&d->globals[i], i};
	qsort(s, d->n_globals, sizeof(*s), cmp_gidx);
	for (size_t i = 0; i < d->n_globals && rc == 0; i++) {
		const struct bml_global_decl *g = s[i].d;
		int already = 0;
		for (size_t j = 0; j < i; j++)
			if (seen[j] && !strcmp(s[j].d->name, g->name))
				already = 1;
		int is_signed = 0, bits = global_type(g->type, &is_signed);
		if (!g->name[0]) {
			rc = md_add(out, NULL, "decl", md_xstrdup("a global without a name"), NULL);
			continue;
		}
		if (already) {
			rc = md_add(out, md_xstrdup(g->name), "decl", md_xstrdup("global declared twice"), NULL);
			continue;
		}
		seen[i] = 1;
		if (strcmp(g->section, "rodata") && strcmp(g->section, "bss")) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "global section ");
			bml_buf_add_goquote(&b, g->section, strlen(g->section));
			bml_buf_adds(&b, " (want rodata or bss)");
			rc = md_add(out, md_xstrdup(g->name), "decl", bml_buf_take(&b), NULL);
			continue;
		}
		if (!bits) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "global type ");
			bml_buf_add_goquote(&b, g->type, strlen(g->type));
			bml_buf_adds(&b, " (want an integer spelling u8 … i64)");
			rc = md_add(out, md_xstrdup(g->name), "decl", bml_buf_take(&b), NULL);
			continue;
		}
		char *spell = md_fmts("%s %s", g->section, g->type);
		int in_elf = 0;
		for (size_t k = 0; k < neg; k++)
			if (!strcmp(eg[k].name, g->name))
				in_elf = 1;
		if (!in_elf) {
			rc = md_add(out, md_xstrdup(g->name), "global_missing_in_elf", spell, NULL);
			continue;
		}
		char sec[8];
		strcpy(sec, g->section[0] == 'r' ? ".rodata" : ".bss");
		char *ps = btf_global_problems(elf, elf_len, g->name, sec, (uint32_t)bits / 8, is_signed, &err);
		if (!ps && err) {
			free(spell);
			char *m = md_fmts("the ELF cannot be read for the global check: %s", err);
			free(err);
			err = NULL;
			rc = md_add(out, md_xstrdup(g->name), "format", m, NULL);
			continue;
		}
		if (!ps) {
			free(spell);
			rc = -1;
			continue;
		}
		if (ps[0]) {
			rc = md_add(out, md_xstrdup(g->name), "global", spell, ps);
		} else {
			free(spell);
			free(ps);
		}
	}
	if (rc == 0 && (!d->allow_undeclared_globals || BML_MUT("maps.globals_always_bidirectional"))) {
		for (size_t k = 0; k < neg && rc == 0; k++) {
			int found = 0;
			for (size_t i = 0; i < d->n_globals; i++)
				if (seen[i] && !strcmp(s[i].d->name, eg[k].name))
					found = 1;
			if (!found)
				rc = md_add(out, md_xstrdup(eg[k].name), "global_undeclared", NULL, md_xstrdup(eg[k].section + 1));
		}
	}
done:
	free(s);
	free(seen);
	free(eg);
	return rc;
}
