

#include "req/from_elf.h"

#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"

#define PREFIX "fentry.s/"

static int is_sleepable_section(const char *s)
{
	return !strncmp(s, PREFIX, sizeof PREFIX - 1);
}

static int declared(const struct bml_requirements *r, const char *name)
{
	for (size_t i = 0; i < r->n_programs; i++)
		if (!strcmp(r->programs[i].symbol.p, name))
			return 1;
	return 0;
}

static const struct bml_attach *sleepable_row(const struct bml_requirements *r, const char *prog)
{
	const struct bml_attach *last = NULL;
	for (size_t i = 0; i < r->n_attaches; i++)
		if (r->attaches[i].sleepable && !strcmp(r->attaches[i].program.p, prog))
			last = &r->attaches[i];
	return last;
}


static int name_held(const struct bml_elf *e, const char *holds, const char *name)
{
	for (size_t i = 0; i < e->n_sections; i++)
		if (holds[i] && !strcmp(e->sections[i].name, name))
			return 1;
	return 0;
}

static char *fail(const char *fmt, const char *a, const char *b, const char *c, const char *d)
{
	struct bml_buf x = {0};
	for (const char *p = fmt; *p; p++) {
		if (p[0] == '%' && p[1] == 'q') {
			const char *v = a;
			a = b, b = c, c = d, d = NULL;
			bml_buf_add_goquote(&x, v, strlen(v));
			p++;
		} else if (p[0] == '%' && p[1] == 's') {
			const char *v = a;
			a = b, b = c, c = d, d = NULL;
			bml_buf_adds(&x, v);
			p++;
		} else {
			bml_buf_addf(&x, "%c", *p);
		}
	}
	return bml_buf_take(&x);
}


static const char *func_section(const struct bml_elf *e, const struct bml_elf_sym *s)
{
	if (BML_ST_TYPE(s->info) != BML_STT_FUNC || s->shndx == BML_SHN_UNDEF || s->shndx >= e->n_sections)
		return NULL;
	return e->sections[s->shndx].name;
}

int bml_req_check_sleepable_sections(const struct bml_elf *e, const struct bml_requirements *r, char **err)
{
	if (BML_MUT("from_elf.sleepable_no_check"))
		return 0;
	int has = 0;
	for (size_t i = 0; i < r->n_attaches; i++)
		has |= r->attaches[i].sleepable;
	for (size_t i = 0; i < e->n_sections; i++)
		has |= is_sleepable_section(e->sections[i].name);
	if (!has)
		return 0;
	struct bml_elf_sym *syms = NULL;
	size_t ns = 0;
	char *serr = NULL;
	if (bml_elf_symbols(e, BML_SHT_SYMTAB, &syms, &ns, &serr)) {
		*err = fail("sleepable: reading the symbol table: %s", serr ? serr : "", NULL, NULL, NULL);
		free(serr);
		return -1;
	}
	int rc = -1;
	char *holds = calloc(e->n_sections + 1, 1);
	if (!holds) {
		*err = strdup("out of memory");
		goto out;
	}
	/* CONTRACT: every FUNC in a fentry.s/ section must be a declared program (so a renamed entry is not missed) */
	for (size_t i = 0; i < ns; i++) {
		const char *sec = func_section(e, &syms[i]);
		if (!sec || !is_sleepable_section(sec))
			continue;
		if (!declared(r, syms[i].name)) {
			*err = fail("sleepable: function %q in section %q (loaded with BPF_F_SLEEPABLE) is not a program declared in the requirements", syms[i].name, sec, NULL, NULL);
			goto out;
		}
		holds[syms[i].shndx] = 1;
	}
	for (size_t i = 0; i < e->n_sections; i++)
		if (is_sleepable_section(e->sections[i].name) && !name_held(e, holds, e->sections[i].name)) {
			*err = fail("sleepable: section %q holds no function declared as a program in the requirements", e->sections[i].name, NULL, NULL, NULL);
			goto out;
		}

	for (size_t p = 0; p < r->n_programs; p++) {
		const char *name = r->programs[p].symbol.p, *sec = NULL;
		for (size_t i = 0; i < ns; i++) {
			const char *s = func_section(e, &syms[i]);
			if (s && !strcmp(syms[i].name, name))
				sec = s;
		}
		if (!sec || !is_sleepable_section(sec))
			continue;
		const struct bml_attach *a = sleepable_row(r, name);
		if (!a) {
			*err = fail("sleepable: program %s is in section %q (loaded with BPF_F_SLEEPABLE) but the requirements have no sleepable row for it", name, sec, NULL, NULL);
			goto out;
		}
		size_t tn = a->target.len;
		if (strlen(sec) != sizeof PREFIX - 1 + tn || memcmp(sec + sizeof PREFIX - 1, a->target.p, tn)) {
			struct bml_buf w = {0};
			bml_buf_adds(&w, PREFIX);
			bml_buf_adds(&w, a->target.p);
			char *want = bml_buf_take(&w);
			*err = fail("sleepable: program %s is in section %q but its trace_fentry attach row names %q (want section %q)", name, sec, a->target.p, want ? want : "");
			free(want);
			goto out;
		}
	}

	for (size_t i = 0; i < r->n_attaches; i++) {
		const struct bml_attach *a = &r->attaches[i];
		if (!a->sleepable)
			continue;
		const char *sec = NULL;
		for (size_t k = 0; k < ns; k++) {
			const char *s = func_section(e, &syms[k]);
			if (s && !strcmp(syms[k].name, a->program.p))
				sec = s;
		}
		if (!sec) {
			*err = fail("sleepable: the sleepable row names program %s, which has no FUNC in the object", a->program.p, NULL, NULL, NULL);
			goto out;
		}
		if (!is_sleepable_section(sec)) {
			*err = fail("sleepable: the sleepable row for program %s (attach %s) but the program is in section %q, not fentry.s/<function>", a->program.p, a->target.p, sec, NULL);
			goto out;
		}
	}
	rc = 0;
out:
	free(holds);
	free(syms);
	return rc;
}
