
#include "maps/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/layout.h"
#include "json/json.h"
#include "util/gostr.h"
#include "util/mutation.h"




static const char *skip_dims(const char *s, int allow_zero)
{
	for (;;) {
		if (s[0] != '[')
			return s;
		const char *p = s + 1;
		if (!(allow_zero ? (*p >= '0' && *p <= '9') : (*p >= '1' && *p <= '9')))
			return s;
		p++;
		while (*p >= '0' && *p <= '9')
			p++;
		if (*p != ']')
			return s;
		s = p + 1;
	}
}


static size_t int_spelling(const char *s)
{
	if (s[0] != 'u' && s[0] != 'i')
		return 0;
	if (s[1] == '8')
		return 2;
	if ((s[1] == '1' && s[2] == '6') || (s[1] == '3' && s[2] == '2') || (s[1] == '6' && s[2] == '4'))
		return 3;
	return 0;
}

static int ident(const char *s)
{
	if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_'))
		return 0;
	for (s++; *s; s++)
		if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '_'))
			return 0;
	return 1;
}


static int member_type_ok(const char *s)
{
	if (!strcmp(s, "bpf_spin_lock") || !strcmp(s, "bpf_timer"))
		return 1;
	const char *p = skip_dims(s, 0);
	size_t k = int_spelling(p);
	if (k) {
		p += k;
		if (!strcmp(p, "") || !strcmp(p, "be"))
			return 1;
		return 0;
	}
	return (!strncmp(p, "record:", 7) && ident(p + 7)) || (!strncmp(p, "kptr:", 5) && ident(p + 5));
}


static char *strip_be(const char *s)
{
	const char *p = skip_dims(s, 1);
	size_t k = int_spelling(p);
	if (k && !strcmp(p + k, "be")) {
		char *o = md_xstrdup(s);
		if (o)
			o[strlen(o) - 2] = 0;
		return o;
	}
	return md_xstrdup(s);
}


static const char *nested_record(const char *s)
{
	const char *p = skip_dims(s, 1);
	if (!strncmp(p, "record:", 7) && p[7] && !strchr(p + 7, '\n'))
		return p + 7;
	return NULL;
}


static char *decl_record(const struct bml_record_decl *d)
{
	struct btf_indexed *ms = calloc(d->n_members + 1, sizeof(*ms));
	if (!ms)
		return NULL;
	for (size_t i = 0; i < d->n_members; i++) {
		ms[i].m.name = d->members[i].name;
		ms[i].m.offset = d->members[i].offset;
		ms[i].m.type = BML_MUT("maps.keep_be") ? md_xstrdup(d->members[i].type) : strip_be(d->members[i].type);
		ms[i].idx = i;
	}
	char *s = btf_shape_string(d->size, ms, d->n_members);
	for (size_t i = 0; i < d->n_members; i++)
		free(ms[i].m.type);
	free(ms);
	return s;
}


static char *record_decl_error(const struct bml_record_decl *d)
{
	for (size_t i = 0; i < d->n_members; i++) {
		const struct bml_record_member *m = &d->members[i];
		if (!m->name[0])
			return md_xstrdup("a member without a name");
		for (size_t j = 0; j < i; j++)
			if (!strcmp(d->members[j].name, m->name))
				return md_fmts("member %s is declared twice", m->name);
		for (size_t j = 0; j < i; j++)
			if (d->members[j].offset == m->offset)
				return md_fmts("two members at offset %u", m->offset);
		if (!member_type_ok(m->type)) {
			struct bml_buf b = {0};
			bml_buf_addf(&b, "member %s has an unreadable type ", m->name);
			bml_buf_add_goquote(&b, m->type, strlen(m->type));
			bml_buf_adds(&b, " (u8…i64, [N]T, record:<T>, kptr:<T>, bpf_spin_lock, bpf_timer)");
			return bml_buf_take(&b);
		}
	}
	return NULL;
}

static int cmp_record_name(const void *a, const void *b)
{
	return strcmp((*(const struct bml_record_decl *const *)a)->name, (*(const struct bml_record_decl *const *)b)->name);
}

int md_check_records(const void *elf, size_t elf_len, const struct bml_map_decls *d, struct bml_map_problems *out)
{
	if (d->n_records == 0)
		return 0;
	if (!elf)
		return md_add(out, NULL, "format",
			   md_xstrdup("records are declared, but only the requirements section was given (the record check needs the ELF BTF)"), NULL);
	struct lbtf b;
	char *err = NULL;
	if (btf_layout_parse(elf, elf_len, &b, &err)) {
		char *m = md_fmts("the ELF BTF cannot be read for the record check: %s", err ? err : "");
		free(err);
		return md_add(out, NULL, "format", m, NULL);
	}
	int rc = 0;
	const struct bml_record_decl **names = calloc(d->n_records, sizeof(*names));
	if (!names) {
		btf_layout_free(&b);
		return -1;
	}
	for (size_t i = 0; i < d->n_records; i++)
		names[i] = &d->records[i];
	qsort(names, d->n_records, sizeof(*names), cmp_record_name);
	for (size_t i = 0; i < d->n_records && rc == 0; i++) {
		const struct bml_record_decl *r = names[i];
		char *key = md_fmts("record:%s", r->name);
		if (!r->name[0]) {
			rc = md_add(out, key, "decl", md_xstrdup("a record without a name"), NULL);
			continue;
		}
		char *de = record_decl_error(r);
		if (de) {
			rc = md_add(out, key, "decl", de, NULL);
			continue;
		}
		const char *nest = NULL;
		for (size_t k = 0; k < r->n_members && !nest; k++) {
			const char *t = nested_record(r->members[k].type);
			if (t) {
				int found = 0;
				for (size_t j = 0; j < d->n_records; j++)
					if (!strcmp(d->records[j].name, t))
						found = 1;
				if (!found)
					nest = t;
			}
		}
		if (nest && !BML_MUT("maps.no_closure")) {
			rc = md_add(out, key, "decl", md_fmts("member type record:%s — the nested record %s must be declared in records too", nest, nest), NULL);
			continue;
		}
		char *want = decl_record(r);
		int missing;
		char *got = btf_layout_record(&b, r->name, &missing);
		if (missing) {
			rc = md_add(out, key, "record_missing", want, NULL);
			continue;
		}
		if (!want || !got) {
			free(key), free(want), free(got);
			rc = -1;
			continue;
		}
		if (strcmp(want, got) != 0) {
			rc = md_add(out, key, "record", want, got);
		} else {
			free(key), free(want), free(got);
		}
	}
	free(names);
	btf_layout_free(&b);
	return rc;
}
