

#include "req/parse_internal.h"

#include <string.h>

#include "util/mutation.h"


static int ident(const char *p, size_t n)
{
	if (n == 0)
		return 0;
	for (size_t i = 0; i < n; i++) {
		char c = p[i];
		if (!(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')))
			return 0;
	}
	return 1;
}


int req_valid_kfield_path(const char *p, size_t n)
{
	int segs = 1;
	for (size_t i = 0; i < n; i++)
		segs += p[i] == '.';
	if (segs > 3)
		return 0;
	for (size_t i = 0; i <= n;) {
		size_t j = i;
		while (j < n && p[j] != '.')
			j++;
		if (!ident(p + i, j - i))
			return 0;
		i = j + 1;
	}
	return 1;
}

int req_kfield_struct_type(struct field t)
{
	return t.n >= 7 && !memcmp(t.p, "struct:", 7);
}


int req_kfield_path_row(const struct bml_requirements *r, struct field *f, int n, const char *row, struct bml_parse_error *e)
{
	int st = req_kfield_struct_type(f[4]);
	if (!memchr(f[3].p, '.', f[3].n) && !st)
		return 0;
	if (r->version < 17 && !BML_MUT("parse.v17_rows_any_version"))
		return req_perr(e, n, row, "min_version", "kfield paths and struct types need version 17");
	if (!req_valid_kfield_path(f[3].p, f[3].n) || (st && !ident(f[4].p + 7, f[4].n - 7)))
		return req_perr(e, n, row, "value", "invalid embedded kfield path or struct name");
	return 0;
}

static int is_struct(const struct bml_kfield *k)
{
	return !strncmp(k->type.p, "struct:", 7);
}


static const struct bml_kfield *prefix_of(const struct bml_requirements *r, const struct bml_kfield *k, const char *f, size_t fn)
{
	for (size_t i = 0; i < r->n_kfields; i++) {
		const struct bml_kfield *p = &r->kfields[i];
		if (is_struct(p) && !strcmp(p->program.p, k->program.p) && !strcmp(p->strct.p, k->strct.p) && p->field.len == fn &&
		    !memcmp(p->field.p, f, fn))
			return p;
	}
	return NULL;
}


int req_kfield_prefixes(const struct bml_requirements *r, struct bml_parse_error *e)
{
	if (BML_MUT("parse.kfield_no_prefix_check"))
		return 0;
	for (size_t i = 0; i < r->n_kfields; i++) {
		const struct bml_kfield *k = &r->kfields[i];
		if (!is_struct(k))
			continue;
		const struct bml_kfield *p = prefix_of(r, k, k->field.p, k->field.len);
		if (p != k && strcmp(p->type.p, k->type.p) != 0)
			return req_perr(e, 0, "kfield", "document", "conflicting embedded kfield prefix %s.%s", k->strct.p, k->field.p);
	}
	for (size_t i = 0; i < r->n_kfields; i++) {
		const struct bml_kfield *k = &r->kfields[i];
		for (size_t j = 0; j < k->field.len; j++) {
			if (k->field.p[j] != '.')
				continue;
			if (!prefix_of(r, k, k->field.p, j)) {
				struct bml_buf b = {0};
				bml_buf_addf(&b, "%.*s", (int)j, k->field.p);
				int rc = req_perr(e, 0, "kfield", "document", "missing embedded kfield struct prefix %s.%s", k->strct.p, b.p ? b.p : "");
				bml_buf_free(&b);
				return rc;
			}
		}
	}
	return 0;
}
