#include "json/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



static int fold_field(const char *k, size_t n, char *out, size_t cap)
{
	size_t o = 0;
	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)k[i];
		char x;
		if (c == 0) /* CONTRACT: a key containing NUL cannot be compared as a C string, so it is not folded (Go compares with lengths, so it does not match) */
			return 0;
		if (c < 0x80) {
			x = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : (char)c;
			i++;
		} else if (c == 0xc5 && i + 1 < n && (unsigned char)k[i + 1] == 0xbf) {
			x = 's';
			i += 2;
		} else if (c == 0xe2 && i + 2 < n && (unsigned char)k[i + 1] == 0x84 && (unsigned char)k[i + 2] == 0xaa) {
			x = 'k';
			i += 3;
		} else {
			return 0;
		}
		if (o + 1 >= cap)
			return 0;
		out[o++] = x;
	}
	out[o] = 0;
	return 1;
}

static int vfail(char **err, enum bml_json_rule *rule, enum bml_json_rule r, const char *fmt, const char *a)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, fmt, a ? a : "");
	*err = bml_buf_take(&b);
	if (rule)
		*rule = r;
	return -1;
}

int bml_json_validate(struct bml_json *j, const struct bml_json_desc *d, char **err, enum bml_json_rule *rule)
{
	if (!d || j->type == BML_JSON_NULL)
		return 0;
	switch (d->kind) {
	case BML_JD_SCALAR:
		return 0;
	case BML_JD_STRING:
		return j->type == BML_JSON_STRING ? 0 : vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal a value into a string%s", NULL);
	case BML_JD_BOOL:
		return j->type == BML_JSON_BOOL ? 0 : vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal a value into a bool%s", NULL);
	case BML_JD_UINT: {
		uint64_t u;
		if (j->type != BML_JSON_NUMBER || bml_go_parse_uint(j->str, j->len, d->bits, &u))
			return vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal %s into an unsigned integer", j->type == BML_JSON_NUMBER ? j->str : "a value");
		return 0;
	}
	case BML_JD_INT: {
		int64_t s;
		if (j->type != BML_JSON_NUMBER || bml_go_parse_int(j->str, j->len, d->bits, &s))
			return vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal %s into an integer", j->type == BML_JSON_NUMBER ? j->str : "a value");
		return 0;
	}
	case BML_JD_ARRAY:
		if (j->type != BML_JSON_ARRAY)
			return vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal a value into an array%s", NULL);
		for (size_t i = 0; i < j->n; i++)
			if (bml_json_validate(j->items[i], d->child, err, rule))
				return -1;
		return 0;
	case BML_JD_MAP:
		if (j->type != BML_JSON_OBJECT)
			return vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal a value into a map%s", NULL);
		for (size_t i = 0; i < j->n; i++)
			if (bml_json_validate(j->members[i].value, d->child, err, rule))
				return -1;
		return 0;
	case BML_JD_STRUCT:
		if (j->type != BML_JSON_OBJECT)
			return vfail(err, rule, BML_JR_TYPE, "json: cannot unmarshal a value into an object%s", NULL);
		for (size_t i = 0; i < j->n; i++) {
			struct bml_json_member *m = &j->members[i];
			const struct bml_json_field *f = NULL;
			char low[128];
			for (size_t k = 0; k < d->n_fields && !f; k++)
				if (strlen(d->fields[k].name) == m->key_len && !memcmp(d->fields[k].name, m->key, m->key_len))
					f = &d->fields[k];
			if (!f && fold_field(m->key, m->key_len, low, sizeof(low))) {
				for (size_t k = 0; k < d->n_fields && !f; k++)
					if (!strcmp(d->fields[k].name, low))
						f = &d->fields[k];
				if (f) {
					char *nk = strdup(f->name);
					if (!nk)
						return vfail(err, rule, BML_JR_OOM, "out of memory%s", NULL);
					free(m->key);
					m->key = nk;
					m->key_len = strlen(nk);
				}
			}
			if (!f)
				return vfail(err, rule, BML_JR_UNKNOWN_KEY, "json: unknown field \"%s\"", m->key);
			if (bml_json_validate(m->value, f->desc, err, rule))
				return -1;
		}
		return 0;
	}
	return 0;
}
