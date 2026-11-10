
#include "json/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_value(struct parser *p, struct bml_json **out, const struct bml_json_desc *desc);

static int parse_array(struct parser *p, struct bml_json *j, const struct bml_json_desc *desc)
{
	const struct bml_json_desc *et = desc && desc->kind == BML_JD_ARRAY ? desc->child : NULL;
	size_t cap = 0;
	json_skip_ws(p);
	if (p->pos < p->len && p->s[p->pos] == ']') {
		p->pos++;
		return 0;
	}
	for (;;) {
		if (j->n == cap) {
			size_t nc = cap ? cap * 2 : 4;
			struct bml_json **ni = realloc(j->items, nc * sizeof(*ni));
			if (!ni)
				return json_fail(p, BML_JR_OOM, "out of memory");
			j->items = ni;
			cap = nc;
		}
		/* CONTRACT: even on failure the element stays attached to the tree (parse_value sets *out before failing); count it first so the free sees it */
		int rc = parse_value(p, &j->items[j->n], et);
		j->n++;
		if (rc)
			return -1;
		json_skip_ws(p);
		if (p->pos >= p->len)
			return json_fail(p, BML_JR_SYNTAX, "unterminated array");
		unsigned char c = p->s[p->pos++];
		if (c == ']')
			return 0;
		if (c != ',')
			return json_fail(p, BML_JR_SYNTAX, "expected , or ]");
	}
}



static int fold_ascii(const char *k, size_t n, char *out, size_t cap)
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

static int parse_object(struct parser *p, struct bml_json *j, const struct bml_json_desc *desc)
{
	size_t cap = 0;
	json_skip_ws(p);
	if (p->pos < p->len && p->s[p->pos] == '}') {
		p->pos++;
		return 0;
	}
	for (;;) {
		json_skip_ws(p);
		if (p->pos >= p->len || p->s[p->pos] != '"')
			return json_fail(p, BML_JR_SYNTAX, "expected object key");
		p->pos++;
		char *key;
		size_t klen;
		size_t kpos = p->pos;
		if (json_parse_string(p, &key, &klen))
			return -1;
		size_t dup = (size_t)-1;
		for (size_t i = 0; i < j->n; i++)
			if (j->members[i].key_len == klen && memcmp(j->members[i].key, key, klen) == 0)
				dup = i;
		if (dup != (size_t)-1 && !p->lenient) {
			free(key);
			p->pos = kpos;
			return json_fail(p, BML_JR_DUPLICATE_KEY, "duplicate key");
		}

		const struct bml_json_desc *vt = NULL;
		if (desc && desc->kind == BML_JD_STRUCT) {
			int exact = 0;
			for (size_t f = 0; f < desc->n_fields; f++) {
				if (strlen(desc->fields[f].name) == klen && !memcmp(desc->fields[f].name, key, klen)) {
					exact = 1;
					vt = desc->fields[f].desc;
				}
			}
			if (!exact && !p->lenient) {
				char low[128];
				if (fold_ascii(key, klen, low, sizeof(low))) {
					for (size_t f = 0; f < desc->n_fields; f++) {
						if (!strcmp(desc->fields[f].name, low)) {
							free(key);
							p->pos = kpos;
							return json_fail(p, BML_JR_KEY_CASE, "key differs only in case from \"%s\"", desc->fields[f].name);
						}
					}
				}
			}
		} else if (desc && desc->kind == BML_JD_MAP) {
			vt = desc->child;
		}
		if (dup != (size_t)-1) {
			free(key);
			bml_json_free(j->members[dup].value);
			j->members[dup].value = NULL;
			json_skip_ws(p);
			if (p->pos >= p->len || p->s[p->pos] != ':')
				return json_fail(p, BML_JR_SYNTAX, "expected :");
			p->pos++;
			if (parse_value(p, &j->members[dup].value, vt))
				return -1;
		} else {
			if (j->n == cap) {
				size_t nc = cap ? cap * 2 : 4;
				struct bml_json_member *nm = realloc(j->members, nc * sizeof(*nm));
				if (!nm) {
					free(key);
					return json_fail(p, BML_JR_OOM, "out of memory");
				}
				j->members = nm;
				cap = nc;
			}
			j->members[j->n].key = key;
			j->members[j->n].key_len = klen;
			j->members[j->n].value = NULL;
			j->n++;
			json_skip_ws(p);
			if (p->pos >= p->len || p->s[p->pos] != ':')
				return json_fail(p, BML_JR_SYNTAX, "expected :");
			p->pos++;
			if (parse_value(p, &j->members[j->n - 1].value, vt))
				return -1;
		}
		json_skip_ws(p);
		if (p->pos >= p->len)
			return json_fail(p, BML_JR_SYNTAX, "unterminated object");
		unsigned char c = p->s[p->pos++];
		if (c == '}')
			return 0;
		if (c != ',')
			return json_fail(p, BML_JR_SYNTAX, "expected , or }");
	}
}

static int parse_value(struct parser *p, struct bml_json **out, const struct bml_json_desc *desc)
{
	*out = NULL;
	json_skip_ws(p);
	if (p->pos >= p->len)
		return json_fail(p, BML_JR_SYNTAX, "unexpected end");
	struct bml_json *j = calloc(1, sizeof(*j));
	if (!j)
		return json_fail(p, BML_JR_OOM, "out of memory");
	*out = j; /* CONTRACT: stays attached to the caller's tree on failure; free the whole tree */
	unsigned char c = p->s[p->pos];
	switch (c) {
	case '{':
	case '[':
		if (++p->depth > (p->lenient ? 10000 : BML_JSON_MAX_DEPTH))
			return json_fail(p, BML_JR_NESTING_TOO_DEEP, "nesting too deep");
		p->pos++;
		j->type = c == '{' ? BML_JSON_OBJECT : BML_JSON_ARRAY;
		if (c == '{' ? parse_object(p, j, desc) : parse_array(p, j, desc))
			return -1;
		p->depth--;
		return 0;
	case '"':
		p->pos++;
		j->type = BML_JSON_STRING;
		return json_parse_string(p, &j->str, &j->len);
	case 't':
		j->type = BML_JSON_BOOL;
		j->boolean = 1;
		return json_lit(p, "true");
	case 'f':
		j->type = BML_JSON_BOOL;
		return json_lit(p, "false");
	case 'n':
		j->type = BML_JSON_NULL;
		return json_lit(p, "null");
	default:
		j->type = BML_JSON_NUMBER;
		return json_parse_number(p, j);
	}
}

int bml_json_parse_ex(const char *data, size_t len, const struct bml_json_desc *desc, int lenient, struct bml_json **out,
		      char **err, enum bml_json_rule *rule)
{
	struct parser p = {.s = (const unsigned char *)data, .len = len, .lenient = lenient};
	struct bml_json *j = NULL;
	*out = NULL;
	*err = NULL;
	if (rule)
		*rule = BML_JR_NONE;
	if (parse_value(&p, &j, desc) == 0) {
		json_skip_ws(&p);
		if (p.pos != p.len)
			json_fail(&p, BML_JR_TRAILING_DATA, "trailing data after the JSON value");
	}
	if (p.err) {
		bml_json_free(j);
		*err = p.err;
		if (rule)
			*rule = p.rule;
		return -1;
	}
	*out = j;
	return 0;
}

int bml_json_parse(const char *data, size_t len, struct bml_json **out, char **err)
{
	return bml_json_parse_ex(data, len, NULL, 0, out, err, NULL);
}
