#define _GNU_SOURCE
#include "json/goscan.h"
#include "json/internal.h"

#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct gs {
	const unsigned char *d;
	size_t n, pos;
	struct bml_json_goerr *e;
};

static int gfail_at(struct gs *s, const char *rule, size_t at, struct bml_buf *detail)
{
	s->e->rule = rule;
	s->e->offset = (int64_t)at;
	s->e->detail = bml_buf_take(detail);
	s->e->nomem = s->e->detail == NULL;
	return -1;
}

static int gfail(struct gs *s, const char *rule, const char *text)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, text);
	return gfail_at(s, rule, s->pos, &b);
}

static void skip_space(struct gs *s)
{
	while (s->pos < s->n && (s->d[s->pos] == ' ' || s->d[s->pos] == '\t' || s->d[s->pos] == '\n' || s->d[s->pos] == '\r'))
		s->pos++;
}



static void quote_byte(struct bml_buf *b, unsigned c)
{
	const char *named = NULL;
	switch (c) {
	case '\a': named = "\\a"; break;
	case '\b': named = "\\b"; break;
	case '\f': named = "\\f"; break;
	case '\n': named = "\\n"; break;
	case '\r': named = "\\r"; break;
	case '\t': named = "\\t"; break;
	case '\v': named = "\\v"; break;
	case '\'': named = "\\'"; break;
	case '\\': named = "\\\\"; break;
	}
	bml_buf_adds(b, "'");
	if (named) {
		bml_buf_adds(b, named);
	} else if (c >= 0x20 && c < 0x7f) {
		char t = (char)c;
		bml_buf_add(b, &t, 1);
	} else if (c < 0x20 || c == 0x7f) {
		bml_buf_addf(b, "\\x%02x", c);
	} else if (c <= 0xa0 || c == 0xad) {
		bml_buf_addf(b, "\\u%04x", c);
	} else {
		json_put_utf8(b, c);
	}
	bml_buf_adds(b, "'");
}

static int hex4(const unsigned char *p, size_t n, uint32_t *out)
{
	if (n < 4)
		return 0;
	uint32_t r = 0;
	for (int i = 0; i < 4; i++) {
		unsigned c = p[i];
		r <<= 4;
		if (c >= '0' && c <= '9')
			r |= c - '0';
		else if (c >= 'a' && c <= 'f')
			r |= c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			r |= c - 'A' + 10;
		else
			return 0;
	}
	*out = r;
	return 1;
}



static int str(struct gs *s, char **out)
{
	struct bml_buf b = {0}, m = {0};
	const char *rule = "syntax";
	bml_buf_add(&b, "", 0);
	s->pos++;
	for (;;) {
		if (s->pos >= s->n) {
			bml_buf_adds(&m, "unterminated string");
			goto fail;
		}
		unsigned c = s->d[s->pos];
		if (c == '"') {
			s->pos++;
			break;
		}
		if (c < 0x20) {
			bml_buf_adds(&m, "control byte in a string");
			goto fail;
		}
		if (c == '\\') {
			if (s->pos + 1 >= s->n) {
				bml_buf_adds(&m, "unterminated escape");
				goto fail;
			}
			unsigned e = s->d[s->pos + 1];
			char lit;
			switch (e) {
			case '"': case '\\': case '/': lit = (char)e; break;
			case 'b': lit = '\b'; break;
			case 'f': lit = '\f'; break;
			case 'n': lit = '\n'; break;
			case 'r': lit = '\r'; break;
			case 't': lit = '\t'; break;
			case 'u': {
				uint32_t r, r2 = 0;
				if (!hex4(s->d + s->pos + 2, s->n - (s->pos + 2), &r)) {
					bml_buf_adds(&m, "bad \\u escape");
					goto fail;
				}
				if (r >= 0xd800 && r <= 0xdfff) {
					rule = "unpaired_surrogate";
					if (r >= 0xdc00) {
						bml_buf_addf(&m, "low surrogate \\u%04X without a high one", r);
						goto fail;
					}
					const unsigned char *rest = s->d + s->pos + 6;
					size_t rn = s->n - (s->pos + 6), skip = rn < 2 ? rn : 2;
					int ok2 = hex4(rest + skip, rn - skip, &r2);
					if (rn < 6 || rest[0] != '\\' || rest[1] != 'u' || !ok2 || r2 < 0xdc00 || r2 > 0xdfff) {
						bml_buf_addf(&m, "high surrogate \\u%04X without a low one", r);
						goto fail;
					}
					json_put_utf8(&b, 0x10000 + ((r - 0xd800) << 10) + (r2 - 0xdc00));
					s->pos += 12;
					continue;
				}
				if (r == 0) {
					rule = "nul";
					bml_buf_adds(&m, "\\u0000 in a string");
					goto fail;
				}
				json_put_utf8(&b, r);
				s->pos += 6;
				continue;
			}
			default:
				bml_buf_adds(&m, "bad escape \\");
				if (e < 0x80) {
					char t = (char)e;
					bml_buf_add(&m, &t, 1);
				} else {
					json_put_utf8(&m, e);
				}
				goto fail;
			}
			bml_buf_add(&b, &lit, 1);
			s->pos += 2;
			continue;
		}
		if (c < 0x80) {
			char t = (char)c;
			bml_buf_add(&b, &t, 1);
			s->pos++;
			continue;
		}
		size_t k = json_utf8_seq(s->d + s->pos, s->n - s->pos);
		if (!k) {
			rule = "invalid_utf8";
			bml_buf_addf(&m, "invalid UTF-8 byte 0x%02x in a string", c);
			goto fail;
		}
		bml_buf_add(&b, (const char *)s->d + s->pos, k);
		s->pos += k;
	}
	if (b.oom) {
		bml_buf_free(&b);
		s->e->nomem = 1;
		return -1;
	}
	if (out)
		*out = bml_buf_take(&b);
	else
		bml_buf_free(&b);
	return 0;
fail:
	bml_buf_free(&b);
	return gfail_at(s, rule, s->pos, &m);
}

static int literal(struct gs *s, const char *lit)
{
	size_t n = strlen(lit);
	if (s->n - s->pos < n || memcmp(s->d + s->pos, lit, n) != 0) {
		struct bml_buf m = {0};
		bml_buf_addf(&m, "want %s", lit);
		return gfail_at(s, "syntax", s->pos, &m);
	}
	s->pos += n;
	return 0;
}

static size_t digits(struct gs *s)
{
	size_t k = 0;
	while (s->pos < s->n && s->d[s->pos] >= '0' && s->d[s->pos] <= '9')
		s->pos++, k++;
	return k;
}

static int number(struct gs *s)
{
	if (s->d[s->pos] == '-')
		s->pos++;
	if (s->pos < s->n && s->d[s->pos] == '0')
		s->pos++;
	else if (digits(s) == 0)
		return gfail(s, "syntax", "bad number");
	if (s->pos < s->n && s->d[s->pos] == '.') {
		s->pos++;
		if (digits(s) == 0)
			return gfail(s, "syntax", "bad number");
	}
	if (s->pos < s->n && (s->d[s->pos] == 'e' || s->d[s->pos] == 'E')) {
		s->pos++;
		if (s->pos < s->n && (s->d[s->pos] == '+' || s->d[s->pos] == '-'))
			s->pos++;
		if (digits(s) == 0)
			return gfail(s, "syntax", "bad number");
	}
	return 0;
}

static int value(struct gs *s, const struct bml_json_desc *t, int depth);



static int lower_key(const char *k, char *out, size_t cap)
{
	size_t o = 0;
	for (const unsigned char *p = (const unsigned char *)k; *p;) {
		char x;
		if (*p < 0x80) {
			x = (char)(*p >= 'A' && *p <= 'Z' ? *p - 'A' + 'a' : *p);
			p++;
		} else if (p[0] == 0xe2 && p[1] == 0x84 && p[2] == 0xaa) {
			x = 'k';
			p += 3;
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

static int same_lower(const char *a, const char *b)
{
	for (; *a && *b; a++, b++) {
		char x = *a >= 'A' && *a <= 'Z' ? (char)(*a - 'A' + 'a') : *a, y = *b >= 'A' && *b <= 'Z' ? (char)(*b - 'A' + 'a') : *b;
		if (x != y)
			return 0;
	}
	return *a == *b;
}

static int object(struct gs *s, const struct bml_json_desc *t, int depth)
{
	const struct bml_json_desc *fields_of = t && t->kind == BML_JD_STRUCT ? t : NULL;
	const struct bml_json_desc *val = t && t->kind == BML_JD_MAP ? t->child : NULL;
	char **seen = NULL;
	size_t n_seen = 0;
	int rc = -1;
	s->pos++;
	skip_space(s);
	if (s->pos < s->n && s->d[s->pos] == '}') {
		s->pos++;
		return 0;
	}
	for (;;) {
		skip_space(s);
		if (s->pos >= s->n || s->d[s->pos] != '"') {
			gfail(s, "syntax", "want an object key");
			goto out;
		}
		size_t at = s->pos;
		char *key = NULL;
		if (str(s, &key))
			goto out;
		for (size_t i = 0; i < n_seen; i++)
			if (!strcmp(seen[i], key)) {
				struct bml_buf m = {0};
				bml_buf_adds(&m, "key ");
				bml_buf_add_goquote(&m, key, strlen(key));
				bml_buf_adds(&m, " appears twice in the same object");
				s->e->key_quote = !bml_json_go_key_quotable(key);
				free(key);
				gfail_at(s, "duplicate_key", at, &m);
				goto out;
			}
		char **ns = realloc(seen, (n_seen + 1) * sizeof *seen);
		if (!ns) {
			free(key);
			s->e->nomem = 1;
			goto out;
		}
		seen = ns;
		seen[n_seen++] = key;
		const struct bml_json_desc *vt = val;
		if (fields_of) {
			const struct bml_json_field *f = NULL;
			for (size_t i = 0; i < fields_of->n_fields && !f; i++)
				if (!strcmp(fields_of->fields[i].name, key))
					f = &fields_of->fields[i];
			if (f) {
				vt = f->desc;
			} else {
				char low[256];
				if (lower_key(key, low, sizeof low))
					for (size_t i = 0; i < fields_of->n_fields; i++)
						if (same_lower(fields_of->fields[i].name, low)) {
							struct bml_buf m = {0};
							bml_buf_adds(&m, "key ");
							bml_buf_add_goquote(&m, key, strlen(key));
							bml_buf_adds(&m, " differs only in case from ");
							bml_buf_add_goquote(&m, fields_of->fields[i].name, strlen(fields_of->fields[i].name));
							s->e->key_quote = !bml_json_go_key_quotable(key);
							gfail_at(s, "key_case", at, &m);
							goto out;
						}
			}
		}
		skip_space(s);
		if (s->pos >= s->n || s->d[s->pos] != ':') {
			gfail(s, "syntax", "want ':'");
			goto out;
		}
		s->pos++;
		skip_space(s);
		if (value(s, vt, depth))
			goto out;
		skip_space(s);
		if (s->pos >= s->n) {
			gfail(s, "syntax", "unexpected end in an object");
			goto out;
		}
		if (s->d[s->pos] == ',') {
			s->pos++;
		} else if (s->d[s->pos] == '}') {
			s->pos++;
			rc = 0;
			goto out;
		} else {
			gfail(s, "syntax", "want ',' or '}'");
			goto out;
		}
	}
out:
	for (size_t i = 0; i < n_seen; i++)
		free(seen[i]);
	free(seen);
	return rc;
}

static int array(struct gs *s, const struct bml_json_desc *t, int depth)
{
	const struct bml_json_desc *et = t && t->kind == BML_JD_ARRAY ? t->child : NULL;
	s->pos++;
	skip_space(s);
	if (s->pos < s->n && s->d[s->pos] == ']') {
		s->pos++;
		return 0;
	}
	for (;;) {
		skip_space(s);
		if (value(s, et, depth))
			return -1;
		skip_space(s);
		if (s->pos >= s->n)
			return gfail(s, "syntax", "unexpected end in an array");
		if (s->d[s->pos] == ',')
			s->pos++;
		else if (s->d[s->pos] == ']')
			return s->pos++, 0;
		else
			return gfail(s, "syntax", "want ',' or ']'");
	}
}

static int value(struct gs *s, const struct bml_json_desc *t, int depth)
{
	if (s->pos >= s->n)
		return gfail(s, "syntax", "unexpected end");
	unsigned c = s->d[s->pos];
	if (c == '{' || c == '[') {
		if (depth + 1 > BML_JSON_MAX_DEPTH) {
			struct bml_buf m = {0};
			bml_buf_addf(&m, "more than %d nested objects / arrays", BML_JSON_MAX_DEPTH);
			return gfail_at(s, "nesting_too_deep", s->pos, &m);
		}
		return c == '{' ? object(s, t, depth + 1) : array(s, t, depth + 1);
	}
	if (c == '"')
		return str(s, NULL);
	if (c == 't')
		return literal(s, "true");
	if (c == 'f')
		return literal(s, "false");
	if (c == 'n')
		return literal(s, "null");
	if (c == '-' || (c >= '0' && c <= '9'))
		return number(s);
	struct bml_buf m = {0};
	bml_buf_adds(&m, "unexpected byte ");
	quote_byte(&m, c);
	return gfail_at(s, "syntax", s->pos, &m);
}

int bml_json_go_scan(const char *data, size_t len, const struct bml_json_desc *desc, struct bml_json_goerr *e)
{
	memset(e, 0, sizeof *e);
	e->offset = -1;
	struct gs s = {.d = (const unsigned char *)(data ? data : ""), .n = len, .e = e};
	skip_space(&s);
	if (value(&s, desc, 0))
		return -1;
	skip_space(&s);
	if (s.pos < s.n)
		return gfail(&s, "trailing_data", "data after the top-level value");
	return 0;
}

void bml_json_goerr_free(struct bml_json_goerr *e)
{
	free(e->detail);
	e->detail = NULL;
}



static int out_of_range(const struct bml_json *j, locale_t c, const char **spelling)
{
	switch (j->type) {
	case BML_JSON_NUMBER: {
		double v = strtod_l(j->str, NULL, c);
		if (isinf(v)) {
			*spelling = j->str;
			return 1;
		}
		return 0;
	}
	case BML_JSON_ARRAY:
		for (size_t i = 0; i < j->n; i++)
			if (out_of_range(j->items[i], c, spelling))
				return 1;
		return 0;
	case BML_JSON_OBJECT:
		for (size_t i = 0; i < j->n; i++)
			if (out_of_range(j->members[i].value, c, spelling))
				return 1;
		return 0;
	default:
		return 0;
	}
}

int bml_json_float64_range(const struct bml_json *j, const char **spelling)
{
	locale_t c = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
	if (!c)
		return -1;
	int r = out_of_range(j, c, spelling);
	freelocale(c);
	return r;
}
