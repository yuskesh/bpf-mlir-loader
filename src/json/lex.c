#include "json/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int json_fail(struct parser *p, enum bml_json_rule rule, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
int json_fail(struct parser *p, enum bml_json_rule rule, const char *fmt, ...)
{
	if (p->err)
		return -1;
	p->rule = rule;
	struct bml_buf b = {0};
	bml_buf_addf(&b, "offset %zu: ", p->pos);
	va_list ap;
	va_start(ap, fmt);
	char tmp[256];
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	bml_buf_adds(&b, tmp);
	p->err = bml_buf_take(&b);
	return -1;
}

void json_skip_ws(struct parser *p)
{
	while (p->pos < p->len) {
		unsigned char c = p->s[p->pos];
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
			break;
		p->pos++;
	}
}


size_t json_utf8_seq(const unsigned char *s, size_t n)
{
	unsigned c = s[0];
	if (c < 0x80)
		return 1;
	size_t k;
	uint32_t cp, min;
	if (c >= 0xc2 && c <= 0xdf) {
		k = 2, cp = c & 0x1f, min = 0x80;
	} else if (c >= 0xe0 && c <= 0xef) {
		k = 3, cp = c & 0x0f, min = 0x800;
	} else if (c >= 0xf0 && c <= 0xf4) {
		k = 4, cp = c & 0x07, min = 0x10000;
	} else {
		return 0;
	}
	if (n < k)
		return 0;
	for (size_t i = 1; i < k; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		cp = (cp << 6) | (s[i] & 0x3f);
	}
	if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
		return 0;
	return k;
}

static int hex4(struct parser *p, uint32_t *out)
{
	if (p->len - p->pos < 4)
		return json_fail(p, BML_JR_SYNTAX, "short \\u escape");
	uint32_t v = 0;
	for (int i = 0; i < 4; i++) {
		unsigned char c = p->s[p->pos + i];
		v <<= 4;
		if (c >= '0' && c <= '9')
			v |= c - '0';
		else if (c >= 'a' && c <= 'f')
			v |= c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			v |= c - 'A' + 10;
		else
			return json_fail(p, BML_JR_SYNTAX, "bad \\u escape");
	}
	p->pos += 4;
	*out = v;
	return 0;
}

void json_put_utf8(struct bml_buf *b, uint32_t cp)
{
	char t[4];
	size_t n;
	if (cp < 0x80) {
		t[0] = (char)cp, n = 1;
	} else if (cp < 0x800) {
		t[0] = (char)(0xc0 | (cp >> 6)), t[1] = (char)(0x80 | (cp & 0x3f)), n = 2;
	} else if (cp < 0x10000) {
		t[0] = (char)(0xe0 | (cp >> 12)), t[1] = (char)(0x80 | ((cp >> 6) & 0x3f)), t[2] = (char)(0x80 | (cp & 0x3f)), n = 3;
	} else {
		t[0] = (char)(0xf0 | (cp >> 18)), t[1] = (char)(0x80 | ((cp >> 12) & 0x3f)),
		t[2] = (char)(0x80 | ((cp >> 6) & 0x3f)), t[3] = (char)(0x80 | (cp & 0x3f)), n = 4;
	}
	bml_buf_add(b, t, n);
}


int json_parse_string(struct parser *p, char **out, size_t *out_len)
{
	struct bml_buf b = {0};
	bml_buf_add(&b, "", 0);
	for (;;) {
		if (p->pos >= p->len) {
			bml_buf_free(&b);
			return json_fail(p, BML_JR_SYNTAX, "unterminated string");
		}
		unsigned char c = p->s[p->pos];
		if (c == '"') {
			p->pos++;
			break;
		}
		if (c < 0x20) {
			bml_buf_free(&b);
			return json_fail(p, BML_JR_SYNTAX, "control character in string");
		}
		if (c == '\\') {
			p->pos++;
			if (p->pos >= p->len) {
				bml_buf_free(&b);
				return json_fail(p, BML_JR_SYNTAX, "unterminated escape");
			}
			unsigned char e = p->s[p->pos++];
			const char *lit = NULL;
			switch (e) {
			case '"': lit = "\""; break;
			case '\\': lit = "\\"; break;
			case '/': lit = "/"; break;
			case 'b': lit = "\b"; break;
			case 'f': lit = "\f"; break;
			case 'n': lit = "\n"; break;
			case 'r': lit = "\r"; break;
			case 't': lit = "\t"; break;
			case 'u': {
				uint32_t cp;
				if (hex4(p, &cp)) {
					bml_buf_free(&b);
					return -1;
				}
				if (cp >= 0xd800 && cp <= 0xdbff) {

					uint32_t lo = 0;
					int ok2 = p->len - p->pos >= 6 && p->s[p->pos] == '\\' && p->s[p->pos + 1] == 'u';
					if (ok2) {
						size_t save = p->pos;
						p->pos += 2;
						char *e0 = p->err;
						if (hex4(p, &lo)) {
							free(p->err);
							p->err = e0;
							ok2 = 0;
						}
						if (!ok2 || lo < 0xdc00 || lo > 0xdfff) {
							ok2 = 0;
							p->pos = save;
						}
					}
					if (!ok2) {
						if (p->lenient) {
							json_put_utf8(&b, 0xfffd);
							continue;
						}
						bml_buf_free(&b);
						return json_fail(p, BML_JR_UNPAIRED_SURROGATE, "unpaired surrogate");
					}
					cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
				} else if (cp >= 0xdc00 && cp <= 0xdfff) {
					if (p->lenient) {
						json_put_utf8(&b, 0xfffd);
						continue;
					}
					bml_buf_free(&b);
					return json_fail(p, BML_JR_UNPAIRED_SURROGATE, "unpaired surrogate");
				}
				if (cp == 0 && !p->lenient) {
					bml_buf_free(&b);
					return json_fail(p, BML_JR_NUL, "\\u0000 in a string");
				}
				json_put_utf8(&b, cp);
				continue;
			}
			default:
				bml_buf_free(&b);
				return json_fail(p, BML_JR_SYNTAX, "bad escape");
			}
			bml_buf_add(&b, lit, 1);
			continue;
		}
		size_t k = json_utf8_seq(p->s + p->pos, p->len - p->pos);
		if (!k && p->lenient) {
			json_put_utf8(&b, 0xfffd);
			p->pos++;
			continue;
		}
		if (!k) {
			bml_buf_free(&b);
			return json_fail(p, BML_JR_INVALID_UTF8, "invalid UTF-8");
		}
		bml_buf_add(&b, (const char *)p->s + p->pos, k);
		p->pos += k;
	}
	*out_len = b.len;
	*out = bml_buf_take(&b);
	if (!*out)
		return json_fail(p, BML_JR_OOM, "out of memory");
	return 0;
}

int json_parse_number(struct parser *p, struct bml_json *j)
{
	size_t start = p->pos;
	if (p->pos < p->len && p->s[p->pos] == '-')
		p->pos++;
	if (p->pos >= p->len)
		return json_fail(p, BML_JR_SYNTAX, "bad number");
	if (p->s[p->pos] == '0') {
		p->pos++;
	} else if (p->s[p->pos] >= '1' && p->s[p->pos] <= '9') {
		while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9')
			p->pos++;
	} else {
		return json_fail(p, BML_JR_SYNTAX, "bad number");
	}
	if (p->pos < p->len && p->s[p->pos] == '.') {
		p->pos++;
		size_t d = p->pos;
		while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9')
			p->pos++;
		if (p->pos == d)
			return json_fail(p, BML_JR_SYNTAX, "bad number");
	}
	if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
		p->pos++;
		if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-'))
			p->pos++;
		size_t d = p->pos;
		while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9')
			p->pos++;
		if (p->pos == d)
			return json_fail(p, BML_JR_SYNTAX, "bad number");
	}
	j->len = p->pos - start;
	j->str = malloc(j->len + 1);
	if (!j->str)
		return json_fail(p, BML_JR_OOM, "out of memory");
	memcpy(j->str, p->s + start, j->len);
	j->str[j->len] = 0;
	return 0;
}

int json_lit(struct parser *p, const char *w)
{
	size_t n = strlen(w);
	if (p->len - p->pos < n || memcmp(p->s + p->pos, w, n) != 0)
		return json_fail(p, BML_JR_SYNTAX, "unexpected token");
	p->pos += n;
	return 0;
}
