#include "util/gostr.h"
#include "util/mutation.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int parse_digits(const char *s, size_t n, int bits, uint64_t *out)
{
	if (n == 0)
		return -1;
	uint64_t max = bits >= 64 ? UINT64_MAX : ((uint64_t)1 << bits) - 1;
	uint64_t v = 0;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c < '0' || c > '9')
			return -1;
		unsigned d = c - '0';
		if (v > (UINT64_MAX - d) / 10)
			return -1;
		v = v * 10 + d;
		if (v > max)
			return -1;
	}
	*out = v;
	return 0;
}

int bml_go_parse_uint(const char *s, size_t n, int bits, uint64_t *out)
{
	if (bits <= 0 || bits > 64)
		bits = 64;
	return parse_digits(s, n, bits, out);
}

int bml_go_parse_int(const char *s, size_t n, int bits, int64_t *out)
{
	if (bits <= 0 || bits > 64)
		bits = 64;
	if (n == 0)
		return -1;
	int neg = 0;
	if ((s[0] == '+' && !BML_MUT("parse.int_no_plus")) || s[0] == '-') {
		neg = s[0] == '-';
		s++;
		n--;
	}
	uint64_t u;
	if (parse_digits(s, n, 64, &u))
		return -1;
	uint64_t cutoff = (uint64_t)1 << (bits - 1);
	if (!neg && u >= cutoff)
		return -1;
	if (neg && u > cutoff)
		return -1;
	*out = neg ? (int64_t)(0 - u) : (int64_t)u;
	return 0;
}

int bml_go_atoi(const char *s, size_t n, int64_t *out)
{
	return bml_go_parse_int(s, n, 64, out);
}

static void grow(struct bml_buf *b, size_t add)
{
	if (b->oom)
		return;
	if (b->len + add + 1 <= b->cap)
		return;
	size_t cap = b->cap ? b->cap : 64;
	while (cap < b->len + add + 1) {
		if (cap > SIZE_MAX / 2) {
			b->oom = 1;
			return;
		}
		cap *= 2;
	}
	char *p = realloc(b->p, cap);
	if (!p) {
		b->oom = 1;
		return;
	}
	b->p = p;
	b->cap = cap;
}

void bml_buf_add(struct bml_buf *b, const char *s, size_t n)
{
	grow(b, n);
	if (b->oom)
		return;
	if (n)
		memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = 0;
}

void bml_buf_adds(struct bml_buf *b, const char *s)
{
	bml_buf_add(b, s, strlen(s));
}

void bml_buf_addf(struct bml_buf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int k = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (k < 0) {
		b->oom = 1;
		return;
	}
	grow(b, (size_t)k);
	if (b->oom)
		return;
	va_start(ap, fmt);
	vsnprintf(b->p + b->len, (size_t)k + 1, fmt, ap);
	va_end(ap);
	b->len += (size_t)k;
}


static size_t utf8_len(const unsigned char *s, size_t n)
{
	unsigned c = s[0];
	size_t k;
	uint32_t min, cp;
	if (c >= 0xc2 && c <= 0xdf) {
		k = 2;
		cp = c & 0x1f;
		min = 0x80;
	} else if (c >= 0xe0 && c <= 0xef) {
		k = 3;
		cp = c & 0x0f;
		min = 0x800;
	} else if (c >= 0xf0 && c <= 0xf4) {
		k = 4;
		cp = c & 0x07;
		min = 0x10000;
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

void bml_buf_add_goquote(struct bml_buf *b, const char *s, size_t n)
{
	const unsigned char *u = (const unsigned char *)s;
	bml_buf_add(b, "\"", 1);
	for (size_t i = 0; i < n;) {
		unsigned c = u[i];
		const char *esc = NULL;
		switch (c) {
		case '\a': esc = "\\a"; break;
		case '\b': esc = "\\b"; break;
		case '\f': esc = "\\f"; break;
		case '\n': esc = "\\n"; break;
		case '\r': esc = "\\r"; break;
		case '\t': esc = "\\t"; break;
		case '\v': esc = "\\v"; break;
		case '\\': esc = "\\\\"; break;
		case '"': esc = "\\\""; break;
		}
		if (esc) {
			bml_buf_adds(b, esc);
			i++;
		} else if (c >= 0x20 && c < 0x7f) {
			bml_buf_add(b, s + i, 1);
			i++;
		} else if (c >= 0x80) {
			size_t k = utf8_len(u + i, n - i);
			if (k) {
				bml_buf_add(b, s + i, k);
				i += k;
			} else {
				bml_buf_addf(b, "\\x%02x", c);
				i++;
			}
		} else {
			bml_buf_addf(b, "\\x%02x", c);
			i++;
		}
	}
	bml_buf_add(b, "\"", 1);
}

char *bml_buf_take(struct bml_buf *b)
{
	if (b->oom) {
		bml_buf_free(b);
		return NULL;
	}
	char *p = b->p;
	if (!p) {
		p = malloc(1);
		if (p)
			p[0] = 0;
	}
	b->p = NULL;
	b->len = b->cap = 0;
	return p;
}

void bml_buf_free(struct bml_buf *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
	b->oom = 0;
}

char *bml_go_errno_str(int err)
{
	char *s = strdup(strerror(err));
	if (s && s[0] >= 'A' && s[0] <= 'Z')
		s[0] = (char)(s[0] - 'A' + 'a');
	return s;
}
