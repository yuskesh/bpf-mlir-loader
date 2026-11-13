#include "req/parse_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"


static const char *const attach_types[] = {"trace_raw_tp", "trace_fentry", "trace_fexit", "kprobe", "uprobe", "tcx", "kretprobe", "uretprobe",
					   "trace_fmod_ret"                                      ,
					   "trace_lsm", "trace_tp", "trace_perf", "freplace", "trace_struct_ops"                                      ,
					   "kprobe_multi", "kretprobe_multi", "uprobe_multi", "uretprobe_multi", "usdt"                                      ,
					   "trace_lsm_cgroup", "ksyscall"                                      ,
					   "netkit"                                      };

int req_eq(struct field f, const char *lit)
{
	size_t n = strlen(lit);
	return f.n == n && memcmp(f.p, lit, n) == 0;
}

int req_str_eq(const struct bml_str *s, struct field f)
{
	return s->len == f.n && (f.n == 0 || memcmp(s->p, f.p, f.n) == 0);
}

int req_str_eq_lit(const struct bml_str *s, const char *lit)
{
	size_t n = strlen(lit);
	return s->len == n && memcmp(s->p, lit, n) == 0;
}
const struct bml_row_kind *req_row_kind(struct field f)
{
	for (size_t i = 0; i < bml_n_row_kinds; i++)
		if (req_eq(f, bml_row_kinds[i].name))
			return &bml_row_kinds[i];
	return NULL;
}

int req_known_attach_type(struct field f)
{
	for (size_t i = 0; i < sizeof(attach_types) / sizeof(attach_types[0]); i++)
		if (req_eq(f, attach_types[i]))
			return 1;
	return 0;
}

int req_valid_int_spelling(struct field f)
{
	static const char *const ok[] = {"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"};
	for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
		if (req_eq(f, ok[i]))
			return 1;
	return 0;
}



int req_enum_bits(struct field f)
{
	return req_eq(f, "enum:8") ? 8 : req_eq(f, "enum:16") ? 16 : req_eq(f, "enum:32") ? 32 : req_eq(f, "enum:64") ? 64 : 0;
}

int req_kfield_type_ok(struct field f)
{
	if (req_valid_int_spelling(f) || req_enum_bits(f))
		return 1;
	if (f.n > 4 && !memcmp(f.p, "ptr:", 4))
		return 1;
	if (f.n < 5 || f.p[0] != '[' || (memcmp(f.p + f.n - 3, "]i8", 3) && memcmp(f.p + f.n - 3, "]u8", 3)))
		return 0;
	const char *d = f.p + 1;
	size_t nd = f.n - 4;
	if (nd == 0 || nd > 2 || d[0] < '1' || d[0] > '9')
		return 0;
	int v = 0;
	for (size_t i = 0; i < nd; i++) {
		if (d[i] < '0' || d[i] > '9')
			return 0;
		v = v * 10 + (d[i] - '0');
	}
	return v >= 1 && v <= 64;
}


int req_mkstr(struct bml_str *s, struct field f)
{
	s->p = malloc(f.n + 1);
	if (!s->p)
		return -1;
	if (f.n)
		memcpy(s->p, f.p, f.n);
	s->p[f.n] = 0;
	s->len = f.n;
	return 0;
}
int req_grow_array(void **arr, size_t *cap, size_t elem, size_t need)
{
	size_t c = *cap ? *cap : 4;
	while (c < need) {
		if (c > SIZE_MAX / 2 / elem)
			return -1;
		c *= 2;
	}
	void *p = realloc(*arr, c * elem);
	if (!p)
		return -1;
	memset((char *)p + *cap * elem, 0, (c - *cap) * elem);
	*arr = p;
	*cap = c;
	return 0;
}




static void vmsg(struct bml_buf *b, const char *fmt, va_list ap)
{
	for (const char *c = fmt; *c; c++) {
		if (*c != '%') {
			bml_buf_add(b, c, 1);
			continue;
		}
		c++;
		switch (*c) {
		case 's':
			bml_buf_adds(b, va_arg(ap, const char *));
			break;
		case 'q': {
			const char *p = va_arg(ap, const char *);
			size_t n = va_arg(ap, size_t);
			bml_buf_add_goquote(b, p, n);
			break;
		}
		case 'd':
			bml_buf_addf(b, "%lld", (long long)va_arg(ap, int64_t));
			break;
		case 'u':
			bml_buf_addf(b, "%llu", (unsigned long long)va_arg(ap, uint64_t));
			break;
		default:
			bml_buf_add(b, "%", 1);
			if (!*c)
				return;
			bml_buf_add(b, c, 1);
		}
	}
}

int req_perr(struct bml_parse_error *e, int line, const char *row, const char *rule, const char *fmt, ...)
{
	struct bml_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	vmsg(&b, fmt, ap);
	va_end(ap);
	e->line = line;
	e->row = row;
	e->rule = rule;
	e->msg = bml_buf_take(&b);
	return -1;
}




int req_scan(struct scanner *s)
{
	if (s->too_long || s->pos >= s->len)
		return 0;
	const char *start = s->data + s->pos;
	size_t rest = s->len - s->pos;
	const char *nl = memchr(start, '\n', rest < SCAN_MAX ? rest : SCAN_MAX);
	size_t n;
	if (nl) {
		n = (size_t)(nl - start);
		s->pos += n + 1;
	} else if (rest < SCAN_MAX) {
		n = rest;
		s->pos = s->len;
	} else {
		s->too_long = 1;
		return 0;
	}
	if (n > 0 && start[n - 1] == '\r' && !BML_MUT("parse.cr_keep"))
		n--;
	s->tok.p = start;
	s->tok.n = n;
	return 1;
}

int req_field_cmp(struct field a, struct field b)
{
	int c = memcmp(a.p, b.p, a.n < b.n ? a.n : b.n);
	return c ? c : (a.n > b.n) - (a.n < b.n);
}

size_t req_split(struct field line, struct field *f)
{
	size_t k = 0;
	const char *p = line.p, *end = line.p + line.n;
	for (;;) {
		const char *t = memchr(p, '\t', (size_t)(end - p));
		const char *e = t ? t : end;
		if (k < MAXF) {
			f[k].p = p;
			f[k].n = (size_t)(e - p);
		}
		k++;
		if (!t)
			break;
		p = t + 1;
	}
	return k;
}

int req_find_program(const struct bml_requirements *r, struct field name)
{
	for (size_t i = 0; i < r->n_programs; i++)
		if (req_str_eq(&r->programs[i].symbol, name))
			return (int)i;
	return -1;
}
