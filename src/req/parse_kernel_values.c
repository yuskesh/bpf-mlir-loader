#include "req/parse_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct field sf(const struct bml_str *s) { return (struct field){s->p, s->len}; }

static int hex_value(struct field f, uint64_t *out)
{
	if (f.n != 18 || memcmp(f.p, "0x", 2))
		return 0;
	uint64_t v = 0;
	for (size_t i = 2; i < f.n; i++) {
		unsigned char c = (unsigned char)f.p[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return 0;
		v = (v << 4) | (uint64_t)(c <= '9' ? c - '0' : c - 'a' + 10);
	}
	*out = v;
	return 1;
}

static int parse_enum(struct bml_requirements *r, struct field *f,
	struct field line, int n, struct bml_parse_error *e)
{
	int core = req_eq(f[0], "coreenum");
	const char *row = core ? "coreenum" : "enumval";
	int pi = req_find_program(r, f[1]);
	if (pi < 0)
		return req_perr(e, n, row, "order", "%s line %d: %s for unknown program %q", SEC, (int64_t)n, row, Q(f[1]));
	uint64_t value = 0;
	if (!req_valid_cname(f[2]) || !req_valid_cname(f[3]) || (!core && !hex_value(f[4], &value)))
		return req_perr(e, n, row, "value", "%s line %d: bad %s row %q", SEC, (int64_t)n, row, Q(line));
	struct bml_enum_value **arr = core ? &r->core_enums : &r->enum_values;
	size_t *count = core ? &r->n_core_enums : &r->n_enum_values;
	size_t *cap = core ? &r->cap_core_enums : &r->cap_enum_values;
	if (*count) {
		const struct bml_enum_value *p = &(*arr)[*count - 1];
		int pp = req_find_program(r, sf(&p->program));
		int ec = req_field_cmp(f[2], sf(&p->enumeration));
		if (pi < pp || (pi == pp && (ec < 0 || (!ec && req_field_cmp(f[3], sf(&p->name)) <= 0))))
			return req_perr(e, n, row, "order", "%s line %d: %s row out of order or repeated %q", SEC, (int64_t)n, row, Q(line));
	}
	if (!core) {
		for (size_t i = 0; i < r->n_enum_values; i++) {
			const struct bml_enum_value *v = &r->enum_values[i];
			if (req_str_eq(&v->enumeration, f[2]) && req_str_eq(&v->name, f[3]) && v->value != value) {
				char prev[19];
				snprintf(prev, sizeof(prev), "0x%016llx", (unsigned long long)v->value);
				char val[19];
				snprintf(val, sizeof(val), "0x%016llx", (unsigned long long)value);
				return req_perr(e, n, row, "value", "%s line %d: enumval %s %s has value %s, but an earlier row has %s", SEC,
					(int64_t)n, v->enumeration.p, v->name.p, val, prev);
			}
		}
	}
	const struct bml_enum_value *other = core ? r->enum_values : r->core_enums;
	size_t no = core ? r->n_enum_values : r->n_core_enums;
	for (size_t i = 0; i < no; i++)
		if (req_str_eq(&other[i].program, f[1]) && req_str_eq(&other[i].enumeration, f[2]) && req_str_eq(&other[i].name, f[3])) {

			struct bml_str p = {0}, en = {0}, name = {0};
			if (req_mkstr(&p, f[1]) || req_mkstr(&en, f[2]) || req_mkstr(&name, f[3])) {
				free(p.p); free(en.p); free(name.p); return -2;
			}
			int rc = req_perr(e, n, row, "value", "%s line %d: %s %s %s %s is also %s row (an immediate and a relocation of the same constant)",
				SEC, (int64_t)n, row, p.p, en.p, name.p, core ? "an enumval" : "a coreenum");
			free(p.p); free(en.p); free(name.p); return rc;
		}
	if (req_grow_array((void **)arr, cap, sizeof(**arr), *count + 1))
		return -2;
	struct bml_enum_value *v = &(*arr)[(*count)++];
	v->value = value;
	return req_mkstr(&v->program, f[1]) || req_mkstr(&v->enumeration, f[2]) || req_mkstr(&v->name, f[3]) ? -2 : 0;
}

int req_parse_kernel_value(struct bml_requirements *r, struct field *f,
	struct field line, int n, struct bml_parse_error *e)
{
	if (req_eq(f[0], "enumval") || req_eq(f[0], "coreenum"))
		return parse_enum(r, f, line, n, e);
	if (req_eq(f[0], "fibflags")) {
		int pi = req_find_program(r, f[1]);
		if (pi < 0)
			return req_perr(e, n, "fibflags", "order", "%s line %d: fibflags for unknown program %q", SEC, (int64_t)n, Q(f[1]));
		uint64_t mask;
		int direct = req_eq(f[2], "direct");
		if ((!direct && !req_eq(f[2], "none")) || bml_go_parse_uint(f[3].p, f[3].n, 32, &mask) || mask != (uint64_t)direct)
			return req_perr(e, n, "fibflags", "value", "%s line %d: bad fibflags row %q (flag none = 0 or direct = %d, the mask must match the name)",
				SEC, (int64_t)n, Q(line), (int64_t)1);
		if (r->n_fib_flags) {
			const struct bml_fib_flag *p = &r->fib_flags[r->n_fib_flags - 1];
			int pp = req_find_program(r, sf(&p->program));
			if (pp > pi || (pp == pi && p->mask >= mask))
				return req_perr(e, n, "fibflags", "order", "%s line %d: fibflags row out of order or repeated %q (program order, then increasing mask)",
					SEC, (int64_t)n, Q(line));
		}
		if (GROW(r->fib_flags, r->n_fib_flags, r->cap_fib_flags))
			return -2;
		struct bml_fib_flag *p = &r->fib_flags[r->n_fib_flags++];
		p->mask = (uint32_t)mask;
		return req_mkstr(&p->program, f[1]) || req_mkstr(&p->name, f[2]) ? -2 : 0;
	}
	if (!req_eq(f[1], "bpf_cpumask"))
		return req_perr(e, n, "kstructsize", "value", "%s line %d: kstructsize names unknown struct %q", SEC, (int64_t)n, Q(f[1]));
	uint64_t size;
	char canonical[16];
	if (bml_go_parse_uint(f[2].p, f[2].n, 32, &size) || !size || size % 8)
		goto bad_size;
	int len = snprintf(canonical, sizeof(canonical), "%u", (unsigned)size);
	if (f[2].n != (size_t)len || memcmp(f[2].p, canonical, (size_t)len))
		goto bad_size;
	if (r->n_struct_sizes) {
		const struct bml_struct_size *p = &r->struct_sizes[r->n_struct_sizes - 1];
		int cmp = req_field_cmp(f[1], sf(&p->strct));
		if (cmp < 0 || (!cmp && size <= p->size))
			return req_perr(e, n, "kstructsize", "order", "%s line %d: kstructsize row out of order or repeated %q", SEC, (int64_t)n, Q(line));
	}
	if (GROW(r->struct_sizes, r->n_struct_sizes, r->cap_struct_sizes))
		return -2;
	struct bml_struct_size *p = &r->struct_sizes[r->n_struct_sizes++];
	p->size = (uint32_t)size;
	return req_mkstr(&p->strct, f[1]) ? -2 : 0;
bad_size:
	return req_perr(e, n, "kstructsize", "value", "%s line %d: bad kstructsize row %q (the size is a positive decimal multiple of 8)", SEC, (int64_t)n, Q(line));
}
