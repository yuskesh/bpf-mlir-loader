



#include "req/parse_internal.h"

#include <string.h>

#define USDT_MAX_ARGS 12

int req_uprobe_family(const struct bml_str *t)
{
	return req_str_eq_lit(t, "uprobe") || req_str_eq_lit(t, "uretprobe") || req_str_eq_lit(t, "uprobe_multi") || req_str_eq_lit(t, "uretprobe_multi") ||
	       req_str_eq_lit(t, "usdt");
}

int req_multi_str(const struct bml_str *t)
{
	return req_str_eq_lit(t, "kprobe_multi") || req_str_eq_lit(t, "kretprobe_multi") || req_str_eq_lit(t, "uprobe_multi") ||
	       req_str_eq_lit(t, "uretprobe_multi");
}

static int of_maps(struct field t)
{
	return req_eq(t, "array_of_maps") || req_eq(t, "hash_of_maps");
}

static int of_maps_str(const struct bml_str *t)
{
	return req_str_eq_lit(t, "array_of_maps") || req_str_eq_lit(t, "hash_of_maps");
}



int req_v12_pending(const struct bml_requirements *r, int n, const char *row, long after_map, struct bml_parse_error *e)
{
	const struct bml_attach *a = r->n_attaches ? &r->attaches[r->n_attaches - 1] : NULL;
	if (a && req_multi_str(&a->attach_type) && (int64_t)a->n_mtargets < a->multi_n && strcmp(row, "arch") != 0 && strcmp(row, "ctxfield") != 0 &&
	    strcmp(row, "binary") != 0 && strcmp(row, "mtarget") != 0) {
		if (n == 0)
			return req_perr(e, 0, "mtarget", "order", "%s: %s attach of %s declares %d functions but has %d mtarget rows", SEC, a->attach_type.p,
					a->program.p, a->multi_n, (int64_t)a->n_mtargets);
		return req_perr(e, n, row, "order", "%s line %d: %s row before the %d mtarget rows of the %s attach of %s are complete (%d so far)", SEC,
				(int64_t)n, row, a->multi_n, a->attach_type.p, a->program.p, (int64_t)a->n_mtargets);
	}
	if (after_map >= 0 && r->version >= 12 && strcmp(row, "innermap") != 0) {
		const struct bml_str *sym = &r->maps[after_map].symbol;
		for (size_t i = 0; i < r->n_maps; i++) {
			const struct bml_map *m = &r->maps[i];
			if (m->symbol.len != sym->len || memcmp(m->symbol.p, sym->p, sym->len) != 0 || !of_maps_str(&m->map_type))
				continue;
			if (n == 0)
				return req_perr(e, 0, "innermap", "order", "%s: map %s (%s) needs an innermap row right after it (version %d)", SEC, m->symbol.p,
						m->map_type.p, (int64_t)12);
			return req_perr(e, n, row, "order", "%s line %d: map %s (%s) needs an innermap row right after it (version %d), got a %s row", SEC,
					(int64_t)n, m->symbol.p, m->map_type.p, (int64_t)12, row);
		}
	}
	return 0;
}


static int valid_symbol_name(struct field s)
{
	if (s.n == 0)
		return 0;
	for (size_t i = 0; i < s.n; i++)
		if ((unsigned char)s.p[i] <= 0x20 || (unsigned char)s.p[i] >= 0x7f)
			return 0;
	return 1;
}


int req_v12_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e)
{
	const char *row = req_eq(f[0], "mtarget") ? "mtarget" : req_eq(f[0], "usdtsem") ? "usdtsem" : "usdtarg";
	struct bml_attach *a = r->n_attaches ? &r->attaches[r->n_attaches - 1] : NULL;
#define OUT_OF_ORDER() req_perr(e, n, row, "order", "%s line %d: %s row out of order %q", SEC, (int64_t)n, row, Q(line))
#define BAD() req_perr(e, n, row, "value", "%s line %d: bad %s row %q", SEC, (int64_t)n, row, Q(line))
	if (!a || !req_str_eq(&a->program, f[1]))
		return OUT_OF_ORDER();
	if (req_eq(f[0], "mtarget")) {
		if (!req_multi_str(&a->attach_type) || a->arch.len == 0 || (req_uprobe_family(&a->attach_type) && a->binary_sha256.len == 0) ||
		    a->n_kprobe_args > 0 || a->n_uprobe_args > 0)
			return OUT_OF_ORDER();
		int64_t idx;
		if (bml_go_atoi(f[2].p, f[2].n, &idx) || idx < 0 || !valid_symbol_name(f[3]))
			return BAD();
		if (idx != (int64_t)a->n_mtargets)
			return OUT_OF_ORDER();
		if (idx >= a->multi_n)
			return req_perr(e, n, row, "value", "%s line %d: mtarget index %d is not below the function count %d of the attach row %q", SEC,
					(int64_t)n, idx, a->multi_n, Q(line));
		if (GROW(a->mtargets, a->n_mtargets, a->cap_mtargets))
			return -2;
		memset(&a->mtargets[a->n_mtargets], 0, sizeof *a->mtargets);
		a->n_mtargets++;
		return req_mkstr(&a->mtargets[a->n_mtargets - 1], f[3]) ? -2 : 0;
	}
	if (req_eq(f[0], "usdtsem")) {
		if (!req_str_eq_lit(&a->attach_type, "usdt") || a->binary_sha256.len == 0 || a->usdt_sem.len != 0)
			return OUT_OF_ORDER();
		if (!req_eq(f[2], "required") && !req_eq(f[2], "none"))
			return BAD();
		return req_mkstr(&a->usdt_sem, f[2]) ? -2 : 0;
	}

	if (!req_str_eq_lit(&a->attach_type, "usdt") || a->usdt_sem.len == 0)
		return OUT_OF_ORDER();
	int64_t na;
	if (bml_go_atoi(f[2].p, f[2].n, &na) || na < 1 || na > USDT_MAX_ARGS || !req_valid_int_spelling(f[3]))
		return BAD();
	if (a->n_usdt_args > 0 && na <= a->usdt_args[a->n_usdt_args - 1].n)
		return OUT_OF_ORDER();
	if (GROW(a->usdt_args, a->n_usdt_args, a->cap_usdt_args))
		return -2;
	struct bml_intarg *k = &a->usdt_args[a->n_usdt_args];
	memset(k, 0, sizeof *k);
	a->n_usdt_args++;
	k->n = na;
	return req_mkstr(&k->type, f[3]) ? -2 : 0;
#undef OUT_OF_ORDER
#undef BAD
}


int req_v12_innermap(struct bml_requirements *r, struct field *f, struct field line, int n, long after_map, struct bml_parse_error *e)
{
	const struct bml_map *outer = NULL;
	if (after_map >= 0) {
		const struct bml_str *sym = &r->maps[after_map].symbol;
		for (size_t i = 0; i < r->n_maps; i++)
			if (r->maps[i].symbol.len == sym->len && !memcmp(r->maps[i].symbol.p, sym->p, sym->len))
				outer = &r->maps[i];
	}
	if (!outer || !req_str_eq(&outer->symbol, f[1]) || !of_maps_str(&outer->map_type))
		return req_perr(e, n, "innermap", "order", "%s line %d: innermap row is not right after its array_of_maps / hash_of_maps map row %q", SEC,
				(int64_t)n, Q(line));
	int64_t id;
	uint64_t maxe, flags;
	if (bml_go_parse_int(f[3].p, f[3].n, 64, &id) || bml_go_parse_uint(f[6].p, f[6].n, 64, &maxe) || bml_go_parse_uint(f[7].p, f[7].n, 64, &flags) ||
	    !req_valid_attach_type_name(f[2]) || of_maps(f[2]) || f[4].n == 0 || f[5].n == 0)
		return req_perr(e, n, "innermap", "value", "%s line %d: bad innermap row %q", SEC, (int64_t)n, Q(line));
	if (GROW(r->innermaps, r->n_innermaps, r->cap_innermaps))
		return -2;
	struct bml_innermap *m = &r->innermaps[r->n_innermaps];
	memset(m, 0, sizeof *m);
	r->n_innermaps++;
	m->id = id;
	m->max_entries = maxe;
	m->flags = flags;
	if (req_mkstr(&m->outer, f[1]) || req_mkstr(&m->map_type, f[2]) || req_mkstr(&m->key, f[4]) || req_mkstr(&m->value, f[5]))
		return -2;
	return 0;
}
