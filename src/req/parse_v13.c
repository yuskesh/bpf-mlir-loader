


#include "req/parse_internal.h"
#include "util/mutation.h"

#include <stdint.h>
#include <string.h>

#define SYSCALL_MAX_ARGS 6


static int kfunc_scalar(struct field s)
{
	return req_valid_int_spelling(s) || req_eq(s, "bool");
}


static int kfunc_type(struct field s, int ret)
{
	if (kfunc_scalar(s) || (ret && req_eq(s, "void")))
		return 1;
	if (s.n > 4 && !memcmp(s.p, "ptr:", 4)) {
		struct field p = {s.p + 4, s.n - 4};
		return req_eq(p, "void") || kfunc_scalar(p) || req_valid_cname(p);
	}
	return 0;
}

int req_v13_kfunc(struct bml_requirements *r, struct field *f, size_t nf, struct field line, int n, struct bml_parse_error *e)
{
	if (req_find_program(r, f[1]) < 0)
		return req_perr(e, n, "kfunc", "order", "%s line %d: kfunc for unknown program %q", SEC, (int64_t)n, Q(f[1]));
	if (!req_valid_cname(f[2]) || !kfunc_type(f[3], 1))
		return req_perr(e, n, "kfunc", "value", "%s line %d: bad kfunc row %q", SEC, (int64_t)n, Q(line));
	for (size_t i = 4; i < nf; i++)
		if (!kfunc_type(f[i], 0))
			return req_perr(e, n, "kfunc", "value", "%s line %d: bad kfunc row %q", SEC, (int64_t)n, Q(line));
	for (size_t i = 0; i < r->n_kfuncs; i++)
		if (req_str_eq(&r->kfuncs[i].program, f[1]) && req_str_eq(&r->kfuncs[i].name, f[2]))
			return req_perr(e, n, "kfunc", "order", "%s line %d: kfunc row repeated %q", SEC, (int64_t)n, Q(line));
	if (GROW(r->kfuncs, r->n_kfuncs, r->cap_kfuncs))
		return -2;
	struct bml_kfunc *k = &r->kfuncs[r->n_kfuncs];
	memset(k, 0, sizeof(*k));
	r->n_kfuncs++;
	if (req_mkstr(&k->program, f[1]) || req_mkstr(&k->name, f[2]) || req_mkstr(&k->ret, f[3]))
		return -2;
	if (nf > 4) {
		size_t cap = 0;
		for (size_t i = 4; i < nf; i++) {
			if (GROW(k->args, k->n_args, cap))
				return -2;
			memset(&k->args[k->n_args], 0, sizeof(*k->args));
			k->n_args++;
			if (req_mkstr(&k->args[k->n_args - 1], f[i]))
				return -2;
		}
	}
	return 0;
}

int req_v13_companion(struct bml_requirements *r, struct field *f, struct field line, int n, struct bml_parse_error *e)
{
	const char *row = req_eq(f[0], "sysarg") ? "sysarg" : "mtargetarg";
	struct bml_attach *a = r->n_attaches ? &r->attaches[r->n_attaches - 1] : NULL;
#define OUT_OF_ORDER() req_perr(e, n, row, "order", "%s line %d: %s row out of order %q", SEC, (int64_t)n, row, Q(line))
#define BAD() req_perr(e, n, row, "value", "%s line %d: bad %s row %q", SEC, (int64_t)n, row, Q(line))
	if (!a || !req_str_eq(&a->program, f[1]))
		return OUT_OF_ORDER();
	if (!strcmp(row, "sysarg")) {
		if (!req_str_eq_lit(&a->attach_type, "ksyscall") || a->arch.len == 0)
			return OUT_OF_ORDER();

		int str = req_eq(f[3], "strptr") || req_eq(f[3], "strarray");
		if (str && r->version < 16 && !BML_MUT("parse.v16_rows_any_version"))
			return req_perr(e, n, row, "min_version", "%s line %d: sysarg type %s needs version 16", SEC, (int64_t)n,
					req_eq(f[3], "strptr") ? "strptr" : "strarray");
		int64_t na;
		if (bml_go_atoi(f[2].p, f[2].n, &na) || na < 1 || na > SYSCALL_MAX_ARGS || !(req_valid_int_spelling(f[3]) || req_eq(f[3], "ptr") || str))
			return BAD();
		if (a->n_sys_args > 0 && na <= a->sys_args[a->n_sys_args - 1].n)
			return OUT_OF_ORDER();
		if (GROW(a->sys_args, a->n_sys_args, a->cap_sys_args))
			return -2;
		struct bml_intarg *s = &a->sys_args[a->n_sys_args];
		memset(s, 0, sizeof(*s));
		a->n_sys_args++;
		s->n = na;
		return req_mkstr(&s->type, f[3]) ? -2 : 0;
	}
	int kp = req_str_eq_lit(&a->attach_type, "kprobe_multi");
	if ((!kp && !req_str_eq_lit(&a->attach_type, "uprobe_multi")) || (int64_t)a->n_mtargets != a->multi_n || a->n_kprobe_args > 0 ||
	    a->n_uprobe_args > 0)
		return OUT_OF_ORDER();
	int64_t i, na;
	if (bml_go_atoi(f[2].p, f[2].n, &i) || bml_go_atoi(f[3].p, f[3].n, &na) || i < 0 || na < 1 ||
	    !(req_valid_int_spelling(f[4]) || req_eq(f[4], "ptr") || (!kp && req_eq(f[4], "strptr"))))
		return BAD();

	if (!kp && req_eq(f[4], "ptr") && r->version < 18 && !BML_MUT("parse.v18_rows_any_version"))
		return req_perr(e, n, row, "min_version", "%s line %d: user mtargetarg type ptr needs version 18", SEC, (int64_t)n);
	if (a->n_mtarget_args > 0) {
		const struct bml_mtargetarg *p = &a->mtarget_args[a->n_mtarget_args - 1];
		if (i < p->i || (i == p->i && na <= p->n))
			return OUT_OF_ORDER();
	}
	if (i >= a->multi_n)
		return req_perr(e, n, row, "value", "%s line %d: mtargetarg index %d is not below the function count %d of the attach row %q", SEC, (int64_t)n,
				i, a->multi_n, Q(line));
	if (GROW(a->mtarget_args, a->n_mtarget_args, a->cap_mtarget_args))
		return -2;
	struct bml_mtargetarg *m = &a->mtarget_args[a->n_mtarget_args];
	memset(m, 0, sizeof(*m));
	a->n_mtarget_args++;
	m->i = i;
	m->n = na;
	return req_mkstr(&m->type, f[4]) ? -2 : 0;
#undef OUT_OF_ORDER
#undef BAD
}
