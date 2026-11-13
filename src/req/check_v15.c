#include "req/check_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"

int ck_fentry_args(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p;
	struct bml_str *st = calloc(a->n_fargs ? a->n_fargs : 1, sizeof *st);
	if (!st)
		return c->oom = 1, 0;
	for (size_t i = 0; i < a->n_fargs; i++)
		st[i] = ck_int_spelling(a->fargs[i].p) ? (struct bml_str){"-", 1} : a->fargs[i];
	int rc = 0;
	if (!HAS(c, func_args, BML_QUERY_FUNC_ARGS)) {
		ck_add(c, "farg_unknown", P, T, 0, NULL);
	} else {
		struct bml_strs d = {0};
		char *msg = NULL;
		int s = c->caps->func_args(c->caps->ctx, T, st, a->n_fargs, &d, &msg);
		if (s == BML_Q_UNKNOWN)
			ck_add(c, "farg_unknown", P, T, 0, msg);
		else if (s != BML_Q_OK)
			rc = ck_fail(c, msg);
		else {
			for (size_t j = 0; j < d.n; j++)
				ck_add(c, "farg", P, T, 0, ck_fmtd("program %s: %s", P, d.s[j]));
			bml_strs_free(&d);
		}
	}
	for (size_t i = 0; rc == 0 && i < a->n_fargs && !BML_MUT("check.fentry_scalar_skip"); i++) {
		const char *t = a->fargs[i].p;
		if (!ck_int_spelling(t))
			continue;
		char *name = ck_fmtd("%zu of %s (%s)", i + 1, T, t);
		if (!HAS(c, func_param, BML_QUERY_FUNC_PARAM)) {
			ck_add(c, "farg_unknown", P, name ? name : "", 0, ck_dupn("no BTF probe"));
			free(name);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int s = c->caps->func_param(c->caps->ctx, T, (int64_t)(i + 1), t, &d, &msg);
		if (s == BML_Q_UNKNOWN)
			ck_add(c, "farg_unknown", P, name ? name : "", 0, msg);
		else if (s != BML_Q_OK)
			rc = ck_fail(c, msg);
		else {
			for (size_t j = 0; j < d.n; j++)
				ck_add(c, "farg", P, name ? name : "", 0, ck_fmtd("program %s: %s", P, d.s[j]));
			bml_strs_free(&d);
		}
		free(name);
	}
	free(st);
	return rc;
}
