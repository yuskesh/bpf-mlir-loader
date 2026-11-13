#include "req/check_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"

int req_attach_mechanism(const char *s, size_t n);

static const struct bml_program *program_of(const struct bml_requirements *r, const char *sym)
{
	for (size_t i = 0; i < r->n_programs; i++)
		if (!strcmp(r->programs[i].symbol.p, sym))
			return &r->programs[i];
	return NULL;
}

void ck_asked_free(struct ck *c)
{
	for (size_t i = 0; i < c->n_asked; i++)
		free(c->asked[i]);
	free(c->asked);
	c->asked = NULL;
	c->n_asked = c->cap_asked = 0;
}


static int asked_once(struct ck *c, const char *program, const char *at)
{
	size_t lp = strlen(program), la = strlen(at);
	for (size_t i = 0; i < c->n_asked; i++)
		if (!memcmp(c->asked[i], program, lp + 1) && !strcmp(c->asked[i] + lp + 1, at))
			return 1;
	if (c->n_asked == c->cap_asked) {
		size_t cap = c->cap_asked ? c->cap_asked * 2 : 8;
		char **nw = realloc(c->asked, cap * sizeof *nw);
		if (!nw) {
			c->oom = 1;
			return 1;
		}
		c->asked = nw;
		c->cap_asked = cap;
	}
	char *k = malloc(lp + la + 2);
	if (!k) {
		c->oom = 1;
		return 1;
	}
	memcpy(k, program, lp + 1);
	memcpy(k + lp + 1, at, la + 1);
	c->asked[c->n_asked++] = k;
	return 0;
}


int ck_check_attach_type(struct ck *c, const char *program, const char *at)
{
	if ((!strcmp(at, "-") || req_attach_mechanism(at, strlen(at))) && !BML_MUT("check.mechanism_asks_attach_type"))
		return 0;
	if (!strcmp(at, "-") || asked_once(c, program, at))
		return 0;
	const struct bml_program *p = program_of(c->req, program);
	if (!p)
		return ck_fail(c, ck_fmtd("attach type %s for unknown program %s", at, program));
	if (!HAS(c, attach_type, BML_QUERY_ATTACH_TYPE)) {
		ck_add(c, "attach_type_unknown", program, at, 0, ck_dupn("no attach type probe"));
		return 0;
	}
	int has = 0;
	char *msg = NULL;
	int st = c->caps->attach_type(c->caps->ctx, p->prog_type.p, p->prog_type_id, at, &has, &msg);
	if (st == BML_Q_UNKNOWN) {
		ck_add(c, "attach_type_unknown", program, at, 0, msg);
		return 0;
	}
	if (st != BML_Q_OK)
		return ck_fail(c, msg);
	free(msg);

	if (!has && (!strcmp(p->prog_type.p, "sk_skb") || !strcmp(p->prog_type.p, "sk_msg"))) {
		const struct bml_loader_decl *d = ck_loader_of(c);
		if (d->sockmap_attach && !strcmp(d->sockmap_attach, "prog_attach"))
			return 0;
	}
	if (!has)
		ck_add(c, "attach_type", program, at, 0, ck_dupn(p->prog_type.p));
	return 0;
}



static int static_map_target(const struct bml_requirements *r, const struct bml_attach *a, char **mismatch)
{
	static const char *const sk[] = {"sockmap", "sockhash"}, *const so[] = {"struct_ops"};
	const char *at = a->attach_type.p;
	const char *const *want = NULL;
	size_t nw = 0;
	if (!strcmp(at, "sk_skb_stream_parser") || !strcmp(at, "sk_skb_stream_verdict") || !strcmp(at, "sk_skb_verdict") || !strcmp(at, "sk_msg_verdict"))
		want = sk, nw = 2;
	else if (!strcmp(at, "struct_ops"))
		want = so, nw = 1;
	*mismatch = NULL;
	if (!want || strcmp(a->tkind.p, "map") != 0 || BML_MUT("check.static_map_target_skip"))
		return 0;
	const char *wj = nw == 2 ? "sockmap or sockhash" : "struct_ops";
	for (size_t i = 0; i < r->n_maps; i++) {
		const struct bml_map *m = &r->maps[i];
		if (strcmp(m->symbol.p, a->tval.p) != 0)
			continue;
		for (size_t k = 0; k < nw; k++)
			if (!strcmp(m->map_type.p, want[k]))
				return 1;
		*mismatch = ck_fmtd("%s attaches to map %s of map type %s, but this attach type needs %s (the object's map rows)", at, m->symbol.p, m->map_type.p,
				    wj);
		return 1;
	}
	*mismatch = ck_fmtd("%s attaches to map %s, which is not a map row of the object", at, a->tval.p);
	return 1;
}

int ck_check_generic_attach(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p;
	if (ck_check_attach_type(c, P, a->attach_type.p))
		return -1;
	if (a->tval.len == 0)
		return 0;
	char *mm = NULL;
	if (static_map_target(c->req, a, &mm)) {
		if (mm)
			ck_add(c, "attach_target", P, a->target.p, 0, mm);
		return 0;
	}
	if (!HAS(c, attach_target, BML_QUERY_ATTACH_TARGET)) {
		ck_add(c, "attach_target_unknown", P, a->target.p, 0, ck_dupn("no attach target probe"));
		return 0;
	}
	int has = 0;
	char *msg = NULL;
	int st = c->caps->attach_target(c->caps->ctx, a->attach_type.p, a->tkind.p, a->tval.p, &has, &msg);
	if (st == BML_Q_UNKNOWN) {
		ck_add(c, "attach_target_unknown", P, a->target.p, 0, msg);
		return 0;
	}
	if (st != BML_Q_OK)
		return ck_fail(c, msg);
	free(msg);
	if (!has)
		ck_add(c, "attach_target", P, a->target.p, 0, ck_dupn(a->attach_type.p));
	return 0;
}



int ck_check_fmod_ret(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p;
	if (a->ret_nargs < 0)
		return ck_fail(c, ck_fmtd("program %s: fmod_ret attach row without a retsig row", P));
	if (!HAS(c, func_sig, BML_QUERY_FUNC_SIG)) {
		ck_add(c, "retsig_unknown", P, T, 0, NULL);
	} else {
		struct bml_strs d = {0};
		char *msg = NULL;
		if (c->caps->func_sig(c->caps->ctx, T, a->ret_nargs, a->ret_type.p, &d, &msg) != BML_Q_OK)
			return ck_fail(c, msg);
		ck_add_diffs(c, "attach", P, T, &d);
	}
	for (size_t i = 0; i < a->n_fargs && !BML_MUT("check.fmodret_skip_farg"); i++) {
		const char *t = a->fargs[i].p;
		if (!strcmp(t, "-"))
			continue;
		char *name = ck_fmtd("%zu of %s (%s)", i + 1, T, t);
		if (!HAS(c, func_param, BML_QUERY_FUNC_PARAM)) {
			ck_add(c, "farg_unknown", P, name ? name : "", 0, ck_dupn("no BTF probe"));
			free(name);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int st = c->caps->func_param(c->caps->ctx, T, (int64_t)(i + 1), t, &d, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "farg_unknown", P, name ? name : "", 0, msg);
			free(name);
			continue;
		}
		if (st != BML_Q_OK) {
			free(name);
			return ck_fail(c, msg);
		}
		for (size_t j = 0; j < d.n; j++)
			ck_add(c, "farg", P, name ? name : "", 0, ck_fmtd("program %s: %s", P, d.s[j]));
		bml_strs_free(&d);
		free(name);
	}
	if (!HAS(c, func, BML_QUERY_FUNC)) {
		ck_add(c, "attach_func_unknown", P, T, 0, NULL);
		return 0;
	}
	struct bml_strs d = {0};
	char *msg = NULL;
	if (c->caps->func(c->caps->ctx, T, &d, &msg) != BML_Q_OK)
		return ck_fail(c, msg);
	ck_add_diffs(c, "attach", P, T, &d);
	return 0;
}

int ck_check_ctx_accesses(struct ck *c)
{
	const struct bml_requirements *r = c->req;
	int ok = HAS(c, ctx_access, BML_QUERY_CTX_ACCESS) && !BML_MUT("check.ctx_access_ignored");
	for (size_t i = 0; i < r->n_ctxaccesses; i++) {
		const struct bml_ctxaccess *x = &r->ctxaccesses[i];
		const char *P = x->program.p;
		if (ck_check_attach_type(c, P, x->attach_type.p))
			return -1;
		char *name = ck_fmtd("%s.%s (%s, %lld bytes)", x->strct.p, x->field.p, x->mode.p, (long long)x->bytes);
		if (!ok) {
			ck_add(c, "ctx_access_unknown", P, name ? name : "", 0, ck_dupn("no ctx access probe"));
			free(name);
			continue;
		}
		const struct bml_program *p = program_of(r, P);
		int allowed = 0;
		char *msg = NULL;
		int st = c->caps->ctx_access(c->caps->ctx, p ? p->prog_type.p : "", p ? p->prog_type_id : 0, x->attach_type.p, x->strct.p,
					     x->field.p, x->mode.p, x->bytes, &allowed, &msg);
		if (st == BML_Q_UNKNOWN)
			ck_add(c, "ctx_access_unknown", P, name ? name : "", 0, msg);
		else if (st != BML_Q_OK) {
			free(name);
			return ck_fail(c, msg);
		} else {
			free(msg);
			if (!allowed)
				ck_add(c, "ctx_access", P, name ? name : "", 0, ck_fmtd("%s / %s", p ? p->prog_type.p : "", x->attach_type.p));
		}
		free(name);
	}
	return 0;
}
