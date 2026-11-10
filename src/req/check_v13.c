

#include "req/check_internal.h"

#include <stdlib.h>
#include <string.h>

#include "caps/caps.h"
#include "req/kfunc_profile.h"

#include "util/gostr.h"
#include "util/mutation.h"


static char *qname(const struct bml_loader_decl *d)
{
	struct bml_buf b = {0};
	bml_buf_add_goquote(&b, d->name ? d->name : "", d->name ? strlen(d->name) : 0);
	return bml_buf_take(&b);
}

static const char *val(const char *s)
{
	return s ? s : "";
}


int ck_check_prog_loader(struct ck *c, const struct bml_attach *a)
{
	const char *AT = a->attach_type.p, *P = a->program.p, *T = a->target.p;
	int lsmcg = !strcmp(AT, "trace_lsm_cgroup") || (a->generic && !strcmp(AT, "lsm_cgroup"));
	int fsess = a->generic && !strcmp(AT, "trace_fsession");
	if (!lsmcg && !fsess)
		return 0;
	const struct bml_loader_decl *d = ck_loader_of(c);
	const char *v = val(lsmcg ? d->lsm_cgroup_load : d->fsession_load);
	if (!strcmp(v, "btf_id"))
		return 0;
	char *q = qname(d);
	if (!q)
		return ck_fail(c, ck_dupn("out of memory"));
	if (lsmcg && !strcmp(v, "none"))
		ck_add(c, "lsm_cgroup_loader", P, T, 0,
		       ck_fmtd("the loader %s cannot load an lsm_cgroup program (lsm_cgroup_load none — it does not set the hook's BTF id and the kernel rejects the load)",
			       q));
	else if (lsmcg)
		ck_add(c, "lsm_cgroup_loader_unknown", P, T, 0, ck_fmtd("the loader %s does not declare lsm_cgroup_load", q));
	else if (!strcmp(v, "none"))
		ck_add(c, "fsession_loader", P, T, 0,
		       ck_fmtd("the loader %s cannot load an fsession program (fsession_load none — it does not set the function's BTF id and the kernel rejects the load)",
			       q));
	else
		ck_add(c, "fsession_loader_unknown", P, T, 0, ck_fmtd("the loader %s does not declare fsession_load", q));
	free(q);
	return 0;
}


int ck_check_tpbuf(struct ck *c, const struct bml_attach *a)
{
	if (!a->tpbuf_type.len || BML_MUT("check.tpbuf_skip"))
		return 0;
	const char *P = a->program.p, *T = a->tval.p;
	char *detail = ck_fmtd("tpbuf tracepoint %s: argument 0 expected pointee %s", T, a->tpbuf_type.p);
	if (!detail)
		return ck_fail(c, ck_dupn("out of memory"));
	if (!HAS(c, tracepoint_buffer, BML_QUERY_TRACEPOINT_BUFFER)) {
		ck_add(c, "attach_unknown", P, T, 0, ck_fmtd("%s; no tracepoint_buffer query", detail));
		free(detail);
		return 0;
	}
	struct bml_strs d = {0};
	char *msg = NULL;
	int st = c->caps->tracepoint_buffer(c->caps->ctx, T, a->tpbuf_type.p, &d, &msg);
	if (st == BML_Q_UNKNOWN) {
		ck_add(c, "attach_unknown", P, T, 0, ck_fmtd("%s; %s", detail, msg ? msg : ""));
		free(msg);
		free(detail);
		return 0;
	}
	if (st != BML_Q_OK) {
		free(detail);
		return ck_fail(c, msg);
	}
	free(msg);
	for (size_t i = 0; i < d.n; i++)
		ck_add(c, "attach", P, T, 0, ck_fmtd("%s; %s", detail, d.s[i]));
	bml_strs_free(&d);
	free(detail);
	return 0;
}


static int check_kfunc_load(struct ck *c, const struct bml_kfunc *k)
{
	const char *P = k->program.p, *N = k->name.p;
	char *why = NULL;
	const struct bml_kfunc_profile_entry *e = bml_req_kfunc_profile_for(c->req, P, &why);
	if (!e) {
		ck_add(c, "kfunc_allowed_unknown", P, N, 0, why);
		return 0;
	}
	if (!HAS(c, kfunc_load, BML_QUERY_KFUNC_LOADS)) {
		ck_add(c, "kfunc_allowed_unknown", P, N, 0, ck_dupn("no kfunc load permission probe"));
		return 0;
	}
	struct bml_kfunc_profile p = {e->kind,	      e->section, e->prog_type,	      e->prog_type_id,	     e->prog_flags,
				      e->attach_type, e->target_kind, e->target, e->context_identity, "kfunc-v1"};
	int ok = 0;
	char *msg = NULL;
	int st = c->caps->kfunc_load(c->caps->ctx, &p, N, k->ret.p, k->args, k->n_args, &ok, &msg);
	if (st == BML_Q_UNKNOWN) {
		ck_add(c, "kfunc_allowed_unknown", P, N, 0, msg);
		return 0;
	}
	if (st != BML_Q_OK)
		return ck_fail(c, msg);
	free(msg);
	if (!ok) {
		char *key = bml_caps_kfunc_load_key(&p, N, k->ret.p, k->args, k->n_args);
		ck_add(c, "kfunc_allowed", P, N, 0, key ? ck_fmtd("kernel rejected this kfunc in the exact initial profile %s", key) : NULL);
		free(key);
	}
	return 0;
}


int ck_check_kfuncs(struct ck *c)
{
	int has = HAS(c, kfunc, BML_QUERY_KFUNC_PROTOS);
	for (size_t i = 0; i < c->req->n_kfuncs; i++) {
		const struct bml_kfunc *k = &c->req->kfuncs[i];
		if (!has) {
			ck_add(c, "kfunc_sig_unknown", k->program.p, k->name.p, 0, ck_dupn("no kfunc prototype probe"));
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int st = c->caps->kfunc(c->caps->ctx, k->name.p, k->ret.p, k->args, k->n_args, &d, &msg);
		if (st == BML_Q_OK && BML_MUT("check.kfunc_args_skip"))
			for (size_t j = d.n; j-- > 0;)
				if (!strncmp(d.s[j], "argument ", 9) || strstr(d.s[j], " arguments (")) {
					free(d.s[j]);
					memmove(d.s + j, d.s + j + 1, (d.n - j - 1) * sizeof *d.s);
					d.n--;
				}
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "kfunc_sig_unknown", k->program.p, k->name.p, 0, msg);
			continue;
		}
		if (st != BML_Q_OK)
			return ck_fail(c, msg);
		free(msg);
		int match = d.n == 0;
		ck_add_diffs(c, "kfunc_sig", k->program.p, k->name.p, &d);
		if (match && !BML_MUT("check.kfunc_allowed_skip") && check_kfunc_load(c, k))
			return -1;
	}
	return 0;
}


static int check_ksyscall(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p;
	char *ta;
	if (ck_check_arch_ctx(c, a, &ta)) {
		free(ta);
		return -1;
	}
	char *w = !strcmp(a->arch.p, "x86_64") ? ck_fmtd("__x64_sys_%s", T) : NULL;
	if (!w) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "no syscall wrapper prefix known for the arch ");
		bml_buf_add_goquote(&b, a->arch.p, a->arch.len);
		ck_add(c, "attach_symbol_unknown", P, T, 0, bml_buf_take(&b));
	} else {
		struct bml_attach b = *a;
		b.target = (struct bml_str){w, strlen(w)};
		b.kprobe_args = NULL;
		b.n_kprobe_args = 0;
		if (ck_check_kprobe_target(c, &b, ta, 0)) {
			free(ta);
			free(w);
			return -1;
		}
	}
	free(ta);
	for (size_t i = 0; i < a->n_sys_args; i++) {
		const struct bml_intarg *s = &a->sys_args[i];
		char *name = ck_fmtd("%lld of syscall %s (%s)", (long long)s->n, T, s->type.p);
		if (!HAS(c, syscall_arg, BML_QUERY_SYSCALL_ARGS)) {
			ck_add(c, "sysarg_unknown", P, name, 0, ck_dupn("no syscall argument probe"));
			free(name);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int st = c->caps->syscall_arg(c->caps->ctx, T, s->n, s->type.p, &d, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "sysarg_unknown", P, name, 0, msg);
			free(name);
			continue;
		}
		if (st != BML_Q_OK) {
			free(name);
			free(w);
			return ck_fail(c, msg);
		}
		free(msg);
		ck_add_diffs(c, "sysarg", P, name, &d);
		free(name);
	}
	const struct bml_loader_decl *d = ck_loader_of(c);
	const char *v = val(d->ksyscall_attach);
	if (strcmp(v, "prefix") != 0) {
		char *q = qname(d);
		char *bare = w ? NULL : ck_fmtd("sys_%s", T);
		if (!strcmp(v, "none"))
			ck_add(c, "ksyscall_loader", P, T, 0,
			       ck_fmtd("the loader %s does not attach a ksyscall program to the syscall wrapper %s (ksyscall_attach none — it attaches to the bare name and fails)",
				       q, w ? w : bare));
		else
			ck_add(c, "ksyscall_loader_unknown", P, T, 0, ck_fmtd("the loader %s does not declare ksyscall_attach", q));
		free(q);
		free(bare);
	}
	free(w);
	return 0;
}


int ck_check_v13(struct ck *c, const struct bml_attach *a)
{
	if (!strcmp(a->attach_type.p, "ksyscall"))
		return check_ksyscall(c, a);
	char *tg = ck_fmtd("lsm:%s", a->target.p);
	if (!tg)
		return ck_fail(c, ck_dupn("out of memory"));
	struct bml_attach g;
	memset(&g, 0, sizeof g);
	g.program = a->program;
	g.attach_type = (struct bml_str){"lsm_cgroup", 10};
	g.target = (struct bml_str){tg, strlen(tg)};
	g.tkind = (struct bml_str){"lsm", 3};
	g.tval = a->target;
	g.generic = 1;
	g.ret_nargs = -1;
	g.ext_nargs = -1;
	int rc = ck_check_generic_attach(c, &g);
	free(tg);
	return rc ? rc : ck_lsm_args(c, a);
}
