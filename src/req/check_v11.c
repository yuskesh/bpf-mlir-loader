


#include "req/check_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"


static int v11_generic(struct ck *c, const struct bml_attach *a)
{
	const char *at = NULL, *kind = NULL, *val = "";
	if (!strcmp(a->attach_type.p, "trace_lsm"))
		at = "lsm_mac", kind = "lsm", val = a->target.p;
	else if (!strcmp(a->attach_type.p, "trace_tp"))
		at = "tracepoint", kind = "tp", val = a->target.p;
	else if (!strcmp(a->attach_type.p, "trace_perf"))
		at = "perf_event", kind = "perf";
	else if (!strcmp(a->attach_type.p, "trace_struct_ops"))
		at = "struct_ops", kind = "map", val = a->target.p;
	else
		return 0;
	char *tg = ck_fmtd("%s%s%s", kind, val[0] ? ":" : "", val);
	if (!tg) {
		c->oom = 1;
		return 0;
	}
	struct bml_attach g;
	memset(&g, 0, sizeof g);
	g.program = a->program;
	g.attach_type = (struct bml_str){(char *)at, strlen(at)};
	g.target = (struct bml_str){tg, strlen(tg)};
	g.tkind = (struct bml_str){(char *)kind, strlen(kind)};
	g.tval = (struct bml_str){(char *)val, strlen(val)};
	g.generic = 1;
	g.ret_nargs = -1;
	g.ext_nargs = -1;
	int rc = ck_check_generic_attach(c, &g);
	free(tg);
	return rc;
}


int ck_lsm_args(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p;
	char *fn = ck_fmtd("bpf_lsm_%s", a->target.p);
	if (!fn)
		return c->oom = 1, 0;
	int any = 0;
	struct bml_str *st = calloc(a->n_fargs ? a->n_fargs : 1, sizeof *st);
	if (!st) {
		free(fn);
		return c->oom = 1, 0;
	}
	for (size_t i = 0; i < a->n_fargs; i++) {
		const char *t = a->fargs[i].p;
		int intdash = !strcmp(t, "-") || ck_int_spelling(t);
		st[i] = intdash ? (struct bml_str){"-", 1} : a->fargs[i];
		any |= !intdash;
	}
	int rc = 0;
	if (any) {
		if (!HAS(c, func_args, BML_QUERY_FUNC_ARGS)) {
			ck_add(c, "farg_unknown", P, fn, 0, NULL);
		} else {
			struct bml_strs d = {0};
			char *msg = NULL;
			int s = c->caps->func_args(c->caps->ctx, fn, st, a->n_fargs, &d, &msg);
			if (s == BML_Q_UNKNOWN)
				ck_add(c, "farg_unknown", P, fn, 0, msg);
			else if (s != BML_Q_OK)
				rc = ck_fail(c, msg);
			else {
				for (size_t j = 0; j < d.n; j++)
					ck_add(c, "farg", P, fn, 0, ck_fmtd("program %s: %s", P, d.s[j]));
				bml_strs_free(&d);
			}
		}
	}
	for (size_t i = 0; rc == 0 && i < a->n_fargs; i++) {
		const char *t = a->fargs[i].p;
		if (!ck_int_spelling(t))
			continue;
		char *name = ck_fmtd("%zu of %s (%s)", i + 1, fn, t);
		if (!HAS(c, func_param, BML_QUERY_FUNC_PARAM)) {
			ck_add(c, "farg_unknown", P, name ? name : "", 0, ck_dupn("no BTF probe"));
			free(name);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int s = c->caps->func_param(c->caps->ctx, fn, (int64_t)(i + 1), t, &d, &msg);
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
	free(fn);
	return rc;
}


static char *syscalls_ctx_problem(const char *event, const struct bml_tpfield *t)
{
	if (BML_MUT("check.syscalls_ctx_skip") || strncmp(event, "syscalls/", 9) != 0)
		return NULL;
	const char *name = event + 9;
	if (t->sign.p[0] == '[')
		return ck_fmtd("field %s: inline array fields are not part of the BPF context of syscalls events", t->field.p);
	int64_t off = t->offset, b = t->bytes;
	if (off == 8 && b == 4)
		return NULL;
	if (!strncmp(name, "sys_enter_", 10) && off >= 16 && off < 64 && (off - 16) % 8 == 0 && b == 8)
		return NULL;
	if (!strncmp(name, "sys_exit_", 9) && off == 16 && b == 8)
		return NULL;
	return ck_fmtd("field %s (offset %lld, %lld bytes) is not part of the BPF context of syscalls events "
		       "(struct syscall_trace_enter: nr at 8 (4 bytes), args[6] at 16 + 8k (8 bytes); struct syscall_trace_exit: nr at 8, ret at 16 (8 bytes)) "
		       "— the tracefs format of a syscalls event is not what a BPF program reads",
		       t->field.p, (long long)off, (long long)b);
}


static int tp_fields(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *ev = a->target.p;
	int ok = HAS(c, tp_field, BML_QUERY_TP_FIELDS);
	for (size_t i = 0; i < a->n_tpfields; i++) {
		const struct bml_tpfield *t = &a->tpfields[i];
		char *name = ck_fmtd("%s.%s (offset %lld, %lld bytes, %s)", ev, t->field.p, (long long)t->offset, (long long)t->bytes, t->sign.p);
		const char *N = name ? name : "";
		char *p = syscalls_ctx_problem(ev, t);
		if (p) {
			ck_add(c, "tpfield", P, N, 0, p);
		} else if (!ok) {
			ck_add(c, "tpfield_unknown", P, N, 0, ck_dupn("no tracepoint format probe (a non-root loader uses caps recorded as root with a live re-probe — ebpf-precheck --caps --live)"));
		} else {
			struct bml_strs d = {0};
			char *msg = NULL;
			int s = c->caps->tp_field(c->caps->ctx, ev, t->field.p, t->offset, t->bytes, t->sign.p, &d, &msg);
			if (s == BML_Q_UNKNOWN)
				ck_add(c, "tpfield_unknown", P, N, 0, msg);
			else if (s != BML_Q_OK) {
				free(name);
				return ck_fail(c, msg);
			} else
				ck_add_diffs(c, "tpfield", P, N, &d);
		}
		free(name);
	}
	return 0;
}


static int ext(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p;
	if (a->ext_nargs < 0)
		return ck_fail(c, ck_fmtd("program %s: freplace attach row without an extret row", P));
	if (!HAS(c, ext_target, BML_QUERY_EXT_TARGETS)) {
		ck_add(c, "ext_target_unknown", P, T, 0,
		       ck_dupn("no replacement target given (the target program is a loader input — a recorded caps does not carry it)"));
		return 0;
	}
	struct bml_strs d = {0};
	char *msg = NULL;
	int s = c->caps->ext_target(c->caps->ctx, P, T, a->ext_nargs, a->ext_ret.p ? a->ext_ret.p : "", a->ext_args, a->n_ext_args, &d, &msg);
	if (s == BML_Q_UNKNOWN) {
		ck_add(c, "ext_target_unknown", P, T, 0, msg);
		return 0;
	}
	if (s != BML_Q_OK)
		return ck_fail(c, msg);
	ck_add_diffs(c, "ext_target", P, T, &d);
	return 0;
}


static int struct_ops(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p;
	if (a->sop_struct.len == 0)
		return ck_fail(c, ck_fmtd("program %s: trace_struct_ops attach row without a structop row", P));
	char *name = ck_fmtd("%s.%s", a->sop_struct.p, a->sop_member.p);
	const char *N = name ? name : "";
	int rc = 0;
	if (!HAS(c, struct_ops_member, BML_QUERY_STRUCT_OPS_MEMBERS)) {
		ck_add(c, "structop_unknown", P, N, 0, ck_dupn("no struct_ops probe"));
	} else {
		struct bml_strs d = {0};
		char *msg = NULL;
		int s = c->caps->struct_ops_member(c->caps->ctx, a->sop_struct.p, a->sop_member.p, a->ret_nargs, a->ret_type.p ? a->ret_type.p : "", a->fargs,
						   a->n_fargs, &d, &msg);
		if (s == BML_Q_UNKNOWN)
			ck_add(c, "structop_unknown", P, N, 0, msg);
		else if (s != BML_Q_OK)
			rc = ck_fail(c, msg);
		else
			ck_add_diffs(c, "structop", P, N, &d);
	}
	free(name);
	return rc;
}

int ck_check_v11(struct ck *c, const struct bml_attach *a)
{
	if (!BML_MUT("check.v11_generic_skip") && v11_generic(c, a))
		return -1;
	const char *t = a->attach_type.p;
	if (!strcmp(t, "trace_lsm"))
		return ck_lsm_args(c, a);
	if (!strcmp(t, "trace_tp"))
		return tp_fields(c, a);
	if (!strcmp(t, "trace_perf")) {
		if (a->arch.len == 0)
			return ck_fail(c, ck_fmtd("program %s: trace_perf attach row without an arch row", a->program.p));
		char *ta;
		int rc = ck_check_arch_ctx(c, a, &ta);
		free(ta);
		return rc;
	}
	if (!strcmp(t, "freplace"))
		return ext(c, a);
	if (!strcmp(t, "trace_struct_ops"))
		return struct_ops(c, a);
	return 0;
}
