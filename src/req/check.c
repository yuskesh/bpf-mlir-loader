#include "req/check_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"

static int check_body(struct ck *c)
{
	const struct bml_requirements *r = c->req;
	const struct bml_caps *caps = c->caps;
	if (ck_has_nul(r))
		return ck_fail(c, ck_dupn("a requirements field contains a NUL byte, which bpf-mlir-loader does not check (strict — Go compares the bytes)"));

	if (ck_check_helper_targets(c))
		return -1;

	for (size_t i = 0; i < r->n_programs; i++) {
		const struct bml_program *p = &r->programs[i];
		int ok = 0;
		char *msg = NULL;
		if (caps->prog_type(caps->ctx, p->prog_type.p, p->prog_type_id, &ok, &msg) != BML_Q_OK)
			return ck_fail(c, msg);
		if (!ok) {
			ck_add(c, "program_type", p->symbol.p, p->prog_type.p, p->prog_type_id, NULL);
			continue;
		}
		int th = HAS(c, tracing_helper, BML_QUERY_TRACING_HELPER);
		const char *at = ck_tracing_attach(r, p->symbol.p);
		for (size_t j = 0; j < p->n_helpers; j++) {
			const struct bml_helper *h = &p->helpers[j];
			if (ck_needs_helper_target(p, h) && !BML_MUT("check.helper_target_generic"))
				continue;
			int hok = 0;
			char *hmsg = NULL;
			int st = th && at[0] ? caps->tracing_helper(caps->ctx, at, h->name.p, h->id, &hok, &hmsg)
					     : caps->helper(caps->ctx, p->prog_type.p, p->prog_type_id, h->name.p, h->id, &hok, &hmsg);
			if (st == BML_Q_UNKNOWN) {
				ck_add(c, "helper_unknown", p->symbol.p, h->name.p, h->id, hmsg);
				continue;
			}
			if (st != BML_Q_OK)
				return ck_fail(c, hmsg);
			if (!hok)
				ck_add(c, "helper", p->symbol.p, h->name.p, h->id, NULL);
		}
	}

	if (r->n_kfuncs > 0 && ck_check_kfuncs(c))
		return -1;
	if (ck_check_enum_values(c) || ck_check_struct_sizes(c)) return -1;

	for (size_t i = 0; i < r->n_attaches; i++) {
		const struct bml_attach *a = &r->attaches[i];
		const char *P = a->program.p, *T = a->target.p, *AT = a->attach_type.p;
		if (a->generic) {

			if (ck_check_generic_attach(c, a) || ck_check_prog_loader(c, a) || ck_check_tpbuf(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "trace_lsm_cgroup") || !strcmp(AT, "ksyscall")) {
			if (ck_check_v13(c, a) || ck_check_prog_loader(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "tcx")) {
			if (!HAS(c, tcx, BML_QUERY_TCX)) {
				ck_add(c, "attach_tcx_unknown", P, T, 0, ck_dupn("no tcx probe"));
				continue;
			}
			int have = 0;
			char *msg = NULL;
			int st = caps->tcx(caps->ctx, &have, &msg);
			if (st == BML_Q_UNKNOWN) {
				ck_add(c, "attach_tcx_unknown", P, T, 0, msg);
				continue;
			}
			if (st != BML_Q_OK)
				return ck_fail(c, msg);
			if (!have)
				ck_add(c, "attach", P, T, 0, ck_dupn("the target kernel has no tcx attach (BPF_TCX_INGRESS / EGRESS links)"));
			continue;
		}
		if (!strcmp(AT, "netkit")) {
			if (ck_check_netkit(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "kprobe_multi") || !strcmp(AT, "kretprobe_multi") || !strcmp(AT, "uprobe_multi") || !strcmp(AT, "uretprobe_multi")) {
			if (ck_check_multi(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "usdt")) {
			if (ck_check_usdt(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "uprobe") || !strcmp(AT, "uretprobe")) {
			if (ck_check_uprobe(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "kprobe") || !strcmp(AT, "kretprobe")) {
			char *ta;
			int rc = ck_check_arch_ctx(c, a, &ta);
			if (rc == 0)
				rc = ck_check_kprobe_target(c, a, ta, 1);
			free(ta);
			if (rc)
				return -1;
			continue;
		}
		if (!strcmp(AT, "trace_lsm") || !strcmp(AT, "trace_tp") || !strcmp(AT, "trace_perf") || !strcmp(AT, "freplace") ||
		    !strcmp(AT, "trace_struct_ops")) {
			if (ck_check_v11(c, a))
				return -1;
			continue;
		}
		if (!strcmp(AT, "trace_fmod_ret")) {
			if (ck_check_fmod_ret(c, a))
				return -1;
			continue;
		}
		if (strcmp(AT, "trace_fentry") != 0 && strcmp(AT, "trace_fexit") != 0)
			continue;
		if (!strcmp(AT, "trace_fexit")) {
			if (a->func_ret.len) {
				if (!HAS(c, func_ret, BML_QUERY_FUNC_RET)) ck_add(c, "funcret_unknown", P, T, 0, ck_dupn("no function return type probe"));
				else {
					struct bml_strs d = {0}; char *msg = NULL;
					int st = caps->func_ret(caps->ctx, T, a->func_ret.p, &d, &msg);
					if (st == BML_Q_UNKNOWN) ck_add(c, "funcret_unknown", P, T, 0, msg);
					else if (st != BML_Q_OK) return ck_fail(c, msg);
					else ck_add_diffs(c, "funcret", P, T, &d);
				}
				continue;
			}
			if (a->ret_nargs < 0)
				return ck_fail(c, ck_fmtd("program %s: fexit attach row without a retsig or funcret row", P));
			if (!HAS(c, func_sig, BML_QUERY_FUNC_SIG)) {
				ck_add(c, "retsig_unknown", P, T, 0, NULL);
				continue;
			}
			struct bml_strs d = {0};
			char *msg = NULL;
			if (caps->func_sig(caps->ctx, T, a->ret_nargs, a->ret_type.p, &d, &msg) != BML_Q_OK)
				return ck_fail(c, msg);
			ck_add_diffs(c, "attach", P, T, &d);
			continue;
		}
		

		if (a->sleepable && ck_check_sleepable(c, a))
			return -1;
		if (a->n_fargs > 0 && ck_fentry_args(c, a) != 0)
			return -1;
		if (!HAS(c, func, BML_QUERY_FUNC)) {
			ck_add(c, "attach_func_unknown", P, T, 0, NULL);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		if (caps->func(caps->ctx, T, &d, &msg) != BML_Q_OK)
			return ck_fail(c, msg);
		ck_add_diffs(c, "attach", P, T, &d);
	}

	int has_tp = HAS(c, tracepoint, BML_QUERY_TRACEPOINT);
	for (size_t i = 0; i < r->n_attaches; i++) {
		const struct bml_attach *a = &r->attaches[i];
		if (strcmp(a->attach_type.p, "trace_raw_tp") != 0)
			continue;
		if (has_tp) {
			struct bml_strs d = {0};
			char *msg = NULL;
			if (caps->tracepoint(caps->ctx, a->target.p, a->args, a->n_args, &d, &msg) != BML_Q_OK)
				return ck_fail(c, msg);
			ck_add_diffs(c, "attach", a->program.p, a->target.p, &d);
		} else {
			ck_add(c, "attach_unknown", a->program.p, a->target.p, 0, NULL);
		}
		if (ck_check_nullable(c, a))
			return -1;
	}

	if (ck_check_kfields_guarded(c)) return -1;

	if (HAS(c, btf_feature, BML_QUERY_BTF_FEATURE) && r->n_btf_features > 0) {
		const struct bml_loader_decl *decl = ck_loader_of(c);
		const char *rewrites[8], *undeclared[8];
		size_t n_rw = 0, n_und = 0;
		for (size_t i = 0; i < r->n_btf_features; i++) {
			const char *f = r->btf_features[i].p;
			int ok = 0;
			char *msg = NULL;
			int st = caps->btf_feature(caps->ctx, f, &ok, &msg);
			if (st != BML_Q_OK && BML_MUT("check.btf_error_as_supported")) {
				free(msg);
				st = BML_Q_OK;
				ok = 1;
			}
			if (st != BML_Q_OK) {
				ck_add(c, "btf_feature_unknown", "", f, 0, msg);
				continue;
			}
			if (ok)
				continue;
			ck_add(c, "btf_feature", "", f, 0, NULL);
			const char *rn = ck_btf_rewrite_name(f);
			if (!rn)
				continue;
			const char *v = bml_kv_get(decl->btf_rewrite, decl->n_btf_rewrite, f);
			if (v && !strcmp(v, "rewrite") && !BML_MUT("check.rewrite_as_keep")) {
				if (n_rw < 8)
					rewrites[n_rw++] = rn;
			} else if (v && (!strcmp(v, "keep") || (!strcmp(v, "rewrite") && BML_MUT("check.rewrite_as_keep")))) {
			} else {
				if (n_und < 8)
					undeclared[n_und++] = f;
			}
		}
		if (n_und) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, "loader ");
			bml_buf_add_goquote(&b, decl->name, strlen(decl->name));
			bml_buf_adds(&b, " does not declare what it does with ");
			for (size_t i = 0; i < n_und; i++) {
				if (i)
					bml_buf_adds(&b, ", ");
				bml_buf_adds(&b, undeclared[i]);
			}
			bml_buf_adds(&b, " on a kernel that lacks it");
			ck_add(c, "btf_feature_unknown", "", "loader rewrites", 0, bml_buf_take(&b));
		}
		if (n_rw) {
			struct bml_buf b = {0};
			for (size_t i = 0; i < n_rw; i++) {
				if (i)
					bml_buf_adds(&b, ", ");
				bml_buf_adds(&b, rewrites[i]);
			}
			ck_add(c, "btf_rewrite", "", "", 0, bml_buf_take(&b));
		}
	} else {
		for (size_t i = 0; i < r->n_btf_features; i++)
			ck_add(c, "btf_feature_unknown", "", r->btf_features[i].p, 0, ck_dupn("this checker cannot probe the target BTF"));
	}

	if (r->n_argtags > 0) {
		int ok_q = HAS(c, arg_tag, BML_QUERY_ARG_TAG);
		for (size_t i = 0; i < r->n_argtags; i++) {
			const struct bml_argtag *t = &r->argtags[i];
			const struct bml_program *p = NULL;
			for (size_t j = 0; j < r->n_programs; j++)
				if (!strcmp(r->programs[j].symbol.p, t->program.p))
					p = &r->programs[j];
			char *name = ck_fmtd("%s (%s)", t->tag.p, t->cls.p);
			if (!ok_q) {
				ck_add(c, "arg_tag_unknown", t->program.p, name, 0, ck_dupn("this checker cannot probe the verifier's reading of argument tags"));
				free(name);
				continue;
			}
			int hasit = 0;
			char *msg = NULL;
			int st = caps->arg_tag(caps->ctx, p ? p->prog_type.p : "", p ? p->prog_type_id : 0, t->tag.p, t->cls.p, &hasit, &msg);
			if (st != BML_Q_OK)
				ck_add(c, "arg_tag_unknown", t->program.p, name, 0, msg);
			else if (!hasit)
				ck_add(c, "arg_tag", t->program.p, name, 0, NULL);
			free(name);
		}
	}

	if (r->n_ctxaccesses > 0 && ck_check_ctx_accesses(c))
		return -1;
	if (ck_check_fib_flags(c)) return -1;
	ck_check_loader_rows(c);
	if (ck_check_ksym_vars(c) || ck_check_kconfigs(c)) return -1;

	for (size_t i = 0; i < r->n_maps; i++) {
		const struct bml_map *m = &r->maps[i];
		int ok = 0;
		char *msg = NULL;
		if (caps->map_type(caps->ctx, m->map_type.p, m->id, &ok, &msg) != BML_Q_OK)
			return ck_fail(c, msg);
		if (!ok)
			ck_add(c, "map_type", m->symbol.p, m->map_type.p, m->id, NULL);
	}
	if (ck_check_innermaps(c))
		return -1;

	const struct bml_map_fields *mf = &r->map_fields;
	if (mf->state != BML_MF_DERIVED) {
		const char *why = mf->state == BML_MF_NOT_DERIVED
					  ? "the requirements were parsed without the ELF (Parse), so map uses were not derived"
					  : (mf->reason ? mf->reason : "");
		for (size_t i = 0; i < r->n_maps; i++)
			if (ck_may_hold_field(&r->maps[i]))
				ck_add(c, "map_field_unknown", "", r->maps[i].symbol.p, 0, ck_dupn(why));
		return 0;
	}
	const char **no_type = NULL;
	size_t n_no = 0;
	for (size_t i = 0; i < c->out->n; i++) {
		if (!strcmp(c->out->u[i].kind, "program_type")) {
			const char **nn = realloc(no_type, (n_no + 1) * sizeof(*nn));
			if (!nn) {
				free(no_type);
				return ck_fail(c, ck_dupn("out of memory"));
			}
			no_type = nn;
			no_type[n_no++] = c->out->u[i].program;
		}
	}
	int has_policy = HAS(c, map_field, BML_QUERY_MAP_FIELD);
	for (size_t i = 0; i < r->n_programs; i++) {
		const struct bml_program *p = &r->programs[i];
		if (ck_in_list(no_type, n_no, p->symbol.p))
			continue;
		const struct bml_mf_prog *u = bml_map_fields_uses(mf, p->symbol.p);
		for (size_t j = 0; u && j < u->n_uses; j++) {
			const struct bml_mf_use *x = &u->uses[j];
			if (!has_policy) {
				ck_add(c, "map_field_unknown", p->symbol.p, x->map, 0, ck_fmtd("%s × %s: no map-field probe", x->field, p->prog_type.p));
				continue;
			}
			int ok = 0;
			char *msg = NULL;
			int st = caps->map_field(caps->ctx, p->prog_type.p, p->prog_type_id, x->field, &ok, &msg);
			if (st == BML_Q_UNKNOWN) {
				ck_add(c, "map_field_unknown", p->symbol.p, x->map, 0, ck_fmtd("%s × %s: %s", x->field, p->prog_type.p, msg));
				free(msg);
				continue;
			}
			if (st != BML_Q_OK) {
				free(no_type);
				return ck_fail(c, msg);
			}
			if (!ok)
				ck_add(c, "map_field", p->symbol.p, x->map, 0, ck_fmtd("%s × %s", x->field, p->prog_type.p));
		}
	}
	free(no_type);
	return 0;
}

int bml_check(const struct bml_requirements *req, const struct bml_caps *caps, struct bml_unmets *out, char **err)
{
	memset(out, 0, sizeof(*out));
	*err = NULL;
	if (!caps || !caps->prog_type || !caps->helper || !caps->map_type) {
		*err = ck_dupn("CheckTarget: no capabilities given (the check is not skipped)");
		return -1;
	}
	struct ck c = {.req = req, .caps = caps, .out = out, .err = err};
	int rc = check_body(&c);
	ck_asked_free(&c);
	if (rc == 0 && c.oom) {
		*err = ck_dupn("out of memory");
		rc = -1;
	}
	if (rc) {
		bml_unmets_free(out);
		if (!*err)
			*err = ck_dupn("check failed");
	}
	return rc;
}
