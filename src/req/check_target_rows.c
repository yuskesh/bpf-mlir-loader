
#include "req/check_internal.h"
#include "req/parse_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"


int ck_needs_helper_target(const struct bml_program *p, const struct bml_helper *h)
{
	return (req_str_eq_lit(&p->prog_type, "tracing") || p->prog_type_id == 26) && (h->id == 147 || req_str_eq_lit(&h->name, "d_path"));
}


int ck_check_helper_targets(struct ck *c)
{
	const struct bml_requirements *r = c->req;
	const struct bml_caps *caps = c->caps;
	for (size_t i = 0; i < r->n_programs; i++) {
		const struct bml_program *p = &r->programs[i];
		for (size_t j = 0; j < p->n_helpers; j++) {
			const struct bml_helper *h = &p->helpers[j];
			if (!ck_needs_helper_target(p, h))
				continue;
			int bound = 0;
			for (size_t k = 0; k < r->n_helper_targets; k++) {
				const struct bml_helper_target *t = &r->helper_targets[k];
				if (t->program.len == p->symbol.len && !memcmp(t->program.p, p->symbol.p, t->program.len) && t->helper_id == h->id &&
				    t->helper.len == h->name.len && !memcmp(t->helper.p, h->name.p, t->helper.len))
					bound = 1;
			}
			if (!bound && !BML_MUT("check.helper_target_companion_optional"))
				ck_add(c, "helper_target_unknown", p->symbol.p, h->name.p, h->id, ck_dupn("missing bound helper_target companion"));
		}
	}
	struct bml_buf errs = {0};
	int have = HAS(c, helper_target, BML_QUERY_HELPER_TARGET);
	for (size_t k = 0; k < r->n_helper_targets; k++) {
		const struct bml_helper_target *t = &r->helper_targets[k];
		char *prefix = ck_fmtd("%s/%s arg%lld:%s: ", t->attach_type.p, t->target.p, (long long)t->arg_index, t->arg_type.p);
		if (!prefix)
			return ck_fail(c, ck_dupn("out of memory"));
		if (!have) {
			ck_add(c, "helper_target_unknown", t->program.p, t->helper.p, t->helper_id, ck_fmtd("%sno target-specific helper probe", prefix));
			free(prefix);
			continue;
		}
		struct bml_strs d = {0};
		char *msg = NULL;
		int st = caps->helper_target(caps->ctx, "tracing", 26, t, &d, &msg);
		if (st == BML_Q_UNKNOWN) {
			ck_add(c, "helper_target_unknown", t->program.p, t->helper.p, t->helper_id, ck_fmtd("%s%s", prefix, msg ? msg : ""));
			free(msg);
		} else if (st != BML_Q_OK && BML_MUT("check.helper_target_error_unknown")) {
			ck_add(c, "helper_target_unknown", t->program.p, t->helper.p, t->helper_id, ck_fmtd("%s%s", prefix, msg ? msg : ""));
			free(msg);
		} else if (st != BML_Q_OK) {
			bml_buf_addf(&errs, "%shelper_target %s/%s: %s", errs.len ? "\n" : "", t->program.p, t->target.p, msg ? msg : "");
			free(msg);
		} else if (d.n && !BML_MUT("check.helper_target_diffs_ignored")) {
			struct bml_buf b = {0};
			bml_buf_adds(&b, prefix);
			for (size_t i = 0; i < d.n; i++)
				bml_buf_addf(&b, "%s%s", i ? "; " : "", d.s[i]);
			ck_add(c, "helper_target", t->program.p, t->helper.p, t->helper_id, bml_buf_take(&b));
			bml_strs_free(&d);
		}
		free(prefix);
	}
	if (errs.len)
		return ck_fail(c, bml_buf_take(&errs));
	bml_buf_free(&errs);
	return 0;
}

int ck_check_netkit(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p;
	if (!HAS(c, netkit, BML_QUERY_NETKIT)) {
		ck_add(c, "attach_netkit_unknown", P, T, 0, ck_dupn("no netkit probe"));
		return 0;
	}
	int have = 0;
	char *msg = NULL;
	int st = c->caps->netkit(c->caps->ctx, T, &have, &msg);
	if (st == BML_Q_UNKNOWN) {
		ck_add(c, "attach_netkit_unknown", P, T, 0, msg);
		return 0;
	}
	if (st != BML_Q_OK)
		return ck_fail(c, msg);
	if (!have && !BML_MUT("check.netkit_false_passes"))
		ck_add(c, "attach", P, T, 0, ck_fmtd("the target kernel has no netkit %s link", T));
	return 0;
}

static const char *program_type_of(const struct bml_requirements *r, const struct bml_str *prog)
{
	for (size_t i = 0; i < r->n_programs; i++)
		if (r->programs[i].symbol.len == prog->len && !memcmp(r->programs[i].symbol.p, prog->p, prog->len))
			return r->programs[i].prog_type.p;
	return "";
}

int ck_check_sleepable(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p, *pt = program_type_of(c->req, &a->program);
	if (!HAS(c, sleepable, BML_QUERY_SLEEPABLE)) {
		ck_add(c, "sleepable_type_unknown", P, T, 0, ck_dupn("no sleepable probe"));
		return 0;
	}
	int have = 0;
	char *msg = NULL;
	int st = c->caps->sleepable(c->caps->ctx, pt, a->attach_type.p, &have, &msg);
	if (st == BML_Q_UNKNOWN) {
		ck_add(c, "sleepable_type_unknown", P, T, 0, msg);
		return 0;
	}
	if (st != BML_Q_OK)
		return ck_fail(c, msg);
	if (!have && !BML_MUT("check.sleepable_false_passes"))
		ck_add(c, "sleepable_type", P, T, 0,
		       ck_fmtd("the target kernel cannot load program type %s with attach type %s sleepable", pt, a->attach_type.p));
	return 0;
}
