#include "req/check_internal.h"

#include <stdlib.h>
#include <string.h>
#include "util/mutation.h"

static int guard_state(struct ck *c, const struct bml_guard *g, int *state, char **why)
{
	const struct bml_caps *caps = c->caps;
	*why = NULL;
	*state = 1;
	if (!strcmp(g->kind.p, "ksym")) {
		if (!HAS(c, ksym_var, BML_QUERY_KSYM_VARS)) { *state = 2; *why = ck_dupn("no ksym_vars query"); return 0; }
		char *value = NULL, *msg = NULL;
		int st = caps->ksym_var(caps->ctx, g->target.p, &value, &msg);
		free(value);
		if (st == BML_Q_UNKNOWN || st == BML_Q_ABSENT) {
			*state = st == BML_Q_UNKNOWN ? 2 : 0; *why = msg; return 0;
		}
		if (st != BML_Q_OK) return ck_fail(c, msg);
		return 0;
	}
	if (!strcmp(g->kind.p, "type") || !strcmp(g->kind.p, "field")) {
		if (!HAS(c, btf_presence, BML_QUERY_BTF_PRESENCE)) { *state = 2; *why = ck_dupn("no btf_presence query"); return 0; }
		int present = 0;
		char *msg = NULL;
		int st = caps->btf_presence(caps->ctx, g->kind.p, g->target.p, &present, &msg);
		if (st == BML_Q_UNKNOWN) { *state = 2; *why = msg; return 0; }
		if (st != BML_Q_OK) return ck_fail(c, msg);
		if (!present) { *state = 0; *why = ck_fmtd("%s %s is absent", g->kind.p, g->target.p); }
		return 0;
	}
	*state = 2; *why = ck_fmtd("unknown guard kind %s", g->kind.p); return 0;
}

int ck_guards_state(struct ck *c, const struct bml_guard_list *gs, int *state, char **why)
{
	*state = 1; *why = NULL;
	for (size_t i = 0; i < gs->count; i++) {
		int64_t n = gs->numbers[i];
		if (n < 0 || (uint64_t)n >= c->req->n_guards) {
			free(*why); *why = NULL; return ck_fail(c, ck_dupn("guard index is outside the parsed document"));
		}
		const struct bml_guard *g = &c->req->guards[n];
		int st;
		char *w = NULL;
		if (guard_state(c, g, &st, &w)) { free(*why); *why = NULL; return -1; }
		if (st == 2 && BML_MUT("check.guard_unknown_false")) st = 0;
		if (!st || (st == 2 && *state != 2)) {
			free(*why);
			*why = ck_fmtd("guard %lld (%s %s) is %s: %s", (long long)n, g->kind.p, g->target.p, st ? "Unknown" : "false", w ? w : "");
			*state = st;
			if (!*why) { free(w); return ck_fail(c, ck_dupn("out of memory")); }
		}
		free(w);
		if (!st) return 0;
	}
	return 0;
}

int ck_check_kfields_guarded(struct ck *c)
{
	const struct bml_requirements *r = c->req;
	struct bml_kfield *plain = r->n_kfields ? calloc(r->n_kfields, sizeof(*plain)) : NULL;
	if (r->n_kfields && !plain) return ck_fail(c, ck_dupn("out of memory"));
	size_t np = 0;
	for (size_t i = 0; i < r->n_kfields; i++)
		if (!r->kfields[i].guards.count) plain[np++] = r->kfields[i];
	int have = HAS(c, kfields, BML_QUERY_KFIELDS);
	if (have) {
		struct bml_strs d = {0}; char *msg = NULL;
		int st = c->caps->kfields(c->caps->ctx, plain, np, &d, &msg);
		free(plain);
		if (st != BML_Q_OK) return ck_fail(c, msg);
		ck_add_diffs(c, "kfield", "", "", &d);
	} else {
		for (size_t i = 0; i < np; i++) {
			char *name = ck_fmtd("%s.%s (%s)", plain[i].strct.p, plain[i].field.p, plain[i].type.p);
			ck_add(c, "kfield_unknown", plain[i].program.p, name, 0, NULL); free(name);
		}
		free(plain);
	}
	for (size_t i = 0; i < r->n_kfields; i++) {
		const struct bml_kfield *k = &r->kfields[i];
		if (!k->guards.count) continue;
		struct bml_strs d = {0};
		if (have) {
			char *msg = NULL;
			if (c->caps->kfields(c->caps->ctx, k, 1, &d, &msg) != BML_Q_OK) return ck_fail(c, msg);
			if (!d.n) { bml_strs_free(&d); continue; }
		}
		int state; char *why = NULL;
		if (ck_guards_state(c, &k->guards, &state, &why)) { bml_strs_free(&d); return -1; }
		char *name = ck_fmtd("%s.%s (%s)", k->strct.p, k->field.p, k->type.p);
		const struct bml_loader_decl *decl = ck_loader_of(c);
		if (!state && decl->core_poisons_missing_field) {                                                        }
		else if (!state) ck_add(c, "kfield_unknown", k->program.p, name, 0,
			ck_fmtd("%s; loader %s does not declare core_poisons_missing_field", why, decl->name));
		else if (state == 2 || !have) ck_add(c, "kfield_unknown", k->program.p, name, 0, ck_dupn(why && why[0] ? why : "no kfields query"));
		else { ck_add_diffs(c, "kfield", "", "", &d); }
		free(why); free(name); bml_strs_free(&d);
	}
	return 0;
}
