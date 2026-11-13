#include "req/check_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

static char *config_reason(const char *type, const char *v, int *oom)
{
	*oom = 0;
	if (!v[0]) { char *s = ck_dupn("the value is empty"); *oom = !s; return s; }
	struct bml_buf b = {0};
	const char *reason = NULL;
	if (v[0] == 'y' || v[0] == 'n' || v[0] == 'm') {
		if (!strcmp(type, "bool")) {
			if (v[0] != 'm') return NULL;
			reason = " implies tristate or char, the extern is bool";
		} else if (!strcmp(type, "tristate") || !strcmp(type, "char")) return NULL;
		else reason = " implies bool, tristate or char, the extern is ";
	} else if (v[0] == '"') { char *s = ck_fmtd("value %s implies a char array, the extern is %s", v, type); *oom = !s; return s; }
	else {
		char *end;
		int saved_errno = errno;
		errno = 0;
		unsigned long long value = strtoull(v, &end, 0);
		int invalid = errno == ERANGE || end == v || *end;
		errno = saved_errno;
		if (invalid) reason = " is not an integer";
		else if (!strcmp(type, "bool") || !strcmp(type, "tristate")) reason = " implies an integer type, the extern is ";
		else {
			int bits = !strcmp(type, "char") ? 8 : atoi(type + 1);
			int sign = !strcmp(type, "char") || type[0] == 'i';
			if (bits == 64) return NULL;
			int fits = sign ? (uint64_t)value + (UINT64_C(1) << (bits - 1)) < (UINT64_C(1) << bits) : ((uint64_t)value >> bits) == 0;
			if (fits) return NULL;
			reason = " does not fit in ";
		}
	}
	bml_buf_adds(&b, "value ");
	bml_buf_add_goquote(&b, v, strlen(v));
	bml_buf_adds(&b, reason);
	if (reason[strlen(reason) - 1] == ' ') bml_buf_adds(&b, type);
	char *s = bml_buf_take(&b); *oom = !s; return s;
}

int ck_check_ksym_vars(struct ck *c)
{
	const struct bml_loader_decl *d = ck_loader_of(c);
	const char *typed = d->typed_ksym ? d->typed_ksym : "";
	for (size_t i = 0; i < c->req->n_ksym_vars; i++) {
		const struct bml_ksym_var *v = &c->req->ksym_vars[i];
		if (strcmp(typed, "btf_id")) {
			int bad = !strcmp(typed, "kallsyms_addr");
			ck_add(c, bad ? "typed_ksym_loader" : "typed_ksym_loader_unknown", "", v->name.p, 0,
				ck_fmtd(bad ? "loader %s declares typed_ksym kallsyms_addr" : "loader %s does not declare typed_ksym", d->name));
		}
		if (!HAS(c, ksym_var, BML_QUERY_KSYM_VARS)) {
			ck_add(c, "ksymvar_unknown", "", v->name.p, 0, ck_dupn("no ksym_vars query")); continue;
		}
		char *got = NULL, *msg = NULL;
		char *want = ck_fmtd("%s %s", v->cls.p, v->slot.p);
		if (!want) return ck_fail(c, ck_dupn("out of memory"));
		int st = c->caps->ksym_var(c->caps->ctx, v->name.p, &got, &msg);
		if (st == BML_Q_UNKNOWN) ck_add(c, "ksymvar_unknown", "", v->name.p, 0, msg);
		else if (st == BML_Q_ABSENT) {
			if (!strcmp(v->bind.p, "strong"))
				ck_add(c, "ksymvar", "", v->name.p, 0, ck_fmtd("%s; the extern is strong (the object reads it as %s)", msg, want));
			else {
				int state; char *why = NULL;
				if (ck_guards_state(c, &v->guards, &state, &why)) { free(msg); free(want); free(got); return -1; }
				if (state == 2) ck_add(c, "ksymvar_unknown", "", v->name.p, 0, ck_fmtd("%s, but %s", msg, why));
				else if (state) ck_add(c, "ksymvar", "", v->name.p, 0,
					ck_fmtd("%s, but no guard of the weak extern is confirmed false (the object reads it as %s)", msg, want));
				free(why);
			}
			free(msg);
		} else if (st != BML_Q_OK) { free(got); free(want); return ck_fail(c, msg); }
		else if (strcmp(got, want)) ck_add(c, "ksymvar", "", v->name.p, 0, ck_fmtd("the target's VAR is %s, the object reads it as %s", got, want));
		free(got); free(want);
	}
	return 0;
}

int ck_check_kconfigs(struct ck *c)
{
	const struct bml_loader_decl *d = ck_loader_of(c);
	const char *loader = d->kconfig ? d->kconfig : "";
	for (size_t i = 0; i < c->req->n_kconfigs; i++) {
		const struct bml_kconfig *v = &c->req->kconfigs[i];
		int strong = !strcmp(v->bind.p, "strong");
		if (!strcmp(loader, "strong_only")) {
			if (!strong) ck_add(c, "kconfig_loader", "", v->name.p, 0, ck_fmtd("loader %s declares kconfig strong_only and the extern is weak", d->name));
		} else if (strcmp(loader, "weak_zero"))
			ck_add(c, "kconfig_loader_unknown", "", v->name.p, 0, ck_fmtd("loader %s does not declare kconfig", d->name));
		if (!HAS(c, kconfig, BML_QUERY_KCONFIG)) {
			ck_add(c, "kconfig_unknown", "", v->name.p, 0, ck_dupn("no kconfig query")); continue;
		}
		char *got = NULL, *msg = NULL;
		int st = c->caps->kconfig(c->caps->ctx, v->name.p, &got, &msg);
		if (st == BML_Q_UNKNOWN) ck_add(c, "kconfig_unknown", "", v->name.p, 0, msg);
		else if (st == BML_Q_ABSENT) {
			if (strong) ck_add(c, "kconfig", "", v->name.p, 0, ck_fmtd("%s; the extern is strong", msg));
			free(msg);
		} else if (st != BML_Q_OK) { free(got); return ck_fail(c, msg); }
		else {
			int oom;
			char *why = config_reason(v->type.p, got, &oom);
			if (oom) { free(got); return ck_fail(c, ck_dupn("out of memory")); }
			if (why) ck_add(c, "kconfig_type", "", v->name.p, 0, why);
		}
		free(got);
	}
	return 0;
}
