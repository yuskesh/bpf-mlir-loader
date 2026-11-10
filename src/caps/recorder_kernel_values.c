
#include "caps/recorder_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

static void record_text(struct bml_recorder *r, const char *q, const char *key,
	int st, const char *text, const char *msg, const char *sentinel)
{
	struct rec *e = slot(r, q, key);
	if (!e) return;
	if (st == BML_Q_ABSENT) {
		size_t n = msg ? strlen(msg) : 0, sn = strlen(sentinel);
		if (n >= sn + 2 && !strcmp(msg + n - sn, sentinel) && !memcmp(msg + n - sn - 2, ": ", 2)) n -= sn + 2;
		e->kind = A_DIFFS;
		e->diffs.s = calloc(1, sizeof(*e->diffs.s));
		if (e->diffs.s) {
			e->diffs.s[0] = strndup(msg ? msg : "", n);
			if (e->diffs.s[0]) e->diffs.n = 1;
		}
	} else if (!put_err(e, st, msg)) {
		e->kind = A_TEXT; e->s = strdup(text ? text : "");
	}
}

static int enum_value(void *ctx, const char *en, const char *name, uint64_t *out, char **msg)
{
	int st = U(ctx)->enum_value(U(ctx)->ctx, en, name, out, msg);
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s/%s", en, name);
	char *key = bml_buf_take(&b), value[19] = {0};
	if (st == BML_Q_OK) snprintf(value, sizeof(value), "0x%016llx", (unsigned long long)*out);
	if (key) record_text(R(ctx), BML_QUERY_ENUM_VALUES, key, st, value, *msg, "enum constant absent");
	free(key); return st;
}

static int struct_size(void *ctx, const char *name, uint32_t *out, char **msg)
{
	int st = U(ctx)->struct_size(U(ctx)->ctx, name, out, msg);
	char value[11] = {0};
	if (st == BML_Q_OK) snprintf(value, sizeof(value), "0x%08x", *out);
	record_text(R(ctx), BML_QUERY_STRUCT_SIZE, name, st, value, *msg, "struct absent"); return st;
}

static int ksym_var(void *ctx, const char *name, char **out, char **msg)
{
	int st = U(ctx)->ksym_var(U(ctx)->ctx, name, out, msg);
	record_text(R(ctx), BML_QUERY_KSYM_VARS, name, st, st == BML_Q_OK ? *out : NULL, *msg, "ksym VAR absent"); return st;
}

static int kconfig(void *ctx, const char *name, char **out, char **msg)
{
	int st = U(ctx)->kconfig(U(ctx)->ctx, name, out, msg);
	record_text(R(ctx), BML_QUERY_KCONFIG, name, st, st == BML_Q_OK ? *out : NULL, *msg, "kconfig option not set"); return st;
}

static int btf_presence(void *ctx, const char *kind, const char *target, int *out, char **msg)
{
	int st = U(ctx)->btf_presence(U(ctx)->ctx, kind, target, out, msg);
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s/%s", kind, target);
	char *key = bml_buf_take(&b);
	if (key) rec_bool(R(ctx), BML_QUERY_BTF_PRESENCE, key, st, st == BML_Q_OK ? *out : 0, *msg);
	free(key); return st;
}

static int func_ret(void *ctx, const char *name, const char *type, struct bml_strs *out, char **msg)
{
	int st = U(ctx)->func_ret(U(ctx)->ctx, name, type, out, msg);
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s/%s", name, type);
	char *key = bml_buf_take(&b);
	if (key) rec_diffs(R(ctx), BML_QUERY_FUNC_RET, key, st, out, *msg);
	free(key); return st;
}

static int fib_flags(void *ctx, const char *prog, int64_t id, uint32_t mask, int *out, char **msg)
{
	int st = U(ctx)->fib_flags(U(ctx)->ctx, prog, id, mask, out, msg);
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s/%lld/%u", prog, (long long)id, mask);
	char *key = bml_buf_take(&b);
	if (key) rec_bool(R(ctx), BML_QUERY_FIB_FLAGS, key, st, st == BML_Q_OK ? *out : 0, *msg);
	free(key); return st;
}

static int netkit(void *ctx, const char *d, int *out, char **msg)
{
	int st = U(ctx)->netkit(U(ctx)->ctx, d, out, msg);
	rec_bool(R(ctx), BML_QUERY_NETKIT, d, st, st == BML_Q_OK ? *out : 0, *msg);
	return st;
}

static int sleepable(void *ctx, const char *pt, const char *at, int *out, char **msg)
{
	int st = U(ctx)->sleepable(U(ctx)->ctx, pt, at, out, msg);
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s/%s", pt, at);
	char *key = bml_buf_take(&b);
	if (key) rec_bool(R(ctx), BML_QUERY_SLEEPABLE, key, st, st == BML_Q_OK ? *out : 0, *msg);
	free(key); return st;
}

static int helper_target(void *ctx, const char *pt, int64_t id, const struct bml_helper_target *h, struct bml_strs *out, char **msg)
{
	int st = U(ctx)->helper_target(U(ctx)->ctx, pt, id, h, out, msg);
	char *key = bml_caps_helper_target_key(pt, id, h);
	if (key) rec_diffs(R(ctx), BML_QUERY_HELPER_TARGET, key, st, out, *msg);
	free(key); return st;
}

void rr_caps_kernel_values(const struct bml_caps *u, struct bml_caps *out)
{
#define W(f) out->f = u->f ? f : NULL
	W(enum_value); W(struct_size); W(ksym_var); W(kconfig); W(btf_presence); W(func_ret); W(fib_flags);
	W(netkit); W(sleepable); W(helper_target);
#undef W
}
