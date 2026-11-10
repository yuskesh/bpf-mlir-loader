
#include "caps/recorded_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"
#include "util/gostr.h"
#include "util/mutation.h"



static const struct query *find_q(const struct bml_recorded *r, const char *q)
{
	for (size_t i = 0; i < r->n_q; i++)
		if (!strcmp(r->q[i].name, q))
			return &r->q[i];
	return NULL;
}


static int reprobe_has(const struct bml_caps *rp, const char *q)
{
	if (rp->has_query && !rp->has_query(rp->ctx, q))
		return 0;
	static const struct {
		const char *q;
		size_t off;
	} cb[] = {
		{BML_QUERY_PROG_TYPE, offsetof(struct bml_caps, prog_type)},	   {BML_QUERY_HELPER, offsetof(struct bml_caps, helper)},
		{BML_QUERY_MAP_TYPE, offsetof(struct bml_caps, map_type)},	   {BML_QUERY_TCX, offsetof(struct bml_caps, tcx)},
		{BML_QUERY_BTF_FEATURE, offsetof(struct bml_caps, btf_feature)},   {BML_QUERY_ARG_TAG, offsetof(struct bml_caps, arg_tag)},
		{BML_QUERY_MAP_FIELD, offsetof(struct bml_caps, map_field)},	   {BML_QUERY_NULLABLE_ARGS, offsetof(struct bml_caps, nullable_args)},
		{BML_QUERY_TRACING_HELPER, offsetof(struct bml_caps, tracing_helper)}, {BML_QUERY_ATTACH_TYPE, offsetof(struct bml_caps, attach_type)},
		{BML_QUERY_CTX_ACCESS, offsetof(struct bml_caps, ctx_access)},	   {BML_QUERY_KFUNC_LOADS, offsetof(struct bml_caps, kfunc_load)},
		{BML_QUERY_FIB_FLAGS, offsetof(struct bml_caps, fib_flags)},
		{BML_QUERY_NETKIT, offsetof(struct bml_caps, netkit)},		   {BML_QUERY_SLEEPABLE, offsetof(struct bml_caps, sleepable)},
		{BML_QUERY_HELPER_TARGET, offsetof(struct bml_caps, helper_target)},
	};
	for (size_t i = 0; i < sizeof cb / sizeof *cb; i++)
		if (!strcmp(cb[i].q, q))
			return *(void *const *)((const char *)rp + cb[i].off) != NULL;
	return 0;
}


static int rec_has_query(void *ctx, const char *q)
{
	const struct bml_caps *rp;
	char *m = NULL;
	if (!strcmp(q, BML_QUERY_HELPER_TARGET)) {
		int ht = rc_helper_target_privilege(ctx, &rp, &m);
		free(m);
		m = NULL;
		if (ht > 0)
			return reprobe_has(rp, q);
	}
	int pv = rc_privileged(ctx, q, &rp, &m);
	free(m);
	if (pv > 0)
		return reprobe_has(rp, q);
	return find_q(ctx, q) != NULL;
}


#define PRIV(Q, CB, ...)                                                                                                               \
	do {                                                                                                                           \
		const struct bml_caps *rp_;                                                                                            \
		int pv_ = rc_privileged(ctx, Q, &rp_, msg);                                                                            \
		if (pv_ < 0)                                                                                                           \
			return *msg ? BML_Q_UNKNOWN : (*msg = strdup("out of memory"), BML_Q_ERROR);                                  \
		if (pv_ > 0)                                                                                                           \
			return rp_->CB ? rp_->CB(rp_->ctx, __VA_ARGS__)                                                                \
				       : (*msg = strdup("recorded caps: the re-probing caps has no " Q " query"), BML_Q_UNKNOWN);      \
	} while (0)

static const struct bml_loader_decl *rec_loader(void *ctx)
{
	return &((struct bml_recorded *)ctx)->loader;
}


static int answer(const struct bml_recorded *r, const char *q, const char *key, const struct answer **out, char **msg)
{
	const struct query *qq = find_q(r, q);
	const struct entry *e = NULL;
	for (size_t i = 0; qq && i < qq->n; i++)
		if (!strcmp(qq->e[i].key, key))
			e = &qq->e[i];
	if (!e) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "recorded caps: no answer for %s ", q);
		bml_buf_add_goquote(&b, key, strlen(key));
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}
	*out = &e->a;
	if (e->a.unknown) {
		*msg = strdup(e->a.unknown);
		return BML_Q_UNKNOWN;
	}
	if (e->a.error) {
		*msg = strdup(e->a.error);
		return BML_Q_ERROR;
	}
	return BML_Q_OK;
}

int rc_answer(const struct bml_recorded *r, const char *q, const char *key, const struct answer **out, char **msg)
{
	return answer(r, q, key, out, msg);
}

int rc_boolean(const struct bml_recorded *r, const char *q, const char *key, int *out, char **msg)
{
	const struct answer *a;
	int st = answer(r, q, key, &a, msg);
	if (st == BML_Q_ERROR && BML_MUT("recorded.missing_key_false") && !strncmp(*msg, "recorded caps: no answer", 24)) {
		free(*msg);
		*msg = NULL;
		*out = 0;
		return BML_Q_OK;
	}
	if (st != BML_Q_OK)
		return st;
	if (!a->has_value) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "recorded caps: %s ", q);
		bml_buf_add_goquote(&b, key, strlen(key));
		bml_buf_adds(&b, " is not a value answer");
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}
	*out = a->value;
	return BML_Q_OK;
}

int rc_diffs(const struct bml_recorded *r, const char *q, const char *key, struct bml_strs *out, char **msg)
{
	const struct answer *a;
	int st = answer(r, q, key, &a, msg);
	if (st != BML_Q_OK)
		return st;
	if (!a->has_diffs) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "recorded caps: %s ", q);
		bml_buf_add_goquote(&b, key, strlen(key));
		bml_buf_adds(&b, " is not a diffs answer");
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}

	for (size_t i = 0; i < a->diffs.n; i++) {
		char **ns = realloc(out->s, (out->n + 1) * sizeof(char *));
		if (!ns)
			return (*msg = strdup("out of memory"), BML_Q_ERROR);
		out->s = ns;
		out->s[out->n] = strdup(a->diffs.s[i]);
		if (!out->s[out->n])
			return (*msg = strdup("out of memory"), BML_Q_ERROR);
		out->n++;
	}
	return BML_Q_OK;
}

#define KEY(...) char *key = rc_fmts(__VA_ARGS__); if (!key) return (*msg = strdup("out of memory"), BML_Q_ERROR)

static int rec_prog_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	PRIV(BML_QUERY_PROG_TYPE, prog_type, name, id, out, msg);
	return rc_boolean(ctx, BML_QUERY_PROG_TYPE, name, out, msg);
}

static int rec_helper(void *ctx, const char *pt, int64_t ptid, const char *h, int64_t hid, int *out, char **msg)
{
	PRIV(BML_QUERY_HELPER, helper, pt, ptid, h, hid, out, msg);
	KEY("%s/%s", pt, h);
	int st = rc_boolean(ctx, BML_QUERY_HELPER, key, out, msg);
	free(key);
	return st;
}

static int rec_tracing_helper(void *ctx, const char *at, const char *h, int64_t hid, int *out, char **msg)
{
	PRIV(BML_QUERY_TRACING_HELPER, tracing_helper, at, h, hid, out, msg);
	KEY("%s/%s", at, h);
	int st = rc_boolean(ctx, BML_QUERY_TRACING_HELPER, key, out, msg);
	free(key);
	return st;
}

static int rec_map_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	PRIV(BML_QUERY_MAP_TYPE, map_type, name, id, out, msg);
	return rc_boolean(ctx, BML_QUERY_MAP_TYPE, name, out, msg);
}

static int rec_tcx(void *ctx, int *out, char **msg)
{
	PRIV(BML_QUERY_TCX, tcx, out, msg);
	return rc_boolean(ctx, BML_QUERY_TCX, "", out, msg);
}

static int rec_btf_feature(void *ctx, const char *f, int *out, char **msg)
{
	PRIV(BML_QUERY_BTF_FEATURE, btf_feature, f, out, msg);
	return rc_boolean(ctx, BML_QUERY_BTF_FEATURE, f, out, msg);
}

static int rec_arg_tag(void *ctx, const char *pt, int64_t ptid, const char *tag, const char *cls, int *out, char **msg)
{
	PRIV(BML_QUERY_ARG_TAG, arg_tag, pt, ptid, tag, cls, out, msg);
	KEY("%s/%s/%s", pt, tag, cls);
	int st = rc_boolean(ctx, BML_QUERY_ARG_TAG, key, out, msg);
	free(key);
	return st;
}

static int rec_kernel_symbol(void *ctx, const char *name, int *out, char **msg)
{
	return rc_boolean(ctx, BML_QUERY_KERNEL_SYM, name, out, msg);
}

static int rec_map_field(void *ctx, const char *pt, int64_t ptid, const char *field, int *out, char **msg)
{
	PRIV(BML_QUERY_MAP_FIELD, map_field, pt, ptid, field, out, msg);
	KEY("%s/%s", pt, field);
	int st = rc_boolean(ctx, BML_QUERY_MAP_FIELD, key, out, msg);
	free(key);
	return st;
}

static int rec_nullable_args(void *ctx, int *out, char **msg)
{
	PRIV(BML_QUERY_NULLABLE_ARGS, nullable_args, out, msg);
	return rc_boolean(ctx, BML_QUERY_NULLABLE_ARGS, "", out, msg);
}



static int rec_attach_type(void *ctx, const char *pt, int64_t ptid, const char *at, int *out, char **msg)
{
	PRIV(BML_QUERY_ATTACH_TYPE, attach_type, pt, ptid, at, out, msg);
	KEY("%s/%s", pt, at);
	int st = rc_boolean(ctx, BML_QUERY_ATTACH_TYPE, key, out, msg);
	free(key);
	return st;
}

static int rec_attach_target(void *ctx, const char *at, const char *kind, const char *value, int *out, char **msg)
{
	KEY("%s/%s:%s", at, kind, value);
	int st = rc_boolean(ctx, BML_QUERY_ATTACH_TARGET, key, out, msg);
	free(key);
	return st;
}

static int rec_ctx_access(void *ctx, const char *pt, int64_t ptid, const char *at, const char *st_, const char *field, const char *mode,
			  int64_t bytes, int *out, char **msg)
{
	PRIV(BML_QUERY_CTX_ACCESS, ctx_access, pt, ptid, at, st_, field, mode, bytes, out, msg);
	KEY("%s/%s/%s.%s/%s/%lld", pt, at, st_, field, mode, (long long)bytes);
	int st = rc_boolean(ctx, BML_QUERY_CTX_ACCESS, key, out, msg);
	free(key);
	return st;
}

static int rec_func_sig(void *ctx, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg)
{
	KEY("%s/%lld/%s", name, (long long)nargs, ret);
	int st = rc_diffs(ctx, BML_QUERY_FUNC_SIG, key, out, msg);
	free(key);
	return st;
}

static int rec_func(void *ctx, const char *name, struct bml_strs *out, char **msg)
{
	return rc_diffs(ctx, BML_QUERY_FUNC, name, out, msg);
}


static int named_args(void *ctx, const char *q, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, name);
	bml_buf_adds(&b, "(");
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(&b, ",");
		bml_buf_adds(&b, args[i].p);
	}
	bml_buf_adds(&b, ")");
	char *key = bml_buf_take(&b);
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_diffs(ctx, q, key, out, msg);
	free(key);
	return st;
}
static int rec_tracepoint(void *ctx, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	return named_args(ctx, BML_QUERY_TRACEPOINT, name, args, n, out, msg);
}

static int rec_func_args(void *ctx, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	return named_args(ctx, BML_QUERY_FUNC_ARGS, name, args, n, out, msg);
}


char *bml_caps_tpfield_key(const char *event, const char *field, int64_t off, int64_t bytes, const char *sign)
{
	return rc_fmts("%s/%s/%lld/%lld/%s", event, field, (long long)off, (long long)bytes, sign);
}

char *bml_caps_proto_key(const char *a, char sep, const char *b_, int64_t nargs, const char *ret, const struct bml_str *args, size_t n)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s%c%s/%lld/%s(", a, sep, b_, (long long)nargs, ret);
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(&b, ",");
		bml_buf_adds(&b, args[i].p);
	}
	bml_buf_adds(&b, ")");
	return bml_buf_take(&b);
}


static int keyed_rc_diffs(void *ctx, const char *q, char *key, struct bml_strs *out, char **msg)
{
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_diffs(ctx, q, key, out, msg);
	free(key);
	return st;
}

static int rec_struct_ops_member(void *ctx, const char *strct, const char *member, int64_t nargs, const char *ret, const struct bml_str *args,
				 size_t n, struct bml_strs *out, char **msg)
{
	return keyed_rc_diffs(ctx, BML_QUERY_STRUCT_OPS_MEMBERS, bml_caps_proto_key(strct, '.', member, nargs, ret[0] ? ret : "-", args, n), out, msg);
}

static int rec_ext_target(void *ctx, const char *program, const char *fn, int64_t nargs, const char *ret, const struct bml_str *args, size_t n,
			  struct bml_strs *out, char **msg)
{
	return keyed_rc_diffs(ctx, BML_QUERY_EXT_TARGETS, bml_caps_proto_key(program, '/', fn, nargs, ret, args, n), out, msg);
}

static int rec_kfields(void *ctx, const struct bml_kfield *kf, size_t n, struct bml_strs *out, char **msg)
{
	for (size_t i = 0; i < n; i++) {
		KEY("%s %s.%s %s", kf[i].program.p, kf[i].strct.p, kf[i].field.p, kf[i].type.p);
		int st = rc_diffs(ctx, BML_QUERY_KFIELDS, key, out, msg);
		free(key);
		if (st != BML_Q_OK) {
			bml_strs_free(out);
			return st;
		}
	}
	return BML_Q_OK;
}

static int rec_struct_field(void *ctx, const char *st, const char *field, int64_t off, int64_t size, struct bml_strs *out, char **msg)
{
	KEY("%s.%s/%lld/%lld", st, field, (long long)off, (long long)size);
	int s = rc_diffs(ctx, BML_QUERY_STRUCT_FIELD, key, out, msg);
	free(key);
	return s;
}

static int rec_func_param(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	KEY("%s/%lld/%s", name, (long long)n, type);
	int st = rc_diffs(ctx, BML_QUERY_FUNC_PARAM, key, out, msg);
	free(key);
	return st;
}


char *bml_caps_kfunc_key(const char *name, const char *ret, const struct bml_str *args, size_t n)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s/%s(", name, ret);
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(&b, ",");
		bml_buf_adds(&b, args[i].p);
	}
	bml_buf_adds(&b, ")");
	return bml_buf_take(&b);
}

static int rec_kfunc(void *ctx, const char *name, const char *ret, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	return keyed_rc_diffs(ctx, BML_QUERY_KFUNC_PROTOS, bml_caps_kfunc_key(name, ret, args, n), out, msg);
}

static int rec_arch(void *ctx, char **out, char **msg)
{
	const struct answer *a;
	int st = answer(ctx, BML_QUERY_ARCH, "", &a, msg);
	if (st != BML_Q_OK)
		return st;
	if (!a->text)
		return (*msg = strdup("recorded caps: arch is not a text answer"), BML_Q_ERROR);
	*out = strdup(a->text);
	return *out ? BML_Q_OK : (*msg = strdup("out of memory"), BML_Q_ERROR);
}

static int rec_uprobe_binary(void *ctx, const char *program, uint8_t **data, size_t *len, char **msg)
{
	struct bml_recorded *r = ctx;
	const struct answer *a;
	int st = answer(r, BML_QUERY_UPROBE_BIN, program, &a, msg);
	if (st != BML_Q_OK)
		return st;
	if (!a->file) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "recorded caps: uprobe_binary ");
		bml_buf_add_goquote(&b, program, strlen(program));
		bml_buf_adds(&b, " is not a file answer");
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}
	char *path = a->file[0] == '/' ? strdup(a->file) : rc_fmts("%s/%s", r->dir, a->file);
	if (!path)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	FILE *f = fopen(path, "rb");
	if (!f) {
		char *es = bml_go_errno_str(errno);
		*msg = rc_fmts("open %s: %s", path, es ? es : "");
		free(es);
		free(path);
		return BML_Q_ERROR;
	}
	struct bml_buf b = {0};
	char tmp[65536];
	size_t n;
	while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
		bml_buf_add(&b, tmp, n);
	int rerr = ferror(f);
	fclose(f);
	if (rerr || b.oom) {
		*msg = rc_fmts("read %s: %s", path, rerr ? "I/O error" : "out of memory");
		free(path);
		bml_buf_free(&b);
		return BML_Q_ERROR;
	}
	free(path);
	*len = b.len;
	*data = (uint8_t *)bml_buf_take(&b);
	return *data ? BML_Q_OK : (*msg = strdup("out of memory"), BML_Q_ERROR);
}

void bml_recorded_caps(struct bml_recorded *r, struct bml_caps *c)
{
	memset(c, 0, sizeof(*c));
	c->ctx = r;
	c->has_query = rec_has_query;
	c->loader = rec_loader;
	c->prog_type = rec_prog_type;
	c->helper = rec_helper;
	c->map_type = rec_map_type;
	c->tracing_helper = rec_tracing_helper;
	c->tcx = rec_tcx;
	c->btf_feature = rec_btf_feature;
	c->arg_tag = rec_arg_tag;
	c->kernel_symbol = rec_kernel_symbol;
	c->map_field = rec_map_field;
	c->nullable_args = rec_nullable_args;
	c->attach_type = rec_attach_type;
	c->attach_target = rec_attach_target;
	c->ctx_access = rec_ctx_access;
	c->func_sig = rec_func_sig;
	c->func = rec_func;
	c->tracepoint = rec_tracepoint;
	c->func_args = rec_func_args;
	c->struct_ops_member = rec_struct_ops_member;
	c->ext_target = rec_ext_target;
	c->kfields = rec_kfields;
	c->struct_field = rec_struct_field;
	c->func_param = rec_func_param;
	c->kfunc = rec_kfunc;
	rc_caps_v16(c);
	rc_caps_e499(c);
	rc_caps_kernel_values(c);
	rc_caps_target_rows(c);
	c->arch = rec_arch;
	c->uprobe_binary = rec_uprobe_binary;
}
