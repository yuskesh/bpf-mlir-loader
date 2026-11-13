#define _GNU_SOURCE
#include "caps/recorder_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caps/recorded.h"
#include "json/json.h"
#include "util/gostr.h"

struct bml_recorder *bml_recorder_new(const struct bml_caps *under)
{
	struct bml_recorder *r = calloc(1, sizeof *r);
	if (r)
		r->under = under;
	return r;
}

static void rec_clear(struct rec *e)
{
	free(e->s);
	e->s = NULL;
	bml_strs_free(&e->diffs);
}

void bml_recorder_free(struct bml_recorder *r)
{
	if (!r)
		return;
	for (size_t i = 0; i < r->n; i++) {
		rec_clear(&r->r[i]);
		free(r->r[i].query);
		free(r->r[i].key);
	}
	free(r->r);
	for (size_t i = 0; i < r->n_files; i++) {
		free(r->files[i].key);
		free(r->files[i].value);
	}
	free(r->files);
	free(r);
}

int bml_recorder_set_binary(struct bml_recorder *r, const char *program, const char *path)
{
	for (size_t i = 0; i < r->n_files; i++)
		if (strcmp(r->files[i].key, program) == 0) {
			char *p = strdup(path);
			if (!p)
				return -1;
			free(r->files[i].value);
			r->files[i].value = p;
			return 0;
		}
	struct bml_kv *nf = realloc(r->files, (r->n_files + 1) * sizeof *nf);
	if (!nf)
		return -1;
	r->files = nf;
	nf[r->n_files].key = strdup(program);
	nf[r->n_files].value = strdup(path);
	if (!nf[r->n_files].key || !nf[r->n_files].value)
		return -1;
	r->n_files++;
	return 0;
}


struct rec *slot(struct bml_recorder *r, const char *q, const char *key)
{
	for (size_t i = 0; i < r->n; i++)
		if (strcmp(r->r[i].query, q) == 0 && strcmp(r->r[i].key, key) == 0) {
			rec_clear(&r->r[i]);
			return &r->r[i];
		}
	struct rec *nr = realloc(r->r, (r->n + 1) * sizeof *nr);
	if (!nr)
		return NULL;
	r->r = nr;
	struct rec *e = &nr[r->n];
	memset(e, 0, sizeof *e);
	e->query = strdup(q);
	e->key = strdup(key);
	if (!e->query || !e->key) {
		free(e->query);
		free(e->key);
		return NULL;
	}
	r->n++;
	return e;
}


int put_err(struct rec *e, int rc, const char *msg)
{
	if (rc == BML_Q_OK)
		return 0;
	e->kind = rc == BML_Q_UNKNOWN ? A_UNKNOWN : A_ERROR;
	e->s = strdup(msg ? msg : "");
	return 1;
}

void rec_bool(struct bml_recorder *r, const char *q, const char *key, int rc, int v, const char *msg)
{
	struct rec *e = slot(r, q, key);
	if (!e || put_err(e, rc, msg))
		return;
	e->kind = A_VALUE;
	e->value = v;
}

void rec_diffs(struct bml_recorder *r, const char *q, const char *key, int rc, const struct bml_strs *d, const char *msg)
{
	struct rec *e = slot(r, q, key);
	if (!e || put_err(e, rc, msg))
		return;
	e->kind = A_DIFFS;
	e->diffs.s = d->n ? calloc(d->n, sizeof *e->diffs.s) : NULL;
	for (size_t i = 0; e->diffs.s && i < d->n; i++)
		if ((e->diffs.s[i] = strdup(d->s[i])))
			e->diffs.n = i + 1;
}

static char *fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmt(const char *f, ...)
{
	char *s = NULL;
	va_list ap;
	va_start(ap, f);
	if (vasprintf(&s, f, ap) < 0)
		s = NULL;
	va_end(ap);
	return s ? s : strdup("");
}

static int has_query(void *ctx, const char *q)
{
	const struct bml_caps *u = U(ctx);
	return !u->has_query || u->has_query(u->ctx, q);
}

static const struct bml_loader_decl *loader(void *ctx)
{
	const struct bml_caps *u = U(ctx);
	return u->loader ? u->loader(u->ctx) : NULL;
}

static int prog_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	int rc = U(ctx)->prog_type(U(ctx)->ctx, name, id, out, msg);
	rec_bool(R(ctx), BML_QUERY_PROG_TYPE, name, rc, *out, *msg);
	return rc;
}

static int helper(void *ctx, const char *pt, int64_t ptid, const char *h, int64_t hid, int *out, char **msg)
{
	int rc = U(ctx)->helper(U(ctx)->ctx, pt, ptid, h, hid, out, msg);
	char *k = fmt("%s/%s", pt, h);
	rec_bool(R(ctx), BML_QUERY_HELPER, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int map_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	int rc = U(ctx)->map_type(U(ctx)->ctx, name, id, out, msg);
	rec_bool(R(ctx), BML_QUERY_MAP_TYPE, name, rc, *out, *msg);
	return rc;
}

static int tracing_helper(void *ctx, const char *at, const char *h, int64_t hid, int *out, char **msg)
{
	int rc = U(ctx)->tracing_helper(U(ctx)->ctx, at, h, hid, out, msg);
	char *k = fmt("%s/%s", at, h);
	rec_bool(R(ctx), BML_QUERY_TRACING_HELPER, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int tcx(void *ctx, int *out, char **msg)
{
	int rc = U(ctx)->tcx(U(ctx)->ctx, out, msg);
	rec_bool(R(ctx), BML_QUERY_TCX, "", rc, *out, *msg);
	return rc;
}

static int btf_feature(void *ctx, const char *f, int *out, char **msg)
{
	int rc = U(ctx)->btf_feature(U(ctx)->ctx, f, out, msg);
	rec_bool(R(ctx), BML_QUERY_BTF_FEATURE, f, rc, *out, *msg);
	return rc;
}

static int arg_tag(void *ctx, const char *pt, int64_t ptid, const char *tag, const char *cls, int *out, char **msg)
{
	int rc = U(ctx)->arg_tag(U(ctx)->ctx, pt, ptid, tag, cls, out, msg);
	char *k = fmt("%s/%s/%s", pt, tag, cls);
	rec_bool(R(ctx), BML_QUERY_ARG_TAG, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int kernel_symbol(void *ctx, const char *name, int *out, char **msg)
{
	int rc = U(ctx)->kernel_symbol(U(ctx)->ctx, name, out, msg);
	rec_bool(R(ctx), BML_QUERY_KERNEL_SYM, name, rc, *out, *msg);
	return rc;
}

static int map_field(void *ctx, const char *pt, int64_t ptid, const char *field, int *out, char **msg)
{
	int rc = U(ctx)->map_field(U(ctx)->ctx, pt, ptid, field, out, msg);
	char *k = fmt("%s/%s", pt, field);
	rec_bool(R(ctx), BML_QUERY_MAP_FIELD, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int nullable_args(void *ctx, int *out, char **msg)
{
	int rc = U(ctx)->nullable_args(U(ctx)->ctx, out, msg);
	rec_bool(R(ctx), BML_QUERY_NULLABLE_ARGS, "", rc, *out, *msg);
	return rc;
}


static int attach_type(void *ctx, const char *pt, int64_t ptid, const char *at, int *out, char **msg)
{
	int rc = U(ctx)->attach_type(U(ctx)->ctx, pt, ptid, at, out, msg);
	char *k = fmt("%s/%s", pt, at);
	rec_bool(R(ctx), BML_QUERY_ATTACH_TYPE, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int attach_target(void *ctx, const char *at, const char *kind, const char *value, int *out, char **msg)
{
	int rc = U(ctx)->attach_target(U(ctx)->ctx, at, kind, value, out, msg);
	char *k = fmt("%s/%s:%s", at, kind, value);
	rec_bool(R(ctx), BML_QUERY_ATTACH_TARGET, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int ctx_access(void *ctx, const char *pt, int64_t ptid, const char *at, const char *st, const char *field, const char *mode,
		      int64_t bytes, int *out, char **msg)
{
	int rc = U(ctx)->ctx_access(U(ctx)->ctx, pt, ptid, at, st, field, mode, bytes, out, msg);
	char *k = fmt("%s/%s/%s.%s/%s/%lld", pt, at, st, field, mode, (long long)bytes);
	rec_bool(R(ctx), BML_QUERY_CTX_ACCESS, k, rc, *out, *msg);
	free(k);
	return rc;
}

static int func_sig(void *ctx, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->func_sig(U(ctx)->ctx, name, nargs, ret, out, msg);
	char *k = fmt("%s/%lld/%s", name, (long long)nargs, ret);
	rec_diffs(R(ctx), BML_QUERY_FUNC_SIG, k, rc, out, *msg);
	free(k);
	return rc;
}

static int func(void *ctx, const char *name, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->func(U(ctx)->ctx, name, out, msg);
	rec_diffs(R(ctx), BML_QUERY_FUNC, name, rc, out, *msg);
	return rc;
}

static int tracepoint(void *ctx, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->tracepoint(U(ctx)->ctx, name, args, n, out, msg);
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s(", name);
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(&b, ",");
		bml_buf_add(&b, args[i].p, args[i].len);
	}
	bml_buf_adds(&b, ")");
	char *k = bml_buf_take(&b);
	if (k)
		rec_diffs(R(ctx), BML_QUERY_TRACEPOINT, k, rc, out, *msg);
	free(k);
	return rc;
}


static int func_args(void *ctx, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->func_args(U(ctx)->ctx, name, args, n, out, msg);
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s(", name);
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(&b, ",");
		bml_buf_add(&b, args[i].p, args[i].len);
	}
	bml_buf_adds(&b, ")");
	char *k = bml_buf_take(&b);
	if (k)
		rec_diffs(R(ctx), BML_QUERY_FUNC_ARGS, k, rc, out, *msg);
	free(k);
	return rc;
}


static int tp_field(void *ctx, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign, struct bml_strs *out,
		    char **msg)
{
	int rc = U(ctx)->tp_field(U(ctx)->ctx, event, field, off, bytes, sign, out, msg);
	char *k = bml_caps_tpfield_key(event, field, off, bytes, sign);
	if (k)
		rec_diffs(R(ctx), BML_QUERY_TP_FIELDS, k, rc, out, *msg);
	free(k);
	return rc;
}

static int struct_ops_member(void *ctx, const char *strct, const char *member, int64_t nargs, const char *ret, const struct bml_str *args,
			     size_t n, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->struct_ops_member(U(ctx)->ctx, strct, member, nargs, ret, args, n, out, msg);
	char *k = bml_caps_proto_key(strct, '.', member, nargs, ret[0] ? ret : "-", args, n);
	if (k)
		rec_diffs(R(ctx), BML_QUERY_STRUCT_OPS_MEMBERS, k, rc, out, *msg);
	free(k);
	return rc;
}


static int ext_target(void *ctx, const char *program, const char *fn, int64_t nargs, const char *ret, const struct bml_str *args, size_t n,
		      struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->ext_target(U(ctx)->ctx, program, fn, nargs, ret, args, n, out, msg);
	char *k = bml_caps_proto_key(program, '/', fn, nargs, ret, args, n);
	struct rec *e = k ? slot(R(ctx), BML_QUERY_EXT_TARGETS, k) : NULL;
	if (e)
		put_err(e, BML_Q_UNKNOWN,
			"the replacement target is a loader input and is not recorded (judge ext with the target program given to a live check)");
	free(k);
	return rc;
}


static int kfields(void *ctx, const struct bml_kfield *kf, size_t n, struct bml_strs *out, char **msg)
{
	memset(out, 0, sizeof *out);
	for (size_t i = 0; i < n; i++) {
		struct bml_strs d = {0};
		char *m = NULL;
		int rc = U(ctx)->kfields(U(ctx)->ctx, &kf[i], 1, &d, &m);
		char *k = fmt("%s %s.%s %s", kf[i].program.p, kf[i].strct.p, kf[i].field.p, kf[i].type.p);
		rec_diffs(R(ctx), BML_QUERY_KFIELDS, k, rc, &d, m);
		free(k);
		if (rc != BML_Q_OK) {
			bml_strs_free(&d);
			bml_strs_free(out);
			*msg = m;
			return rc;
		}
		free(m);
		char **ns = d.n ? realloc(out->s, (out->n + d.n) * sizeof *ns) : out->s;
		if (d.n && !ns) {
			bml_strs_free(&d);
			bml_strs_free(out);
			*msg = strdup("out of memory");
			return BML_Q_ERROR;
		}
		out->s = ns;
		for (size_t j = 0; j < d.n; j++)
			out->s[out->n++] = d.s[j];
		free(d.s);
	}
	return BML_Q_OK;
}

static int struct_field(void *ctx, const char *st, const char *field, int64_t off, int64_t size, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->struct_field(U(ctx)->ctx, st, field, off, size, out, msg);
	char *k = fmt("%s.%s/%lld/%lld", st, field, (long long)off, (long long)size);
	rec_diffs(R(ctx), BML_QUERY_STRUCT_FIELD, k, rc, out, *msg);
	free(k);
	return rc;
}

static int func_param(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->func_param(U(ctx)->ctx, name, n, type, out, msg);
	char *k = fmt("%s/%lld/%s", name, (long long)n, type);
	rec_diffs(R(ctx), BML_QUERY_FUNC_PARAM, k, rc, out, *msg);
	free(k);
	return rc;
}


static int kfunc(void *ctx, const char *name, const char *ret, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->kfunc(U(ctx)->ctx, name, ret, args, n, out, msg);
	char *k = bml_caps_kfunc_key(name, ret, args, n);
	rec_diffs(R(ctx), BML_QUERY_KFUNC_PROTOS, k, rc, out, *msg);
	free(k);
	return rc;
}

static int syscall_arg(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->syscall_arg(U(ctx)->ctx, name, n, type, out, msg);
	char *k = fmt("%s/%lld/%s", name, (long long)n, type);
	rec_diffs(R(ctx), BML_QUERY_SYSCALL_ARGS, k, rc, out, *msg);
	free(k);
	return rc;
}


static int kfunc_load(void *ctx, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n, int *out, char **msg)
{
	int rc = U(ctx)->kfunc_load(U(ctx)->ctx, p, name, ret, args, n, out, msg);
	char *k = bml_caps_kfunc_load_key(p, name, ret, args, n);
	rec_bool(R(ctx), BML_QUERY_KFUNC_LOADS, k, rc, *out, *msg);
	free(k);
	return rc;
}
static int tracepoint_buffer(void *ctx, const char *name, const char *pointee, struct bml_strs *out, char **msg)
{
	int rc = U(ctx)->tracepoint_buffer(U(ctx)->ctx, name, pointee, out, msg);
	char *k = fmt("%s/0/%s", name, pointee);
	rec_diffs(R(ctx), BML_QUERY_TRACEPOINT_BUFFER, k, rc, out, *msg);
	free(k);
	return rc;
}

static int arch(void *ctx, char **out, char **msg)
{
	int rc = U(ctx)->arch(U(ctx)->ctx, out, msg);
	struct rec *e = slot(R(ctx), BML_QUERY_ARCH, "");
	if (e && !put_err(e, rc, *msg)) {
		e->kind = A_TEXT;
		e->s = strdup(*out ? *out : "");
	}
	return rc;
}

void bml_recorder_caps(struct bml_recorder *r, struct bml_caps *out)
{
	const struct bml_caps *u = r->under;
	memset(out, 0, sizeof *out);
	out->ctx = r;
	out->has_query = has_query;
	out->loader = loader;
	out->prog_type = prog_type;
	out->helper = helper;
	out->map_type = map_type;
#define W(f) out->f = u->f ? f : NULL
	W(tracing_helper);
	W(tcx);
	W(btf_feature);
	W(arg_tag);
	W(kernel_symbol);
	W(map_field);
	W(nullable_args);
	W(attach_type);
	W(attach_target);
	W(ctx_access);
	W(func_sig);
	W(func);
	W(tracepoint);
	W(func_args);
	W(tp_field);
	W(struct_ops_member);
	W(ext_target);
	W(kfields);
	W(struct_field);
	W(func_param);
	W(kfunc);
	W(syscall_arg);
	W(kfunc_load);
	W(tracepoint_buffer);
	W(arch);
#undef W
	rr_caps_files(u, out);
	rr_caps_kernel_values(u, out);
}

