

#define _GNU_SOURCE
#include "caps/live_caps.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caps/live_internal.h"

static struct bml_live_caps *LC(void *ctx)
{
	return ctx;
}

static const struct bml_loader_decl *loader(void *ctx)
{
	return LC(ctx)->decl;
}

static int has_query(void *ctx, const char *q)
{
	if (strcmp(q, BML_QUERY_UPROBE_BIN) == 0)
		return LC(ctx)->n_bins > 0;
	if (strcmp(q, BML_QUERY_EXT_TARGETS) == 0)
		return LC(ctx)->n_exts > 0;
	return 1;
}

static int q_tp_field(void *ctx, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign, struct bml_strs *out,
		      char **msg)
{
	return bml_live_tp_field(&LC(ctx)->live, event, field, off, bytes, sign, out, msg);
}

static int q_struct_ops_member(void *ctx, const char *strct, const char *member, int64_t nargs, const char *ret, const struct bml_str *args,
			       size_t n, struct bml_strs *out, char **msg)
{
	return bml_live_struct_ops_member(&LC(ctx)->live, strct, member, nargs, ret, args, n, out, msg);
}


static int q_ext_target(void *ctx, const char *program, const char *fn, int64_t nargs, const char *ret, const struct bml_str *args, size_t n,
			struct bml_strs *out, char **msg)
{
	struct bml_live_caps *c = LC(ctx);
	memset(out, 0, sizeof *out);
	for (size_t i = c->n_exts; i-- > 0;) {
		if (strcmp(c->exts[i].program, program) != 0)
			continue;
		if (!c->exts[i].ok) {
			if (asprintf(msg, "reading the replacement target of %s: %s: cannot be determined on this target", program,
				     c->exts[i].err ? c->exts[i].err : "") < 0)
				*msg = NULL;
			return BML_Q_UNKNOWN;
		}
		return bml_ext_target_check(&c->exts[i].kb, fn, nargs, ret, args, n, out, msg);
	}
	if (asprintf(msg, "no --ext-target for program %s: cannot be determined on this target", program) < 0)
		*msg = NULL;
	return BML_Q_UNKNOWN;
}

static int q_prog_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	(void)name;
	return bml_live_prog_type(&LC(ctx)->live, id, out, msg);
}

static int q_helper(void *ctx, const char *pt, int64_t ptid, const char *h, int64_t hid, int *out, char **msg)
{
	(void)pt;
	(void)h;
	return bml_live_helper(&LC(ctx)->live, ptid, hid, out, msg);
}

static int q_map_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	(void)name;
	return bml_live_map_type(&LC(ctx)->live, id, out, msg);
}

static int q_tracing_helper(void *ctx, const char *at, const char *h, int64_t hid, int *out, char **msg)
{
	(void)h;
	return bml_live_tracing_helper(&LC(ctx)->live, at, h, hid, out, msg);
}

static int q_tcx(void *ctx, int *out, char **msg)
{
	return bml_live_tcx(&LC(ctx)->live, out, msg);
}

static int q_btf_feature(void *ctx, const char *f, int *out, char **msg)
{
	return bml_live_btf_feature(&LC(ctx)->live, f, out, msg);
}

static int q_arg_tag(void *ctx, const char *pt, int64_t ptid, const char *tag, const char *cls, int *out, char **msg)
{
	return bml_live_arg_tag(&LC(ctx)->live, pt, ptid, tag, cls, out, msg);
}

static int q_kernel_symbol(void *ctx, const char *name, int *out, char **msg)
{
	(void)ctx;
	return bml_live_kernel_symbol(name, out, msg);
}

static int q_map_field(void *ctx, const char *pt, int64_t ptid, const char *field, int *out, char **msg)
{
	return bml_live_map_field(&LC(ctx)->live, pt, ptid, field, out, msg);
}

static int q_nullable(void *ctx, int *out, char **msg)
{
	return bml_live_nullable_args(&LC(ctx)->live, out, msg);
}

static int q_attach_type(void *ctx, const char *pt, int64_t ptid, const char *at, int *out, char **msg)
{
	return bml_live_attach_type(&LC(ctx)->live, pt, ptid, at, out, msg);
}

static int q_attach_target(void *ctx, const char *at, const char *kind, const char *value, int *out, char **msg)
{
	return bml_live_attach_target(&LC(ctx)->live, at, kind, value, out, msg);
}

static int q_ctx_access(void *ctx, const char *pt, int64_t ptid, const char *at, const char *st, const char *field, const char *mode,
			int64_t bytes, int *out, char **msg)
{
	return bml_live_ctx_access(&LC(ctx)->live, pt, ptid, at, st, field, mode, bytes, out, msg);
}

static int q_func_sig(void *ctx, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg)
{
	return bml_live_func_sig(&LC(ctx)->live, name, nargs, ret, out, msg);
}

static int q_func(void *ctx, const char *name, struct bml_strs *out, char **msg)
{
	return bml_live_func(&LC(ctx)->live, name, out, msg);
}

static int q_tracepoint(void *ctx, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	return bml_live_tracepoint(&LC(ctx)->live, name, args, n, out, msg);
}
static int q_func_args(void *ctx, const char *name, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	return bml_live_func_args(&LC(ctx)->live, name, args, n, out, msg);
}

static int q_kfields(void *ctx, const struct bml_kfield *kf, size_t n, struct bml_strs *out, char **msg)
{
	return bml_live_kfields(&LC(ctx)->live, kf, n, out, msg);
}

static int q_struct_field(void *ctx, const char *st, const char *field, int64_t off, int64_t size, struct bml_strs *out, char **msg)
{
	return bml_live_struct_field(&LC(ctx)->live, st, field, off, size, out, msg);
}

static int q_func_param(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	return bml_live_func_param(&LC(ctx)->live, name, n, type, out, msg);
}

static int q_kfunc(void *ctx, const char *name, const char *ret, const struct bml_str *args, size_t n, struct bml_strs *out, char **msg)
{
	return bml_live_kfunc(&LC(ctx)->live, name, ret, args, n, out, msg);
}

static int q_syscall_arg(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	return bml_live_syscall_arg(&LC(ctx)->live, name, n, type, out, msg);
}

static int q_kfunc_load(void *ctx, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n, int *out,
			char **msg)
{
	return bml_live_kfunc_load(&LC(ctx)->live, p, name, ret, args, n, out, msg);
}

static int q_tracepoint_buffer(void *ctx, const char *name, const char *pointee, struct bml_strs *out, char **msg)
{
	return bml_live_tracepoint_buffer(&LC(ctx)->live, name, pointee, out, msg);
}

static int q_arch(void *ctx, char **out, char **msg)
{
	(void)ctx;
	return bml_live_arch(out, msg);
}


static int q_uprobe_binary(void *ctx, const char *program, uint8_t **data, size_t *len, char **msg)
{
	struct bml_live_caps *c = LC(ctx);
	*data = NULL;
	*len = 0;
	for (size_t i = c->n_bins; i-- > 0;) {
		if (strcmp(c->bins[i].program, program) != 0)
			continue;
		size_t cap = 1 << 16, n = 0;
		uint8_t *b = malloc(cap);
		for (;;) {
			if (!b) {
				*msg = strdup("out of memory");
				return BML_Q_UNKNOWN;
			}
			if (n == cap) {
				uint8_t *nb = realloc(b, cap *= 2);
				if (!nb) {
					free(b);
					b = NULL;
					continue;
				}
				b = nb;
			}
			ssize_t r = pread(c->bins[i].fd, b + n, cap - n, (off_t)n);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0) {
				free(b);
				*msg = strdup("read the binary failed");
				return BML_Q_UNKNOWN;
			}
			if (r == 0)
				break;
			n += (size_t)r;
		}
		*data = b;
		*len = n;
		return BML_Q_OK;
	}
	*msg = strdup("no --binary for program");
	return BML_Q_UNKNOWN;
}


static int q_uprobe_debug(void *ctx, const char *program, const uint8_t *id, size_t n, uint8_t **data, size_t *len, char **path, char **msg)
{
	struct bml_live_caps *c = LC(ctx);
	*data = NULL, *len = 0, *path = NULL;
	for (size_t i = 0; i < c->n_debugs; i++)
		if (!strcmp(c->debugs[i].program, program))
			return bml_caps_debug_read_file(c->debugs[i].path, data, len, path, msg);
	char *p;
	int st = bml_caps_debug_build_id_path(c->debug_root ? c->debug_root : "/usr/lib/debug", id, n, &p, msg);
	if (st != BML_Q_OK)
		return st;
	st = bml_caps_debug_read_file(p, data, len, path, msg);
	free(p);
	return st;
}

void bml_live_caps(struct bml_live_caps *c, struct bml_caps *out)
{
	memset(out, 0, sizeof *out);
	out->ctx = c;
	out->has_query = has_query;
	out->loader = c->decl ? loader : NULL;
	out->prog_type = q_prog_type;
	out->helper = q_helper;
	out->map_type = q_map_type;
	out->tracing_helper = q_tracing_helper;
	out->tcx = q_tcx;
	out->btf_feature = q_btf_feature;
	out->arg_tag = q_arg_tag;
	out->kernel_symbol = q_kernel_symbol;
	out->map_field = q_map_field;
	out->nullable_args = q_nullable;
	out->attach_type = q_attach_type;
	out->attach_target = q_attach_target;
	out->ctx_access = q_ctx_access;
	out->func_sig = q_func_sig;
	out->func = q_func;
	out->tracepoint = q_tracepoint;
	out->func_args = q_func_args;
	out->tp_field = q_tp_field;
	out->struct_ops_member = q_struct_ops_member;
	out->ext_target = q_ext_target;
	out->kfields = q_kfields;
	out->struct_field = q_struct_field;
	out->func_param = q_func_param;
	out->kfunc = q_kfunc;
	out->syscall_arg = q_syscall_arg;
	out->kfunc_load = q_kfunc_load;
	out->tracepoint_buffer = q_tracepoint_buffer;
	out->arch = q_arch;
	out->uprobe_binary = q_uprobe_binary;
	out->uprobe_debug = q_uprobe_debug;
	lv_caps_kernel_values(out);
}

void bml_live_caps_free(struct bml_live_caps *c)
{
	for (size_t i = 0; i < c->n_bins; i++) {
		free(c->bins[i].program);
		free(c->bins[i].path);
		if (c->bins[i].fd >= 0)
			close(c->bins[i].fd);
	}
	free(c->bins);
	for (size_t i = 0; i < c->n_exts; i++) {
		free(c->exts[i].program);
		free(c->exts[i].err);
		if (c->exts[i].ok)
			bml_kbtf_free(&c->exts[i].kb);
	}
	free(c->exts);
	for (size_t i = 0; i < c->n_debugs; i++)
		free(c->debugs[i].program), free(c->debugs[i].path);
	free(c->debugs);
	free(c->debug_root);
	bml_live_free(&c->live);
	memset(c, 0, sizeof *c);
}
