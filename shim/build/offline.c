#include "shim/build/elf_internal.h"

#include <stdlib.h>
#include <string.h>

#include "caps/caps.h"
#include "req/check.h"
#include "util/gostr.h"
#include "util/mutation.h"

struct offline {
	const struct bml_build_target *t;
	size_t n;
	const char *root;
};

static int has_query(void *ctx, const char *q)
{
	(void)ctx;
	return !strcmp(q, BML_QUERY_PROG_TYPE) || !strcmp(q, BML_QUERY_HELPER) || !strcmp(q, BML_QUERY_MAP_TYPE) ||
	       !strcmp(q, BML_QUERY_UPROBE_BIN) || !strcmp(q, BML_QUERY_UPROBE_DEBUG);
}

static int q_prog_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	(void)ctx, (void)name, (void)id, (void)msg;
	*out = BML_MUT("build.offline_progtype_true") ? 1 : 0;
	return BML_Q_OK;
}

static int q_helper(void *ctx, const char *pt, int64_t ptid, const char *h, int64_t hid, int *out, char **msg)
{
	(void)ctx, (void)pt, (void)ptid, (void)h, (void)hid;
	*out = 0;
	*msg = strdup("cannot be determined on this target");
	return BML_Q_UNKNOWN;
}

static int q_map_type(void *ctx, const char *name, int64_t id, int *out, char **msg)
{
	(void)ctx, (void)name, (void)id, (void)msg;
	*out = BML_MUT("build.offline_maptype_true") ? 1 : 0;
	return BML_Q_OK;
}

static int q_uprobe_binary(void *ctx, const char *program, uint8_t **data, size_t *len, char **msg)
{
	const struct offline *o = ctx;
	const struct bml_build_target *t = NULL;
	*data = NULL;
	*len = 0;
	for (size_t i = 0; i < o->n; i++)
		if (o->t[i].program && !strcmp(o->t[i].program, program))
			t = &o->t[i];
	if (t && t->error && BML_MUT("build.target_error_ignored"))
		t = NULL;
	if (!t) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "no target file for %s", program);
		*msg = bml_buf_take(&b);
		return BML_Q_UNKNOWN;
	}
	if (t->error) {
		*msg = strdup(t->error);
		return BML_Q_UNKNOWN;
	}
	*data = malloc(t->len ? t->len : 1);
	if (!*data) {
		*msg = strdup("out of memory");
		return BML_Q_ERROR;
	}
	if (t->len)
		memcpy(*data, t->data, t->len);
	*len = t->len;
	return BML_Q_OK;
}

static int q_uprobe_debug(void *ctx, const char *program, const uint8_t *id, size_t n, uint8_t **data, size_t *len, char **path,
			  char **msg)
{
	const struct offline *o = ctx;
	(void)program;
	*data = NULL, *len = 0, *path = NULL;
	char *p = NULL;
	int st = bml_caps_debug_build_id_path(o->root ? o->root : "", id, n, &p, msg);
	if (st != BML_Q_OK)
		return st;
	st = bml_caps_debug_read_file(p, data, len, path, msg);
	free(p);
	return st;
}

static char *dup0(const char *s)
{
	return strdup(s ? s : "");
}

void bml_build_unmets_free(struct bml_build_unmet *u, size_t n)
{
	for (size_t i = 0; u && i < n; i++) {
		free(u[i].kind);
		free(u[i].program);
		free(u[i].name);
		free(u[i].detail);
	}
	free(u);
}

int bml_build_check_offline(const void *elf, size_t len, const struct bml_build_target *targets, size_t n_targets,
			    const char *debug_root, struct bml_build_unmet **unmets, size_t *n_unmets, struct bml_build_error *err)
{
	bb_init(err);
	*unmets = NULL;
	*n_unmets = 0;
	struct bml_requirements *req;
	if (bb_read_requirements(elf, len, &req, err))
		return err->code;
	struct offline o = {.t = targets, .n = targets ? n_targets : 0, .root = debug_root};
	struct bml_caps c;
	memset(&c, 0, sizeof c);
	c.ctx = &o;
	c.has_query = has_query;
	c.prog_type = q_prog_type;
	c.helper = q_helper;
	c.map_type = q_map_type;
	c.uprobe_binary = q_uprobe_binary;
	c.uprobe_debug = q_uprobe_debug;
	struct bml_unmets us = {0};
	char *cerr = NULL;
	if (bml_check(req, &c, &us, &cerr)) {
		cerr ? bb_fail(err, cerr) : bb_nomem(err);
		free(cerr);
		bml_unmets_free(&us);
		bml_requirements_free(req);
		return err->code;
	}
	struct bml_build_unmet *out = us.n ? calloc(us.n, sizeof *out) : NULL;
	int oom = us.n && !out;
	for (size_t i = 0; !oom && i < us.n; i++) {
		const struct bml_unmet *u = &us.u[i];
		out[i].kind = dup0(u->kind);
		out[i].program = dup0(u->program);
		out[i].name = dup0(u->name);
		out[i].id = u->id;
		out[i].detail = dup0(u->detail);
		oom = !out[i].kind || !out[i].program || !out[i].name || !out[i].detail;
	}
	if (oom) {
		bml_build_unmets_free(out, us.n);
		bb_nomem(err);
	} else {
		*unmets = out;
		*n_unmets = us.n;
	}
	bml_unmets_free(&us);
	bml_requirements_free(req);
	return err->code;
}
