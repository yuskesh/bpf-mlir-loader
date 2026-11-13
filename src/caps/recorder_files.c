#include "caps/recorder_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

static int uprobe_binary(void *ctx, const char *program, uint8_t **data, size_t *len, char **msg)
{
	int rc = U(ctx)->uprobe_binary(U(ctx)->ctx, program, data, len, msg);
	struct rec *e = slot(R(ctx), BML_QUERY_UPROBE_BIN, program);
	if (e && !put_err(e, rc, *msg)) {
		const char *p = bml_kv_get(R(ctx)->files, R(ctx)->n_files, program);
		e->kind = p ? A_FILE : A_UNKNOWN;
		e->s = strdup(p ? p : "the binary path was not given to the recorder");
	}
	return rc;
}

static int uprobe_debug(void *ctx, const char *program, const uint8_t *id, size_t n, uint8_t **data, size_t *len, char **path, char **msg)
{
	int rc = U(ctx)->uprobe_debug(U(ctx)->ctx, program, id, n, data, len, path, msg);
	char *key = bml_caps_uprobe_debug_key(program, id, n);
	struct rec *e = key ? slot(R(ctx), BML_QUERY_UPROBE_DEBUG, key) : NULL;
	free(key);
	if (e && !put_err(e, rc, *msg)) {
		e->kind = *path && **path ? A_FILE : A_UNKNOWN;
		e->s = strdup(*path && **path ? *path : "the separate DWARF path was not given to the recorder");
	}
	return rc;
}

void rr_caps_files(const struct bml_caps *u, struct bml_caps *out)
{
	out->uprobe_binary = u->uprobe_binary ? uprobe_binary : NULL;
	out->uprobe_debug = u->uprobe_debug ? uprobe_debug : NULL;
}
