/* caps/recorded_v16.c — the tracepoint_fields and syscall_args of recorded caps, a C port of bpf-mlir's CheckTracepointField and CheckSyscallArg
 * of RecordedCaps. A missing key for the types strptr and strarray is Unknown (no other answer is substituted); a missing key for an integer type is an error, as before. */
#include "caps/recorded_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/gopath.h"
#include "util/gostr.h"
#include "util/mutation.h"

/* whether c.Queries[q][key] exists */
static int has_key(const struct bml_recorded *r, const char *q, const char *key)
{
	for (size_t i = 0; i < r->n_q; i++)
		if (!strcmp(r->q[i].name, q))
			for (size_t j = 0; j < r->q[i].n; j++)
				if (!strcmp(r->q[i].e[j].key, key))
					return 1;
	return 0;
}

/* values that need evidence of the type: strptr and strarray, and byte arrays [N]u8 / [N]i8 */
static int is_str(const char *t)
{
	return !BML_MUT("caps.rec_str_absent_fatal") && (!strcmp(t, "strptr") || !strcmp(t, "strarray") || t[0] == '[');
}

static int keyed(void *ctx, const char *q, char *key, int str, const char *unknown, struct bml_strs *out, char **msg)
{
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st;
	if (str && !has_key(ctx, q, key))
		st = (*msg = unknown ? strdup(unknown) : rc_fmts("recorded caps: no typed tracepoint field answer for %s", key)) ? BML_Q_UNKNOWN : BML_Q_ERROR;
	else
		st = rc_diffs(ctx, q, key, out, msg);
	free(key);
	return st;
}

/* the key is "<cat>/<event>/<field>/<offset>/<number of bytes>/<i|u|strptr|strarray>" (TPFieldKey) */
static int rec_tp_field(void *ctx, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign, struct bml_strs *out,
			char **msg)
{
	return keyed(ctx, BML_QUERY_TP_FIELDS, bml_caps_tpfield_key(event, field, off, bytes, sign), is_str(sign), NULL, out, msg);
}

/* the key is "<syscall>/<n>/<type>" (SysargKey) */
static int rec_syscall_arg(void *ctx, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	return keyed(ctx, BML_QUERY_SYSCALL_ARGS, rc_fmts("%s/%lld/%s", name, (long long)n, type), is_str(type),
		     "no recorded syscall string argument answer", out, msg);
}

/* RecordedCaps.UprobeDebugFile: a relative path in a file answer is relative to the directory of caps.json (not the cwd of the calling process) */
static int rec_uprobe_debug(void *ctx, const char *program, const uint8_t *id, size_t n, uint8_t **data, size_t *len, char **path, char **msg)
{
	const struct bml_recorded *r = ctx;
	*data = NULL, *len = 0, *path = NULL;
	char *key = bml_caps_uprobe_debug_key(program, id, n);
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	const struct answer *a;
	int st = rc_answer(r, BML_QUERY_UPROBE_DEBUG, key, &a, msg);
	if (st == BML_Q_OK && !a->file) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "recorded caps: uprobe_debug ");
		bml_buf_add_goquote(&b, key, strlen(key));
		bml_buf_adds(&b, " is not a file answer");
		*msg = bml_buf_take(&b);
		st = BML_Q_ERROR;
	}
	free(key);
	if (st != BML_Q_OK)
		return st;
	const char *e[2] = {r->dir, a->file};
	char *p = a->file[0] == '/' ? strdup(a->file) : bml_go_path_join(e, 2);
	if (!p)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	st = bml_caps_debug_read_file(p, data, len, path, msg);
	free(p);
	return st;
}

void rc_caps_v16(struct bml_caps *c)
{
	c->tp_field = rec_tp_field;
	c->syscall_arg = rec_syscall_arg;
	c->uprobe_debug = rec_uprobe_debug;
}
