#include "caps/recorded_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"
#include "util/gostr.h"

static void jstr(struct bml_buf *b, const char *s)
{
	s = s ? s : "";
	bml_json_write_string_html(b, s, strlen(s));
}

char *bml_caps_kfunc_load_key(const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, "[");
	jstr(&b, p->recipe);
	bml_buf_adds(&b, ",");
	jstr(&b, name);
	bml_buf_adds(&b, ",");
	jstr(&b, ret);
	bml_buf_adds(&b, ",[");
	for (size_t i = 0; i < n; i++) {
		if (i)
			bml_buf_adds(&b, ",");
		bml_json_write_string_html(&b, args[i].p, args[i].len);
	}
	bml_buf_adds(&b, "],");
	jstr(&b, p->prog_type);
	bml_buf_addf(&b, ",%lld,", (long long)p->prog_type_id);
	jstr(&b, p->kind);
	bml_buf_adds(&b, ",");
	jstr(&b, p->section);
	bml_buf_addf(&b, ",%u,", p->prog_flags);
	jstr(&b, p->attach_type);
	bml_buf_adds(&b, ",");
	jstr(&b, p->target_kind);
	bml_buf_adds(&b, ",");
	jstr(&b, p->target);
	bml_buf_adds(&b, ",");
	jstr(&b, p->context_identity);
	bml_buf_adds(&b, "]");
	return bml_buf_take(&b);
}

static int rec_kfunc_load(void *ctx, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n,
			  int *out, char **msg)
{
	const struct bml_caps *rp;
	int pv = rc_privileged(ctx, BML_QUERY_KFUNC_LOADS, &rp, msg);
	if (pv < 0)
		return *msg ? BML_Q_UNKNOWN : (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (pv > 0)
		return rp->kfunc_load ? rp->kfunc_load(rp->ctx, p, name, ret, args, n, out, msg)
				      : (*msg = strdup("recorded caps: the re-probing caps has no " BML_QUERY_KFUNC_LOADS " query"), BML_Q_UNKNOWN);
	char *key = bml_caps_kfunc_load_key(p, name, ret, args, n);
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_boolean(ctx, BML_QUERY_KFUNC_LOADS, key, out, msg);
	free(key);
	return st;
}

static int rec_tracepoint_buffer(void *ctx, const char *name, const char *pointee, struct bml_strs *out, char **msg)
{
	char *key = rc_fmts("%s/0/%s", name, pointee);
	if (!key)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_diffs(ctx, BML_QUERY_TRACEPOINT_BUFFER, key, out, msg);
	free(key);
	return st;
}

void rc_caps_e499(struct bml_caps *c)
{
	c->kfunc_load = rec_kfunc_load;
	c->tracepoint_buffer = rec_tracepoint_buffer;
}
