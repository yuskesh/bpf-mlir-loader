/* caps/live_helperlog.c — kload's helperAnswer (bpf-mlir's kernel/internal/kload/helperlog.go): the answer of the
 * live helper probe after cilium's own check. cilium answers "not supported" only for a refusal in the last five
 * verifier log lines. 7.3.1 prints an explanation block after it, which leaves an EINVAL verifier error, and kload
 * classifies that error again over every line. Only a line with a refusal text and the probed helper's exact #<id>
 * becomes false (a blocking helper Unmet). Every other error stays a checking error, never Unknown. */
#include "caps/live_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* cilium's three refusal texts (features/prog.go) */
static const char *const refusals[] = {"invalid func", "program of this type cannot use helper", "unknown func"};

/* lineRefusesHelper: a refusal text and the exact #<id> (followed by a non-digit or the end, so #13 is not #136) */
static int line_refuses(const char *l, uint32_t id, int any_helper)
{
	int refused = 0;
	for (size_t i = 0; i < sizeof refusals / sizeof refusals[0] && !refused; i++)
		refused = strstr(l, refusals[i]) != NULL;
	if (!refused)
		return 0;
	if (any_helper)
		return 1;
	char tag[16];
	int tn = snprintf(tag, sizeof tag, "#%u", id);
	for (const char *p = l; (p = strstr(p, tag));) {
		p += tn;
		if (*p < '0' || *p > '9')
			return 1;
	}
	return 0;
}

int lv_helper_answer(const struct lv_helper_in *in, uint32_t id, const struct lv_helper_opts *o)
{
	static const struct lv_helper_opts product;
	if (!o)
		o = &product;
	if (in->ok)
		return LV_OK;
	if (in->notsup)
		return LV_NOTSUP;
	if (!in->verifier || in->err != EINVAL)
		return LV_HELPER_KEPT;
	size_t from = o->window > 0 && in->n_lines > (size_t)o->window ? in->n_lines - (size_t)o->window : 0;
	for (size_t i = from; i < in->n_lines; i++)
		if (line_refuses(in->lines[i], id, o->any_helper))
			return o->rescue_unknown ? LV_HELPER_UNKNOWN : LV_NOTSUP;
	return LV_HELPER_KEPT;
}
