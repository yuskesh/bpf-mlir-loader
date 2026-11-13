#include "caps/live_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "btf/kernel_values.h"

static int target_error(struct bml_live *l, const char *what, char **msg)
{
	struct bml_buf b = {0};
	int unavailable = l->kb_rc == -2 || (l->kb_err && (strstr(l->kb_err, "permission denied") || strstr(l->kb_err, "operation not permitted")));
	bml_buf_addf(&b, unavailable ? "%s BTF unavailable: %s: cannot be determined on this target" : "%s target BTF: %s", what, l->kb_err ? l->kb_err : "");
	*msg = bml_buf_take(&b);
	return *msg && unavailable ? BML_Q_UNKNOWN : BML_Q_ERROR;
}

int bml_live_enum_value(struct bml_live *l, const char *en, const char *name, uint64_t *out, char **msg)
{
	const char *err;
	const struct bml_kbtf *kb = lv_kb(l, &err);
	struct bml_buf b = {0};
	if (!kb) {
		bml_buf_addf(&b, "enum %s", en); char *what = bml_buf_take(&b);
		if (!what) return (*msg = strdup("out of memory"), BML_Q_ERROR);
		int st = target_error(l, what, msg); free(what); return st;
	}
	uint32_t id;
	size_t n = bml_kbtf_exact_kind(kb, en, KBTF_ENUM, 1, &id);
	int st = BML_Q_ABSENT;
	if (!n) bml_buf_addf(&b, "target BTF has no enum %s: enum constant absent", en);
	else if (n > 1) {
		bml_buf_addf(&b, "enum %s target BTF: type %s(*btf.Enum): multiple matching types", en, en); st = BML_Q_ERROR;
	} else if (!bml_kbtf_enum_constant(kb, id, name, out)) bml_buf_addf(&b, "target BTF enum %s has no %s: enum constant absent", en, name);
	else return BML_Q_OK;
	*msg = bml_buf_take(&b); return *msg ? st : BML_Q_ERROR;
}

int bml_live_func_ret(struct bml_live *l, const char *name, const char *ret, struct bml_strs *out, char **msg)
{
	memset(out, 0, sizeof(*out));
	const char *err;
	const struct bml_kbtf *kb = lv_kb(l, &err);
	struct bml_buf b = {0};
	if (!kb) {
		bml_buf_addf(&b, "function %s: target", name); char *what = bml_buf_take(&b);
		if (!what) return (*msg = strdup("out of memory"), BML_Q_ERROR);
		int st = target_error(l, what, msg);
		if (st == BML_Q_ERROR) {
			free(*msg); bml_buf_addf(&b, "target BTF: %s", err ? err : ""); *msg = bml_buf_take(&b);
		}
		free(what); return st;
	}
	uint32_t id;
	size_t n = bml_kbtf_exact_kind(kb, name, KBTF_FUNC, 1, &id);
	if (!n) bml_buf_addf(&b, "kernel function %s is not in the target BTF (fexit needs a BTF FUNC to attach to)", name);
	else if (n > 1) bml_buf_addf(&b, "kernel function %s: type %s(*btf.Func): multiple matching types", name, name);
	else {
		struct kbtf_type fn, proto, t;
		bml_kbtf_type(kb, id, &fn); bml_kbtf_type(kb, fn.size_type, &proto);
		if (proto.kind != KBTF_FUNC_PROTO) bml_buf_addf(&b, "kernel function %s has no FUNC_PROTO", name);
		else {
			int cyc;
			bml_kbtf_type(kb, bml_kbtf_underlying(kb, proto.size_type, &cyc), &t);
			if (!cyc && t.kind == KBTF_UNKN) bml_buf_addf(&b, "kernel function %s returns void in the target BTF (the object reads %s)", name, ret);
			else if (cyc || t.kind != KBTF_INT) bml_buf_addf(&b, "kernel function %s does not return an integer in the target BTF (the object reads %s)", name, ret);
			else {
				char got[32]; lv_int_spell(kb, &t, got, sizeof(got));
				if (strcmp(got, ret)) bml_buf_addf(&b, "kernel function %s returns %s in the target BTF, but the object reads %s", name, got, ret);
			}
		}
	}
	if (b.len && lv_push(out, &b)) return lv_oom(out, msg);
	return BML_Q_OK;
}
