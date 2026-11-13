#include "caps/value_sources.h"
#include "caps/live_internal.h"

#include <stdlib.h>
#include <string.h>

#include "btf/kernel_values.h"

static int named_type(struct bml_live *l, const char *name, uint32_t kind, uint32_t *id, char **msg)
{
	struct bml_kernel_sources *s = lv_value_sources(l);
	if (!s) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	lv_value_modules(l, s);
	const char *err;
	const struct bml_kbtf *kb = lv_kb(l, &err);
	const char *noun = kind == KBTF_VAR ? "VAR" : "struct";
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s %s", noun, name);
	char *what = bml_buf_take(&b);
	if (!what) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = BML_Q_OK;
	if (!kb) {
		bml_buf_addf(&b, "%s: target BTF unavailable: %s: cannot be determined on this target", what, err ? err : "");
		*msg = bml_buf_take(&b); st = *msg ? BML_Q_UNKNOWN : BML_Q_ERROR;
	} else {
		size_t n = bml_kbtf_exact_kind(kb, name, kind, 1, id);
		if (!n) st = lv_value_absent(s, what, name, kind, kind == KBTF_VAR ? "ksym VAR absent" : "struct absent", msg);
		else if (n > 1) {
			bml_buf_addf(&b, "%s: vmlinux has %zu %s of the name: cannot be determined on this target", what, n, kind == KBTF_VAR ? "VARs" : "structs");
			*msg = bml_buf_take(&b); st = *msg ? BML_Q_UNKNOWN : BML_Q_ERROR;
		}
	}
	free(what); return st;
}

int bml_live_ksym_var(struct bml_live *l, const char *name, char **out, char **msg)
{
	*out = NULL;
	uint32_t id;
	int st = named_type(l, name, KBTF_VAR, &id, msg);
	if (st != BML_Q_OK) return st;
	char *slot = bml_kbtf_var_slot(&l->kb, id);
	if (!slot) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s %s", bml_kbtf_var_percpu(&l->kb, id) ? "percpu" : "plain", slot);
	free(slot); *out = bml_buf_take(&b);
	return *out ? BML_Q_OK : (*msg = strdup("out of memory"), BML_Q_ERROR);
}

int bml_live_struct_size(struct bml_live *l, const char *name, uint32_t *out, char **msg)
{
	uint32_t id;
	int st = named_type(l, name, KBTF_STRUCT, &id, msg);
	if (st != BML_Q_OK) return st;
	struct kbtf_type t;
	bml_kbtf_type(&l->kb, id, &t); *out = t.size_type; return BML_Q_OK;
}

int bml_live_btf_presence(struct bml_live *l, const char *kind, const char *target, int *out, char **msg)
{
	*out = 0;
	int field = !strcmp(kind, "field");
	if (!field && strcmp(kind, "type")) return (*msg = strdup("unknown BTF presence query kind"), BML_Q_ERROR);
	const char *dot = field ? strchr(target, '.') : NULL;
	if (field && (!dot || dot == target || !dot[1])) return (*msg = strdup("invalid BTF presence field target"), BML_Q_ERROR);
	char *name = field ? strndup(target, (size_t)(dot - target)) : strdup(target);
	if (!name) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	uint32_t id;
	int st = named_type(l, name, KBTF_STRUCT, &id, msg);
	free(name);
	if (st == BML_Q_ABSENT) { free(*msg); *msg = NULL; return BML_Q_OK; }
	if (st != BML_Q_OK) return st;
	if (!field) { *out = 1; return BML_Q_OK; }
	struct kbtf_member m;
	int twice;
	int found = lv_find_member_path(&l->kb, id, dot + 1, &m, &twice);
	if (found < 0 && found != -2) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	*out = found > 0; return BML_Q_OK;
}
