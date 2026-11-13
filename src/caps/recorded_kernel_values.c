#include "caps/recorded_internal.h"

#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

static int text_or_absent(void *ctx, const char *q, const char *key,
	const char *sentinel, char **out, char **msg)
{
	const struct answer *a;
	int st = rc_answer(ctx, q, key, &a, msg);
	if (st != BML_Q_OK) return st;
	if (a->has_diffs) {
		struct bml_buf b = {0};
		for (size_t i = 0; i < a->diffs.n; i++) {
			if (i) bml_buf_adds(&b, "; ");
			bml_buf_adds(&b, a->diffs.s[i]);
		}
		bml_buf_addf(&b, ": %s", sentinel);
		*msg = bml_buf_take(&b);
		return *msg ? BML_Q_ABSENT : BML_Q_ERROR;
	}
	if (!a->text) {
		*msg = rc_fmts("recorded caps: %s \"%s\" is not a text or diffs answer", q, key);
		return BML_Q_ERROR;
	}
	*out = strdup(a->text);
	return *out ? BML_Q_OK : (*msg = strdup("out of memory"), BML_Q_ERROR);
}

static int hex_pattern(const char *s, size_t width, uint64_t *out)
{
	if (strlen(s) != width + 2 || memcmp(s, "0x", 2)) return 0;
	uint64_t v = 0;
	for (size_t i = 2; i < width + 2; i++) {
		unsigned char c = (unsigned char)s[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
		v = (v << 4) | (uint64_t)(c <= '9' ? c - '0' : c - 'a' + 10);
	}
	*out = v;
	return 1;
}

static int rec_enum(void *ctx, const char *enumeration, const char *name, uint64_t *out, char **msg)
{
	char *key = rc_fmts("%s/%s", enumeration, name), *text = NULL;
	if (!key) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = text_or_absent(ctx, BML_QUERY_ENUM_VALUES, key, "enum constant absent", &text, msg);
	if (st == BML_Q_OK && !hex_pattern(text, 16, out)) {
		*msg = rc_fmts("recorded caps: enum_values \"%s\": value \"%s\" is not 0x and 16 lowercase hexadecimal digits", key, text);
		st = BML_Q_ERROR;
	}
	free(key); free(text); return st;
}

static int rec_size(void *ctx, const char *name, uint32_t *out, char **msg)
{
	char *text = NULL;
	int st = text_or_absent(ctx, BML_QUERY_STRUCT_SIZE, name, "struct absent", &text, msg);
	uint64_t v;
	if (st == BML_Q_OK) {
		if (!hex_pattern(text, 8, &v)) {
			*msg = rc_fmts("recorded caps: kstruct_size \"%s\": size \"%s\" is not 0x and 8 lowercase hexadecimal digits", name, text);
			st = BML_Q_ERROR;
		} else *out = (uint32_t)v;
	}
	free(text); return st;
}

static int rec_ksym(void *ctx, const char *name, char **out, char **msg)
{
	return text_or_absent(ctx, BML_QUERY_KSYM_VARS, name, "ksym VAR absent", out, msg);
}

static int rec_config(void *ctx, const char *name, char **out, char **msg)
{
	return text_or_absent(ctx, BML_QUERY_KCONFIG, name, "kconfig option not set", out, msg);
}

static int rec_presence(void *ctx, const char *kind, const char *target, int *out, char **msg)
{
	char *key = rc_fmts("%s/%s", kind, target);
	if (!key) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_boolean(ctx, BML_QUERY_BTF_PRESENCE, key, out, msg);
	free(key); return st;
}

static int rec_return(void *ctx, const char *name, const char *type, struct bml_strs *out, char **msg)
{
	char *key = rc_fmts("%s/%s", name, type);
	if (!key) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_diffs(ctx, BML_QUERY_FUNC_RET, key, out, msg);
	free(key); return st;
}

static int rec_fib(void *ctx, const char *prog, int64_t id, uint32_t mask, int *out, char **msg)
{
	const struct bml_caps *rp;
	int pv = rc_privileged(ctx, BML_QUERY_FIB_FLAGS, &rp, msg);
	if (pv < 0) return *msg ? BML_Q_UNKNOWN : (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (pv > 0)
		return rp->fib_flags ? rp->fib_flags(rp->ctx, prog, id, mask, out, msg) :
			(*msg = strdup("recorded caps: the re-probing caps has no fib_lookup_flags query"), BML_Q_UNKNOWN);
	char *key = rc_fmts("%s/%lld/%u", prog, (long long)id, mask);
	if (!key) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	int st = rc_boolean(ctx, BML_QUERY_FIB_FLAGS, key, out, msg);
	free(key); return st;
}

void rc_caps_kernel_values(struct bml_caps *c)
{
	c->enum_value = rec_enum;
	c->struct_size = rec_size;
	c->ksym_var = rec_ksym;
	c->kconfig = rec_config;
	c->btf_presence = rec_presence;
	c->func_ret = rec_return;
	c->fib_flags = rec_fib;
}
