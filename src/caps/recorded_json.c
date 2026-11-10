







#include "caps/recorded_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"
#include "util/gostr.h"
#include "util/mutation.h"

char *rc_fmts(const char *f, ...) __attribute__((format(printf, 1, 2)));
char *rc_fmts(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	int k = vsnprintf(NULL, 0, f, ap);
	va_end(ap);
	char *p = k >= 0 ? malloc((size_t)k + 1) : NULL;
	if (!p)
		return NULL;
	va_start(ap, f);
	vsnprintf(p, (size_t)k + 1, f, ap);
	va_end(ap);
	return p;
}

void rc_answer_free(struct answer *a)
{
	free(a->unknown);
	free(a->error);
	free(a->text);
	free(a->file);
	bml_strs_free(&a->diffs);
}

void bml_recorded_free(struct bml_recorded *r)
{
	if (!r)
		return;
	free(r->format);
	free(r->probed_cap);
	bml_loader_decl_free(&r->loader);
	for (size_t i = 0; i < r->n_q; i++) {
		free(r->q[i].name);
		for (size_t j = 0; j < r->q[i].n; j++) {
			free(r->q[i].e[j].key);
			rc_answer_free(&r->q[i].e[j].a);
		}
		free(r->q[i].e);
	}
	free(r->q);
	free(r->dir);
	free(r->scope.load_cap);
	free(r);
}



int rc_check_keys(const struct bml_json *o, const char *const *allowed, size_t n, const char *where, char **err)
{
	for (size_t i = 0; i < o->n; i++) {
		int ok = 0;
		for (size_t k = 0; k < n; k++)
			if (strlen(allowed[k]) == o->members[i].key_len && !memcmp(allowed[k], o->members[i].key, o->members[i].key_len))
				ok = 1;
		if (!ok) {
			*err = rc_fmts("caps: json: unknown field \"%s\" in %s (key names are exact — case matters)", o->members[i].key, where);
			return -1;
		}
	}
	return 0;
}


int rc_get_str(const struct bml_json *o, const char *key, char **out, char **err)
{
	*out = NULL;
	const struct bml_json *v = bml_json_get(o, key);
	if (!v || v->type == BML_JSON_NULL)
		return 0;
	if (v->type != BML_JSON_STRING) {
		*err = rc_fmts("caps: json: cannot unmarshal %s into field %s of type string", v->type == BML_JSON_NUMBER ? "number" : "value", key);
		return -1;
	}
	if (memchr(v->str, 0, v->len)) {
		*err = rc_fmts("caps: field %s contains a NUL byte (not supported)", key);
		return -1;
	}
	*out = strdup(v->str);
	return *out ? 0 : (*err = rc_fmts("out of memory"), -1);
}

int rc_get_bool(const struct bml_json *o, const char *key, int *set, int *out, char **err)
{
	*set = 0;
	*out = 0;
	const struct bml_json *v = bml_json_get(o, key);
	if (!v || v->type == BML_JSON_NULL)
		return 0;
	if (v->type != BML_JSON_BOOL) {
		*err = rc_fmts("caps: json: cannot unmarshal into field %s of type bool", key);
		return -1;
	}
	*set = 1;
	*out = v->boolean;
	return 0;
}


int rc_get_kv(const struct bml_json *o, const char *key, struct bml_kv **out, size_t *n, int *has, char **err)
{
	*out = NULL;
	*n = 0;
	*has = 0;
	const struct bml_json *v = bml_json_get(o, key);
	if (!v || v->type == BML_JSON_NULL)
		return 0;
	*has = 1;
	if (v->type != BML_JSON_OBJECT) {
		*err = rc_fmts("caps: json: cannot unmarshal into field %s of type map[string]string", key);
		return -1;
	}
	*out = v->n ? calloc(v->n, sizeof(**out)) : NULL;
	if (v->n && !*out)
		return (*err = rc_fmts("out of memory"), -1);
	for (size_t i = 0; i < v->n; i++) {
		const struct bml_json *x = v->members[i].value;
		if (x->type != BML_JSON_STRING && x->type != BML_JSON_NULL) {
			*err = rc_fmts("caps: json: cannot unmarshal into %s[%s] of type string", key, v->members[i].key);
			return -1;
		}
		if (memchr(v->members[i].key, 0, v->members[i].key_len) || (x->type == BML_JSON_STRING && memchr(x->str, 0, x->len))) {
			*err = rc_fmts("caps: %s contains a NUL byte (not supported)", key);
			return -1;
		}
		(*out)[i].key = strdup(v->members[i].key);
		(*out)[i].value = strdup(x->type == BML_JSON_STRING ? x->str : "");
		(*n)++;
		if (!(*out)[i].key || !(*out)[i].value)
			return (*err = rc_fmts("out of memory"), -1);
	}
	return 0;
}

int rc_decode_answer(const struct bml_json *v, struct answer *a, char **err)
{
	memset(a, 0, sizeof(*a));
	if (v->type == BML_JSON_NULL)
		return 0;
	if (v->type != BML_JSON_OBJECT)
		return (*err = rc_fmts("caps: json: cannot unmarshal into an answer"), -1);
	static const char *const keys[] = {"value", "unknown", "error", "diffs", "text", "file"};
	if (rc_check_keys(v, keys, 6, "an answer", err))
		return -1;
	if (rc_get_bool(v, "value", &a->has_value, &a->value, err) || rc_get_str(v, "unknown", &a->unknown, err) ||
	    rc_get_str(v, "error", &a->error, err) || rc_get_str(v, "text", &a->text, err) || rc_get_str(v, "file", &a->file, err))
		return -1;

	if (a->unknown && !a->unknown[0])
		free(a->unknown), a->unknown = NULL;
	if (a->error && !a->error[0])
		free(a->error), a->error = NULL;
	if (a->file && !a->file[0])
		free(a->file), a->file = NULL;
	const struct bml_json *d = bml_json_get(v, "diffs");
	if (d && d->type != BML_JSON_NULL) {
		if (d->type != BML_JSON_ARRAY)
			return (*err = rc_fmts("caps: json: cannot unmarshal into field diffs of type []string"), -1);
		a->has_diffs = 1;
		a->diffs.s = d->n ? calloc(d->n, sizeof(char *)) : NULL;
		if (d->n && !a->diffs.s)
			return (*err = rc_fmts("out of memory"), -1);
		for (size_t i = 0; i < d->n; i++) {
			const struct bml_json *x = d->items[i];
			if (x->type != BML_JSON_STRING && x->type != BML_JSON_NULL)
				return (*err = rc_fmts("caps: json: cannot unmarshal into diffs[%zu] of type string", i), -1);
			if (x->type == BML_JSON_STRING && memchr(x->str, 0, x->len))
				return (*err = rc_fmts("caps: diffs contain a NUL byte (not supported)"), -1);
			a->diffs.s[i] = strdup(x->type == BML_JSON_STRING ? x->str : "");
			if (!a->diffs.s[i])
				return (*err = rc_fmts("out of memory"), -1);
			a->diffs.n++;
		}
	}
	return 0;
}
static const struct bml_json_desc d_string = {.kind = BML_JD_STRING};
static const struct bml_json_desc d_bool = {.kind = BML_JD_BOOL};
static const struct bml_json_desc d_int = {.kind = BML_JD_INT, .bits = 64};
static const struct bml_json_desc d_strings = {.kind = BML_JD_ARRAY, .child = &d_string};
static const struct bml_json_desc d_strmap = {.kind = BML_JD_MAP, .child = &d_string};
static const struct bml_json_field f_answer[] = {{"value", &d_bool},  {"unknown", &d_string}, {"error", &d_string},
						 {"diffs", &d_strings}, {"text", &d_string},   {"file", &d_string}};
static const struct bml_json_desc d_answer = {.kind = BML_JD_STRUCT, .fields = f_answer, .n_fields = 6};
static const struct bml_json_desc d_answers = {.kind = BML_JD_MAP, .child = &d_answer};
static const struct bml_json_desc d_queries = {.kind = BML_JD_MAP, .child = &d_answers};
static const struct bml_json_field f_loader[] = {{"name", &d_string},
						 {"kprobe_alias_prefix", &d_strmap},
						 {"uprobe_reopens_path", &d_bool},
						 {"core_poisons_missing_field", &d_bool},
						 {"btf_rewrite", &d_strmap},
						 {"usdt_attach", &d_string}                           ,
						 {"sockmap_attach", &d_string}                           ,
						 {"lsm_cgroup_load", &d_string},
						 {"fsession_load", &d_string},
						 {"ksyscall_attach", &d_string}, {"hidden_data_vars", &d_string}, {"typed_ksym", &d_string},
						 {"kconfig", &d_string}, {"arena_cast", &d_string}, {"arena_premmap", &d_string}};
const struct bml_json_desc rc_d_loader = {.kind = BML_JD_STRUCT, .fields = f_loader, .n_fields = sizeof(f_loader) / sizeof(f_loader[0])};
static const struct bml_json_field f_probed[] = {{"uid", &d_int}, {"cap_eff", &d_string}};
static const struct bml_json_desc d_probed = {.kind = BML_JD_STRUCT, .fields = f_probed, .n_fields = 2};
static const struct bml_json_field f_caps[] = {{"format", &d_string},     {"probed_as", &d_probed}, {"loader", &rc_d_loader},
					       {"queries", &d_queries}, {"privileged_queries", &d_queries}                                           };
const struct bml_json_desc rc_d_caps = {.kind = BML_JD_STRUCT, .fields = f_caps, .n_fields = 5};

struct bml_json *rc_strict(const char *data, size_t len, const struct bml_json_desc *d, const char *prefix, char **err,
			       enum bml_json_rule *rule)
{
	struct bml_json *j;
	char *e = NULL;
	if (bml_json_parse_ex(data, len, d, 0, &j, &e, rule)) {
		*err = rc_fmts("%sjson: %s", prefix, e ? e : "");
		free(e);
		return NULL;
	}
	if (bml_json_validate(j, d, &e, rule)) {
		*err = rc_fmts("%s%s", prefix, e ? e : "");
		free(e);
		bml_json_free(j);
		return NULL;
	}
	return j;
}
int bml_loader_decl_parse(const char *data, size_t len, struct bml_loader_decl *d, char **err, enum bml_json_rule *rule)
{
	memset(d, 0, sizeof(*d));
	*err = NULL;
	if (rule)
		*rule = BML_JR_NONE;
	struct bml_json *j = rc_strict(data, len, &rc_d_loader, "", err, rule);
	if (!j)
		return -1;
	int set, rc = -1;
	if (j->type == BML_JSON_NULL) {
		d->name = strdup("");
		rc = d->name ? 0 : -1;
	} else if (!rc_get_str(j, "name", &d->name, err) &&
		   !rc_get_kv(j, "kprobe_alias_prefix", &d->kprobe_alias_prefix, &d->n_kprobe_alias_prefix, &d->has_kprobe_alias_prefix, err) &&
		   !rc_get_bool(j, "uprobe_reopens_path", &set, &d->uprobe_reopens_path, err) &&
		   !rc_get_bool(j, "core_poisons_missing_field", &set, &d->core_poisons_missing_field, err) &&
		   !rc_get_kv(j, "btf_rewrite", &d->btf_rewrite, &d->n_btf_rewrite, &d->has_btf_rewrite, err) &&
		   !rc_get_str(j, "usdt_attach", &d->usdt_attach, err) && !rc_get_str(j, "sockmap_attach", &d->sockmap_attach, err) &&
		   !rc_get_str(j, "lsm_cgroup_load", &d->lsm_cgroup_load, err) && !rc_get_str(j, "fsession_load", &d->fsession_load, err) &&
		   !rc_get_str(j, "ksyscall_attach", &d->ksyscall_attach, err) &&
		   !rc_get_str(j, "hidden_data_vars", &d->hidden_data_vars, err) && !rc_get_str(j, "typed_ksym", &d->typed_ksym, err) &&
		   !rc_get_str(j, "kconfig", &d->kconfig, err) && !rc_get_str(j, "arena_cast", &d->arena_cast, err) &&
		   !rc_get_str(j, "arena_premmap", &d->arena_premmap, err)) {
		if (!d->name)
			d->name = strdup("");
		rc = d->name ? 0 : -1;
	}
	bml_json_free(j);
	if (rc) {
		bml_loader_decl_free(d);
		if (!*err)
			*err = strdup("out of memory");
	}
	return rc;
}
