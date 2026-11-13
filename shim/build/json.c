#include "shim/build/internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/goscan.h"
#include "json/json.h"
#include "maps/mapdecl.h"
#include "util/gostr.h"
#include "util/mutation.h"

struct bml_build_json {
	struct bml_json *root;
};



struct descs {
	void **p;
	size_t n;
};

static void *dalloc(struct descs *d, size_t size)
{
	void **np = realloc(d->p, (d->n + 1) * sizeof *np);
	if (!np)
		return NULL;
	d->p = np;
	void *x = calloc(1, size ? size : 1);
	if (x)
		d->p[d->n++] = x;
	return x;
}

static void descs_free(struct descs *d)
{
	for (size_t i = 0; i < d->n; i++)
		free(d->p[i]);
	free(d->p);
}


static int to_desc(const struct bml_build_shape *s, int depth, struct descs *d, const struct bml_json_desc **out, const char **why)
{
	if (!s)
		return *why = "a NULL shape", -1;
	if (depth > 64)
		return *why = "a shape nested more than 64 deep (a cycle?)", -1;
	struct bml_json_desc *x = dalloc(d, sizeof *x);
	if (!x)
		return -2;
	switch (s->kind) {
	case BML_BUILD_SHAPE_STRING: x->kind = BML_JD_STRING; break;
	case BML_BUILD_SHAPE_BOOL: x->kind = BML_JD_BOOL; break;
	case BML_BUILD_SHAPE_INT:
	case BML_BUILD_SHAPE_UINT:
		if (s->bits != 8 && s->bits != 16 && s->bits != 32 && s->bits != 64)
			return *why = "an integer shape needs bits 8, 16, 32 or 64", -1;
		x->kind = s->kind == BML_BUILD_SHAPE_INT ? BML_JD_INT : BML_JD_UINT;
		x->bits = s->bits;
		break;
	case BML_BUILD_SHAPE_ARRAY:
	case BML_BUILD_SHAPE_MAP: {
		x->kind = s->kind == BML_BUILD_SHAPE_ARRAY ? BML_JD_ARRAY : BML_JD_MAP;
		int rc = to_desc(s->elem, depth + 1, d, &x->child, why);
		if (rc)
			return rc;
		break;
	}
	case BML_BUILD_SHAPE_STRUCT: {
		struct bml_json_field *f = dalloc(d, s->n_fields * sizeof *f);
		if (!f)
			return -2;
		if (s->n_fields && !s->fields)
			return *why = "a struct shape without its fields", -1;
		for (size_t i = 0; i < s->n_fields; i++) {
			if (!s->fields[i].name || !s->fields[i].name[0])
				return *why = "a struct field without a name", -1;
			f[i].name = s->fields[i].name;
			int rc = to_desc(s->fields[i].shape, depth + 1, d, &f[i].desc, why);
			if (rc)
				return rc;
		}
		x->kind = BML_JD_STRUCT;
		x->fields = f;
		x->n_fields = s->n_fields;
		break;
	}
	default:
		return *why = "an unknown shape kind", -1;
	}
	*out = x;
	return 0;
}




static int scan_step(const void *data, size_t len, const struct bml_json_desc *desc, const char *prefix, int parts,
		     struct bml_build_error *err)
{
	struct bml_json_goerr ge;
	if (bml_json_go_scan(data, len, desc, &ge) == 0)
		return 0;
	if (ge.nomem) {
		bml_json_goerr_free(&ge);
		return bb_nomem(err);
	}
	if (BML_MUT("build.json_no_key_case") && !strcmp(ge.rule, "key_case")) {
		bml_json_goerr_free(&ge);
		return 0;
	}
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%sjson: %s at byte %lld: %s", prefix, ge.rule, (long long)ge.offset, ge.detail);
	char *t = bml_buf_take(&b);
	if (ge.key_quote) {
		int rc = t ? bb_unsupported(err, "json-key-quote", t) : bb_nomem(err);
		free(t);
		if (parts && rc == BML_BUILD_UNSUPPORTED)
			snprintf(err->rule, sizeof err->rule, "%s", ge.rule);
		bml_json_goerr_free(&ge);
		return err->code;
	}
	int rc = bb_fail(err, t);
	free(t);
	if (parts && rc == BML_BUILD_FAIL) {
		snprintf(err->rule, sizeof err->rule, "%s", ge.rule);
		err->offset = ge.offset;
		err->detail = ge.detail;
		ge.detail = NULL;
	}
	bml_json_goerr_free(&ge);
	return err->code;
}




static const struct bml_json_member *repeated_member(const struct bml_json *j)
{
	if (!j)
		return NULL;
	if (j->type == BML_JSON_ARRAY) {
		for (size_t i = 0; i < j->n; i++) {
			const struct bml_json_member *d = repeated_member(j->items[i]);
			if (d)
				return d;
		}
	} else if (j->type == BML_JSON_OBJECT) {
		for (size_t i = 0; i < j->n; i++) {
			const struct bml_json_member *m = &j->members[i];
			for (size_t k = 0; k < i; k++)
				if (j->members[k].key_len == m->key_len && !memcmp(j->members[k].key, m->key, m->key_len))
					return m;
			const struct bml_json_member *d = repeated_member(m->value);
			if (d)
				return d;
		}
	}
	return NULL;
}



static int typed_step(const void *data, size_t len, const struct bml_json_desc *desc, int parts, struct bml_json **out,
		      struct bml_build_error *err)
{
	struct bml_json *j = NULL;
	char *m = NULL;
	enum bml_json_rule rule = BML_JR_NONE;

	const struct bml_json_desc *pdesc = BML_MUT("build.json_no_key_case") ? NULL : desc;
	if (bml_json_parse_ex(data ? data : "", len, pdesc, 0, &j, &m, &rule)) {
		int rc = rule == BML_JR_OOM ? bb_nomem(err) : bb_unsupported(err, "json-scan", m);
		free(m);
		return rc;
	}
	if (desc && bml_json_validate(j, desc, &m, &rule)) {
		int rc;
		if (rule == BML_JR_OOM) {
			rc = bb_nomem(err);
		} else if (rule == BML_JR_UNKNOWN_KEY) {
			rc = bb_unsupported(err, "json-unknown-key", m);
			if (parts && rc == BML_BUILD_UNSUPPORTED) {

				static const char pre[] = "json: unknown field \"";
				size_t ml = strlen(m), pl = sizeof pre - 1;
				struct bml_buf b = {0};
				bml_buf_adds(&b, "unknown field ");
				char *key = ml > pl && !strncmp(m, pre, pl) ? strndup(m + pl, ml - pl - 1) : NULL;
				if (key && bml_json_go_key_quotable(key)) {
					bml_buf_add_goquote(&b, key, strlen(key));
					err->detail = bml_buf_take(&b);
				} else {
					free(bml_buf_take(&b));
				}
				free(key);
				snprintf(err->rule, sizeof err->rule, "unknown_key");
			}
		} else {
			rc = bb_unsupported(err, "json-type", m);
			if (parts && rc == BML_BUILD_UNSUPPORTED)
				snprintf(err->rule, sizeof err->rule, "type");
		}
		free(m);
		bml_json_free(j);
		return rc;
	}
	const struct bml_json_member *dup = desc ? repeated_member(j) : NULL;
	if (dup) {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "two members fold to the field ");
		bml_buf_add_goquote(&b, dup->key, dup->key_len);
		char *t = bml_buf_take(&b);
		int rc = t ? bb_unsupported(err, "json-alias-collision", t) : bb_nomem(err);
		free(t);
		bml_json_free(j);
		return rc;
	}
	*out = j;
	return 0;
}

int bml_build_json_check_any(const void *data, size_t len, struct bml_build_error *err)
{
	bb_init(err);
	if (scan_step(data, len, NULL, "", 1, err))
		return err->code;
	struct bml_json *j = NULL;
	if (typed_step(data, len, NULL, 1, &j, err))
		return err->code;
	const char *num = NULL;
	int r = bml_json_float64_range(j, &num);
	if (r < 0) {
		bml_json_free(j);
		return bb_nomem(err);
	}
	if (r) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "the number %s is out of the float64 range", num);
		char *t = bml_buf_take(&b);
		bb_unsupported(err, "json-any-number-range", t);
		free(t);
		if (err->code == BML_BUILD_UNSUPPORTED)
			snprintf(err->rule, sizeof err->rule, "type");
	}
	bml_json_free(j);
	return err->code;
}

int bml_build_json_decode(const void *data, size_t len, const struct bml_build_shape *shape, struct bml_build_json **doc,
			  struct bml_build_error *err)
{
	bb_init(err);
	*doc = NULL;
	struct descs d = {0};
	const struct bml_json_desc *desc = NULL;
	const char *why = NULL;
	int rc = to_desc(shape, 0, &d, &desc, &why);
	if (rc) {
		descs_free(&d);
		return rc == -2 ? bb_nomem(err) : bb_unsupported(err, "shape", why);
	}
	struct bml_json *j = NULL;
	if (!scan_step(data, len, desc, "", 1, err) && !typed_step(data, len, desc, 1, &j, err)) {
		if (!(*doc = malloc(sizeof **doc))) {
			bml_json_free(j);
			bb_nomem(err);
		} else {
			(*doc)->root = j;
		}
	}
	descs_free(&d);
	return err->code;
}

int bml_build_map_decls_validate(const void *data, size_t len, struct bml_build_error *err)
{
	bb_init(err);
	const struct bml_json_desc *desc = bml_map_decls_desc();
	struct bml_json *j = NULL;
	if (scan_step(data, len, desc, "maps: ", 0, err) || typed_step(data, len, desc, 0, &j, err))
		return err->code;
	bml_json_free(j);
	return BML_BUILD_OK;
}



#define NODE(n) ((const struct bml_json *)(const void *)(n))

void bml_build_json_free(struct bml_build_json *doc)
{
	if (!doc)
		return;
	bml_json_free(doc->root);
	free(doc);
}

const struct bml_build_json_node *bml_build_json_root(const struct bml_build_json *doc)
{
	return doc ? (const struct bml_build_json_node *)(const void *)doc->root : NULL;
}

int bml_build_json_type(const struct bml_build_json_node *n)
{
	switch (n ? NODE(n)->type : BML_JSON_NULL) {
	case BML_JSON_BOOL: return BML_BUILD_JSON_BOOL;
	case BML_JSON_NUMBER: return BML_BUILD_JSON_NUMBER;
	case BML_JSON_STRING: return BML_BUILD_JSON_STRING;
	case BML_JSON_ARRAY: return BML_BUILD_JSON_ARRAY;
	case BML_JSON_OBJECT: return BML_BUILD_JSON_OBJECT;
	default: return BML_BUILD_JSON_NULL;
	}
}

int bml_build_json_bool(const struct bml_build_json_node *n)
{
	return n && NODE(n)->type == BML_JSON_BOOL && NODE(n)->boolean;
}

const char *bml_build_json_string_value(const struct bml_build_json_node *n, size_t *len)
{
	if (!n || NODE(n)->type != BML_JSON_STRING)
		return NULL;
	if (len)
		*len = NODE(n)->len;
	return NODE(n)->str;
}

int bml_build_json_int64(const struct bml_build_json_node *n, int64_t *out)
{
	return n && NODE(n)->type == BML_JSON_NUMBER ? bml_json_int64(NODE(n), out) : -1;
}

int bml_build_json_uint64(const struct bml_build_json_node *n, uint64_t *out)
{
	return n && NODE(n)->type == BML_JSON_NUMBER ? bml_json_uint64(NODE(n), out) : -1;
}

size_t bml_build_json_count(const struct bml_build_json_node *n)
{
	return n && (NODE(n)->type == BML_JSON_ARRAY || NODE(n)->type == BML_JSON_OBJECT) ? NODE(n)->n : 0;
}

const struct bml_build_json_node *bml_build_json_index(const struct bml_build_json_node *n, size_t i)
{
	if (!n || NODE(n)->type != BML_JSON_ARRAY || i >= NODE(n)->n)
		return NULL;
	return (const struct bml_build_json_node *)(const void *)NODE(n)->items[i];
}

const char *bml_build_json_member(const struct bml_build_json_node *n, size_t i, size_t *key_len,
				  const struct bml_build_json_node **value)
{
	if (!n || NODE(n)->type != BML_JSON_OBJECT || i >= NODE(n)->n)
		return NULL;
	const struct bml_json_member *m = &NODE(n)->members[i];
	if (key_len)
		*key_len = m->key_len;
	if (value)
		*value = (const struct bml_build_json_node *)(const void *)m->value;
	return m->key;
}

const struct bml_build_json_node *bml_build_json_get(const struct bml_build_json_node *n, const char *key, size_t key_len)
{
	if (!n || !key || NODE(n)->type != BML_JSON_OBJECT)
		return NULL;
	for (size_t i = 0; i < NODE(n)->n; i++) {
		const struct bml_json_member *m = &NODE(n)->members[i];
		if (m->key_len == key_len && !memcmp(m->key, key, key_len))
			return (const struct bml_build_json_node *)(const void *)m->value;
	}
	return NULL;
}
