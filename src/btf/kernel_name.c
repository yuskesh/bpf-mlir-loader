#define _GNU_SOURCE
#include "util/mutation.h"
#include "btf/kernel.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


const char *bml_kbtf_type_name(const struct kbtf_type *t)
{
	switch (t->kind) {
	case KBTF_INT: case KBTF_STRUCT: case KBTF_UNION: case KBTF_ENUM: case KBTF_FWD: case KBTF_TYPEDEF: case KBTF_FUNC:
	case KBTF_VAR: case KBTF_DATASEC: case KBTF_FLOAT: case KBTF_ENUM64:
		return t->name;
	}
	return "";
}


static long last_flavor(const char *s)
{
	long at = -1;
	for (const char *p = strstr(s, "___"); p; p = strstr(p + 1, "___"))
		at = p - s;
	return at;
}


static size_t essential_len(const char *s)
{
	long at = last_flavor(s);
	return at > 0 ? (size_t)at : strlen(s);
}


static size_t key_len(const char *s)
{
	long at = last_flavor(s);
	return at >= 0 ? (size_t)at : strlen(s);
}


static int key_cmp(const struct bml_kbtf *kb, uint32_t id, const char *s, size_t n)
{
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	size_t kl = key_len(t.name);
	int r = memcmp(t.name, s, kl < n ? kl : n);
	if (r)
		return r;
	return kl < n ? -1 : kl > n;
}

#ifdef BML_TEST_CAPS
static int idx_cmp(const void *a, const void *b, void *ctx)
{
	const struct bml_kbtf *kb = ctx;
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
	struct kbtf_type ty;
	bml_kbtf_type(kb, y, &ty);
	int r = key_cmp(kb, x, ty.name, key_len(ty.name));
	return r ? r : (x > y) - (x < y);
}
#endif



struct idx_key {
	const char *name;
	size_t len;
	uint32_t id;
};

static int key_ent_cmp(const void *a, const void *b)
{
	const struct idx_key *x = a, *y = b;
	int r = memcmp(x->name, y->name, x->len < y->len ? x->len : y->len);
	if (r)
		return r;
	if (x->len != y->len)
		return x->len < y->len ? -1 : 1;
	return (x->id > y->id) - (x->id < y->id);
}

int bml_kbtf_build_index(struct bml_kbtf *kb, char **err)
{
	kb->idx = malloc((size_t)kb->n * sizeof *kb->idx);
	struct idx_key *k = malloc((size_t)kb->n * sizeof *k);
	if (!kb->idx || !k) {
		free(k);
		*err = strdup("out of memory");
		return -1;
	}
	size_t n = 0;
	for (uint32_t id = 1; id < kb->n; id++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, id, &t);
		if (t.name[0])
			k[n++] = (struct idx_key){t.name, BML_MUT("kbtf.index_full_name") ? strlen(t.name) : key_len(t.name), id};
	}
	qsort(k, n, sizeof *k, key_ent_cmp);
	for (size_t i = 0; i < n; i++)
		kb->idx[i] = k[i].id;
	kb->nidx = (uint32_t)n;
	free(k);
	return 0;
}

#ifdef BML_TEST_CAPS

int bml_kbtf_build_index_reference(struct bml_kbtf *kb, char **err)
{
	kb->idx = malloc((size_t)kb->n * sizeof *kb->idx);
	if (!kb->idx) {
		*err = strdup("out of memory");
		return -1;
	}
	kb->nidx = 0;
	for (uint32_t id = 1; id < kb->n; id++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, id, &t);
		if (t.name[0])
			kb->idx[kb->nidx++] = id;
	}
	qsort_r(kb->idx, kb->nidx, sizeof *kb->idx, idx_cmp, kb);
	return 0;
}
#endif

static int err_msg(char **err, int rc, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static int err_msg(char **err, int rc, const char *fmt, ...)
{
	struct bml_buf b = {0};
	va_list ap;
	char tmp[1024];
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	bml_buf_adds(&b, tmp);
	*err = bml_buf_take(&b);
	return rc;
}

int bml_kbtf_any_by_name(const struct bml_kbtf *kb, const char *name, uint32_t **ids, size_t *n, char **err)
{
	*err = NULL;
	*ids = NULL, *n = 0;
	size_t elen = essential_len(name);

	uint32_t *c = NULL;
	size_t nc = 0, cap = 0;

	size_t lo = 0, hi = kb->nidx;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (key_cmp(kb, kb->idx[mid], name, elen) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (elen > 0)
		for (size_t k = lo; k < kb->nidx && key_cmp(kb, kb->idx[k], name, elen) == 0; k++) {
			uint32_t i = kb->idx[k];
			struct kbtf_type t;
			bml_kbtf_type(kb, i, &t);
			const char *tn = bml_kbtf_type_name(&t);
			if (tn[0] == 0 || essential_len(tn) != elen)
				continue;
			if (nc == cap) {
				cap = cap ? cap * 2 : 8;
				uint32_t *nw = realloc(c, cap * sizeof *c);
				if (!nw) {
					free(c);
					return err_msg(err, 2, "out of memory");
				}
				c = nw;
			}
			c[nc++] = i;
		}
	if (nc == 0) {
		free(c);
		return err_msg(err, 1, "not found");
	}

	for (size_t i = 0; i < nc; i++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, c[i], &t);
		if (strcmp(bml_kbtf_type_name(&t), name) != 0) {
			memmove(c + i, c + i + 1, (nc - i - 1) * sizeof *c);
			nc--;
			continue;
		}
	}
	*ids = c, *n = nc;
	return 0;
}

int bml_kbtf_by_name(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t *id, char **err)
{
	uint32_t *c;
	size_t nc;
	int rc = bml_kbtf_any_by_name(kb, name, &c, &nc, err);
	if (rc)
		return rc;
	const char *want = bml_kbtf_goname(kind);
	int found = 0;
	for (size_t i = 0; i < nc; i++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, c[i], &t);
		if (strcmp(bml_kbtf_goname(t.kind), want) != 0)
			continue;
		if (found && BML_MUT("live.name_first_match"))
			break;
		if (found) {
			free(c);
			return err_msg(err, 2, "type %s(*btf.%s): multiple matching types", name, want);
		}
		found = 1;
		*id = c[i];
	}
	free(c);
	if (!found)
		return err_msg(err, 1, "*btf.%s %s: not found", want, name);
	return 0;
}
