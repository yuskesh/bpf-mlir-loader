

#define _GNU_SOURCE
#include "caps/recorder_internal.h"

#include <stdlib.h>
#include <string.h>

#include "caps/recorded.h"
#include "json/json.h"
#include "util/gostr.h"


static void jstr(struct bml_buf *b, const char *s)
{

	struct bml_buf t = {0};
	bml_json_write_string(&t, s, strlen(s));
	if (t.oom)
		b->oom = 1;
	for (size_t i = 0; i < t.len; i++) {
		char c = t.p[i];
		if (c == '<' || c == '>' || c == '&')
			bml_buf_adds(b, c == '<' ? "\\u003c" : c == '>' ? "\\u003e" : "\\u0026");
		else
			bml_buf_add(b, &c, 1);
	}
	bml_buf_free(&t);
}

static void ind(struct bml_buf *b, int d)
{
	bml_buf_adds(b, "\n");
	for (int i = 0; i < d; i++)
		bml_buf_adds(b, "  ");
}

static int cmp_kv(const void *a, const void *b)
{
	return strcmp(((const struct bml_kv *)a)->key, ((const struct bml_kv *)b)->key);
}

static void kv_map(struct bml_buf *b, const struct bml_kv *kv, size_t n, int has, int d)
{
	if (!has) {
		bml_buf_adds(b, "null");
		return;
	}
	if (!n) {
		bml_buf_adds(b, "{}");
		return;
	}
	struct bml_kv *s = malloc(n * sizeof *s);
	if (!s) {
		b->oom = 1;
		return;
	}
	memcpy(s, kv, n * sizeof *s);
	qsort(s, n, sizeof *s, cmp_kv);
	bml_buf_adds(b, "{");
	for (size_t i = 0; i < n; i++) {
		ind(b, d + 1);
		jstr(b, s[i].key);
		bml_buf_adds(b, ": ");
		jstr(b, s[i].value);
		if (i + 1 < n)
			bml_buf_adds(b, ",");
	}
	ind(b, d);
	bml_buf_adds(b, "}");
	free(s);
}

static void answer(struct bml_buf *b, const struct rec *e, int d)
{
	static const char *const field[] = {"value", "unknown", "error", "diffs", "text", "file"};
	if ((e->kind == A_UNKNOWN || e->kind == A_ERROR || e->kind == A_FILE) && !e->s[0]) {
		bml_buf_adds(b, "{}");
		return;
	}
	bml_buf_adds(b, "{");
	ind(b, d + 1);
	bml_buf_addf(b, "\"%s\": ", field[e->kind]);
	if (e->kind == A_VALUE)
		bml_buf_adds(b, e->value ? "true" : "false");
	else if (e->kind == A_DIFFS) {
		if (!e->diffs.n)
			bml_buf_adds(b, "[]");
		else {
			bml_buf_adds(b, "[");
			for (size_t i = 0; i < e->diffs.n; i++) {
				ind(b, d + 2);
				jstr(b, e->diffs.s[i]);
				if (i + 1 < e->diffs.n)
					bml_buf_adds(b, ",");
			}
			ind(b, d + 1);
			bml_buf_adds(b, "]");
		}
	} else
		jstr(b, e->s);
	ind(b, d);
	bml_buf_adds(b, "}");
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static int cmp_rec_key(const void *a, const void *b)
{
	return strcmp((*(const struct rec *const *)a)->key, (*(const struct rec *const *)b)->key);
}

char *bml_recorder_json(const struct bml_recorder *r, long long uid, const char *cap_eff, const struct bml_loader_decl *l,
			size_t *len)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, "{\n  \"format\": \"" BML_RECORDED_FORMAT "\",\n  \"probed_as\": {\n    \"uid\": ");
	bml_buf_addf(&b, "%lld,\n    \"cap_eff\": ", uid);
	jstr(&b, cap_eff);
	bml_buf_adds(&b, "\n  },\n  \"loader\": {\n    \"name\": ");
	jstr(&b, l->name ? l->name : "");
	bml_buf_adds(&b, ",\n    \"kprobe_alias_prefix\": ");
	kv_map(&b, l->kprobe_alias_prefix, l->n_kprobe_alias_prefix, l->has_kprobe_alias_prefix, 2);
	bml_buf_addf(&b, ",\n    \"uprobe_reopens_path\": %s,\n    \"core_poisons_missing_field\": %s,\n    \"btf_rewrite\": ",
		     l->uprobe_reopens_path ? "true" : "false", l->core_poisons_missing_field ? "true" : "false");
	kv_map(&b, l->btf_rewrite, l->n_btf_rewrite, l->has_btf_rewrite, 2);

	const char *const lkeys[] = {"usdt_attach", "sockmap_attach", "lsm_cgroup_load", "fsession_load", "ksyscall_attach",
		"hidden_data_vars", "typed_ksym", "kconfig", "arena_cast", "arena_premmap"};
	const char *const lvals[] = {l->usdt_attach, l->sockmap_attach, l->lsm_cgroup_load, l->fsession_load, l->ksyscall_attach,
		l->hidden_data_vars, l->typed_ksym, l->kconfig, l->arena_cast, l->arena_premmap};
	for (size_t i = 0; i < sizeof(lkeys) / sizeof(lkeys[0]); i++)
		if (lvals[i] && lvals[i][0]) {
			bml_buf_addf(&b, ",\n    \"%s\": ", lkeys[i]);
			jstr(&b, lvals[i]);
		}
	bml_buf_adds(&b, "\n  },\n  \"queries\": {");

	const char *names[64];
	size_t nn = 0;
	const char *base[] = {BML_QUERY_PROG_TYPE, BML_QUERY_HELPER, BML_QUERY_MAP_TYPE};
	for (size_t i = 0; i < 3; i++)
		names[nn++] = base[i];
	for (size_t i = 0; i < r->n; i++) {
		size_t j = 0;
		while (j < nn && strcmp(names[j], r->r[i].query) != 0)
			j++;
		if (j == nn && nn < 64)
			names[nn++] = r->r[i].query;
	}
	qsort(names, nn, sizeof *names, cmp_str);
	const struct rec **es = malloc((r->n + 1) * sizeof *es);
	if (!es) {
		bml_buf_free(&b);
		return NULL;
	}

	for (int dep = 0; dep < 2; dep++) {
		size_t ng = 0;
		for (size_t i = 0; i < nn; i++)
			ng += bml_caps_privilege_dependent(names[i]) == dep;
		if (dep) {
			if (!ng)
				break;
			bml_buf_adds(&b, ",\n  \"privileged_queries\": {");
		}
		if (!ng)
			bml_buf_adds(&b, "}");
		for (size_t i = 0, k = 0; i < nn; i++) {
			if (bml_caps_privilege_dependent(names[i]) != dep)
				continue;
			ind(&b, 2);
			jstr(&b, names[i]);
			bml_buf_adds(&b, ": ");
			size_t ne = 0;
			for (size_t j = 0; j < r->n; j++)
				if (strcmp(r->r[j].query, names[i]) == 0)
					es[ne++] = &r->r[j];
			qsort(es, ne, sizeof *es, cmp_rec_key);
			if (!ne)
				bml_buf_adds(&b, "{}");
			else {
				bml_buf_adds(&b, "{");
				for (size_t j = 0; j < ne; j++) {
					ind(&b, 3);
					jstr(&b, es[j]->key);
					bml_buf_adds(&b, ": ");
					answer(&b, es[j], 3);
					if (j + 1 < ne)
						bml_buf_adds(&b, ",");
				}
				ind(&b, 2);
				bml_buf_adds(&b, "}");
			}
			if (++k < ng)
				bml_buf_adds(&b, ",");
		}
		if (ng)
			bml_buf_adds(&b, "\n  }");
	}
	free(es);
	bml_buf_adds(&b, "\n}\n");
	if (b.oom) {
		bml_buf_free(&b);
		return NULL;
	}
	*len = b.len;
	return bml_buf_take(&b);
}
