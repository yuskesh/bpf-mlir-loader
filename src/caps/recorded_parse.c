#include "caps/recorded_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"
#include "util/gostr.h"
#include "util/mutation.h"

static const char *const known_queries[] = {
	BML_QUERY_PROG_TYPE,  BML_QUERY_HELPER,       BML_QUERY_MAP_TYPE,   BML_QUERY_TCX,          BML_QUERY_FUNC_SIG,
	BML_QUERY_FUNC,       BML_QUERY_TRACEPOINT,   BML_QUERY_KFIELDS,    BML_QUERY_BTF_FEATURE,  BML_QUERY_ARG_TAG,
	BML_QUERY_ARCH,       BML_QUERY_STRUCT_FIELD, BML_QUERY_KERNEL_SYM, BML_QUERY_FUNC_PARAM,   BML_QUERY_UPROBE_BIN,
	BML_QUERY_MAP_FIELD,  BML_QUERY_NULLABLE_ARGS, BML_QUERY_TRACING_HELPER, BML_QUERY_FUNC_ARGS,
	BML_QUERY_ATTACH_TYPE, BML_QUERY_ATTACH_TARGET, BML_QUERY_CTX_ACCESS,
	BML_QUERY_TP_FIELDS, BML_QUERY_STRUCT_OPS_MEMBERS, BML_QUERY_EXT_TARGETS,
	BML_QUERY_KFUNC_PROTOS, BML_QUERY_SYSCALL_ARGS,
	BML_QUERY_KFUNC_LOADS, BML_QUERY_TRACEPOINT_BUFFER,
	BML_QUERY_UPROBE_DEBUG,
	BML_QUERY_ENUM_VALUES, BML_QUERY_FIB_FLAGS, BML_QUERY_KSYM_VARS, BML_QUERY_KCONFIG,
	BML_QUERY_BTF_PRESENCE, BML_QUERY_FUNC_RET, BML_QUERY_STRUCT_SIZE,
	BML_QUERY_NETKIT, BML_QUERY_HELPER_TARGET, BML_QUERY_SLEEPABLE,
};

#define FORMATS                                                                                                                        \
	"\"" BML_RECORDED_FORMAT "\" (or \"ebpf-caps 19\" / \"ebpf-caps 18\" / \"ebpf-caps 17\" / \"ebpf-caps 16\" /\"ebpf-caps 15\" / \"ebpf-caps 14\" / \"ebpf-caps 13\" / \"ebpf-caps 12\" / \"ebpf-caps 11\" / \"ebpf-caps 10\" / \"" BML_RECORDED_FORMAT_V9 "\" / \"" BML_RECORDED_FORMAT_V8 "\" / \"" BML_RECORDED_FORMAT_V7 "\" / \"" BML_RECORDED_FORMAT_V6 "\" / \"" \
	BML_RECORDED_FORMAT_V5 "\" / \"" BML_RECORDED_FORMAT_V4 "\" / \"" BML_RECORDED_FORMAT_V3 "\" / \"" BML_RECORDED_FORMAT_V2 "\")"


static int cmp_query(const void *a, const void *b)
{
	return strcmp(((const struct query *)a)->name, ((const struct query *)b)->name);
}

static int cmp_entry(const void *a, const void *b)
{
	return strcmp(((const struct entry *)a)->key, ((const struct entry *)b)->key);
}


static int decode_queries(const struct bml_json *qs, const char *where, struct bml_recorded *r, int priv, char **err)
{
	if (!qs || qs->type == BML_JSON_NULL)
		return 0;
	if (qs->type != BML_JSON_OBJECT) {
		*err = rc_fmts("caps: json: cannot unmarshal into %s", where);
		return -1;
	}
	struct query *nq = qs->n ? realloc(r->q, (r->n_q + qs->n) * sizeof(*r->q)) : r->q;
	if (qs->n && !nq) {
		*err = rc_fmts("out of memory");
		return -1;
	}
	r->q = nq;
	for (size_t i = 0; i < qs->n; i++) {
		const struct bml_json *m = qs->members[i].value;
		struct query *q = &r->q[r->n_q++];
		memset(q, 0, sizeof *q);
		q->priv = priv;
		q->name = strdup(qs->members[i].key);
		if (!q->name) {
			*err = rc_fmts("out of memory");
			return -1;
		}
		if (m->type == BML_JSON_NULL)
			continue;
		if (m->type != BML_JSON_OBJECT) {
			*err = rc_fmts("caps: json: cannot unmarshal into %s[%s]", where, q->name);
			return -1;
		}
		q->e = m->n ? calloc(m->n, sizeof(*q->e)) : NULL;
		if (m->n && !q->e) {
			*err = rc_fmts("out of memory");
			return -1;
		}
		for (size_t k = 0; k < m->n; k++) {
			struct entry *e = &q->e[q->n];
			if (memchr(m->members[k].key, 0, m->members[k].key_len)) {
				*err = rc_fmts("caps: a query key contains a NUL byte (not supported)");
				return -1;
			}
			e->key = strdup(m->members[k].key);
			q->n++;
			if (!e->key) {
				*err = rc_fmts("out of memory");
				return -1;
			}
			if (rc_decode_answer(m->members[k].value, &e->a, err))
				return -1;
		}
	}
	return 0;
}

static const char *const ebpf_caps1_msg =
	"caps: format \"ebpf-caps 1\" is no longer read (the loader's BTF rewrites moved from the query btf_rewrites to the loader declaration's btf_rewrite); record the caps again as \"" BML_RECORDED_FORMAT "\"";



static int peek_format(const char *data, size_t len, char **fmt, size_t *flen)
{
	struct bml_json *j;
	char *e;
	*fmt = NULL, *flen = 0;
	if (bml_json_parse_ex(data, len, NULL, 1, &j, &e, NULL)) {
		free(e);
		return 0;
	}
	int bad = 0;
	const struct bml_json *f = NULL;
	if (j->type == BML_JSON_OBJECT) {
		for (size_t i = 0; i < j->n; i++) {
			const struct bml_json_member *m = &j->members[i];
			if (m->key_len == 6 && !strncasecmp(m->key, "format", 6)) {
				if (m->value->type == BML_JSON_STRING)
					f = m->value;
				else if (m->value->type == BML_JSON_NULL)
					f = NULL;
				else
					bad = 1;
			}
		}
	} else if (j->type != BML_JSON_NULL) {
		bad = 1;
	}
	if (!bad && f) {
		*fmt = malloc(f->len + 1);
		if (*fmt) {
			memcpy(*fmt, f->str, f->len);
			(*fmt)[f->len] = 0;
			*flen = f->len;
		}
	}
	bml_json_free(j);
	return !bad;
}


static int old_format(const char *data, size_t len)
{
	char *f;
	size_t n;
	int r = peek_format(data, len, &f, &n) && f && n == 11 && !memcmp(f, "ebpf-caps 1", 11);
	free(f);
	return r;
}


static int known_format(const char *f, size_t n)
{
	static const char *const known[] = {BML_RECORDED_FORMAT, BML_RECORDED_FORMAT_V19, BML_RECORDED_FORMAT_V18, BML_RECORDED_FORMAT_V17, BML_RECORDED_FORMAT_V16, BML_RECORDED_FORMAT_V15, BML_RECORDED_FORMAT_V14,
		BML_RECORDED_FORMAT_V13, BML_RECORDED_FORMAT_V12, BML_RECORDED_FORMAT_V11, BML_RECORDED_FORMAT_V10,
		BML_RECORDED_FORMAT_V9, BML_RECORDED_FORMAT_V8, BML_RECORDED_FORMAT_V7, BML_RECORDED_FORMAT_V6, BML_RECORDED_FORMAT_V5,
					    BML_RECORDED_FORMAT_V4, BML_RECORDED_FORMAT_V3, BML_RECORDED_FORMAT_V2, "ebpf-caps 1"};
	for (size_t i = 0; i < sizeof known / sizeof *known; i++)
		if (strlen(known[i]) == n && !memcmp(known[i], f, n))
			return 1;
	return 0;
}

static char *format_unknown_msg(const char *f, size_t n)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, "caps: format ");
	bml_buf_add_goquote(&b, f ? f : "", f ? n : 0);
	bml_buf_adds(&b, ", want " FORMATS);
	return bml_buf_take(&b);
}
struct bml_recorded *bml_recorded_parse_rule(const char *data, size_t len, const char *dir, char **err, enum bml_json_rule *rule)
{
	*err = NULL;
	if (rule)
		*rule = BML_JR_NONE;

	if (old_format(data, len)) {
		*err = strdup(ebpf_caps1_msg);
		return NULL;
	}

	struct bml_json *j;
	char *pe = NULL;
	if (bml_json_parse_ex(data, len, &rc_d_caps, 0, &j, &pe, rule)) {
		*err = rc_fmts("caps: json: %s", pe ? pe : "");
		free(pe);
		return NULL;
	}
	char *hf;
	size_t hn;
	if (peek_format(data, len, &hf, &hn) && !known_format(hf ? hf : "", hf ? hn : 0) && !BML_MUT("caps.format_unknown_late")) {
		*err = format_unknown_msg(hf, hn);
		free(hf);
		bml_json_free(j);
		if (rule)
			*rule = BML_JR_CAPS_FORMAT_UNKNOWN;
		return NULL;
	}
	free(hf);
	if (bml_json_validate(j, &rc_d_caps, &pe, rule)) {
		*err = rc_fmts("caps: %s", pe ? pe : "");
		free(pe);
		bml_json_free(j);
		return NULL;
	}
	struct bml_recorded *r = calloc(1, sizeof(*r));
	if (!r) {
		bml_json_free(j);
		*err = rc_fmts("out of memory");
		return NULL;
	}
	r->dir = strdup(dir ? dir : ".");
	if (j->type == BML_JSON_NULL) {
		*err = strdup("caps: format \"\", want " FORMATS);
		goto fail;
	}
	if (j->type != BML_JSON_OBJECT) {
		*err = rc_fmts("caps: json: cannot unmarshal into the caps (want an object)");
		goto fail;
	}
	static const char *const top[] = {"format", "probed_as", "loader", "queries", "privileged_queries"};
	if (rc_check_keys(j, top, 5, "the caps", err))
		goto fail;
	if (rc_get_str(j, "format", &r->format, err))
		goto fail;
	const struct bml_json *pa = bml_json_get(j, "probed_as");
	if (pa && pa->type != BML_JSON_NULL) {
		if (pa->type != BML_JSON_OBJECT) {
			*err = rc_fmts("caps: json: cannot unmarshal into probed_as");
			goto fail;
		}
		static const char *const pk[] = {"uid", "cap_eff"};
		if (rc_check_keys(pa, pk, 2, "probed_as", err))
			goto fail;
		const struct bml_json *uid = bml_json_get(pa, "uid");
		int64_t u = 0;
		if (uid && uid->type != BML_JSON_NULL && bml_json_int64(uid, &u)) {
			*err = rc_fmts("caps: json: cannot unmarshal into probed_as.uid of type int");
			goto fail;
		}
		char *ce = NULL;
		if (rc_get_str(pa, "cap_eff", &ce, err))
			goto fail;
		r->has_probed = 1;
		r->probed_uid = (long long)u;
		r->probed_cap = ce ? ce : strdup("");
	}
	const struct bml_json *ld = bml_json_get(j, "loader");
	int have_loader = 0;
	if (ld && ld->type != BML_JSON_NULL) {
		if (ld->type != BML_JSON_OBJECT) {
			*err = rc_fmts("caps: json: cannot unmarshal into loader");
			goto fail;
		}
		static const char *const lk[] = {"name",        "kprobe_alias_prefix", "uprobe_reopens_path", "core_poisons_missing_field", "btf_rewrite",
						 "usdt_attach", "sockmap_attach",      "lsm_cgroup_load",     "fsession_load",              "ksyscall_attach",
						 "hidden_data_vars", "typed_ksym", "kconfig", "arena_cast", "arena_premmap"};
		if (rc_check_keys(ld, lk, sizeof(lk) / sizeof(lk[0]), "loader", err))
			goto fail;
		int set;
		if (rc_get_str(ld, "name", &r->loader.name, err) ||
		    rc_get_kv(ld, "kprobe_alias_prefix", &r->loader.kprobe_alias_prefix, &r->loader.n_kprobe_alias_prefix, &r->loader.has_kprobe_alias_prefix, err) ||
		    rc_get_bool(ld, "uprobe_reopens_path", &set, &r->loader.uprobe_reopens_path, err) ||
		    rc_get_bool(ld, "core_poisons_missing_field", &set, &r->loader.core_poisons_missing_field, err) ||
		    rc_get_kv(ld, "btf_rewrite", &r->loader.btf_rewrite, &r->loader.n_btf_rewrite, &r->loader.has_btf_rewrite, err) ||
		    rc_get_str(ld, "usdt_attach", &r->loader.usdt_attach, err) || rc_get_str(ld, "sockmap_attach", &r->loader.sockmap_attach, err) ||
		    rc_get_str(ld, "lsm_cgroup_load", &r->loader.lsm_cgroup_load, err) || rc_get_str(ld, "fsession_load", &r->loader.fsession_load, err) ||
		    rc_get_str(ld, "ksyscall_attach", &r->loader.ksyscall_attach, err) ||
		    rc_get_str(ld, "hidden_data_vars", &r->loader.hidden_data_vars, err) || rc_get_str(ld, "typed_ksym", &r->loader.typed_ksym, err) ||
		    rc_get_str(ld, "kconfig", &r->loader.kconfig, err) || rc_get_str(ld, "arena_cast", &r->loader.arena_cast, err) ||
		    rc_get_str(ld, "arena_premmap", &r->loader.arena_premmap, err))
			goto fail;
		have_loader = 1;
	}
	if (decode_queries(bml_json_get(j, "queries"), "queries", r, 0, err))
		goto fail;

	const struct bml_json *pq = bml_json_get(j, "privileged_queries");
	int has_pq = pq && pq->type != BML_JSON_NULL;
	if (decode_queries(pq, "privileged_queries", r, 1, err))
		goto fail;

	if (r->format && !strcmp(r->format, "ebpf-caps 1")) {
		*err = strdup(ebpf_caps1_msg);
		goto fail;
	}

	if (r->n_q) /* CONTRACT: qsort with a NULL base is UB (even when n is 0) */
		qsort(r->q, r->n_q, sizeof *r->q, cmp_query);
	for (size_t i = 0; i < r->n_q; i++)
		if (r->q[i].n)
			qsort(r->q[i].e, r->q[i].n, sizeof *r->q[i].e, cmp_entry);
	int version = rc_format_version(r->format);
	int trc = rc_check_target_queries(r, j, version, err);
	if (trc) { if (trc > 0) goto newer; goto fail; }
	int v10 = version >= 10;
	int v9 = v10 || (r->format && !strcmp(r->format, BML_RECORDED_FORMAT_V9));
	int v8 = v9 || (r->format && !strcmp(r->format, BML_RECORDED_FORMAT_V8));
	int v7 = v8 || (r->format && !strcmp(r->format, BML_RECORDED_FORMAT_V7));
	int v6 = v7 || (r->format && !strcmp(r->format, BML_RECORDED_FORMAT_V6));
	int v5plus = v6 || (r->format && !strcmp(r->format, BML_RECORDED_FORMAT_V5));
	if (!r->format || (!v5plus && strcmp(r->format, BML_RECORDED_FORMAT_V4) != 0 && strcmp(r->format, BML_RECORDED_FORMAT_V3) != 0 &&
			   strcmp(r->format, BML_RECORDED_FORMAT_V2) != 0)) {
		*err = format_unknown_msg(r->format, r->format ? strlen(r->format) : 0);
		if (rule)
			*rule = BML_JR_CAPS_FORMAT_UNKNOWN;
		goto fail;
	}

	if (r->loader.usdt_attach && r->loader.usdt_attach[0] && !v7) {
		*err = rc_fmts("caps: loader key \"usdt_attach\" is new in \"" BML_RECORDED_FORMAT_V7 "\", but the format is \"%s\"", r->format);
		goto newer;
	}
	if (rc_added_loader_version(r, version, err)) goto newer;

	if (!v8) {
		const char *const nk[] = {"sockmap_attach", "lsm_cgroup_load", "fsession_load", "ksyscall_attach"};
		const char *const nv[] = {r->loader.sockmap_attach, r->loader.lsm_cgroup_load, r->loader.fsession_load, r->loader.ksyscall_attach};
		for (size_t k = 0; k < 4; k++)
			if (nv[k] && nv[k][0]) {
				*err = rc_fmts("caps: loader key \"%s\" is new in \"" BML_RECORDED_FORMAT_V8 "\", but the format is \"%s\"", nk[k], r->format);
				goto newer;
			}
	}

	static const char *const v9_queries[] = {BML_QUERY_KFUNC_LOADS, BML_QUERY_TRACEPOINT_BUFFER};
	if (!v9)
		for (size_t k = 0; k < 2; k++)
			for (size_t i = 0; i < r->n_q; i++)
				if (!strcmp(r->q[i].name, v9_queries[k])) {
					*err = rc_fmts("caps: query \"%s\" is new in \"" BML_RECORDED_FORMAT_V9 "\", but the format is \"%s\"", v9_queries[k], r->format);
					goto newer;
				}

	for (size_t i = 0; !v10 && i < r->n_q; i++)
		if (!strcmp(r->q[i].name, BML_QUERY_UPROBE_DEBUG)) {
			*err = rc_fmts("caps: query \"" BML_QUERY_UPROBE_DEBUG "\" is new in \"" BML_RECORDED_FORMAT_V10 "\", but the format is \"%s\"", r->format);
			goto newer;
		}
	if (rc_added_query_version(r, version, err)) goto newer;

	if (has_pq && !v6) {
		*err = rc_fmts("caps: privileged_queries is new in \"" BML_RECORDED_FORMAT_V6 "\", but the format is \"%s\"", r->format);
		goto newer;
	}
	if (v6) {
		for (size_t i = 0; i < r->n_q; i++)
			if (!r->q[i].priv && bml_caps_privilege_dependent(r->q[i].name)) {
				*err = rc_fmts("caps: query \"%s\" depends on the probing privilege — \"%s\" keeps it under privileged_queries", r->q[i].name,
					       r->format);
				goto fail;
			}
		for (size_t i = 0; i < r->n_q; i++)
			if (r->q[i].priv && !bml_caps_privilege_dependent(r->q[i].name)) {
				*err = rc_fmts("caps: query \"%s\" does not depend on the probing privilege — \"%s\" keeps it under queries", r->q[i].name,
					       r->format);
				goto fail;
			}
	}
	if (!strcmp(r->format, BML_RECORDED_FORMAT_V2))
		for (size_t i = 0; i < r->n_q; i++)
			if (!strcmp(r->q[i].name, BML_QUERY_FUNC_ARGS)) {
				*err = rc_fmts("caps: query \"func_args\" is new in \"" BML_RECORDED_FORMAT_V3 "\", but the format is \"" BML_RECORDED_FORMAT_V2 "\"");
				goto newer;
			}

	static const char *const v4_queries[] = {BML_QUERY_ATTACH_TYPE, BML_QUERY_ATTACH_TARGET, BML_QUERY_CTX_ACCESS};
	if (!v5plus && strcmp(r->format, BML_RECORDED_FORMAT_V4) != 0)
		for (size_t k = 0; k < sizeof v4_queries / sizeof *v4_queries; k++)
			for (size_t i = 0; i < r->n_q; i++)
				if (!strcmp(r->q[i].name, v4_queries[k])) {
					*err = rc_fmts("caps: query \"%s\" is new in \"" BML_RECORDED_FORMAT_V4 "\", but the format is \"%s\"", v4_queries[k],
						       r->format);
					goto newer;
				}

	static const char *const v5_queries[] = {BML_QUERY_TP_FIELDS, BML_QUERY_STRUCT_OPS_MEMBERS, BML_QUERY_EXT_TARGETS};
	if (!v5plus)
		for (size_t k = 0; k < sizeof v5_queries / sizeof *v5_queries; k++)
			for (size_t i = 0; i < r->n_q; i++)
				if (!strcmp(r->q[i].name, v5_queries[k])) {
					*err = rc_fmts("caps: query \"%s\" is new in \"" BML_RECORDED_FORMAT_V5 "\", but the format is \"%s\"", v5_queries[k],
						       r->format);
					goto newer;
				}

	static const char *const v8_queries[] = {BML_QUERY_KFUNC_PROTOS, BML_QUERY_SYSCALL_ARGS};
	if (!v8)
		for (size_t k = 0; k < 2; k++)
			for (size_t i = 0; i < r->n_q; i++)
				if (!strcmp(r->q[i].name, v8_queries[k])) {
					*err = rc_fmts("caps: query \"%s\" is new in \"" BML_RECORDED_FORMAT_V8 "\", but the format is \"%s\"", v8_queries[k], r->format);
					goto newer;
				}
	if (!have_loader || !r->loader.name || !r->loader.name[0]) {
		*err = rc_fmts("caps: no loader declaration (a recorded target is judged for a named loader)");
		goto fail;
	}
	char *ve = NULL;
	if (bml_loader_decl_validate(&r->loader, &ve)) {
		*err = rc_fmts("caps: %s", ve ? ve : "");
		free(ve);
		goto fail;
	}
	for (size_t i = 0; i < r->n_q; i++) {
		int ok = 0;
		for (size_t k = 0; k < sizeof(known_queries) / sizeof(known_queries[0]); k++)
			if (!strcmp(r->q[i].name, known_queries[k]))
				ok = 1;
		if (!ok) {
			*err = rc_fmts("caps: unknown query \"%s\"", r->q[i].name);
			goto fail;
		}
	}
	static const char *const required[] = {BML_QUERY_PROG_TYPE, BML_QUERY_HELPER, BML_QUERY_MAP_TYPE};
	for (size_t k = 0; k < 3; k++) {
		int found = 0;
		for (size_t i = 0; i < r->n_q; i++)
			if (!strcmp(r->q[i].name, required[k]))
				found = 1;
		if (!found) {
			*err = rc_fmts("caps: query \"%s\" is required", required[k]);
			goto fail;
		}
	}
	for (size_t i = 0; i < r->n_q; i++) {
		for (size_t k = 0; k < r->q[i].n; k++) {
			const struct answer *a = &r->q[i].e[k].a;
			int n = !!a->has_value + !!a->unknown + !!a->error + !!a->has_diffs + !!a->text + !!a->file;
			if (n != 1) {
				*err = rc_fmts("caps: %s[\"%s\"]: an answer has exactly one of value / unknown / error / diffs / text / rewrites / file",
					    r->q[i].name, r->q[i].e[k].key);
				goto fail;
			}
			if (!strcmp(r->q[i].name, BML_QUERY_UPROBE_DEBUG) && !a->file && !a->unknown && !a->error) {
				*err = rc_fmts("caps: %s[\"%s\"]: an answer has exactly one of file / unknown / error", r->q[i].name, r->q[i].e[k].key);
				goto fail;
			}
		}
	}
	bml_json_free(j);
	return r;
newer:
	if (rule)
		*rule = BML_JR_CAPS_KEY_NEWER_FORMAT;
fail:
	bml_json_free(j);
	bml_recorded_free(r);
	if (!*err)
		*err = rc_fmts("out of memory");
	return NULL;
}

struct bml_recorded *bml_recorded_read(const char *path, char **err)
{
	*err = NULL;
	FILE *f = fopen(path, "rb");
	if (!f) {
		char *es = bml_go_errno_str(errno);
		*err = rc_fmts("open %s: %s", path, es ? es : "");
		free(es);
		return NULL;
	}
	struct bml_buf b = {0};
	char tmp[65536];
	size_t n;
	while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
		bml_buf_add(&b, tmp, n);
	fclose(f);
	char *dir = strdup(path);
	char *slash = dir ? strrchr(dir, '/') : NULL;
	if (slash)
		*slash = 0;
	struct bml_recorded *r = bml_recorded_parse(b.p ? b.p : "", b.len, slash ? dir : ".", err);
	if (!r && *err) {
		char *e2 = rc_fmts("%s: %s", path, *err);
		free(*err);
		*err = e2;
	}
	free(dir);
	bml_buf_free(&b);
	return r;
}
int bml_recorded_probed_as(const struct bml_recorded *r, long long *uid, char **cap)
{
	if (!r->has_probed)
		return 0;
	*uid = r->probed_uid;
	*cap = strdup(r->probed_cap ? r->probed_cap : "");
	return 1;
}

struct bml_recorded *bml_recorded_parse(const char *data, size_t len, const char *dir, char **err)
{
	return bml_recorded_parse_rule(data, len, dir, err, NULL);
}
