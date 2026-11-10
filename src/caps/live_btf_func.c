



#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"

#define ERR_UNKNOWN "cannot be determined on this target"


static int unknown(char **msg, const char *fmt, const char *a, const char *b)
{
	struct bml_buf m = {0};
	bml_buf_addf(&m, fmt, a, b ? b : "");
	bml_buf_adds(&m, ": " ERR_UNKNOWN);
	*msg = bml_buf_take(&m);
	return BML_Q_UNKNOWN;
}


static int func_proto(struct bml_live *l, const char *name, const struct bml_kbtf **kb, struct kbtf_type *fp, struct bml_strs *out, char **msg)
{
	const char *verr;
	*kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!*kb)
		return unknown(msg, "target BTF: %s%s", verr ? verr : "", NULL);
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(*kb, name, KBTF_FUNC, &id, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	if (rc) {
		rc = unknown(msg, "kernel function %s has no FUNC in the target BTF (%s)", name, err);
		free(err);
		return rc;
	}
	struct kbtf_type fn;
	bml_kbtf_type(*kb, id, &fn);
	bml_kbtf_type(*kb, fn.size_type, fp);
	if (fp->kind != KBTF_FUNC_PROTO)
		return unknown(msg, "kernel function %s has no FUNC_PROTO%s", name, NULL);
	return -1;
}

int bml_live_func_btf_id(struct bml_live *l, const char *name, uint32_t *id, char **err)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	*err = NULL;
	if (!kb) {
		*err = strdup(verr ? verr : "no target BTF");
		return -1;
	}
	int rc = lv_lookup(kb, name, KBTF_FUNC, id, err);
	if (rc < 0 && !*err)
		*err = strdup("out of memory");
	return rc ? -1 : 0;
}


const char *bml_arg_name(const char *n)
{
	return n && n[0] ? n : "unnamed";
}


static void describe_param(const struct bml_kbtf *kb, struct bml_buf *b, uint32_t type)
{
	int cyc;
	uint32_t u = bml_kbtf_underlying(kb, type, &cyc);
	struct kbtf_type t;
	bml_kbtf_type(kb, u, &t);
	char s[32];
	if (!cyc && t.kind == KBTF_INT) {
		lv_int_spell(kb, &t, s, sizeof s);
		bml_buf_adds(b, s);
	} else if (!cyc && t.kind == KBTF_PTR)
		bml_buf_adds(b, "ptr");
	else if (!cyc && (t.kind == KBTF_ENUM || t.kind == KBTF_ENUM64))
		bml_buf_addf(b, "enum%u", (uint32_t)(t.size_type * 8u));
	else
		bml_kbtf_gotype(kb, b, u, cyc);
}

static int is_int_spelling(const char *s)
{
	static const char *const k[] = {"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"};
	for (size_t i = 0; i < sizeof k / sizeof *k; i++)
		if (!strcmp(s, k[i]))
			return 1;
	return 0;
}


int lv_compare_proto(const struct bml_kbtf *kb, const struct kbtf_type *fp, const char *what, int64_t nargs, const char *ret,
		     const struct bml_str *args, size_t n_args, struct bml_strs *out)
{
	struct bml_buf b = {0};
	if (nargs >= 0 && (int64_t)fp->vlen != nargs) {
		bml_buf_addf(&b, "%s takes %u arguments in the target BTF, but the object declares %lld", what, fp->vlen, (long long)nargs);
		if (lv_push(out, &b))
			return -1;
	}
	if (ret[0]) {
		int cyc;
		uint32_t u = bml_kbtf_underlying(kb, fp->size_type, &cyc);
		struct bml_buf got = {0};
		if (fp->size_type == 0 || (!cyc && u == 0))
			bml_buf_adds(&got, "void");
		else
			describe_param(kb, &got, fp->size_type);
		char *g = bml_buf_take(&got);
		if (!g)
			return -1;
		if (strcmp(g, ret) != 0) {
			bml_buf_addf(&b, "%s returns %s in the target BTF, but the object declares %s", what, g, ret);
			if (lv_push(out, &b)) {
				free(g);
				return -1;
			}
		}
		free(g);
	}
	for (size_t i = 0; i < n_args; i++) {
		const char *want = args[i].p;
		if (!strcmp(want, "-"))
			continue;
		if (i >= fp->vlen) {
			bml_buf_addf(&b, "%s has no argument %zu in the target BTF (it takes %u)", what, i, fp->vlen);
		} else {
			const char *pn;
			uint32_t pt;
			int cyc;
			bml_kbtf_param(kb, fp, (uint32_t)i, &pn, &pt);
			if (!strncmp(want, "enum:", 5) || is_int_spelling(want)) {
				struct bml_buf got = {0};
				describe_param(kb, &got, pt);
				char *g = bml_buf_take(&got);
				if (!g)
					return -1;
				char enum_want[24];
				if (!strncmp(want, "enum:", 5)) snprintf(enum_want, sizeof(enum_want), "enum%s", want + 5);
				if (strcmp(g, !strncmp(want, "enum:", 5) ? enum_want : want) != 0)
					bml_buf_addf(&b, "argument %zu (%s) of %s is %s in the target BTF, but the object reads it as %s", i, bml_arg_name(pn), what, g,
						     want);
				free(g);
			} else {
				struct kbtf_type p;
				bml_kbtf_type(kb, bml_kbtf_underlying(kb, pt, &cyc), &p);
				if (cyc || p.kind != KBTF_PTR) {
					bml_buf_addf(&b, "argument %zu (%s) of %s is ", i, bml_arg_name(pn), what);
					describe_param(kb, &b, pt);
					bml_buf_addf(&b, " in the target BTF, not a pointer to struct %s", want);
				} else {
					struct kbtf_type st;
					bml_kbtf_type(kb, bml_kbtf_underlying(kb, p.size_type, &cyc), &st);
					if (cyc || st.kind != KBTF_STRUCT || strcmp(st.name, want) != 0) {
						bml_buf_addf(&b, "argument %zu (%s) of %s points to ", i, bml_arg_name(pn), what);
						bml_kbtf_format(kb, &b, p.size_type, 0, 's');
						bml_buf_addf(&b, " in the target BTF, not struct %s", want);
					}
				}
			}
		}
		if (b.len && lv_push(out, &b))
			return -1;
	}
	bml_buf_free(&b);
	return 0;
}


int bml_live_struct_ops_member(struct bml_live *l, const char *strct, const char *member, int64_t nargs, const char *ret, const struct bml_str *args,
			       size_t n_args, struct bml_strs *out, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!kb)
		return unknown(msg, "reading the target BTF failed (%s)%s", verr ? verr : "", NULL);
	uint32_t id;
	char *err = NULL;
	char *vname = NULL;
	if (asprintf(&vname, "bpf_struct_ops_%s", strct) < 0)
		return lv_oom(out, msg);
	int rc = lv_lookup(kb, vname, KBTF_STRUCT, &id, &err);
	free(vname);
	if (rc < 0)
		return lv_oom(out, msg);
	if (rc) {
		struct bml_buf m = {0};
		bml_buf_addf(&m, "bpf_struct_ops_%s is not in vmlinux BTF (%s) — a module struct_ops is not checked: " ERR_UNKNOWN, strct, err ? err : "");
		free(err);
		*msg = bml_buf_take(&m);
		return BML_Q_UNKNOWN;
	}
	rc = lv_lookup(kb, strct, KBTF_STRUCT, &id, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	if (rc) {
		rc = unknown(msg, "struct %s is not in vmlinux BTF (%s)", strct, err);
		free(err);
		return rc;
	}
	struct kbtf_type st;
	bml_kbtf_type(kb, id, &st);
	struct bml_buf b = {0};
	for (uint32_t i = 0; i < st.vlen; i++) {
		struct kbtf_member m;
		bml_kbtf_member(kb, &st, i, &m);
		if (strcmp(m.name, member) != 0)
			continue;
		int cyc;
		struct kbtf_type pt, proto;
		bml_kbtf_type(kb, bml_kbtf_underlying(kb, m.type, &cyc), &pt);
		if (cyc || pt.kind != KBTF_PTR) {
			bml_buf_addf(&b, "member %s of struct %s is ", member, strct);
			describe_param(kb, &b, m.type);
			bml_buf_adds(&b, " in the target BTF, not a function pointer");
			return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
		}
		bml_kbtf_type(kb, bml_kbtf_underlying(kb, pt.size_type, &cyc), &proto);
		if (cyc || proto.kind != KBTF_FUNC_PROTO) {
			bml_buf_addf(&b, "member %s of struct %s points to ", member, strct);
			bml_kbtf_format(kb, &b, pt.size_type, 0, 's');
			bml_buf_adds(&b, " in the target BTF, not a function");
			return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
		}
		char *what = NULL;
		if (asprintf(&what, "struct_ops member %s.%s", strct, member) < 0)
			return lv_oom(out, msg);
		rc = lv_compare_proto(kb, &proto, what, nargs, ret, args, n_args, out);
		free(what);
		return rc ? lv_oom(out, msg) : BML_Q_OK;
	}
	bml_buf_addf(&b, "struct %s has no member %s in the target BTF", strct, member);
	return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
}

int bml_live_func_param(struct bml_live *l, const char *name, int64_t n, const char *type, struct bml_strs *out, char **msg)
{
	const struct bml_kbtf *kb;
	struct kbtf_type fp;
	int rc = func_proto(l, name, &kb, &fp, out, msg);
	if (rc >= 0)
		return rc;
	struct bml_buf b = {0};
	if (n < 1) {
		*msg = strdup("kprobearg index below 1");
		return BML_Q_ERROR;
	}
	if (n > (int64_t)fp.vlen) {
		bml_buf_addf(&b, "kernel function %s takes %u arguments in the target BTF, but the object reads argument %lld", name, fp.vlen,
			     (long long)n);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	const char *pn;
	uint32_t pt;
	bml_kbtf_param(kb, &fp, (uint32_t)(n - 1), &pn, &pt);
	struct bml_buf got = {0};
	describe_param(kb, &got, pt);
	char *g = bml_buf_take(&got);
	if (!g)
		return lv_oom(out, msg);
	if (strcmp(g, type) != 0) {
		bml_buf_addf(&b, "argument %lld (%s) of kernel function %s is %s in the target BTF, but the object reads it as %s", (long long)n,
			     bml_arg_name(pn), name, g, type);
		if (lv_push(out, &b)) {
			free(g);
			return lv_oom(out, msg);
		}
	}
	free(g);
	return BML_Q_OK;
}

int bml_live_func_args(struct bml_live *l, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out, char **msg)
{
	const struct bml_kbtf *kb;
	struct kbtf_type fp;
	int rc = func_proto(l, name, &kb, &fp, out, msg);
	if (rc >= 0)
		return rc;
	struct bml_buf b = {0};
	if (n_args > fp.vlen) {
		bml_buf_addf(&b, "kernel function %s takes %u arguments in the target BTF, but the object declares %zu", name, fp.vlen, n_args);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	for (size_t i = 0; i < n_args; i++) {
		if (!strcmp(args[i].p, "-"))
			continue;
		const char *pn;
		uint32_t pt;
		int cyc;
		bml_kbtf_param(kb, &fp, (uint32_t)i, &pn, &pt);
		struct kbtf_type p;
		bml_kbtf_type(kb, bml_kbtf_underlying(kb, pt, &cyc), &p);
		if (cyc || p.kind != KBTF_PTR) {
			bml_buf_addf(&b, "argument %zu (%s) of kernel function %s is ", i, bml_arg_name(pn), name);
			describe_param(kb, &b, pt);
			bml_buf_addf(&b, " in the target BTF, not a pointer to struct %s", args[i].p);
		} else {
			struct kbtf_type st;
			bml_kbtf_type(kb, bml_kbtf_underlying(kb, p.size_type, &cyc), &st);
			if (cyc || st.kind != KBTF_STRUCT || strcmp(st.name, args[i].p) != 0) {
				bml_buf_addf(&b, "argument %zu (%s) of kernel function %s points to ", i, bml_arg_name(pn), name);
				bml_kbtf_format(kb, &b, p.size_type, 0, 's');
				bml_buf_addf(&b, " in the target BTF, not struct %s", args[i].p);
			}
		}
		if (b.len && lv_push(out, &b))
			return lv_oom(out, msg);
	}
	bml_buf_free(&b);
	return BML_Q_OK;
}
