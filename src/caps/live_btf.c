#include "caps/live_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"
#include "btf/kernel_values.h"
#include "caps/value_sources.h"

void bml_live_free(struct bml_live *l)
{
	lv_value_sources_free(l);
	free(l->kb_err);
	if (l->kb_done && l->kb_rc == 0)
		bml_kbtf_free(&l->kb);
	free(l->helpers);
	for (size_t i = 0; i < l->n_memo; i++)
		free(l->memo[i].key), free(l->memo[i].msg);
	free(l->memo);
	memset(l, 0, sizeof *l);
}


int lv_vmlinux(struct bml_live *l, const struct bml_kbtf **kb)
{
	if (!l->kb_done) {
		l->kb_done = 1;
		l->kb_rc = bml_kbtf_load_kernel(&l->kb, &l->kb_err);
		if (l->kb_rc != 0 && !l->kb_err)
			l->kb_err = strdup("load vmlinux failed");
	}
	*kb = l->kb_rc == 0 ? &l->kb : NULL;
	return l->kb_rc;
}

const struct bml_kbtf *lv_kb(struct bml_live *l, const char **err)
{
	const struct bml_kbtf *kb;
	lv_vmlinux(l, &kb);
	*err = l->kb_err;
	return kb;
}

int lv_msg(char **msg, int rc, const char *prefix, const char *err)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s%s", prefix, err ? err : "");
	*msg = bml_buf_take(&b);
	return rc;
}


int lv_push(struct bml_strs *out, struct bml_buf *b)
{
	char *s = bml_buf_take(b);
	char **nw = s ? realloc(out->s, (out->n + 1) * sizeof *out->s) : NULL;
	if (!nw) {
		free(s);
		return -1;
	}
	out->s = nw;
	out->s[out->n++] = s;
	return 0;
}

int lv_oom(struct bml_strs *out, char **msg)
{
	bml_strs_free(out);
	*msg = strdup("out of memory");
	return BML_Q_ERROR;
}


void lv_int_spell(const struct bml_kbtf *kb, const struct kbtf_type *t, char *dst, size_t n)
{
	int sgn = (bml_kbtf_u32(kb, t->aux) >> 24 & 0xf) & 1;
	snprintf(dst, n, "%c%u", sgn ? 'i' : 'u', (uint32_t)(t->size_type * 8u));
}


int lv_lookup(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t *id, char **err)
{
	*err = NULL;
	size_t n = bml_kbtf_exact_kind(kb, name, kind, 1, id);
	if (n == 1 || (n && BML_MUT("live.name_first_match"))) return 0;
	struct bml_buf b = {0};
	if (!n) bml_buf_adds(&b, "not found");
	else bml_buf_addf(&b, "type %s(*btf.%s): multiple matching types", name, bml_kbtf_goname(kind));
	*err = bml_buf_take(&b);
	return *err ? (n ? 2 : 1) : -1;
}

int bml_live_func(struct bml_live *l, const char *name, struct bml_strs *out, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!kb)
		return lv_msg(msg, BML_Q_ERROR, "target BTF: ", verr);
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(kb, name, KBTF_FUNC, &id, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	struct bml_buf b = {0};
	if (rc == 1)
		bml_buf_addf(&b, "kernel function %s is not in the target BTF (fentry needs a BTF FUNC to attach to)", name);
	else if (rc == 2)
		bml_buf_addf(&b, "kernel function %s: %s", name, err);
	free(err);
	if (rc && lv_push(out, &b))
		return lv_oom(out, msg);
	return BML_Q_OK;
}

int bml_live_func_sig(struct bml_live *l, const char *name, int64_t nargs, const char *ret, struct bml_strs *out, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!kb)
		return lv_msg(msg, BML_Q_ERROR, "target BTF: ", verr);
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(kb, name, KBTF_FUNC, &id, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	struct bml_buf b = {0};
	if (rc) {
		if (rc == 1)
			bml_buf_addf(&b, "kernel function %s is not in the target BTF (fexit needs a BTF FUNC to attach to)", name);
		else
			bml_buf_addf(&b, "kernel function %s: %s", name, err);
		free(err);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	struct kbtf_type fn, fp;
	bml_kbtf_type(kb, id, &fn);
	bml_kbtf_type(kb, fn.size_type, &fp);
	if (fp.kind != KBTF_FUNC_PROTO) {
		bml_buf_addf(&b, "kernel function %s has no FUNC_PROTO", name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	if ((int64_t)fp.vlen != nargs) {
		bml_buf_addf(&b, "kernel function %s takes %u arguments in the target BTF, but the object reads its return value after %lld (fexit's return slot is after the arguments)",
			     name, fp.vlen, (long long)nargs);
		if (lv_push(out, &b))
			return lv_oom(out, msg);
	}
	int cyc;
	struct kbtf_type rt;
	bml_kbtf_type(kb, bml_kbtf_underlying(kb, fp.size_type, &cyc), &rt);
	if (cyc || rt.kind != KBTF_INT)
		bml_buf_addf(&b, "kernel function %s does not return an integer in the target BTF (the object reads %s)", name, ret);
	else {
		char got[32];
		lv_int_spell(kb, &rt, got, sizeof got);
		if (strcmp(got, ret) != 0)
			bml_buf_addf(&b, "kernel function %s returns %s in the target BTF, but the object reads %s", name, got, ret);
	}
	if (b.len && lv_push(out, &b))
		return lv_oom(out, msg);
	bml_buf_free(&b);
	return BML_Q_OK;
}


static int is_int_spelling(const char *s)
{
	static const char *const ok[] = {"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"};
	for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++)
		if (!strcmp(s, ok[i]))
			return 1;
	return 0;
}

int bml_live_tracepoint(struct bml_live *l, const char *name, const struct bml_str *args, size_t n_args, struct bml_strs *out,
			char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!kb)
		return lv_msg(msg, BML_Q_ERROR, "target BTF: ", verr);
	struct bml_buf b = {0}, tn = {0};
	bml_buf_addf(&tn, "btf_trace_%s", name);
	char *tname = bml_buf_take(&tn);
	if (!tname)
		return lv_oom(out, msg);
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(kb, tname, KBTF_TYPEDEF, &id, &err);
	free(tname);
	if (rc < 0)
		return lv_oom(out, msg);
	if (rc) {
		bml_buf_addf(&b, "tracepoint %s: the target has no btf_trace_%s (%s)", name, name, err);
		free(err);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	struct kbtf_type td, ptr, fp;
	bml_kbtf_type(kb, id, &td);
	bml_kbtf_type(kb, td.size_type, &ptr);
	if (ptr.kind != KBTF_PTR) {
		bml_buf_addf(&b, "tracepoint %s: btf_trace_%s is not a function pointer", name, name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	bml_kbtf_type(kb, ptr.size_type, &fp);
	if (fp.kind != KBTF_FUNC_PROTO) {
		bml_buf_addf(&b, "tracepoint %s: btf_trace_%s does not point to a function prototype", name, name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}

	if (fp.vlen == 0) {
		bml_buf_addf(&b, "tracepoint %s: the prototype has no parameters", name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	if (n_args > fp.vlen - 1) {
		bml_buf_addf(&b, "tracepoint %s: the program declares %zu arguments but the target passes %u", name, n_args, fp.vlen - 1);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	for (size_t i = 0; i < n_args; i++) {
		const char *pn;
		uint32_t pt;
		int cyc;
		if (!strcmp(args[i].p, "-"))
			continue;
		bml_kbtf_param(kb, &fp, (uint32_t)i + 1, &pn, &pt);
		struct kbtf_type p;
		uint32_t pu = bml_kbtf_underlying(kb, pt, &cyc);
		bml_kbtf_type(kb, pu, &p);
		if (is_int_spelling(args[i].p)) {
			if (cyc || p.kind != KBTF_INT) {
				bml_buf_addf(&b, "tracepoint %s: argument %zu is ", name, i);
				bml_kbtf_format(kb, &b, pt, 0, 's');
				bml_buf_addf(&b, ", not an integer %s", args[i].p);
			} else {
				char got[32];
				lv_int_spell(kb, &p, got, sizeof got);
				if (strcmp(got, args[i].p) != 0)
					bml_buf_addf(&b, "tracepoint %s: argument %zu is %s (%s), not %s", name, i, got, p.name, args[i].p);
			}
		} else if (cyc || p.kind != KBTF_PTR) {
			bml_buf_addf(&b, "tracepoint %s: argument %zu is ", name, i);
			bml_kbtf_format(kb, &b, pt, 0, 's');
			bml_buf_addf(&b, ", not a pointer to struct %s", args[i].p);
		} else {
			struct kbtf_type st;
			uint32_t su = bml_kbtf_underlying(kb, p.size_type, &cyc);
			bml_kbtf_type(kb, su, &st);
			if (cyc || st.kind != KBTF_STRUCT || strcmp(st.name, args[i].p) != 0) {
				bml_buf_addf(&b, "tracepoint %s: argument %zu points to ", name, i);
				bml_kbtf_format(kb, &b, p.size_type, 0, 's');
				bml_buf_addf(&b, ", not struct %s", args[i].p);
			}
		}
		if (b.len && lv_push(out, &b))
			return lv_oom(out, msg);
	}
	bml_buf_free(&b);
	return BML_Q_OK;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}



int bml_live_kfields(struct bml_live *l, const struct bml_kfield *kf, size_t n, struct bml_strs *out, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!kb)
		return lv_msg(msg, BML_Q_ERROR, "target BTF: ", verr);
	for (size_t i = 0; i < n; i++) {
		const struct bml_kfield *k = &kf[i];
		struct bml_buf b = {0};
		bml_buf_addf(&b, "program %s reads %s.%s as %s: ", k->program.p, k->strct.p, k->field.p, k->type.p);
		uint32_t id;
		char *err = NULL;
		int rc = lv_lookup(kb, k->strct.p, KBTF_STRUCT, &id, &err);
		if (rc < 0) {
			bml_buf_free(&b);
			return lv_oom(out, msg);
		}
		if (rc) {
			bml_buf_addf(&b, "the target has no struct %s (%s)", k->strct.p, err);
			free(err);
			if (lv_push(out, &b))
				return lv_oom(out, msg);
			continue;
		}
		struct kbtf_member mb = {0};
		int twice = 0;
		int found = lv_find_member_path(kb, id, k->field.p, &mb, &twice);
		if (found == -1) {
			bml_buf_free(&b);
			return lv_oom(out, msg);
		}
		int cyc = 0;
		struct kbtf_type ft = {0};
		if (found)
			bml_kbtf_type(kb, bml_kbtf_underlying(kb, mb.type, &cyc), &ft);
		if (!found)
			bml_buf_addf(&b, "the target struct %s has no field %s%s", k->strct.p, k->field.p,
				     twice ? " (the member search met the same anonymous type twice — nested in a cycle or shared)" : "");
		else if (!strncmp(k->type.p, "struct:", 7)) {
			if (!lv_kfield_embedded(kb, &mb, k->type.p + 7, &b)) {
				bml_buf_free(&b);
				continue;
			}
		} else if (!strncmp(k->type.p, "ptr:", 4) || !strcmp(k->type.p, "strptr")) {

			int sp = k->type.p[0] == 's';
			if (cyc || ft.kind != KBTF_PTR) {
				bml_buf_adds(&b, "the target field is ");
				bml_kbtf_format(kb, &b, mb.type, 0, 's');
				bml_buf_adds(&b, ", not a pointer");
			} else {
				int c2;
				struct kbtf_type pt;
				bml_kbtf_type(kb, bml_kbtf_underlying(kb, ft.size_type, &c2), &pt);
				int vp = !strcmp(k->type.p, "ptr:void");
				if (sp ? (c2 || pt.kind != KBTF_INT || pt.size_type != 1) : vp ? (c2 || pt.kind != KBTF_UNKN) : (c2 || pt.kind != KBTF_STRUCT || strcmp(pt.name, k->type.p + 4) != 0)) {
					bml_buf_adds(&b, "the target field points to ");
					bml_kbtf_format(kb, &b, ft.size_type, 0, 's');
					if (sp)
						bml_buf_adds(&b, ", not a 1-byte integer (char)");
					else if (vp) bml_buf_adds(&b, ", not void");
					else
						bml_buf_addf(&b, ", not struct %s", k->type.p + 4);
				} else {
					bml_buf_free(&b);
					continue;
				}
			}
		} else if (k->type.p[0] == '[') {
			int64_t want = 0;
			const char *rb = strchr(k->type.p, ']');
			bml_go_atoi(k->type.p + 1, rb ? (size_t)(rb - k->type.p - 1) : 0, &want);
			if (cyc || ft.kind != KBTF_ARRAY) {
				bml_buf_adds(&b, "the target field is ");
				bml_kbtf_format(kb, &b, mb.type, 0, 's');
				bml_buf_adds(&b, ", not an array");
			} else {
				int c2;
				uint32_t el = bml_kbtf_u32(kb, ft.aux), ne = bml_kbtf_u32(kb, ft.aux + 8);
				struct kbtf_type et;
				bml_kbtf_type(kb, bml_kbtf_underlying(kb, el, &c2), &et);
				if (c2 || et.kind != KBTF_INT || et.size_type != 1) {
					bml_buf_adds(&b, "the target array's element is ");
					bml_kbtf_format(kb, &b, el, 0, 's');
					bml_buf_adds(&b, ", not a 1-byte integer");
				} else if ((int64_t)ne != want)
					bml_buf_addf(&b, "the target array has %u elements", ne);
				else {
					bml_buf_free(&b);
					continue;
				}
			}
		} else if (mb.bitfield_size != 0)
			bml_buf_addf(&b, "the target field is a bitfield (%u bits)", mb.bitfield_size);
		else if (!strncmp(k->type.p, "enum:", 5)) {
			int bits = atoi(k->type.p + 5);
			if (cyc || (ft.kind != KBTF_ENUM && ft.kind != KBTF_ENUM64)) {
				bml_buf_adds(&b, "the target field is "); bml_kbtf_format(kb, &b, mb.type, 0, 's'); bml_buf_adds(&b, ", not an enum");
			} else if (ft.size_type * 8u != (unsigned)bits) bml_buf_addf(&b, "the target field is a %u-bit enum (%s)", ft.size_type * 8u, ft.name);
			else { bml_buf_free(&b); continue; }
		}
		else {
			int cyc;
			struct kbtf_type it;
			bml_kbtf_type(kb, bml_kbtf_underlying(kb, mb.type, &cyc), &it);
			if (cyc || it.kind != KBTF_INT) {
				bml_buf_adds(&b, "the target field is ");
				bml_kbtf_format(kb, &b, mb.type, 0, 's');
				bml_buf_adds(&b, ", not an integer");
			} else {
				char got[32];
				lv_int_spell(kb, &it, got, sizeof got);
				if (strcmp(got, k->type.p) == 0) {
					bml_buf_free(&b);
					continue;
				}
				bml_buf_addf(&b, "the target field is %s (%s)", got, it.name);
			}
		}
		if (lv_push(out, &b))
			return lv_oom(out, msg);
	}
	if (out->n > 1)
		qsort(out->s, out->n, sizeof *out->s, cmp_str);
	return BML_Q_OK;
}

int bml_live_struct_field(struct bml_live *l, const char *st, const char *field, int64_t offset, int64_t size,
			  struct bml_strs *out, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	memset(out, 0, sizeof *out);
	if (!kb)
		return lv_msg(msg, BML_Q_UNKNOWN, "target BTF: ", verr);
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(kb, st, KBTF_STRUCT, &id, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	struct bml_buf b = {0};
	if (rc) {
		if (rc == 1)
			bml_buf_addf(&b, "struct %s is not in the target BTF", st);
		else
			bml_buf_addf(&b, "struct %s: %s", st, err);
		free(err);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	for (uint32_t j = 0; j < t.vlen; j++) {
		struct kbtf_member m;
		bml_kbtf_member(kb, &t, j, &m);
		if (strcmp(m.name, field) != 0)
			continue;
		int64_t sz;
		if (m.bitfield_size != 0 || m.offset % 8 != 0)
			bml_buf_addf(&b, "%s.%s is a bitfield in the target BTF", st, field);
		else if (bml_kbtf_sizeof(kb, m.type, &sz, &err) != 0) {
			bml_buf_addf(&b, "%s.%s: %s", st, field, err);
			free(err);
		} else if ((int64_t)(m.offset / 8) != offset || sz != size)
			bml_buf_addf(&b, "%s.%s is at offset %u with %lld bytes in the target BTF, but the object reads offset %lld with %lld bytes",
				     st, field, m.offset / 8, (long long)sz, (long long)offset, (long long)size);
		if (b.len && lv_push(out, &b))
			return lv_oom(out, msg);
		bml_buf_free(&b);
		return BML_Q_OK;
	}
	bml_buf_addf(&b, "%s has no member %s in the target BTF", st, field);
	return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
}

