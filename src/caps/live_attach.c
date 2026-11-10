







#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btf/kernel.h"
#include "util/gostr.h"

#define UNK ": cannot be determined on this target"

char *lv_res_text(const struct lv_res *r)
{
	if (r->text)
		return strdup(r->text);
	struct bml_buf b = {0};
	bml_buf_adds(&b, "load program: ");
	if (r->cause == 1)
		bml_buf_adds(&b, "bad CO-RE relocation");
	else if (r->cause == 2)
		bml_buf_adds(&b, "unknown kfunc");
	else {
		char *e = bml_go_errno_str(r->err);
		bml_buf_adds(&b, e ? e : "");
		free(e);
	}
	if (!r->verifier) {
		if (r->suffix)
			bml_buf_adds(&b, r->suffix);
		return bml_buf_take(&b);
	}

	size_t n = r->n_lines;
	if (n > 0 && !strncmp(r->lines[n - 1], "processed ", 10))
		n--;
	if (n == 0)
		return bml_buf_take(&b);
	size_t from = n - 1;
	const char *last = r->lines[n - 1];
	if (n >= 2 && (last[0] == '\t' || (last[0] == 'R' && last[1] >= '0' && last[1] <= '9') ||
		       !strncmp(last, "invalid bpf_context access", 26)))
		from = n - 2;
	for (size_t i = from; i < n; i++) {
		const char *s = r->lines[i];
		size_t l = strlen(s);
		while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' || *s == '\v' || *s == '\f')
			s++, l--;
		while (l && (s[l - 1] == ' ' || s[l - 1] == '\t' || s[l - 1] == '\n' || s[l - 1] == '\r' || s[l - 1] == '\v' || s[l - 1] == '\f'))
			l--;
		bml_buf_adds(&b, ": ");
		bml_buf_add(&b, s, l);
	}
	size_t omitted = r->n_lines - (n - from);
	if (omitted > 0)
		bml_buf_addf(&b, " (%zu line(s) omitted)", omitted);
	return bml_buf_take(&b);
}


struct outcome {
	int accepted, verifier, einval;
	char *text;
};

static void probe_load(struct bml_live *l, uint32_t pt, uint32_t at, const uint8_t *ins, size_t n, struct outcome *o)
{
	struct lv_prog p = {0};
	struct lv_res r;
	p.type = pt;
	p.attach_type = at;
	p.insns = ins;
	p.n_insns = n;
	p.license = "GPL";
	p.name = "ebpf_probe";
	p.log_mode = LV_LOG_0;
	memset(o, 0, sizeof *o);
	if (lv_prog_load(l, &p, &r) == 0) {
		lv_close(r.fd);
		o->accepted = 1;
		o->text = strdup("accept");
		return;
	}
	o->verifier = r.verifier;
	o->einval = r.err == EINVAL;
	o->text = lv_res_text(&r);
	lv_res_free(&r);
}

static int is_btf_attach_type(int64_t pt)
{
	return pt == BPF_PROG_TYPE_TRACING || pt == BPF_PROG_TYPE_LSM || pt == BPF_PROG_TYPE_EXT || pt == BPF_PROG_TYPE_STRUCT_OPS;
}

static char *fmtd(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmtd(const char *f, ...)
{
	char *s = NULL;
	va_list ap;
	va_start(ap, f);
	if (vasprintf(&s, f, ap) < 0)
		s = NULL;
	va_end(ap);
	return s ? s : strdup("out of memory");
}


static int attach_type_value(struct bml_live *l, const char *name, uint64_t *v, char **err)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	if (!kb) {
		*err = strdup(verr ? verr : "no target BTF");
		return -1;
	}
	uint32_t id;
	if (lv_lookup(kb, "bpf_attach_type", KBTF_ENUM, &id, err) != 0) {
		if (!*err)
			*err = strdup("out of memory");
		return -1;
	}
	char want[160];
	snprintf(want, sizeof want, "BPF_%s", name);
	for (char *c = want + 4; *c; c++)
		if (*c >= 'a' && *c <= 'z')
			*c = (char)(*c - 'a' + 'A');
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	size_t step = t.kind == KBTF_ENUM64 ? 12 : 8;
	for (uint32_t i = 0; i < t.vlen; i++) {
		const uint8_t *e = t.aux + (size_t)i * step;
		const char *nm = (const char *)kb->strs + bml_kbtf_u32(kb, e);
		if (strcmp(nm, want) != 0)
			continue;
		uint64_t lo = bml_kbtf_u32(kb, e + 4);
		*v = t.kind == KBTF_ENUM64 ? (lo | (uint64_t)bml_kbtf_u32(kb, e + 8) << 32) : lo;
		return 0;
	}
	return 1;
}


static int ctx_member_walk(const struct bml_kbtf *kb, const struct kbtf_type *t, int64_t base, const char *field, int64_t *off, char **err)
{
	for (uint32_t i = 0; i < t->vlen; i++) {
		struct kbtf_member m;
		bml_kbtf_member(kb, t, i, &m);
		int64_t o = base + (int64_t)(m.offset / 8);
		if (!m.name[0]) {
			int cyc = 0;
			struct kbtf_type in;
			bml_kbtf_type(kb, bml_kbtf_underlying(kb, m.type, &cyc), &in);
			if (!cyc && (in.kind == KBTF_STRUCT || in.kind == KBTF_UNION)) {
				int rc = ctx_member_walk(kb, &in, o, field, off, err);
				if (rc <= 0)
					return rc;
			}
			continue;
		}
		if (strcmp(m.name, field) != 0)
			continue;
		int cyc = 0;
		uint32_t ty = bml_kbtf_underlying(kb, m.type, &cyc);
		struct kbtf_type tt;
		bml_kbtf_type(kb, ty, &tt);
		if (!cyc && tt.kind == KBTF_ARRAY)
			ty = bml_kbtf_underlying(kb, bml_kbtf_u32(kb, tt.aux), &cyc);
		int64_t sz;
		if (bml_kbtf_sizeof(kb, ty, &sz, err) != 0)
			return -1;
		*off = o;
		return 0;
	}
	return 1;
}

static int ctx_member(struct bml_live *l, const char *st, const char *field, int64_t *off, char **err)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	if (!kb) {
		*err = strdup(verr ? verr : "no target BTF");
		return -1;
	}
	uint32_t id;
	if (lv_lookup(kb, st, KBTF_STRUCT, &id, err) != 0) {
		if (!*err)
			*err = strdup("out of memory");
		return -1;
	}
	struct kbtf_type t;
	bml_kbtf_type(kb, id, &t);
	return ctx_member_walk(kb, &t, 0, field, off, err);
}

static const uint8_t ret_zero[16] = {0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t ret_one[16] = {0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};



static const uint8_t *probe_ret(const char *at)
{
	static const char *const ret_one_types[] = {
		"cgroup_udp4_recvmsg",      "cgroup_udp6_recvmsg",      "cgroup_unix_recvmsg",
		"cgroup_inet4_getpeername", "cgroup_inet6_getpeername", "cgroup_unix_getpeername",
		"cgroup_inet4_getsockname", "cgroup_inet6_getsockname", "cgroup_unix_getsockname",
	};
	for (size_t i = 0; i < sizeof ret_one_types / sizeof *ret_one_types; i++)
		if (!strcmp(at, ret_one_types[i]))
			return ret_one;
	return ret_zero;
}


static int memo(struct bml_live *l, const char *key, int (*f)(void *), void *arg, int *out, char **msg, int *val, char **why)
{
	struct lv_memo *m = lv_memo_get(l, key);
	if (!m) {
		*val = 0;
		*why = NULL;
		int rc = f(arg);
		if (lv_memo_put(l, key, rc, *val) != 0) {
			free(*why);
			*msg = strdup("out of memory");
			return BML_Q_ERROR;
		}
		l->memo[l->n_memo - 1].msg = *why;
		m = &l->memo[l->n_memo - 1];
	}
	*out = m->value;
	if (m->rc != BML_Q_OK)
		*msg = strdup(m->msg ? m->msg : "");
	return m->rc;
}

struct at_arg {
	struct bml_live *l;
	const char *pt, *at;
	int64_t ptid;
	int val;
	char *why;
};

static int probe_attach_type(void *p)
{
	struct at_arg *a = p;
	uint64_t v = 0;
	char *err = NULL;
	int rc = attach_type_value(a->l, a->at, &v, &err);
	if (rc < 0) {
		a->why = fmtd("reading enum bpf_attach_type from the target BTF failed (%s)" UNK, err);
		free(err);
		return BML_Q_UNKNOWN;
	}
	if (rc == 1)
		return BML_Q_OK;
	

	const char *tgt = NULL, *resolved = NULL;
	if (!strcmp(a->at, "modify_return") && a->ptid == BPF_PROG_TYPE_TRACING)
		tgt = "bpf_modify_return_test", resolved = "bpf_modify_return_test";
	else if (!strcmp(a->at, "trace_iter") && a->ptid == BPF_PROG_TYPE_TRACING)
		tgt = "bpf_map", resolved = "bpf_iter_bpf_map";
	else if ((!strcmp(a->at, "lsm_mac") || !strcmp(a->at, "lsm_cgroup")) && a->ptid == BPF_PROG_TYPE_LSM)
		tgt = "file_open", resolved = "bpf_lsm_file_open";
	else if (!strcmp(a->at, "trace_fsession") && a->ptid == BPF_PROG_TYPE_TRACING)
		tgt = "bpf_fentry_test1", resolved = "bpf_fentry_test1";
	if (tgt) {
		struct lv_prog p = {0};
		struct lv_res r;
		p.type = (uint32_t)a->ptid;
		p.attach_type = (uint32_t)v;
		p.attach_to = resolved;
		p.attach_kind = KBTF_FUNC;
		p.insns = ret_zero;
		p.n_insns = 2;
		p.license = "GPL";
		p.name = "ebpf_probe";
		p.log_mode = LV_LOG_0;
		if (lv_prog_load(a->l, &p, &r) == 0) {
			lv_close(r.fd);
			a->val = 1;
			return BML_Q_OK;
		}
		char *t = lv_res_text(&r);
		lv_res_free(&r);
		a->why = fmtd("%s with expected attach type %s on %s was not accepted (%s)" UNK, a->pt, a->at, tgt, t ? t : "");
		free(t);
		return BML_Q_UNKNOWN;
	}

	if (a->ptid == BPF_PROG_TYPE_PERF_EVENT && !strcmp(a->at, "perf_event")) {
		struct outcome ctl;
		probe_load(a->l, (uint32_t)a->ptid, 0, ret_zero, 2, &ctl);
		int rc2 = BML_Q_OK;
		if (ctl.accepted)
			a->val = 1;
		else {
			a->why = fmtd("%s (link-only attach type %s) did not load with expected attach type 0 (%s)" UNK, a->pt, a->at, ctl.text);
			rc2 = BML_Q_UNKNOWN;
		}
		free(ctl.text);
		return rc2;
	}
	if (is_btf_attach_type(a->ptid)) {
		a->why = fmtd("program type %s needs a BTF attach target to load (no expected-attach-type probe)" UNK, a->pt);
		return BML_Q_UNKNOWN;
	}

	if (a->ptid == BPF_PROG_TYPE_SK_SKB || a->ptid == BPF_PROG_TYPE_SK_MSG) {
		int src = lv_sockmap_link_probe(a->l, a->pt, (uint32_t)a->ptid, a->at, (uint32_t)v, &a->val, &a->why);
		if (src != -2)
			return src;
	}

	if (a->ptid == BPF_PROG_TYPE_KPROBE &&
	    (!strcmp(a->at, "trace_kprobe_multi") || !strcmp(a->at, "trace_uprobe_multi") || !strcmp(a->at, "trace_kprobe_session"))) {
		int src = lv_multi_link_probe(a->l, a->pt, a->at, (uint32_t)v, &a->val, &a->why);
		if (src != -2)
			return src;
	}
	struct outcome x, ctl;
	probe_load(a->l, (uint32_t)a->ptid, (uint32_t)v, probe_ret(a->at), 2, &x);
	if (x.accepted) {
		free(x.text);
		a->val = 1;
		return BML_Q_OK;
	}
	probe_load(a->l, (uint32_t)a->ptid, 0, ret_zero, 2, &ctl);
	int rc2 = BML_Q_OK;
	if (!(ctl.accepted && x.einval && !x.verifier)) {
		a->why = fmtd("%s with expected attach type %s was not accepted (%s) and the control without it gave %s" UNK, a->pt, a->at, x.text,
			      ctl.text);
		rc2 = BML_Q_UNKNOWN;
	}
	free(x.text);
	free(ctl.text);
	return rc2;
}

int bml_live_attach_type(struct bml_live *l, const char *pt, int64_t ptid, const char *at, int *out, char **msg)
{
	char *key = fmtd("at/%lld/%s", (long long)ptid, at);
	struct at_arg a = {.l = l, .pt = pt, .at = at, .ptid = ptid};
	int rc = memo(l, key, probe_attach_type, &a, out, msg, &a.val, &a.why);
	free(key);
	return rc;
}

struct ctx_arg {
	struct bml_live *l;
	const char *pt, *at, *st, *field, *mode;
	int64_t ptid, bytes;
	int val;
	char *why;
};

static int probe_ctx_access(void *p)
{
	struct ctx_arg *a = p;
	uint64_t v = 0;
	if (strcmp(a->at, "-") != 0) {
		char *err = NULL;
		int rc = attach_type_value(a->l, a->at, &v, &err);
		if (rc < 0) {
			a->why = fmtd("reading enum bpf_attach_type from the target BTF failed (%s)" UNK, err);
			free(err);
			return BML_Q_UNKNOWN;
		}
		if (rc == 1) {
			a->why = fmtd("the target kernel has no attach type %s (attach_type decides)" UNK, a->at);
			return BML_Q_UNKNOWN;
		}
	}
	if (is_btf_attach_type(a->ptid)) {
		a->why = fmtd("program type %s needs a BTF attach target to load (no ctx-access probe)" UNK, a->pt);
		return BML_Q_UNKNOWN;
	}
	int64_t off = 0;
	char *err = NULL;
	int rc = ctx_member(a->l, a->st, a->field, &off, &err);
	if (rc < 0) {
		a->why = fmtd("reading %s from the target BTF failed (%s)" UNK, a->st, err);
		free(err);
		return BML_Q_UNKNOWN;
	}
	if (rc == 1)
		return BML_Q_OK;
	uint8_t sz;
	switch (a->bytes) {
	case 1: sz = 0x10; break;
	case 2: sz = 0x08; break;
	case 4: sz = 0x00; break;
	case 8: sz = 0x18; break;
	default:
		a->why = fmtd("ctx access width %lld", (long long)a->bytes);
		return BML_Q_ERROR;
	}
	uint8_t ins[32] = {0};
	size_t n;
	int16_t o16 = (int16_t)off;
	if (!strcmp(a->mode, "w")) {
		ins[0] = 0xb7, ins[1] = 0x02;
		ins[8] = (uint8_t)(0x63 | sz), ins[9] = 0x21;
		memcpy(ins + 10, &o16, 2);
		n = 2;
	} else {
		ins[0] = (uint8_t)(0x61 | sz), ins[1] = 0x12;
		memcpy(ins + 2, &o16, 2);
		n = 1;
	}
	memcpy(ins + n * 8, probe_ret(a->at), 16);
	struct outcome x, ctl;
	probe_load(a->l, (uint32_t)a->ptid, (uint32_t)v, ins, n + 2, &x);
	if (x.accepted) {
		free(x.text);
		a->val = 1;
		return BML_Q_OK;
	}
	probe_load(a->l, (uint32_t)a->ptid, (uint32_t)v, probe_ret(a->at), 2, &ctl);
	int rc2 = BML_Q_OK;
	if (!(ctl.accepted && x.verifier)) {
		a->why = fmtd("%s %s of %s.%s was not accepted (%s) and the control without it gave %s" UNK, a->pt, a->mode, a->st, a->field,
			      x.text, ctl.text);
		rc2 = BML_Q_UNKNOWN;
	}
	free(x.text);
	free(ctl.text);
	return rc2;
}

int bml_live_ctx_access(struct bml_live *l, const char *pt, int64_t ptid, const char *at, const char *st, const char *field, const char *mode,
			int64_t bytes, int *out, char **msg)
{
	char *key = fmtd("ctx/%lld/%s/%s.%s/%s/%lld", (long long)ptid, at, st, field, mode, (long long)bytes);
	struct ctx_arg a = {.l = l, .pt = pt, .at = at, .st = st, .field = field, .mode = mode, .ptid = ptid, .bytes = bytes};
	int rc = memo(l, key, probe_ctx_access, &a, out, msg, &a.val, &a.why);
	free(key);
	return rc;
}




int bml_live_attach_target(struct bml_live *l, const char *at, const char *kind, const char *value, int *out, char **msg)
{
	(void)at;
	*out = 0;
	int iter = !strcmp(kind, "iter"), rawtp = !strcmp(kind, "rawtp"), fn = !strcmp(kind, "func"), lsm = !strcmp(kind, "lsm");
	if (!strcmp(kind, "tp"))
		return lv_tracefs_event_id(value, out, msg);
	if (!iter && !rawtp && !fn && !lsm) {
		*msg = fmtd("no probe yet for attach targets of kind %s" UNK, kind);
		return BML_Q_UNKNOWN;
	}
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	if (!kb) {
		*msg = fmtd("reading the target BTF failed (%s)" UNK, verr ? verr : "");
		return BML_Q_UNKNOWN;
	}
	char *name = iter ? fmtd("bpf_iter_%s", value) : rawtp ? fmtd("btf_trace_%s", value) : lsm ? fmtd("bpf_lsm_%s", value) : fmtd("%s", value);
	uint32_t id;
	char *err = NULL;
	int rc = lv_lookup(kb, name, rawtp ? KBTF_TYPEDEF : KBTF_FUNC, &id, &err);
	free(name);
	if (rc < 0) {
		*msg = strdup("out of memory");
		return BML_Q_ERROR;
	}
	if (rc == 0) {
		*out = 1;
		return BML_Q_OK;
	}
	int st = BML_Q_UNKNOWN;
	if ((iter || lsm) && rc == 1)
		st = BML_Q_OK;
	else if (iter || lsm)
		*msg = fmtd("looking up bpf_%s_%s failed (%s)" UNK, iter ? "iter" : "lsm", value, err ? err : "");
	else if (rawtp)
		*msg = fmtd("btf_trace_%s is not in vmlinux BTF (%s) — a module tracepoint is not checked" UNK, value, err ? err : "");
	else
		*msg = fmtd("FUNC %s is not in vmlinux BTF (%s) — a module function is not checked" UNK, value, err ? err : "");
	free(err);
	return st;
}
