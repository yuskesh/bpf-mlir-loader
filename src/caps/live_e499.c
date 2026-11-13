#define _GNU_SOURCE
#include "caps/live_internal.h"
#include "caps/live_arena.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/gostr.h"

#define UNK ": cannot be determined on this target"

static int unknown(char **msg, const char *f, const char *a, const char *b)
{
	struct bml_buf m = {0};
	bml_buf_addf(&m, f, a ? a : "", b ? b : "");
	bml_buf_adds(&m, UNK);
	*msg = bml_buf_take(&m);
	return *msg ? BML_Q_UNKNOWN : BML_Q_ERROR;
}

static const struct recipe {
	const char *name, *ret, *args[1];
	size_t n;
} recipes[] = {
	{"bpf_task_from_pid", "ptr:task_struct", {"i32"}, 1},	   {"bpf_task_acquire", "ptr:task_struct", {"ptr:task_struct"}, 1},
	{"bpf_task_release", "void", {"ptr:task_struct"}, 1},	   {"bpf_session_is_return", "bool", {"ptr:void"}, 1},
	{"bpf_session_cookie", "ptr:u64", {"ptr:void"}, 1},
};

static const struct recipe *recipe_of(const char *n)
{
	for (size_t i = 0; i < sizeof recipes / sizeof *recipes; i++)
		if (!strcmp(recipes[i].name, n))
			return &recipes[i];
	return NULL;
}


struct spec {
	uint32_t type, attach;
	const char *attach_to;
	uint32_t attach_kind;
	uint32_t flags;
	int ret;
};

static int initial_spec(const struct bml_kfunc_profile *p, struct spec *s, char *buf, size_t bn)
{
	memset(s, 0, sizeof *s);
	if (strcmp(p->recipe, "kfunc-v1") != 0 || !p->context_identity[0] || !strcmp(p->kind, "fsession") || !strcmp(p->kind, "struct_ops"))
		return -1;
	const char *k = p->kind, *tn = k, *sec = "", *tk = "none", *at = "";
	int64_t id = 0;
	int needs_target = 0;
	if (!strcmp(k, "syscall"))
		s->type = BPF_PROG_TYPE_SYSCALL, id = 31, s->flags = BPF_F_SLEEPABLE, sec = "syscall", at = "-";
	else if (!strcmp(k, "xdp"))
		s->type = BPF_PROG_TYPE_XDP, id = 6, s->attach = BPF_XDP, sec = "xdp", at = "xdp", s->ret = 2;
	else if (!strcmp(k, "sched_cls")) {
		int in = !strcmp(p->attach_type, "tcx_ingress");
		int nk = !strncmp(p->attach_type, "netkit_", 7), primary = !strcmp(p->attach_type, "netkit_primary");
		s->type = BPF_PROG_TYPE_SCHED_CLS, id = 3, s->attach = nk ? (primary ? BPF_NETKIT_PRIMARY : BPF_NETKIT_PEER) : in ? BPF_TCX_INGRESS : BPF_TCX_EGRESS;
		sec = nk ? (primary ? "netkit/primary" : "netkit/peer") : in ? "tcx/ingress" : "tcx/egress";
		at = nk ? (primary ? "netkit_primary" : "netkit_peer") : in ? "tcx_ingress" : "tcx_egress";
	} else if (!strcmp(k, "cgroup_skb")) {
		int in = !strcmp(p->section, "cgroup_skb/ingress");
		s->type = BPF_PROG_TYPE_CGROUP_SKB, id = 8, s->attach = in ? BPF_CGROUP_INET_INGRESS : BPF_CGROUP_INET_EGRESS;
		sec = in ? "cgroup_skb/ingress" : "cgroup_skb/egress", tk = "cgroup", at = p->attach_type, s->ret = 1;
	} else if (!strcmp(k, "tracepoint")) {
		s->type = BPF_PROG_TYPE_TRACEPOINT, id = 5, tk = "tp", at = "-";
		const char *slash = strchr(p->target, '/');
		if (!slash || slash == p->target || !slash[1] || strchr(slash + 1, '/') || strpbrk(p->target, " \t\n:"))
			return -1;
		snprintf(buf, bn, "tracepoint/%s", p->target), sec = buf;
	} else if (!strcmp(k, "raw_tp")) {
		s->type = BPF_PROG_TYPE_RAW_TRACEPOINT, id = 17, tn = "raw_tracepoint", tk = "rawtp", at = "-", needs_target = 1;
		snprintf(buf, bn, "raw_tp/%s", p->target), sec = buf;
	} else if (!strcmp(k, "perf_event")) {
		s->type = BPF_PROG_TYPE_PERF_EVENT, id = 7, tk = "perf", at = "-", sec = "perf_event";
		if (p->target[0])
			return -1;
	} else if (!strcmp(k, "lsm")) {
		s->type = BPF_PROG_TYPE_LSM, id = 29, tk = "lsm", at = "lsm_mac", needs_target = 1;
		s->attach = BPF_LSM_MAC, s->attach_kind = KBTF_FUNC;
		snprintf(buf, bn, "lsm/%s", p->target), sec = buf;
	} else if (!strcmp(k, "cgroup_sock")) {
		s->type = BPF_PROG_TYPE_CGROUP_SOCK, id = 9, tk = "cgroup", at = "cgroup_inet_sock_create", sec = "cgroup/sock_create";
		s->attach = BPF_CGROUP_INET_SOCK_CREATE;
	} else if (!strcmp(k, "cgroup_device")) {
		s->type = BPF_PROG_TYPE_CGROUP_DEVICE, id = 15, tk = "cgroup", at = "cgroup_device", sec = "cgroup/dev";
		s->attach = BPF_CGROUP_DEVICE;
	} else if (!strcmp(k, "cgroup_sock_addr")) {
		s->type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR, id = 18, tk = "cgroup", at = "cgroup_inet4_connect", sec = "cgroup/connect4";
		s->attach = BPF_CGROUP_INET4_CONNECT;
	} else if (!strcmp(k, "cgroup_sockopt")) {
		s->type = BPF_PROG_TYPE_CGROUP_SOCKOPT, id = 25, tk = "cgroup", at = "cgroup_getsockopt", sec = "cgroup/getsockopt";
		s->attach = BPF_CGROUP_GETSOCKOPT;
	} else if (!strcmp(k, "cgroup_sysctl")) {
		s->type = BPF_PROG_TYPE_CGROUP_SYSCTL, id = 23, tk = "cgroup", at = "cgroup_sysctl", sec = "cgroup/sysctl";
		s->attach = BPF_CGROUP_SYSCTL;
	} else if (!strcmp(k, "sock_ops")) {
		s->type = BPF_PROG_TYPE_SOCK_OPS, id = 13, tk = "cgroup", at = "cgroup_sock_ops", sec = "sockops";
		s->attach = BPF_CGROUP_SOCK_OPS;
	} else if (!strcmp(k, "tp_btf") || !strcmp(k, "fentry") || !strcmp(k, "fexit") || !strcmp(k, "iter") || !strcmp(k, "fmod_ret")) {
		s->type = BPF_PROG_TYPE_TRACING, id = 26, tn = "tracing", tk = "func", needs_target = 1;
		if (!strcmp(k, "tp_btf"))
			s->attach = BPF_TRACE_RAW_TP, tk = "tp", at = "trace_raw_tp", s->attach_kind = KBTF_TYPEDEF;
		else if (!strcmp(k, "fentry"))
			s->attach = BPF_TRACE_FENTRY, at = "trace_fentry", s->attach_kind = KBTF_FUNC;
		else if (!strcmp(k, "fexit"))
			s->attach = BPF_TRACE_FEXIT, at = "trace_fexit", s->attach_kind = KBTF_FUNC;
		else if (!strcmp(k, "iter"))
			s->attach = BPF_TRACE_ITER, tk = "iter", at = "trace_iter", s->attach_kind = KBTF_FUNC;
		else
			s->attach = BPF_MODIFY_RETURN, at = "modify_return", s->attach_kind = KBTF_FUNC;
		snprintf(buf, bn, "%s/%s", k, p->target);
		sec = buf;
	} else if (!strcmp(k, "kprobe_session")) {
		s->type = BPF_PROG_TYPE_KPROBE, id = 2, tn = "kprobe", tk = "func", needs_target = 1, s->attach = BPF_TRACE_KPROBE_SESSION;
		at = "trace_kprobe_session";
		snprintf(buf, bn, "kprobe.session/%s", p->target);
		sec = buf;
	} else
		return -1;
	if (needs_target && (!p->target[0] || strpbrk(p->target, "/ \t\n:")))
		return -1;
	if (p->prog_type_id != id || strcmp(p->prog_type, tn) || strcmp(p->section, sec) || strcmp(p->target_kind, tk) || p->prog_flags != s->flags ||
	    strcmp(p->attach_type, at))
		return -1;
	if ((!strcmp(tk, "none") || !strcmp(tk, "cgroup")) && p->target[0])
		return -1;
	return 0;
}


static int dep_id(struct bml_live *l, const struct recipe *r, uint32_t *id, char **msg)
{
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	if (!kb)
		return unknown(msg, "kfunc %s BTF unavailable: %s", r->name, verr);
	char *err = NULL;
	int rc = lv_lookup(kb, r->name, KBTF_FUNC, id, &err);
	if (rc < 0)
		return (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (rc) {
		int st = unknown(msg, "kfunc dependency %s: %s", r->name, err);
		free(err);
		return st;
	}
	struct kbtf_type fn, fp;
	bml_kbtf_type(kb, *id, &fn);
	bml_kbtf_type(kb, fn.size_type, &fp);
	if (fp.kind != KBTF_FUNC_PROTO)
		return unknown(msg, "kfunc dependency %s has no FUNC_PROTO", r->name, NULL);
	struct bml_str args[1] = {{(char *)r->args[0], strlen(r->args[0])}};
	struct bml_strs d = {0};
	char *m = NULL;
	int st = bml_live_kfunc(l, r->name, r->ret, args, r->n, &d, &m);
	if (st != BML_Q_OK)
		return (*msg = m, st);
	if (d.n) {
		struct bml_buf b = {0};
		for (size_t i = 0; i < d.n; i++)
			bml_buf_addf(&b, "%s%s", i ? "; " : "", d.s[i]);
		char *j = bml_buf_take(&b);
		bml_strs_free(&d);
		st = unknown(msg, "kfunc dependency %s prototype: %s", r->name, j);
		free(j);
		return st;
	}
	if (*id == 0 || *id > INT32_MAX)
		return unknown(msg, "kfunc dependency %s invalid vmlinux FUNC ID", r->name, NULL);
	return BML_Q_OK;
}

#define I(code, regs, off, imm) {(code), (regs), (uint8_t)((off) & 0xff), (uint8_t)((uint16_t)(off) >> 8), (uint8_t)(imm), (uint8_t)((uint32_t)(imm) >> 8), (uint8_t)((uint32_t)(imm) >> 16), (uint8_t)((uint32_t)(imm) >> 24)}
#define CALL(id) I(0x85, 0x20, 0, (id))
#define MOVI(dst, v) I(0xb7, (dst), 0, (v))
#define MOVR(dst, src) I(0xbf, (dst) | (src) << 4, 0, 0)
#define JEQ0(dst, off) I(0x15, (dst), (off), 0)
#define EXIT I(0x95, 0, 0, 0)

int bml_live_kfunc_load(struct bml_live *l, const struct bml_kfunc_profile *p, const char *name, const char *ret, const struct bml_str *args, size_t n,
			int *out, char **msg)
{
	*out = 0;
	*msg = NULL;
	struct spec s;
	char secbuf[512];
	if (initial_spec(p, &s, secbuf, sizeof secbuf))
		return unknown(msg, "no finite load-only recipe for initial profile %s", p->kind, NULL);
	if (lv_arena_kfunc_name(name))
		return lv_arena_kfunc_load(l, p, name, ret, args, n, out, msg);
	const struct recipe *r = recipe_of(name);
	if (!r || strcmp(r->ret, ret) || n != r->n || strcmp(args[0].p, r->args[0]))
		return unknown(msg, "no strict kfunc recipe for %s", name, NULL);
	int session = !strncmp(name, "bpf_session_", 12);
	if (session && strcmp(p->kind, "kprobe_session"))
		return unknown(msg, "session recipe needs original kprobe_session context", NULL, NULL);
	uint32_t ids[3] = {0};
	const char *deps[3];
	size_t nd = 0;
	if (session)
		deps[nd++] = name;
	else if (!strcmp(name, "bpf_task_acquire"))
		deps[nd++] = "bpf_task_from_pid", deps[nd++] = "bpf_task_acquire", deps[nd++] = "bpf_task_release";
	else
		deps[nd++] = "bpf_task_from_pid", deps[nd++] = "bpf_task_release";
	for (size_t i = 0; i < nd; i++) {
		int st = dep_id(l, recipe_of(deps[i]), &ids[i], msg);
		if (st != BML_Q_OK)
			return st;
	}
	int32_t pid = (int32_t)getpid(), rv = s.ret;
	uint8_t ins[14][8];
	size_t ni = 0;
	if (session) {
		uint8_t x[][8] = {CALL(ids[0]), MOVI(0, rv), EXIT};
		memcpy(ins, x, sizeof x), ni = 3;
	} else if (nd == 2) {
		uint8_t x[][8] = {MOVI(1, pid), CALL(ids[0]), MOVR(6, 0), JEQ0(6, 2), MOVR(1, 6), CALL(ids[1]), MOVI(0, rv), EXIT};
		memcpy(ins, x, sizeof x), ni = 8;
	} else {
		uint8_t x[][8] = {MOVI(1, pid), CALL(ids[0]), MOVR(6, 0), JEQ0(6, 8),  MOVR(1, 6), CALL(ids[1]), MOVR(7, 0),
				  JEQ0(7, 2),	MOVR(1, 7),   CALL(ids[2]), MOVR(1, 6), CALL(ids[2]), MOVI(0, rv), EXIT};
		memcpy(ins, x, sizeof x), ni = 14;
	}
	struct lv_prog pr = {0};
	struct lv_res res;
	pr.type = s.type;
	pr.attach_type = s.attach;
	pr.flags = s.flags;
	pr.insns = &ins[0][0];
	pr.n_insns = ni;
	pr.license = "GPL";
	pr.name = "kfunc_probe";
	pr.log_mode = LV_LOG_1;
	char resolved[512];
	if (s.attach_kind) {
		snprintf(resolved, sizeof resolved, "%s%s", s.attach == BPF_TRACE_RAW_TP ? "btf_trace_" : s.attach == BPF_TRACE_ITER ? "bpf_iter_" :
			 s.attach == BPF_LSM_MAC ? "bpf_lsm_" : "",
			 p->target);
		pr.attach_to = resolved;
		pr.attach_kind = s.attach_kind;
	}
	if (lv_prog_load(l, &pr, &res) == 0) {
		lv_close(res.fd);
		*out = 1;
		return BML_Q_OK;
	}

	char want[256];
	snprintf(want, sizeof want, "calling kernel function %s is not allowed", name);
	int named = 0, other = 0;
	for (size_t i = 0; res.verifier && i < res.n_lines && !other; i++) {
		const char *ln = res.lines[i];
		while (*ln == ' ' || *ln == '\t')
			ln++;
		size_t k = strlen(ln);
		while (k && (ln[k - 1] == ' ' || ln[k - 1] == '\t' || ln[k - 1] == '\n' || ln[k - 1] == '\r'))
			k--;
		if (k == strlen(want) && !memcmp(ln, want, k))
			named = 1;
		else if (memmem(ln, k, "calling kernel function ", 24) && memmem(ln, k, " is not allowed", 15))
			other = 1;
	}
	char *t = lv_res_text(&res);
	lv_res_free(&res);
	int st = BML_Q_OK;
	if (other)
		st = unknown(msg, "different callee denial: %s", t, NULL);
	else if (!named)
		st = unknown(msg, "kfunc load result does not establish named permission denial: %s", t, NULL);
	free(t);
	return st;
}




static int strip(const struct bml_kbtf *kb, uint32_t id, uint32_t *out, const char **err)
{
	uint32_t seen[34];
	for (int i = 0; i <= 32; i++) {
		struct kbtf_type t;
		bml_kbtf_type(kb, id, &t);
		if (t.kind != KBTF_TYPEDEF && t.kind != KBTF_CONST && t.kind != KBTF_VOLATILE && t.kind != KBTF_RESTRICT && t.kind != KBTF_TYPE_TAG) {
			*out = id;
			return 0;
		}
		for (int j = 0; j < i; j++)
			if (seen[j] == id)
				return (*err = "BTF modifier cycle"), -1;
		seen[i] = id;
		if (i == 32)
			break;
		id = t.size_type;
	}
	*err = "BTF modifier depth exceeds 32";
	return -1;
}

int bml_live_tracepoint_buffer(struct bml_live *l, const char *name, const char *pointee, struct bml_strs *out, char **msg)
{
	memset(out, 0, sizeof *out);
	*msg = NULL;
	const char *verr;
	const struct bml_kbtf *kb = lv_kb(l, &verr);
	if (!kb)
		return unknown(msg, "tracepoint %s BTF unavailable: %s", name, verr);
	struct bml_buf b = {0};
	if (strcmp(pointee, "i32") != 0) {
		bml_buf_addf(&b, "tracepoint %s: argument 0 unsupported pointee %s (expected i32)", name, pointee);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	char tn[512];
	snprintf(tn, sizeof tn, "btf_trace_%s", name);
	uint32_t td;
	char *err = NULL;
	int rc = lv_lookup(kb, tn, KBTF_TYPEDEF, &td, &err);
	if (rc < 0)
		return lv_oom(out, msg);
	if (rc == 1) {
		free(err);
		bml_buf_addf(&b, "tracepoint %s: argument 0 expected pointee i32; no btf_trace_%s in target BTF", name, name);
		return lv_push(out, &b) ? lv_oom(out, msg) : BML_Q_OK;
	}
	if (rc) {
		int r2 = asprintf(msg, "tracepoint %s BTF lookup: %s", name, err);
		free(err);
		return r2 < 0 ? lv_oom(out, msg) : BML_Q_ERROR;
	}

	const char *why = NULL, *se = NULL;
	char got[256] = "";
	uint32_t ptr, fp, ret, d0, a0, pt;
	struct kbtf_type t;
	bml_kbtf_type(kb, td, &t);
	if (strip(kb, t.size_type, &ptr, &se))
		why = se;
	else if (bml_kbtf_type(kb, ptr, &t), t.kind != KBTF_PTR)
		why = "target must be a function pointer";
	else if (strip(kb, t.size_type, &fp, &se))
		why = se;
	else if (bml_kbtf_type(kb, fp, &t), t.kind != KBTF_FUNC_PROTO)
		why = "function pointer must target FUNC_PROTO";
	else if (t.vlen < 2)
		why = "FUNC_PROTO data / argument 0 missing";
	else {
		struct kbtf_type proto = t, x;
		const char *pn;
		uint32_t p0, p1;
		bml_kbtf_param(kb, &proto, 0, &pn, &p0);
		bml_kbtf_param(kb, &proto, 1, &pn, &p1);
		if (strip(kb, proto.size_type, &ret, &se))
			why = se;
		else if (bml_kbtf_type(kb, ret, &x), x.kind != KBTF_UNKN)
			why = "return must be void";
		else if (strip(kb, p0, &d0, &se) || (bml_kbtf_type(kb, d0, &x), x.kind != KBTF_PTR) || strip(kb, x.size_type, &d0, &se) ||
			 (bml_kbtf_type(kb, d0, &x), x.kind != KBTF_UNKN))
			why = "data must be void pointer";
		else if (strip(kb, p1, &a0, &se))
			why = se;
		else if (bml_kbtf_type(kb, a0, &x), x.kind != KBTF_PTR)
			why = "argument 0 must be a pointer";
		else if (strip(kb, x.size_type, &pt, &se))
			why = se;
		else {
			bml_kbtf_type(kb, pt, &x);
			if (x.kind != KBTF_INT) {
				struct bml_buf g = {0};
				bml_buf_adds(&g, "argument 0 expected pointee i32; got ");
				bml_kbtf_gotype(kb, &g, pt, 0);
				char *s = bml_buf_take(&g);
				snprintf(got, sizeof got, "%s", s ? s : "");
				free(s);
				why = got;
			} else {
				uint32_t enc = bml_kbtf_u32(kb, x.aux) >> 24 & 0xf;
				if (x.size_type != 4 || enc != 1) {
					snprintf(got, sizeof got, "argument 0 expected pointee i32; got INT %s size=%u encoding=%u", x.name, x.size_type, enc);
					why = got;
				}
			}
		}
	}
	if (why) {
		bml_buf_addf(&b, "tracepoint %s: argument 0 expected pointee i32; %s", name, why);
		if (lv_push(out, &b))
			return lv_oom(out, msg);
	}
	return BML_Q_OK;
}
