/* caps/live_prog.c — a C port of prog_type (features.HaveProgramType), helper (HaveProgramHelper), the tracing helper (kload's
 * tracinghelper.go) and tcx (kload's HasTCX). */
#define _GNU_SOURCE
#include "util/gostr.h"
#include "util/mutation.h"
#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

static const uint8_t insn_ret0[] = {0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t insn_mov_ret[] = {0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};

/* The BTF of the stage 1 and stage 2 programs of Extension (FUNC "a" global, then FUNC_PROTO (ctx: struct xdp_md *); 110 bytes) and the func_info */
static const uint8_t ext_btf[] = {
	0x9f, 0xeb, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
	0x0e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x78,
	0x64, 0x70, 0x5f, 0x6d, 0x64, 0x00, 0x63, 0x74, 0x78, 0x00,
};
static const uint8_t ext_func_info[] = {0, 0, 0, 0, 1, 0, 0, 0};

/* answer state to BML_Q_* (kload's have: present is true, ErrNotSupported is false, anything else is an error) */
static int have(int state, int *out, char **msg, const char *what)
{
	*out = state == LV_OK;
	if (state == LV_OK || state == LV_NOTSUP)
		return BML_Q_OK;
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s: probe failed", what);
	*msg = bml_buf_take(&b);
	return BML_Q_ERROR;
}

static int unknown(char **msg, const char *what)
{
	*msg = strdup(what);
	return BML_Q_UNKNOWN;
}

/* The classification of probeProgram: success means present; EINVAL, E2BIG or ErrNotSupported in the chain means absent; anything else is an error (not remembered) */
static int classify(const struct lv_res *r, int ok)
{
	if (ok)
		return LV_OK;
	if (r->err == EPERM && r->verifier && BML_MUT("live.prog_eperm_true"))
		return LV_OK;
	if (r->err == EINVAL || r->err == E2BIG || r->notsup)
		return LV_NOTSUP;
	return -1;
}

static int probe_extension(struct bml_live *l)
{
	struct lv_prog p = {0};
	struct lv_res r1, r2;
	p.type = BPF_PROG_TYPE_XDP;
	p.insns = insn_mov_ret;
	p.n_insns = 2;
	p.license = "";
	p.log_mode = LV_LOG_DISABLED;
	p.btf = ext_btf;
	p.btf_len = sizeof ext_btf;
	p.func_info = ext_func_info;
	p.func_info_cnt = 1;
	int ok = lv_prog_load(l, &p, &r1) == 0;
	lv_res_free(&r1);
	if (!ok) /* an error at stage 1 is kept as it is (it does not go through probeProgram, so EINVAL is an error too) */
	{
		l->prog_type_errno[BPF_PROG_TYPE_EXT] = !r1.notsup && (!r1.verifier || r1.n_lines == 0) ? r1.err : 0; /* kept for the error sentence */
		return r1.notsup ? LV_NOTSUP : -1;
	}
	/* Stage 2: findTargetInProgram. If stage 1 has no BTF (a kernel without ext infos) the result is ErrNotSupported. Go reads the BTF
	 * back and looks up "a" to get id 1; the C code uses the constant 1 (a failure while reading it back is not ported, a known limitation). */
	int st;
	if (lv_feat(l, LVF_EXT_INFOS) != LV_OK)
		st = LV_NOTSUP;
	else {
		p.type = BPF_PROG_TYPE_EXT;
		p.attach_btf_id = 1;
		p.attach_prog_fd = (uint32_t)r1.fd;
		ok = lv_prog_load(l, &p, &r2) == 0;
		st = classify(&r2, ok);
		l->prog_type_errno[BPF_PROG_TYPE_EXT] = st < 0 && (!r2.verifier || r2.n_lines == 0) ? r2.err : 0; /* kept for the error sentence */
		lv_close(r2.fd);
		lv_res_free(&r2);
	}
	lv_close(r1.fd);
	return st;
}

static int probe_prog_type(struct bml_live *l, uint32_t pt)
{
	if (pt == BPF_PROG_TYPE_EXT)
		return probe_extension(l);
	struct lv_prog p = {0};
	struct lv_res r;
	p.type = pt;
	p.insns = insn_ret0;
	p.n_insns = 3;
	p.license = "";
	p.log_mode = LV_LOG_DISABLED;
	switch (pt) {
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR: p.attach_type = BPF_CGROUP_INET4_CONNECT; break;
	case BPF_PROG_TYPE_CGROUP_SOCKOPT: p.attach_type = BPF_CGROUP_GETSOCKOPT; break;
	case BPF_PROG_TYPE_TRACING:
		p.attach_type = BPF_TRACE_FENTRY;
		p.attach_to = "bpf_init";
		p.attach_kind = KBTF_FUNC;
		break;
	case BPF_PROG_TYPE_STRUCT_OPS: p.license = "GPL"; break;
	case BPF_PROG_TYPE_LSM:
		p.license = "GPL";
		p.attach_type = BPF_LSM_MAC;
		p.attach_to = "bpf_lsm_file_mprotect";
		p.attach_kind = KBTF_FUNC;
		break;
	case BPF_PROG_TYPE_SK_LOOKUP: p.attach_type = BPF_SK_LOOKUP; break;
	case BPF_PROG_TYPE_SYSCALL: p.flags = BPF_F_SLEEPABLE; break;
	case BPF_PROG_TYPE_NETFILTER: p.attach_type = BPF_NETFILTER; break;
	}
	int ok = lv_prog_load(l, &p, &r) == 0;
	lv_close(r.fd);
	int st = classify(&r, ok);
	if (pt == BPF_PROG_TYPE_STRUCT_OPS && st < 0 && r.err == ENOTSUPP)
		st = LV_OK;
	l->prog_type_errno[pt] = st < 0 && (!r.verifier || r.n_lines == 0) ? r.err : 0; /* kept for the error sentence (cilium's form, for an error without a log) */
	lv_res_free(&r);
	return st;
}

/* HaveProgramType with a cache (the key is the low 32 bits of the id; 0 and values from 33 up are not in the table and are errors) */
static int prog_type_state(struct bml_live *l, int64_t id)
{
	uint32_t pt = (uint32_t)id;
	if (pt == 0 || pt > 32)
		return -1;
	if (l->prog_type[pt] != LV_UNSET)
		return l->prog_type[pt];
	int st = probe_prog_type(l, pt);
	if (st == LV_OK || st == LV_NOTSUP)
		l->prog_type[pt] = st;
	return st;
}

/* The String of cilium v0.22's ebpf.ProgramType (0..32; checked by printing ebpf.ProgramType(i).String() with go run) */
static const char *const pt_names[33] = {
	"UnspecifiedProgram", "SocketFilter",  "Kprobe",        "SchedCLS",       "SchedACT",       "TracePoint",   "XDP",
	"PerfEvent",     "CGroupSKB",     "CGroupSock",    "LWTIn",          "LWTOut",         "LWTXmit",      "SockOps",
	"SkSKB",         "CGroupDevice",  "SkMsg",         "RawTracepoint",  "CGroupSockAddr", "LWTSeg6Local", "LircMode2",
	"SkReuseport",   "FlowDissector", "CGroupSysctl",  "RawTracepointWritable", "CGroupSockopt", "Tracing", "StructOps",
	"Extension",     "LSM",           "SkLookup",      "Syscall",        "Netfilter",
};

int bml_live_prog_type(struct bml_live *l, int64_t id, int *out, char **msg)
{
	uint32_t pt = (uint32_t)id;
	if ((pt == 0 || pt > 32) && !BML_MUT("live.nofeature_text_old")) { /* cilium's haveProgramTypeMatrix has no key for it */
		struct bml_buf b = {0};
		if (pt == 0)
			bml_buf_adds(&b, "no feature probe for UnspecifiedProgram");
		else
			bml_buf_addf(&b, "no feature probe for ProgramType(%u)", pt);
		*out = 0;
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}
	int st = prog_type_state(l, id);
	if (st != LV_OK && st != LV_NOTSUP && pt <= 32 && l->prog_type_errno[pt] && !BML_MUT("live.prog_type_text_old")) {
		/* cilium's FeatureTest says "detect support for %s: %w" (Name is the String of the ProgramType) and NewProgram says
		 * "load program: %w" (the errno is spelled as Go spells it). A verifier error (one with a log) is not ported and keeps its earlier
		 * sentence; if it became visible it would show up in the differential test. */
		char *e = bml_go_errno_str(l->prog_type_errno[pt]);
		struct bml_buf b = {0};
		bml_buf_addf(&b, "detect support for %s: load program: %s", pt_names[pt], e ? e : "");
		free(e);
		*out = 0;
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}
	return have(st, out, msg, "prog type");
}

/* call <id>; ld_imm64 r0, 0; exit */
static void helper_insns(uint8_t ins[32], uint32_t h)
{
	memset(ins, 0, 32);
	ins[0] = 0x85;
	memcpy(ins + 4, &h, 4);
	ins[8] = 0x18;
	ins[24] = 0x95;
}

/* whether line contains a and, unless tag is NULL, tag as well */
static int has2(const char *line, const char *a, const char *tag)
{
	return strstr(line, a) && (!tag || strstr(line, tag));
}

static int helper_rejected(char **lines, size_t from, size_t n, const char *tag)
{
	for (size_t i = from; i < n; i++)
		if (has2(lines[i], "invalid func", tag) || has2(lines[i], "program of this type cannot use helper", tag) ||
		    strstr(lines[i], "unknown func"))
			return 1;
	return 0;
}

static int probe_helper(struct bml_live *l, uint32_t pt, uint32_t h)
{
	if (h & 0x70000000u) /* platform.DecodeConstant: a number from a non-Linux platform (ErrNotSupportedOnOS) */
		return LV_NOTSUP;
	uint8_t ins[32];
	helper_insns(ins, h);
	struct lv_prog p = {0};
	struct lv_res r;
	p.type = pt;
	p.insns = ins;
	p.n_insns = 4;
	p.license = "GPL";
	p.log_mode = LV_LOG_1;
	switch (pt) {
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR: p.attach_type = BPF_CGROUP_INET4_CONNECT; break;
	case BPF_PROG_TYPE_CGROUP_SOCKOPT: p.attach_type = BPF_CGROUP_GETSOCKOPT; break;
	case BPF_PROG_TYPE_SK_LOOKUP: p.attach_type = BPF_SK_LOOKUP; break;
	case BPF_PROG_TYPE_SYSCALL: p.flags = BPF_F_SLEEPABLE; break;
	case BPF_PROG_TYPE_NETFILTER: p.attach_type = BPF_NETFILTER; break;
	}
	int ok = lv_prog_load(l, &p, &r) == 0;
	lv_close(r.fd);
	int st = -1;
	char tag[16];
	snprintf(tag, sizeof tag, "#%u", h);
	if (ok)
		st = LV_OK;
	else if (!r.verifier)
		st = r.notsup ? LV_NOTSUP : -1;
	else if (r.err == EACCES)
		st = LV_OK;
	else if (r.err == EINVAL && helper_rejected(r.lines, r.n_lines > 5 && !BML_MUT("live.helper_all_lines") ? r.n_lines - 5 : 0, r.n_lines, tag))
		st = LV_NOTSUP;
	lv_res_free(&r);
	return st;
}

int bml_live_helper(struct bml_live *l, int64_t prog_type_id, int64_t helper_id, int *out, char **msg)
{
	uint32_t pt = (uint32_t)prog_type_id, h = (uint32_t)helper_id;
	*out = 0;
	if (pt == BPF_PROG_TYPE_TRACING || pt == BPF_PROG_TYPE_STRUCT_OPS || pt == BPF_PROG_TYPE_EXT || pt == BPF_PROG_TYPE_LSM) {
		/* kload: fmt.Errorf("cilium/ebpf has no helper probe for %v: %w", ebpf.ProgramType(id), ErrUnknown); %v is the String of cilium's ProgramType */
		if (BML_MUT("live.helper_unknown_text_old"))
			return unknown(msg, "cilium/ebpf has no helper probe for this program type");
		const char *nm = pt == BPF_PROG_TYPE_TRACING ? "Tracing" : pt == BPF_PROG_TYPE_STRUCT_OPS ? "StructOps" : pt == BPF_PROG_TYPE_EXT ? "Extension" : "LSM";
		char m[128];
		snprintf(m, sizeof m, "cilium/ebpf has no helper probe for %s: cannot be determined on this target", nm);
		return unknown(msg, m);
	}
	for (size_t i = 0; i < l->n_helpers; i++)
		if (l->helpers[i].pt == pt && l->helpers[i].helper == h)
			return have(l->helpers[i].state, out, msg, "helper");
	int st = prog_type_state(l, prog_type_id);
	if (st == LV_OK)
		st = probe_helper(l, pt, h);
	if (st == LV_OK || st == LV_NOTSUP) {
		struct lv_helper_cache *c = realloc(l->helpers, (l->n_helpers + 1) * sizeof *c);
		if (c) {
			l->helpers = c;
			c[l->n_helpers++] = (struct lv_helper_cache){pt, h, st};
		}
	}
	return have(st, out, msg, "helper");
}

/* kload's tracing helper (the memo remembers errors and Unknown alike) */
/* kload's probeTracingHelper. The Unknown sentence matches Go byte for byte: `Tracing helper probe (<at>, <helper>): <reason>: cannot be
 * determined on this target`. For Unknown, *why receives the reason sentence (malloc'd). */
static int probe_tracing_helper(struct bml_live *l, const char *at, const char *helper, int64_t id, int *value, char **why)
{
	struct lv_prog p = {0};
	struct bml_buf b = {0};
	*value = 0;
	*why = NULL;
	if (strcmp(at, "trace_fentry") == 0 || strcmp(at, "trace_fexit") == 0) {
		p.attach_type = strcmp(at, "trace_fentry") == 0 ? BPF_TRACE_FENTRY : BPF_TRACE_FEXIT;
		p.attach_to = "bpf_fentry_test1";
		p.attach_kind = KBTF_FUNC;
	} else if (strcmp(at, "trace_raw_tp") == 0) {
		p.attach_type = BPF_TRACE_RAW_TP;
		p.attach_to = "btf_trace_sched_process_fork";
		p.attach_kind = KBTF_TYPEDEF;
	} else if (strcmp(at, "trace_iter") == 0) { /* cilium resolves AttachTo bpf_map_elem to FUNC bpf_iter_bpf_map_elem */
		p.attach_type = BPF_TRACE_ITER;
		p.attach_to = "bpf_iter_bpf_map_elem";
		p.attach_kind = KBTF_FUNC;
	} else if (strcmp(at, "modify_return") == 0) {
		p.attach_type = BPF_MODIFY_RETURN;
		p.attach_to = "bpf_modify_return_test";
		p.attach_kind = KBTF_FUNC;
	} else {
		bml_buf_adds(&b, "no Tracing helper probe for attach type ");
		bml_buf_add_goquote(&b, at, strlen(at));
		bml_buf_adds(&b, ": cannot be determined on this target");
		*why = bml_buf_take(&b);
		return BML_Q_UNKNOWN;
	}
	uint32_t h = (uint32_t)id;
	if (h & 0x70000000u) { /* a marshal error (cilium's asm: a constant of a non-Linux platform); it is not a VerifierError */
		bml_buf_addf(&b, "Tracing helper probe (%s, %s): instruction 0: function BuiltinFunc(%d) (): not supported on linux: cannot be determined on this target",
			     at, helper, (int32_t)h);
		*why = bml_buf_take(&b);
		return BML_Q_UNKNOWN;
	}
	uint8_t ins[32];
	helper_insns(ins, h);
	p.type = BPF_PROG_TYPE_TRACING;
	p.insns = ins;
	p.n_insns = 4;
	p.license = "GPL";
	p.name = "helper_probe";
	p.log_mode = LV_LOG_1;
	struct lv_res r;
	int ok = lv_prog_load(l, &p, &r) == 0;
	lv_close(r.fd);
	char tag[32];
	snprintf(tag, sizeof tag, "#%lld", (long long)id);
	int rc = BML_Q_UNKNOWN;
	if (ok) {
		*value = 1;
		rc = BML_Q_OK;
	} else if (!r.verifier) {
		char *e = bml_go_errno_str(r.err);
		bml_buf_addf(&b, "Tracing helper probe (%s, %s): load program: %s: cannot be determined on this target", at, helper, e ? e : "");
		free(e);
	} else if (r.err == EACCES) {
		*value = 1;
		rc = BML_Q_OK;
	} else if (r.err == EINVAL && helper_rejected(r.lines, 0, r.n_lines, tag))
		rc = BML_Q_OK;
	else {
		for (size_t i = 0; i < r.n_lines; i++)
			if (has2(r.lines[i], "supported only for", tag))
				rc = BML_Q_OK;
		if (rc == BML_Q_UNKNOWN) { /* the helper line of the log (if there is none, the last line before the processed line), quoted with %q */
			const char *last = "";
			for (size_t i = 0; i < r.n_lines; i++)
				if (strstr(r.lines[i], tag))
					last = r.lines[i];
			if (!last[0])
				for (size_t i = 0; i < r.n_lines; i++)
					if (strncmp(r.lines[i], "processed ", 10) != 0)
						last = r.lines[i];
			bml_buf_addf(&b, "Tracing helper probe (%s, %s): the verifier rejected it for another reason (", at, helper);
			bml_buf_add_goquote(&b, last, strlen(last));
			bml_buf_adds(&b, "): cannot be determined on this target");
		}
	}
	if (rc == BML_Q_UNKNOWN && !BML_MUT("live.tracing_helper_text_old"))
		*why = bml_buf_take(&b);
	else
		bml_buf_free(&b);
	lv_res_free(&r);
	return rc;
}

int bml_live_tracing_helper(struct bml_live *l, const char *attach_type, const char *helper, int64_t helper_id, int *out, char **msg)
{
	char key[128];
	snprintf(key, sizeof key, "th:%s/%lld", attach_type, (long long)helper_id);
	struct lv_memo *m = lv_memo_get(l, key);
	int rc, v;
	const char *why;
	if (m) {
		rc = m->rc;
		v = m->value;
		why = m->msg;
	} else {
		char *w = NULL;
		rc = probe_tracing_helper(l, attach_type, helper, helper_id, &v, &w);
		if (lv_memo_put(l, key, rc, v) != 0) {
			free(w);
			*msg = strdup("out of memory");
			return BML_Q_ERROR;
		}
		l->memo[l->n_memo - 1].msg = w; /* Go's memo also remembers the answer and the error sentence (the key is the attach kind and id; the name is that of the first query) */
		why = w;
	}
	*out = v;
	if (rc == BML_Q_UNKNOWN)
		return unknown(msg, why ? why : "tracing helper probe could not decide");
	return rc;
}

int bml_live_tcx(struct bml_live *l, int *out, char **msg)
{
	struct lv_prog p = {0};
	struct lv_res r;
	*out = 0;
	p.type = BPF_PROG_TYPE_SCHED_CLS;
	p.insns = insn_mov_ret;
	p.n_insns = 2;
	p.license = "GPL";
	p.log_mode = LV_LOG_0;
	int ok = lv_prog_load(l, &p, &r) == 0;
	lv_res_free(&r);
	if (!ok)
		return unknown(msg, "load a sched_cls probe failed");
	uint8_t attr[64] = {0};
	uint32_t v[3] = {(uint32_t)r.fd, 0xffffffffu, BPF_TCX_INGRESS};
	memcpy(attr, v, sizeof v);
	int rc = lv_bpf(BPF_LINK_CREATE, attr, sizeof attr);
	if (!BML_MUT("live.tcx_keep_prog"))
		lv_close(r.fd);
	if (rc >= 0) {
		lv_close(rc); /* kload does not close it (the answer is the same) */
		return unknown(msg, "create a tcx link on ifindex ^0 succeeded unexpectedly");
	}
	if (rc == -ENODEV) {
		*out = 1;
		return BML_Q_OK;
	}
	if (rc == -EINVAL)
		return BML_Q_OK;
	return unknown(msg, "create a tcx link failed");
}
