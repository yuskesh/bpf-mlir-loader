


#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include "load/load.h"
#include "util/mutation.h"

#define RUN_FUNCS "test_run_skb_data / test_run_flow_dissector / test_run_ctx_inout / test_run_netfilter / test_run_xdp_data / test_run_tracing"
#define NF_HOOK_STATE_SIZE 48


static int64_t run_prog(int64_t obj, const char *prog, int64_t len, int family, const char *what, struct bpf_program **p, const char **kind)
{
	int64_t e;
	struct abi_object *o = abi_object_get(obj, &e);
	if (!o || (e = abi_program(o, prog, len, p)))
		return e;
	int fam = BML_RUN_NONE;
	const char *k = bml_load_section_kind(bpf_program__section_name(*p), &fam);
	*kind = k ? k : abi_kind_name(o, *p);
	if (fam != family && !BML_MUT("run.kind_any"))
		return abi_fail(BML_STATE, "bml: %s is a %s program, not %s — test-run it with its own function (%s)", bpf_program__name(*p), *kind,
				what, RUN_FUNCS);
	return 0;
}

static int bad_buf(const void *b, int64_t n)
{
	return n < 0 || n > UINT32_MAX || (!b && n);
}

static int64_t run_err(const char *kind, const char *name, int err)
{
	return abi_fail(BML_OTHER, "bml: %s test run %s: %s", kind, name, abi_errno(err));
}

static int64_t skb_body(int64_t obj, const char *prog, int64_t len, const uint8_t *data, int64_t n)
{
	struct bpf_program *p;
	const char *kind;
	int64_t e = run_prog(obj, prog, len, BML_RUN_SKB, "an skb program (socket_filter / sched_cls / sched_act / cgroup_skb / lwt_*)", &p, &kind);
	if (e)
		return e;
	if (bad_buf(data, n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	LIBBPF_OPTS(bpf_test_run_opts, t, .data_in = data, .data_size_in = (uint32_t)n, .repeat = 1);
	if (bpf_prog_test_run_opts(bpf_program__fd(p), &t) != 0)
		return run_err(kind, bpf_program__name(p), errno);
	return abi_ok((int64_t)(int32_t)t.retval);
}

static int64_t flow_body(int64_t obj, const char *prog, int64_t len, const uint8_t *data, int64_t n, uint8_t *keys, int64_t cap)
{
	struct bpf_program *p;
	const char *kind;
	int64_t e = run_prog(obj, prog, len, BML_RUN_FLOW, "flow_dissector", &p, &kind);
	if (e)
		return e;
	if (bad_buf(data, n) || bad_buf(keys, cap))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	if ((uint64_t)cap < sizeof(struct bpf_flow_keys))
		return abi_fail(BML_VALUE_RANGE, "bml: flow_dissector test run %s: the keys buffer has %lld bytes, struct bpf_flow_keys needs %zu (not truncated)",
				bpf_program__name(p), (long long)cap, sizeof(struct bpf_flow_keys));
	LIBBPF_OPTS(bpf_test_run_opts, t, .data_in = data, .data_size_in = (uint32_t)n, .data_out = keys, .data_size_out = (uint32_t)cap,
		    .repeat = 1);
	if (bpf_prog_test_run_opts(bpf_program__fd(p), &t) != 0)
		return run_err(kind, bpf_program__name(p), errno);
	if ((int64_t)t.data_size_out != cap)
		return abi_fail(BML_VALUE_RANGE, "bml: flow_dissector test run %s: the kernel wrote %u bytes of flow keys into a %lld-byte buffer",
				bpf_program__name(p), t.data_size_out, (long long)cap);
	return abi_ok((int64_t)(int32_t)t.retval);
}

static int64_t ctx_body(int64_t obj, const char *prog, int64_t len, uint8_t *ctx, int64_t n)
{
	struct bpf_program *p;
	const char *kind;
	int64_t e = run_prog(obj, prog, len, BML_RUN_CTX, "a ctx-only program (syscall / raw_tp / sk_lookup)", &p, &kind);
	if (e)
		return e;
	const char *name = bpf_program__name(p);
	if (bad_buf(ctx, n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	int raw = !strcmp(kind, "raw_tp"), sys = !strcmp(kind, "syscall"), skl = !strcmp(kind, "sk_lookup");
	if (raw && (n % 8 != 0 || n > 12 * 8))
		return abi_fail(BML_VALUE_RANGE, "bml: raw_tp test run %s: the ctx has %lld bytes — the arguments are u64 values, at most 12 (96 bytes)", name,
				(long long)n);
	if (sys && n > 65535)
		return abi_fail(BML_VALUE_RANGE, "bml: syscall test run %s: the ctx has %lld bytes, at most 65535", name, (long long)n);
	

	LIBBPF_OPTS(bpf_test_run_opts, t, .ctx_in = ctx, .ctx_size_in = (uint32_t)n);
	if (skl) {
		t.ctx_out = ctx;
		t.ctx_size_out = (uint32_t)n;
		t.repeat = 1;
	}
	int rc = bpf_prog_test_run_opts(bpf_program__fd(p), &t), err = errno;
	if (rc != 0)
		return run_err(kind, name, err);
	if (skl && (int64_t)t.ctx_size_out != n)
		return abi_fail(BML_VALUE_RANGE, "bml: sk_lookup test run %s: the kernel wrote back %u bytes of ctx into a %lld-byte buffer", name,
				t.ctx_size_out, (long long)n);
	return abi_ok((int64_t)(int32_t)t.retval);
}

static int64_t nf_body(int64_t obj, const char *prog, int64_t len, const uint8_t *data, int64_t n, int64_t pf, int64_t hook)
{
	struct bpf_program *p;
	const char *kind;
	int64_t e = run_prog(obj, prog, len, BML_RUN_NF, "netfilter", &p, &kind);
	if (e)
		return e;
	if (bad_buf(data, n))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL buffer with a length");
	if (pf != 2 && pf != 10)
		return abi_fail(BML_VALUE_RANGE, "bml: netfilter test run %s: pf %lld — the kernel takes NFPROTO_IPV4 (2) or NFPROTO_IPV6 (10)",
				bpf_program__name(p), (long long)pf);
	if (hook < 0 || hook > 4)
		return abi_fail(BML_VALUE_RANGE, "bml: netfilter test run %s: hook %lld — NF_INET_PRE_ROUTING (0) .. NF_INET_POST_ROUTING (4)",
				bpf_program__name(p), (long long)hook);
	uint8_t st[NF_HOOK_STATE_SIZE] = {0};
	st[0] = (uint8_t)hook;
	st[1] = (uint8_t)pf;
	LIBBPF_OPTS(bpf_test_run_opts, t, .data_in = data, .data_size_in = (uint32_t)n, .ctx_in = st, .ctx_size_in = sizeof st, .repeat = 1);
	if (bpf_prog_test_run_opts(bpf_program__fd(p), &t) != 0)
		return run_err(kind, bpf_program__name(p), errno);
	return abi_ok((int64_t)(int32_t)t.retval);
}


#define ENTRY(call)                                                                                                                         \
	int64_t e;                                                                                                                          \
	struct abi_object *o = abi_object_acquire(obj, &e);                                                                                 \
	if (!o)                                                                                                                             \
		return e;                                                                                                                   \
	e = call;                                                                                                                           \
	abi_object_release(o);                                                                                                              \
	return e

int64_t bml_test_run_skb_data(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n)
{
	ENTRY(skb_body(obj, prog, prog_len, data, n));
}

int64_t bml_test_run_flow_dissector(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n, uint8_t *keys_out,
				    int64_t keys_cap)
{
	ENTRY(flow_body(obj, prog, prog_len, data, n, keys_out, keys_cap));
}

int64_t bml_test_run_ctx_inout(int64_t obj, const char *prog, int64_t prog_len, uint8_t *ctx_inout, int64_t ctx_len)
{
	ENTRY(ctx_body(obj, prog, prog_len, ctx_inout, ctx_len));
}

int64_t bml_test_run_netfilter(int64_t obj, const char *prog, int64_t prog_len, const uint8_t *data, int64_t n, int64_t pf, int64_t hook)
{
	ENTRY(nf_body(obj, prog, prog_len, data, n, pf, hook));
}
