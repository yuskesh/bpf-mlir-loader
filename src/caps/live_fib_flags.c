

#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int unknown(char **msg, const char *why)
{
	struct bml_buf b = {0}; bml_buf_addf(&b, "%s: cannot be determined on this target", why);
	*msg = bml_buf_take(&b); return *msg ? BML_Q_UNKNOWN : BML_Q_ERROR;
}

static int probe(struct bml_live *l, uint32_t mask, int *out, char **msg)
{
#define I(code_, d, s, off_, imm_) ((struct bpf_insn){.code = (code_), .dst_reg = (d), .src_reg = (s), .off = (off_), .imm = (imm_)})
	struct bpf_insn ins[17];
	size_t n = 0;
	ins[n++] = I(0xbf, 6, 1, 0, 0); ins[n++] = I(0xb7, 0, 0, 0, 0);
	for (int off = -64; off < 0; off += 8) ins[n++] = I(0x7b, 10, 0, off, 0);
	ins[n++] = I(0xbf, 1, 6, 0, 0); ins[n++] = I(0xbf, 2, 10, 0, 0);
	ins[n++] = I(0x07, 2, 0, 0, -64); ins[n++] = I(0xb7, 3, 0, 0, 64);
	ins[n++] = I(0xb7, 4, 0, 0, (int32_t)mask); ins[n++] = I(0x85, 0, 0, 0, 69); ins[n++] = I(0x95, 0, 0, 0, 0);
#undef I
	struct lv_prog p = {.type = BPF_PROG_TYPE_XDP, .insns = (const uint8_t *)ins, .n_insns = n,
		.license = "GPL", .name = "ebpf_fib_probe", .log_mode = LV_LOG_DISABLED};
	struct lv_res r;
	if (lv_prog_load(l, &p, &r)) {
		char *text = lv_res_text(&r);
		struct bml_buf b = {0}; bml_buf_addf(&b, "the fib_lookup probe did not run (load: %s)", text ? text : "out of memory");
		free(text); lv_close(r.fd); lv_res_free(&r);
		char *why = bml_buf_take(&b);
		if (!why) return (*msg = strdup("out of memory"), BML_Q_ERROR);
		int st = unknown(msg, why); free(why); return st;
	}
	uint8_t data[64] = {0};
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = (uint32_t)r.fd; attr.test.data_size_in = sizeof(data);
	attr.test.data_in = (uint64_t)(uintptr_t)data; attr.test.repeat = 1;
	int rc = lv_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	lv_close(r.fd); lv_res_free(&r);
	if (rc < 0) {
		char *text = bml_go_errno_str(-rc);
		struct bml_buf b = {0}; bml_buf_addf(&b, "the fib_lookup probe did not run (test_run: %s)", text ? text : "out of memory"); free(text);
		char *why = bml_buf_take(&b);
		if (!why) return (*msg = strdup("out of memory"), BML_Q_ERROR);
		int st = unknown(msg, why); free(why); return st;
	}
	int32_t ret = (int32_t)attr.test.retval;
	if (ret == -EAFNOSUPPORT || ret == -EINVAL) { *out = ret == -EAFNOSUPPORT; return BML_Q_OK; }
	char why[96]; snprintf(why, sizeof(why), "the fib_lookup probe returned %d (only -EAFNOSUPPORT or -EINVAL decide)", ret);
	return unknown(msg, why);
}

int bml_live_fib_flags(struct bml_live *l, const char *prog, int64_t id, uint32_t mask, int *out, char **msg)
{
	*out = 0;
	char why[180];
	if (strcmp(prog, "xdp") || id != 6) {
		snprintf(why, sizeof(why), "no fib_lookup flag probe for program type %s/%lld (only xdp/6)", prog, (long long)id);
		return unknown(msg, why);
	}
	if (mask > 1) {
		snprintf(why, sizeof(why), "fib_lookup flag mask %u is not one a fibflags row carries", mask); return unknown(msg, why);
	}
	char key[48]; snprintf(key, sizeof(key), "fib:xdp/6/%u", mask);
	struct lv_memo *m = lv_memo_get(l, key);
	if (!m) {
		char *text = NULL; int value = 0;
		int st = probe(l, mask, &value, &text);
		if (lv_memo_put(l, key, st, value)) { free(text); return (*msg = strdup("out of memory"), BML_Q_ERROR); }
		l->memo[l->n_memo - 1].msg = text;
		m = &l->memo[l->n_memo - 1];
	}
	*out = m->value;
	if (m->rc != BML_Q_OK) *msg = strdup(m->msg ? m->msg : "out of memory");
	return m->rc;
}
