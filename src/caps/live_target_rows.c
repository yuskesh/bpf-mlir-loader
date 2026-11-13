#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "util/mutation.h"


int bml_live_netkit_answer(int link_rc)
{
	if (link_rc >= 0)
		return BML_LV_UNEXPECTED;
	if (link_rc == -ENODEV)
		return BML_MUT("live.netkit_enodev_unknown") ? BML_LV_UNKNOWN : BML_LV_TRUE;
	if (link_rc == -EINVAL)
		return BML_MUT("live.netkit_einval_true") ? BML_LV_TRUE : BML_LV_FALSE;
	return BML_LV_UNKNOWN;
}


int bml_live_sleepable_refused_by_type(int verifier, const char *const *lines, size_t n)
{
	if (BML_MUT("live.sleepable_any_refusal"))
		return 1;
	if (!verifier)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (strstr(lines[i], "Program of this type cannot be sleepable"))
			return 1;
	return 0;
}


int bml_live_helper_target_denied(int err, int verifier, const char *const *lines, size_t n)
{
	if (BML_MUT("live.helper_target_any_einval") && err == EINVAL)
		return 1;
	if (!verifier || err != EINVAL)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (strstr(lines[i], "helper call is not allowed in probe"))
			return 1;
	return 0;
}

static void insn(uint8_t *out, uint8_t code, uint8_t regs, int16_t off, int32_t imm)
{
	out[0] = code;
	out[1] = regs;
	out[2] = (uint8_t)off;
	out[3] = (uint8_t)((uint16_t)off >> 8);
	for (unsigned j = 0; j < 4; j++)
		out[j + 4] = (uint8_t)((uint32_t)imm >> (8 * j));
}

static const uint8_t mov_ret[16] = {0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0};


static int probe_close(int fd)
{
	int e = lv_close_checked(fd);
	return BML_MUT("live.target_close_ignored") ? 0 : e;
}


static int add_close_unknown(char **msg, const char *what, int err)
{
	char *e = bml_go_errno_str(err), *line = NULL;
	int st = lv_unknownf(&line, "%s: %s", what, e ? e : "");
	free(e);
	if (st != BML_Q_UNKNOWN)
		return st;
	if (!*msg) {
		*msg = line;
		return st;
	}
	struct bml_buf b = {0};
	bml_buf_addf(&b, "%s\n%s", *msg, line);
	free(*msg);
	free(line);
	*msg = bml_buf_take(&b);
	return *msg ? st : BML_Q_ERROR;
}

int bml_live_netkit(struct bml_live *l, const char *direction, int *out, char **msg)
{
	*out = 0;
	uint32_t at;
	if (!strcmp(direction, "primary"))
		at = BPF_NETKIT_PRIMARY;
	else if (!strcmp(direction, "peer"))
		at = BPF_NETKIT_PEER;
	else {
		struct bml_buf b = {0};
		bml_buf_adds(&b, "netkit: unknown direction ");
		bml_buf_add_goquote(&b, direction, strlen(direction));
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}
	struct lv_prog p = {0};
	struct lv_res r;
	p.type = BPF_PROG_TYPE_SCHED_CLS;
	p.attach_type = at;
	p.insns = mov_ret;
	p.n_insns = 2;
	p.license = "GPL";
	p.log_mode = LV_LOG_0;
	if (lv_prog_load(l, &p, &r)) {
		char *e = lv_res_text(&r);
		int st = lv_unknownf(msg, "load a netkit %s probe: %s", direction, e ? e : "");
		free(e);
		lv_res_free(&r);
		return st;
	}
	int prog = r.fd;
	lv_res_free(&r);
	uint8_t attr[64] = {0};
	uint32_t v[3] = {(uint32_t)prog, 0xffffffffu                                            , at};
	memcpy(attr, v, sizeof v);
	int rc = lv_bpf(BPF_LINK_CREATE, attr, sizeof attr);
	int ans = bml_live_netkit_answer(rc), st;
	if (ans == BML_LV_TRUE || ans == BML_LV_FALSE) {
		*out = ans == BML_LV_TRUE;
		st = BML_Q_OK;
	} else if (ans == BML_LV_UNEXPECTED) {
		st = lv_unknownf(msg, "create a netkit %s link on ifindex ^0 succeeded unexpectedly", direction);
		int le = probe_close(rc);
		if (le)
			st = add_close_unknown(msg, "close unexpected netkit link", -le);
	} else {
		char *e = bml_go_errno_str(-rc);
		st = lv_unknownf(msg, "create a netkit %s link: %s", direction, e ? e : "");
		free(e);
	}
	int pe = probe_close(prog);
	if (pe) {
		*out = 0;
		st = add_close_unknown(msg, "close netkit probe program", -pe);
	}
	return st;
}

static const char *sleepable_target(void)
{
#if defined(__x86_64__)
	return "__x64_sys_getpgid";
#elif defined(__aarch64__)
	return "__arm64_sys_getpgid";
#else
	return "";
#endif
}

static int load_fentry(struct bml_live *l, const char *name, const char *target, uint32_t flags, const uint8_t *ins, size_t n, struct lv_res *r)
{
	struct lv_prog p = {0};
	p.type = BPF_PROG_TYPE_TRACING;
	p.attach_type = BPF_TRACE_FENTRY;
	p.flags = flags;
	p.insns = ins;
	p.n_insns = n;
	p.license = "GPL";
	p.name = name;
	p.log_mode = LV_LOG_1;
	p.attach_to = target;
	p.attach_kind = KBTF_FUNC;
	return lv_prog_load(l, &p, r);
}

int bml_live_sleepable(struct bml_live *l, const char *pt, const char *at, int *out, char **msg)
{
	*out = 0;
	if (strcmp(pt, "tracing") || strcmp(at, "trace_fentry"))
		return lv_unknownf(msg, "sleepable probe (%s/%s): no probe for this pair", pt, at);
	const char *target = sleepable_target();
	if (!target[0])
		return lv_unknownf(msg, "sleepable probe (%s/%s): no sleepable-capable probe target for this architecture", pt, at);
	struct lv_res s;
	if (load_fentry(l, "ebpf_slp_probe", target, BPF_F_SLEEPABLE, mov_ret, 2, &s) == 0) {
		int e = probe_close(s.fd);
		lv_res_free(&s);
		if (e)
			return add_close_unknown(msg, "close the accepted sleepable probe program", -e);
		*out = 1;
		return BML_Q_OK;
	}
	char *stxt = lv_res_text(&s);
	int st;
	struct lv_res c;
	if (load_fentry(l, "ebpf_slp_probe", target, 0, mov_ret, 2, &c)) {
		char *ctxt = lv_res_text(&c);
		st = lv_unknownf(msg, "sleepable probe (%s/%s): the sleepable load failed (%s) and so did the control load without the flag (%s)", pt, at,
				 stxt ? stxt : "", ctxt ? ctxt : "");
		free(ctxt);
	} else {
		int e = probe_close(c.fd);
		if (e) {
			st = lv_unknownf(msg, "sleepable probe (%s/%s): the sleepable load was refused (%s)", pt, at, stxt ? stxt : "");
			st = add_close_unknown(msg, "close the control sleepable probe program", -e);
		} else if (bml_live_sleepable_refused_by_type(s.verifier, (const char *const *)s.lines, s.n_lines))
			st = BML_Q_OK;
		else
			st = lv_unknownf(msg, "sleepable probe (%s/%s): the sleepable load was refused for another reason than the program type (%s) while the control load succeeded",
					 pt, at, stxt ? stxt : "");
	}
	lv_res_free(&c);
	lv_res_free(&s);
	free(stxt);
	return st;
}


static size_t helper_target_insns(uint8_t ins[][8])
{
	size_t n = 0;
	insn(ins[n++], 0x79, 0x11, 0, 0);
	insn(ins[n++], 0x15, 0x01, 13, 0);
	insn(ins[n++], 0xb7, 0x00, 0, 0);
	for (int16_t off = -64; off < 0; off += 8)
		insn(ins[n++], 0x7b, 0x0a, off, 0);
	insn(ins[n++], 0xbf, 0xa2, 0, 0);
	insn(ins[n++], 0x07, 0x02, 0, -64);
	insn(ins[n++], 0xb7, 0x03, 0, 64);
	insn(ins[n++], 0x85, 0x00, 0, 147);
	insn(ins[n++], 0xb7, 0x00, 0, 0);
	insn(ins[n++], 0x95, 0x00, 0, 0);
	return n;
}

static int one_diff(struct bml_strs *out, char *text, char **msg)
{
	out->s = calloc(1, sizeof *out->s);
	if (!out->s || !text) {
		free(text);
		free(out->s);
		out->s = NULL;
		*msg = strdup("out of memory");
		return BML_Q_ERROR;
	}
	out->s[0] = text;
	out->n = 1;
	return BML_Q_OK;
}

int bml_live_helper_target(struct bml_live *l, const char *pt, int64_t id, const struct bml_helper_target *h, struct bml_strs *out, char **msg)
{
	memset(out, 0, sizeof *out);
	if (strcmp(pt, "tracing") || id != BPF_PROG_TYPE_TRACING || strcmp(h->helper.p, "d_path") || h->helper_id != 147 ||
	    strcmp(h->attach_type.p, "trace_fentry") || h->arg_index != 0 || strcmp(h->arg_type.p, "path"))
		return one_diff(out, strdup("unsupported target-specific helper profile"), msg);
	struct bml_str path = {(char *)"path", 4};
	int st = bml_live_func_args(l, h->target.p, &path, 1, out, msg);
	if (st != BML_Q_OK || out->n)
		return st;
	uint8_t ins[17][8];
	size_t n = helper_target_insns(ins);
	struct lv_res r;
	if (load_fentry(l, "typed_dpath", h->target.p, 0, (const uint8_t *)ins, n, &r) == 0) {
		int e = probe_close(r.fd);
		lv_res_free(&r);
		if (e) {
			char *t = bml_go_errno_str(-e);
			struct bml_buf b = {0};
			bml_buf_addf(&b, "helper_target close: %s", t ? t : "");
			free(t);
			*msg = bml_buf_take(&b);
			return BML_Q_ERROR;
		}
		return BML_Q_OK;
	}
	struct bml_buf log = {0};
	for (size_t i = 0; i < r.n_lines; i++)
		bml_buf_addf(&log, "%s%s", i ? "\n" : "", r.lines[i]);
	char *joined = bml_buf_take(&log);
	if (bml_live_helper_target_denied(r.err, r.verifier, (const char *const *)r.lines, r.n_lines)) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "helper d_path is not allowed at trace_fentry/%s: %s", h->target.p, joined ? joined : "");
		st = one_diff(out, bml_buf_take(&b), msg);
	} else if (r.verifier) {
		char *e = bml_go_errno_str(r.err);
		st = lv_unknownf(msg, "helper_target trace_fentry/%s load was not accepted: errno %s; verifier log:\n%s", h->target.p, e ? e : "", joined ? joined : "");
		free(e);
	} else {
		char *e = lv_res_text(&r);
		st = lv_unknownf(msg, "helper_target trace_fentry/%s load was not accepted: %s", h->target.p, e ? e : "");
		free(e);
	}
	free(joined);
	lv_res_free(&r);
	return st;
}
