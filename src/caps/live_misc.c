

#define _GNU_SOURCE
#include "caps/live_internal.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/mutation.h"

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
	size_t n = 0;
	for (; h[0] && h[1] && n < cap; h += 2) {
		int a = h[0] <= '9' ? h[0] - '0' : h[0] - 'a' + 10, b = h[1] <= '9' ? h[1] - '0' : h[1] - 'a' + 10;
		out[n++] = (uint8_t)(a << 4 | b);
	}
	return n;
}

static const struct {
	const char *name, *hex;
} feature_blob[] = {
	{"int", "9feb010018000000000000001000000010000000050000000100000000000001040000002000000100696e7400"},
	{"ptr", "9feb010018000000000000001c0000001c000000050000000100000000000001040000002000000100000000000000020100000000696e7400"},
	{"const", "9feb010018000000000000001c0000001c0000000500000001000000000000010400000020000001000000000000000a0100000000696e7400"},
	{"array", "9feb010018000000000000002800000028000000050000000100000000000001040000002000000100000000000000030000000001000000010000000100000000696e7400"},
	{"struct", "9feb010018000000000000002800000028000000090000000100000000000001040000002000000105000000010000040400000007000000010000000000000000696e740073006100"},
	{"func", "9feb0100180000000000000030000000300000000900000001000000000000010400000020000001000000000100000d010000000500000001000000070000000000000c0200000000696e740061006600"},
	{"func_proto", "9feb0100180000000000000030000000300000000900000001000000000000010400000020000001000000000100000d010000000500000001000000070000000000000c0200000000696e740061006600"},
	{"func_global", "9feb0100180000000000000030000000300000000900000001000000000000010400000020000001000000000100000d010000000500000001000000070000000100000c0200000000696e740061006600"},
	{"var", "9feb0100180000000000000020000000200000000700000001000000000000010400000020000001050000000000000e010000000100000000696e74007600"},
	{"datasec", "9feb0100180000000000000038000000380000000d00000001000000000000010400000020000001050000000000000e0100000001000000070000000100000f0400000002000000000000000400000000696e740076002e6461746100"},
	{"decl_tag", "9feb0100180000000000000040000000400000001400000001000000000000010400000020000001000000000100000d010000000500000001000000070000000100000c020000000900000000000011030000000000000000696e740061006600656270665f70726f626500"},

	{"type_tag", "9feb010018000000000000002800000028000000100000000100000000000001040000002000000105000000000000120100000000000000000000020200000000696e7400656270665f70726f626500"},
	{"enum", "9feb0100180000000000000024000000240000000900000001000000000000010400000020000001050000000100000604000000070000000000000000696e740065004500"},
	{"enum64", "9feb010018000000000000002800000028000000090000000100000000000001040000002000000105000000010000130800000007000000000000000000000000696e740065004500"},
};

int bml_live_btf_feature(struct bml_live *l, const char *feature, int *out, char **msg)
{
	*out = 0;
	const char *hex = NULL;
	for (size_t i = 0; i < sizeof feature_blob / sizeof *feature_blob; i++)
		if (strcmp(feature_blob[i].name, feature) == 0)
			hex = feature_blob[i].hex;
	if (!hex) {
		*msg = strdup("no probe blob for BTF feature");
		return BML_Q_ERROR;
	}
	uint8_t blob[128];
	size_t n = unhex(hex, blob, sizeof blob);
	struct lv_res r;
	int fd = lv_btf_handle(l, blob, n, &r);
	int has;
	if (fd >= 0) {
		lv_close(fd);
		has = 1;
	} else if (!r.notsup && r.err == EINVAL)
		has = 0;
	else {
		

		struct bml_buf b = {0};
		if (r.notsup && !BML_MUT("live.attach_target_errno"))
			bml_buf_addf(&b, "probe BTF %s: BTF not supported (requires >= v4.18)", feature);
		else
			bml_buf_adds(&b, "probe BTF: load failed");
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	}

	struct lv_kmo o;
	lv_kmo(l, &o);
	int rw = -1;
	if (strcmp(feature, "func_global") == 0)
		rw = o.strip_func_linkage;
	else if (strcmp(feature, "decl_tag") == 0)
		rw = o.replace_decl_tags;
	else if (strcmp(feature, "type_tag") == 0)
		rw = o.replace_type_tags;
	else if (strcmp(feature, "enum64") == 0)
		rw = o.replace_enum64;
	if (rw >= 0 && rw == has) {
		*msg = strdup("the probe and cilium/ebpf's own probe disagree");
		return BML_Q_UNKNOWN;
	}
	*out = has;
	return BML_Q_OK;
}


static const char argtag_insns[] = "b702000000000000" "7b2af8ff00000000" "bfa1000000000000" "07010000f8ffffff" "8510000002000000"
				   "b700000002000000" "9500000000000000" "7910000000000000" "9500000000000000";
static const uint8_t argtag_func_info[] = {0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 2, 0, 0, 0};
static const char argtag_btf_u[] =
	"9feb0100180000000000000078000000780000001e000000010000000100000c050000000e0000000100000c080000001000000000000001040000002000"
	"0001000000000000000200000000000000000100000d03000000140000000400000018000000000000010800000040000000000000000000000206000000"
	"000000000100000d030000001c00000007000000006172677461675f70726f6265006600696e740063747800753634007000";
static const char argtag_btf_t[] =
	"9feb0100180000000000000088000000880000002a000000010000000100000c050000000e0000000100000c080000001000000000000001040000002000"
	"0001000000000000000200000000000000000100000d03000000140000000400000018000000000000010800000040000000000000000000000206000000"
	"000000000100000d030000001c000000070000001e000000000000110200000000000000006172677461675f70726f6265006600696e74006374780075"
	"36340070006172673a6e6f6e6e756c6c00";


static int load_line(struct bml_live *l, struct lv_prog *p, const char *pick, const char *tp, char **line, char **why)
{
	struct lv_res r;
	*line = NULL;
	int ok = lv_prog_load(l, p, &r) == 0;
	lv_close(r.fd);
	if (ok) {
		*line = strdup("accept");
		lv_res_free(&r);return *line?BML_Q_OK:BML_Q_ERROR;
	}
	if (!r.verifier) {
		char *e=lv_res_text(&r);
		int rc=e?(tp?lv_unknownf(why,"nullable-argument probe (%s) did not reach the verifier: %s",tp,e)
			:lv_unknownf(why,"argument-tag probe did not reach the verifier: %s",e)):BML_Q_ERROR;
		free(e);
		lv_res_free(&r);
		return rc;
	}
	struct bml_buf b = {0};
	for (size_t i = 0; i < r.n_lines && !b.len; i++) {
		int hit = strcmp(pick, "argtag") == 0
				  ? strstr(r.lines[i], "invalid") || strstr(r.lines[i], "arg#") || strstr(r.lines[i], "tag")
				  : strstr(r.lines[i], "invalid mem access") != NULL;
		if (hit)
			bml_buf_adds(&b, r.lines[i]);
	}
	if (!b.len)
		for (size_t i = 0; i < r.n_lines; i++) {
			if (i)
				bml_buf_adds(&b, " | ");
			bml_buf_adds(&b, r.lines[i]);
		}
	lv_res_free(&r);

	char *s = bml_buf_take(&b);
	if (!s)
		s = strdup("");
	if(!s)return BML_Q_ERROR;
	char *st = s;
	while (*st == ' ' || *st == '\t' || *st == '\n' || *st == '\r' || *st == '\v' || *st == '\f')
		st++;
	size_t n = strlen(st);
	while (n && (st[n - 1] == ' ' || st[n - 1] == '\t' || st[n - 1] == '\n' || st[n - 1] == '\r' || st[n - 1] == '\v' ||
		     st[n - 1] == '\f'))
		n--;
	*line = strndup(st, n);
	free(s);
	return *line?BML_Q_OK:BML_Q_ERROR;
}

static int probe_arg_tag(struct bml_live *l, const char *name, uint32_t pt, const char *tag, const char *cls, int *value, char **why)
{
	*value = 0;
	if(pt!=BPF_PROG_TYPE_XDP)return lv_unknownf(why,"no argument-tag probe for program type %s",name);
	if(strcmp(tag,"arg:nonnull") || strcmp(cls,"mem"))return lv_unknownf(why,"no probe for %s on %s pointers",tag,cls);
	struct lv_kmo o;
	lv_kmo(l, &o);
	if (o.replace_decl_tags)
		return lv_unknownf(why,"the loader would replace decl tags on this target");
	uint8_t ins[72], bu[256], bt[256];
	unhex(argtag_insns, ins, sizeof ins);
	size_t nu = unhex(argtag_btf_u, bu, sizeof bu), nt = unhex(argtag_btf_t, bt, sizeof bt);
	struct lv_prog p = {0};
	p.type = BPF_PROG_TYPE_XDP;
	p.insns = ins;
	p.n_insns = 9;
	p.license = "GPL";
	p.name = "argtag_probe";
	p.log_mode = LV_LOG_0;
	p.func_info = argtag_func_info;
	p.func_info_cnt = 2;
	p.bpf2bpf = 1;
	p.btf = bu;
	p.btf_len = nu;
	const char *mem_or_null = "invalid mem access 'mem_or_null'";
	char *u, *t;
	int rc=load_line(l,&p,"argtag",NULL,&u,why);
	if(rc!=BML_Q_OK)return rc;
	int ctl = u && strstr(u, mem_or_null);
	if(!ctl)rc=lv_unknownf(why,"the untagged control was not rejected as \"%s\" (%s) — the probe cannot tell",mem_or_null,u);
	free(u);if(!ctl)return rc;
	p.btf = bt;
	p.btf_len = nt;
	rc=load_line(l,&p,"argtag",NULL,&t,why);
	if(rc!=BML_Q_OK)return rc;
	if (t && strcmp(t, "accept") == 0) {
		*value = 1;
		rc = BML_Q_OK;
	} else if (t && strstr(t, mem_or_null))
		rc = BML_Q_OK;
	else rc=lv_unknownf(why,"the tagged probe was rejected for another reason (%s)",t);
	free(t);
	return rc;
}

int bml_live_arg_tag(struct bml_live *l, const char *prog_type, int64_t prog_type_id, const char *tag, const char *cls, int *out, char **msg)
{
	char key[256];
	snprintf(key, sizeof key, "at:%lld/%s/%s", (long long)prog_type_id, tag, cls);
	struct lv_memo *m = lv_memo_get(l, key);
	if(m)return lv_memo_answer(m,out,msg);
	int v;char *why=NULL;
	int rc=probe_arg_tag(l,prog_type,(uint32_t)prog_type_id,tag,cls,&v,&why);
	return lv_memo_reason(l,key,rc,v,why,out,msg);
}

static int nullable_load(struct bml_live *l, const char *tp, int arg, char **line, char **why)
{
	uint8_t ins[32] = {0x79, 0x12, 0, 0, 0, 0, 0, 0, 0x61, 0x20, 0, 0, 0, 0, 0, 0, 0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95};
	int16_t off = (int16_t)(arg * 8);
	memcpy(ins + 2, &off, 2);
	char target[128];
	snprintf(target, sizeof target, "btf_trace_%s", tp);
	struct lv_prog p = {0};
	p.type = BPF_PROG_TYPE_TRACING;
	p.attach_type = BPF_TRACE_RAW_TP;
	p.attach_to = target;
	p.attach_kind = KBTF_TYPEDEF;
	p.insns = ins;
	p.n_insns = 4;
	p.license = "GPL";
	p.name = "nullable_probe";
	p.log_mode = LV_LOG_0;
	return load_line(l, &p, "nullable", tp, line, why);
}

static int probe_nullable(struct bml_live *l, int *value, char **why)
{
	char *c, *n;
	*value = 0;
	int rc=nullable_load(l,"sched_process_fork",0,&c,why);
	if(rc!=BML_Q_OK)return rc;
	int ok = c && strcmp(c, "accept") == 0;
	if(!ok)rc=lv_unknownf(why,"the control (sched_process_fork argument 0) was not accepted (%s) — the probe cannot tell",c);
	free(c);
	if(!ok)return rc;
	rc=nullable_load(l,"sched_pi_setprio",1,&n,why);
	if(rc!=BML_Q_OK)return rc;
	if (n && strcmp(n, "accept") == 0)
		rc = BML_Q_OK;
	else if (n && strstr(n, "or_null")) {
		*value = 1;
		rc = BML_Q_OK;
	}
	else rc=lv_unknownf(why,"the NULL-able read was rejected for another reason (%s)",n);
	free(n);
	return rc;
}

int bml_live_nullable_args(struct bml_live *l, int *out, char **msg)
{
	const char *key="nullable";struct lv_memo *m=lv_memo_get(l,key);
	if(m)return lv_memo_answer(m,out,msg);
	int v;char *why=NULL;int rc=probe_nullable(l,&v,&why);
	return lv_memo_reason(l,key,rc,v,why,out,msg);
}
