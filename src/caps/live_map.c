


#define _GNU_SOURCE
#include "caps/live_internal.h"

#include "util/gostr.h"
#include "util/mutation.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

struct mt {
	uint32_t key, value, max, flags, inner_fd, btf_fd, btf_key, btf_value, vmlinux_value;
	int ebadf_ok, enotsupp_ok;
};

static int map_type_attrs(uint32_t t, struct mt *m)
{
	memset(m, 0, sizeof *m);
	m->key = 4;
	m->value = 4;
	m->max = 1;
	switch (t) {
	case BPF_MAP_TYPE_STACK_TRACE: m->value = 8; break;
	case BPF_MAP_TYPE_LPM_TRIE: m->key = 8; m->value = 8; m->flags = BPF_F_NO_PREALLOC; break;
	case BPF_MAP_TYPE_ARRAY_OF_MAPS: case BPF_MAP_TYPE_HASH_OF_MAPS: m->inner_fd = 0xffffffffu; m->ebadf_ok = 1; break;
	case BPF_MAP_TYPE_CGROUP_STORAGE: case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: m->key = 16; m->max = 0; break;
	case BPF_MAP_TYPE_QUEUE: case BPF_MAP_TYPE_STACK: m->key = 0; break;
	case BPF_MAP_TYPE_SK_STORAGE: case BPF_MAP_TYPE_INODE_STORAGE: case BPF_MAP_TYPE_TASK_STORAGE: case BPF_MAP_TYPE_CGRP_STORAGE:
		m->max = 0;
		m->flags = BPF_F_NO_PREALLOC;
		m->btf_fd = 0xffffffffu;
		m->btf_key = 1;
		m->btf_value = 1;
		m->ebadf_ok = 1;
		break;
	case BPF_MAP_TYPE_STRUCT_OPS: m->vmlinux_value = 1; m->enotsupp_ok = 1; break;
	case BPF_MAP_TYPE_RINGBUF: case BPF_MAP_TYPE_USER_RINGBUF: m->key = 0; m->value = 0; m->max = (uint32_t)getpagesize(); break;
	case BPF_MAP_TYPE_BLOOM_FILTER: m->key = 0; break;
	case BPF_MAP_TYPE_ARENA: m->key = 0; m->value = 0; m->flags = BPF_F_MMAPABLE; break;
	}
	return 0;
}

static int probe_map_type(uint32_t t)
{
	struct mt m;
	map_type_attrs(t, &m);
	uint8_t attr[96] = {0};
	uint32_t v[6] = {t, m.key, m.value, m.max, m.flags, m.inner_fd};
	memcpy(attr, v, sizeof v);
	memcpy(attr + 48, &m.btf_fd, 4);
	memcpy(attr + 52, &m.btf_key, 4);
	memcpy(attr + 56, &m.btf_value, 4);
	memcpy(attr + 60, &m.vmlinux_value, 4);
	int fd = lv_bpf(BPF_MAP_CREATE, attr, sizeof attr);
	if (fd >= 0) {
		lv_close(fd);
		return LV_OK;
	}
	if (fd == -EINVAL || fd == -E2BIG)
		return LV_NOTSUP;
	if ((m.ebadf_ok && fd == -EBADF) || (m.enotsupp_ok && fd == -ENOTSUPP))
		return LV_OK;
	return fd;
}

int bml_live_map_type(struct bml_live *l, int64_t id, int *out, char **msg)
{
	uint32_t t = (uint32_t)id;
	int st;
	*out = 0;
	if ((t == 0 || t > 33) && !BML_MUT("live.nofeature_text_old")) {
		struct bml_buf b = {0};
		if (t == 0)
			bml_buf_adds(&b, "no feature probe for UnspecifiedMap");
		else
			bml_buf_addf(&b, "no feature probe for MapType(%u)", t);
		*msg = bml_buf_take(&b);
		return BML_Q_ERROR;
	} else if (t == 0 || t > 33)
		st = -1;
	else if (l->map_type[t] != LV_UNSET)
		st = l->map_type[t];
	else {
		st = probe_map_type(t);
		if (st == LV_OK || st == LV_NOTSUP)
			l->map_type[t] = st;
	}
	*out = st == LV_OK;
	if (st == LV_OK || st == LV_NOTSUP)
		return BML_Q_OK;
	

	static const char *const mt_names[34] = {
		"UnspecifiedMap", "Hash", "Array", "ProgramArray", "PerfEventArray", "PerCPUHash", "PerCPUArray", "StackTrace", "CGroupArray",
		"LRUHash", "LRUCPUHash", "LPMTrie", "ArrayOfMaps", "HashOfMaps", "DevMap", "SockMap", "CPUMap", "XSKMap", "SockHash",
		"CGroupStorage", "ReusePortSockArray", "PerCPUCGroupStorage", "Queue", "Stack", "SkStorage", "DevMapHash", "StructOpsMap",
		"RingBuf", "InodeStorage", "TaskStorage", "BloomFilter", "UserRingbuf", "CgroupStorage", "Arena",
	};

	char *e = st < 0 && t >= 1 && t <= 33 && !BML_MUT("live.attach_target_errno") ? bml_go_errno_str(-st) : NULL;
	if (e) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "detect support for %s: %s", mt_names[t], e);
		free(e);
		*msg = bml_buf_take(&b);
	} else
		*msg = strdup("map type: probe failed");
	return BML_Q_ERROR;
}


static const char *const mf_btf[2][2] = {
	{"9feb01001800000000000000440000004400000010000000010000000000000104000000200000000500000002000004080000000c00000003000000000000000e00000003000000200000000100000000000001040000002000000000753332006d665f76616c0066006100",
	 "9feb010018000000000000005c0000005c00000022000000010000000000000104000000200000000500000002000004080000000c00000004000000000000000e0000000300000020000000010000000000000104000000200000001000000001000004040000001e000000030000000000000000753332006d665f76616c00660061006270665f7370696e5f6c6f636b0076616c00"},
	{"9feb010018000000000000006c0000006c00000014000000010000000000000104000000200000000500000002000004180000000c00000005000000000000000e0000000300000080000000010000000000000104000000200000001000000000000001080000004000000000000000000000030000000004000000030000000200000000753332006d665f76616c006600610075363400",
	 "9feb01001800000000000000840000008400000027000000010000000000000104000000200000000500000002000004180000000c00000006000000000000000e000000030000008000000001000000000000010400000020000000100000000000000108000000400000000000000000000003000000000400000003000000020000001400000001000004100000001e000000050000000000000000753332006d665f76616c0066006100753634006270665f74696d6572005f5f6f706171756500"},
};

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
	size_t n = 0;
	for (; h[0] && h[1] && n < cap; h += 2) {
		int a = h[0] <= '9' ? h[0] - '0' : h[0] - 'a' + 10, b = h[1] <= '9' ? h[1] - '0' : h[1] - 'a' + 10;
		out[n++] = (uint8_t)(a << 4 | b);
	}
	return n;
}


static int field_map(struct bml_live *l, const char *name, uint32_t value_size, const char *btf_hex, char **why)
{
	uint8_t btf[256];
	size_t n = unhex(btf_hex, btf, sizeof btf);
	struct lv_kmo o;
	lv_kmo(l, &o);
	struct lv_res r;
	int btf_fd = lv_btf_handle_reason(l, btf, n, &r);
	if (btf_fd < 0) {
		int mb = lv_feat(l, LVF_MAP_BTF);
		if (mb != LV_NOTSUP) {
			char *e=mb==LV_OK?(r.text?strdup(r.text):NULL):bml_go_errno_str(mb<-1?-mb:0);
			if(e){
				if(mb==LV_OK)asprintf(why,"creating map: load BTF: %s",e);
				else asprintf(why,"creating map: load BTF: detect support for Map BTF (Var/Datasec): %s%s",l->feat[LVF_BTF]==LV_OK?"":"detect support for BTF: ",e);
			}
			free(e);lv_res_free(&r);return -1;
		}
	}
	lv_res_free(&r);
	uint8_t attr[96] = {0};
	uint32_t v[4] = {BPF_MAP_TYPE_ARRAY, 4, value_size, 1};
	memcpy(attr, v, sizeof v);
	char nm[16];
	lv_obj_name(l, name, nm);
	memcpy(attr + 28, nm, 16);
	if (btf_fd >= 0) {
		uint32_t b[3] = {(uint32_t)btf_fd, 1, 2};
		memcpy(attr + 48, b, sizeof b);
	}
	int fd = lv_bpf(BPF_MAP_CREATE, attr, sizeof attr);
	if (fd < 0 && (fd == -ENOTSUPP || fd == -EINVAL) && btf_fd >= 0) {
		memset(attr + 48, 0, 12);
		fd = lv_bpf(BPF_MAP_CREATE, attr, sizeof attr);
	}
	lv_close(btf_fd);
	if(fd<0){char *e=bml_go_errno_str(-fd);
		if(e)asprintf(why,"creating map: map create: %s%s",e,fd==-EPERM?" (MEMLOCK may be too low, consider rlimit.RemoveMemlock)":"");
		free(e);}
	return fd >= 0 ? fd : -1;
}

enum { MF_ERROR, MF_ACCEPT, MF_REJECT };

static int map_field_load(struct bml_live *l, uint32_t pt, int map_fd, char **text)
{
	uint8_t ins[32] = {0x18, 0x11};
	uint32_t fd = (uint32_t)map_fd;
	memcpy(ins + 4, &fd, 4);
	ins[16] = 0xb7;
	ins[24] = 0x95;
	struct lv_prog p = {0};
	p.type = pt;
	p.insns = ins;
	p.n_insns = 4;
	p.license = "GPL";
	p.name = "mapfield_probe";
	p.log_mode = LV_LOG_0;
	if (pt == BPF_PROG_TYPE_TRACING) {
		p.attach_type = BPF_TRACE_FENTRY;
		p.attach_to = "do_sys_poll";
		p.attach_kind = KBTF_FUNC;
	}
	struct lv_res r;
	int ok = lv_prog_load(l, &p, &r) == 0;
	lv_close(r.fd);
	int out = ok ? MF_ACCEPT : r.verifier && r.err == EINVAL ? MF_REJECT : MF_ERROR;
	if(ok)*text=strdup("accept");
	else if(out==MF_REJECT){
		const char *last="";size_t len=0;
		for(size_t i=r.n_lines;i>0;i--){
			const char *s=r.lines[i-1];while(*s && strchr(" \t\r\n\v\f",*s))s++;
			size_t n=strlen(s);while(n && strchr(" \t\r\n\v\f",s[n-1]))n--;
			if(n && strncmp(s,"processed ",10) && strncmp(s,"verification time",17)){last=s;len=n;break;}
		}
		asprintf(text,"reject:EINVAL:%.*s",(int)len,last);
	}else{char *e=lv_res_text(&r);if(e){char *nl=strchr(e,'\n');if(nl)*nl=0;asprintf(text,"error:%s",e);}free(e);}
	lv_res_free(&r);
	return out;
}

static int probe_map_field(struct bml_live *l, const char *name, uint32_t pt, const char *field, int *value, char **why)
{
	*value = 0;
	if (pt != BPF_PROG_TYPE_XDP && pt != BPF_PROG_TYPE_KPROBE && pt != BPF_PROG_TYPE_TRACING)
		return lv_unknownf(why,"no map-field probe for program type %s",name);
	int k = strcmp(field, "bpf_spin_lock") == 0 ? 0 : strcmp(field, "bpf_timer") == 0 ? 1 : -1;
	if (k < 0)
		return lv_unknownf(why,"no probe for map field %s",field);
	uint32_t vs = k == 0 ? 8 : 24;
	char *err=NULL;
	int plain = field_map(l, "mf_plain", vs, mf_btf[k][0], &err);
	if (plain < 0){int rc=err?lv_unknownf(why,"creating the map without %s failed (%s)",field,err):BML_Q_ERROR;free(err);return rc;}
	int fm = field_map(l, "mf_field", vs, mf_btf[k][1], &err);
	if (fm < 0) {
		lv_close(plain);
		int rc=err?lv_unknownf(why,"creating the map with %s failed (%s)",field,err):BML_Q_ERROR;free(err);return rc;
	}
	char *at=NULL,*bt=NULL,*ct=NULL;
	int a = map_field_load(l, pt, plain,&at), b = map_field_load(l, pt, fm,&bt), c = map_field_load(l, BPF_PROG_TYPE_XDP, fm,&ct);
	lv_close(fm);
	lv_close(plain);
	int rc=BML_Q_OK;
	if(!at || !bt || !ct)rc=BML_Q_ERROR;
	else if (a != MF_ACCEPT)
		rc=lv_unknownf(why,"the %s probe without %s was not accepted (%s) — cannot attribute a rejection to the field",name,field,at);
	else if (b == MF_ACCEPT) {
		*value = 1;
	}
	else if (c != MF_ACCEPT)
		rc=lv_unknownf(why,"the xdp control with %s was not accepted (%s)",field,ct);
	else if (b != MF_REJECT)
		rc=lv_unknownf(why,"the %s probe with %s failed without a verifier rejection (%s)",name,field,bt);
	free(at);free(bt);free(ct);return rc;
}

int bml_live_map_field(struct bml_live *l, const char *prog_type, int64_t prog_type_id, const char *field, int *out, char **msg)
{
	char key[160];
	snprintf(key, sizeof key, "mf:%lld/%s", (long long)prog_type_id, field);
	struct lv_memo *m = lv_memo_get(l, key);
	if(m)return lv_memo_answer(m,out,msg);
	int v;char *why=NULL;
	int rc=probe_map_field(l,prog_type,(uint32_t)prog_type_id,field,&v,&why);
	return lv_memo_reason(l,key,rc,v,why,out,msg);
}
