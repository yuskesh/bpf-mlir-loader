
#define _GNU_SOURCE
#include "caps/live_arena.h"
#include "caps/live_internal.h"
#include "util/gostr.h"
#include <linux/bpf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int lv_arena_kfunc_name(const char *name)
{
	return !strcmp(name,"bpf_arena_alloc_pages") || !strcmp(name,"bpf_arena_free_pages");
}

static int dependency(struct bml_live *l,const char *name,const char *ret,const struct bml_str *args,size_t n,uint32_t *id,char **msg)
{
	const char *why=NULL;const struct bml_kbtf *kb=lv_kb(l,&why);
	if(!kb)return lv_unknownf(msg,"arena kfunc %s BTF unavailable: %s",name,why?why:"");
	char *err=NULL;int rc=lv_lookup(kb,name,KBTF_FUNC,id,&err);
	if(rc<0){free(err);*msg=strdup("out of memory");return BML_Q_ERROR;}
	if(rc){int st=lv_unknownf(msg,"arena kfunc %s lookup: %s",name,err?err:"out of memory");free(err);return st;}
	struct kbtf_type fn,fp;bml_kbtf_type(kb,*id,&fn);bml_kbtf_type(kb,fn.size_type,&fp);
	if(fp.kind!=KBTF_FUNC_PROTO || !*id || *id>INT32_MAX)return lv_unknownf(msg,"arena kfunc %s invalid FUNC_PROTO/ID",name);
	struct bml_strs diffs={0};int st=bml_live_kfunc(l,name,ret,args,n,&diffs,msg);
	if(st!=BML_Q_OK)return st;
	if(diffs.n){
		struct bml_buf b={0};for(size_t i=0;i<diffs.n;i++)bml_buf_addf(&b,"%s%s",i?"; ":"",diffs.s[i]);
		char *detail=bml_buf_take(&b);bml_strs_free(&diffs);
		st=lv_unknownf(msg,"arena kfunc %s prototype: %s",name,detail?detail:"out of memory");free(detail);return st;
	}
	return BML_Q_OK;
}


static int classify(const char *name,struct lv_res *r,char **msg)
{
	char want[128];snprintf(want,sizeof want,"calling kernel function %s is not allowed",name);
	int named=0,other=0;
	for(size_t i=0;r->verifier && i<r->n_lines;i++){
		const char *s=r->lines[i];while(*s==' ' || *s=='\t')s++;
		size_t n=strlen(s);while(n && (s[n-1]==' ' || s[n-1]=='\t' || s[n-1]=='\n' || s[n-1]=='\r'))n--;
		if(n==strlen(want) && !memcmp(s,want,n))named=1;
		else if(memmem(s,n,"calling kernel function ",24) && memmem(s,n," is not allowed",15))other=1;
	}
	if(named && !other)return BML_Q_OK;
	char *detail=lv_res_text(r);
	int st=lv_unknownf(msg,"arena kfunc load does not establish named permission denial: %s",detail?detail:"");
	free(detail);return st;
}

static void insn(uint8_t out[8],uint8_t code,uint8_t regs,int32_t imm)
{
	memset(out,0,8);out[0]=code;out[1]=regs;for(unsigned j=0;j<4;j++)out[j+4]=(uint8_t)((uint32_t)imm>>(8*j));
}

int lv_arena_kfunc_load(struct bml_live *l,const struct bml_kfunc_profile *p,const char *name,const char *ret,
	const struct bml_str *args,size_t n,int *out,char **msg)
{
	*out=0;*msg=NULL;

	if(strcmp(p->kind,"syscall"))return lv_unknownf(msg,"arena recipe needs original syscall context");
	int alloc=!strcmp(name,"bpf_arena_alloc_pages");
	static const char *const spell[]={"ptr:void","ptr:void","u32","i32","u64"};
	if(!lv_arena_kfunc_name(name) || n!=(alloc?5u:3u) || strcmp(ret,alloc?"ptr:void":"void"))
		return lv_unknownf(msg,"no strict arena kfunc recipe for %s",name);
	for(size_t i=0;i<n;i++)if(args[i].len!=strlen(spell[i]) || memcmp(args[i].p,spell[i],args[i].len))
		return lv_unknownf(msg,"no strict arena kfunc recipe for %s",name);
	uint32_t id=0;int st=dependency(l,name,ret,args,n,&id,msg);if(st!=BML_Q_OK)return st;
	union bpf_attr a;memset(&a,0,sizeof a);
	a.map_type=BPF_MAP_TYPE_ARENA;a.max_entries=1;a.map_flags=BPF_F_MMAPABLE;a.map_extra=UINT64_C(0x100001000);
	int mfd=lv_bpf(BPF_MAP_CREATE,&a,sizeof a);
	if(mfd<0){char *why=bml_go_errno_str(-mfd);st=lv_unknownf(msg,"arena recipe map create: %s",why?why:"");free(why);return st;}
	uint8_t instructions[9][8];memset(instructions,0,sizeof instructions);size_t count=0;
	insn(instructions[count++],0x18,0x11,mfd);count++;
	insn(instructions[count++],0xb7,2,0);insn(instructions[count++],0xb7,3,1);
	if(alloc){insn(instructions[count++],0xb7,4,-1);insn(instructions[count++],0xb7,5,0);}
	insn(instructions[count++],0x85,0x20,(int32_t)id);
	insn(instructions[count++],0xb7,0,0);insn(instructions[count++],0x95,0,0);
	struct lv_prog program={.type=BPF_PROG_TYPE_SYSCALL,.flags=BPF_F_SLEEPABLE,.insns=(const uint8_t *)instructions,
		.n_insns=count,.license="GPL",.name="arena_probe",.log_mode=LV_LOG_1};
	struct lv_res result;
	if(!lv_prog_load(l,&program,&result)){lv_close(result.fd);*out=1;st=BML_Q_OK;}
	else st=classify(name,&result,msg);
	lv_res_free(&result);lv_close(mfd);return st;
}
