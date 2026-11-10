
#include "load/arena_extern.h"
#include "load/internal.h"
#include "caps/live.h"
#include "req/from_elf.h"
#include "req/kfunc_profile.h"
#include <stdlib.h>
#include <string.h>

static int equal(const struct bml_str *s,const char *text)
{return s->len==strlen(text) && !memcmp(s->p,text,s->len);}
static int signature(const struct bml_kfunc *k,int alloc)
{
	static const char *const args[]={"ptr:void","ptr:void","u32","i32","u64"};
	if(k->n_args!=(alloc?5u:3u) || !equal(&k->ret,alloc?"ptr:void":"void"))return 0;
	for(size_t i=0;i<k->n_args;i++)if(!equal(&k->args[i],args[i]))return 0;
	return 1;
}
static int profile(const struct bml_kfunc_profile_entry *p)
{
	return p && !p->reason && !strcmp(p->kind,"syscall") && !strcmp(p->section,"syscall") && !strcmp(p->prog_type,"syscall") &&
		p->prog_type_id==31 && p->prog_flags==16 && !strcmp(p->attach_type,"-") && !strcmp(p->target_kind,"none") &&
		!p->target[0] && p->context_identity && p->context_identity[0];
}
static int btf_proof(const struct bml_elf *e,const char *name,struct bml_live *view,uint64_t *metadata)
{
	const struct bml_elf_shdr *s=bml_elf_section(e,".BTF");const uint8_t *raw;size_t len;char *err=NULL;
	unsigned count=0;for(size_t i=0;i<e->n_sections;i++)count+=!strcmp(e->sections[i].name,".BTF");
	if(count!=1 || !s || bml_elf_section_data(e,s,&raw,&len,&err)){free(err);return 0;}
	uint8_t *copy=malloc(len?len:1);if(!copy)return 0;memcpy(copy,raw,len);
	if(bml_kbtf_from_raw(copy,len,&view->kb,&err)){free(err);return 0;}
	view->kb_done=1;
	uint32_t fn=0;unsigned found=0,ksyms=0,member=0;
	for(uint32_t i=1;i<view->kb.n;i++){
		struct kbtf_type t;bml_kbtf_type(&view->kb,i,&t);
		if(!strcmp(t.name,name)){if(t.kind!=KBTF_FUNC || t.vlen!=2)return 0;fn=i;found++;}
	}
	if(found!=1)return 0;
	for(uint32_t i=1;i<view->kb.n;i++){
		struct kbtf_type ds;bml_kbtf_type(&view->kb,i,&ds);
		if(ds.kind!=KBTF_DATASEC || strcmp(ds.name,".ksyms"))continue;
		ksyms++;
		for(uint32_t j=0;j<ds.vlen;j++)if(bml_kbtf_u32(&view->kb,ds.aux+12*j)==fn){
			if(bml_kbtf_u32(&view->kb,ds.aux+12*j+4) || bml_kbtf_u32(&view->kb,ds.aux+12*j+8))return 0;
			*metadata=(uint64_t)(ds.aux+12*j+4-view->kb.raw);member++;
		}
	}
	if(ksyms!=1 || member!=1)return 0;
	struct bml_str args[]={{"ptr:void",8},{"ptr:void",8},{"u32",3},{"i32",3},{"u64",3}};
	int alloc=!strcmp(name,"bpf_arena_alloc_pages");struct bml_strs diffs={0};char *msg=NULL;
	int rc=bml_live_kfunc(view,name,alloc?"ptr:void":"void",args,alloc?5:3,&diffs,&msg);
	int ok=rc==BML_Q_OK && !diffs.n;bml_strs_free(&diffs);free(msg);return ok;
}

/* CONTRACT: Every relocation overlapping the candidate instruction/metadata must be unique,
 * including references to a different symbol or from a second relocation section. */
static int unique_relocation(const struct bml_elf *e,uint32_t target,uint64_t offset,uint64_t width)
{
	unsigned overlaps=0;
	for(size_t i=0;i<e->n_sections;i++){
		const struct bml_elf_shdr *s=&e->sections[i];if(s->type!=BML_SHT_REL || s->info!=target)continue;
		const uint8_t *p;size_t n;char *err=NULL;
		if(bml_elf_section_data(e,s,&p,&n,&err) || n%16){free(err);return 0;}
		for(size_t j=0;j<n;j+=16){
			uint64_t at=bml_elf_u64(e,p+j);uint32_t type=(uint32_t)bml_elf_u64(e,p+j+8);
			uint64_t span=type==1 || type==2 || type==10?8:4;
			if(at>UINT64_MAX-span || offset>UINT64_MAX-width)return 0;
			overlaps+=at<offset+width && offset<at+span;
		}
	}
	return overlaps==1;
}

static int caller(const struct bml_elf *e,const struct bml_elf_sym *syms,size_t ns,uint32_t section,uint64_t offset,
	const struct bml_requirements *req,const char *name,int alloc,unsigned char *seen)
{
	const struct bml_elf_sym *fn=NULL;unsigned count=0;
	for(size_t i=0;i<ns;i++)if(syms[i].shndx==section && BML_ST_TYPE(syms[i].info)==BML_STT_FUNC &&
		syms[i].value<=offset && syms[i].size>=8 && offset-syms[i].value<=syms[i].size-8){fn=&syms[i];count++;}
	if(count!=1 || strcmp(e->sections[section].name,"syscall"))return 0;
	char *why=NULL;const struct bml_kfunc_profile_entry *p=bml_req_kfunc_profile_for(req,fn->name,&why);
	int ok=profile(p);free(why);if(!ok)return 0;
	count=0;
	for(size_t i=0;i<req->n_kfuncs;i++)if(equal(&req->kfuncs[i].name,name) && equal(&req->kfuncs[i].program,fn->name)){
		if(!signature(&req->kfuncs[i],alloc))return 0;
		count++;seen[i]=1;
	}
	return count==1;
}

int lb_arena_extern(const struct bml_elf *e,const struct bml_elf_sym *syms,size_t ns,size_t candidate,struct bml_load_result *result)
{
	const char *name=syms[candidate].name;int alloc=!strcmp(name,"bpf_arena_alloc_pages");
	if(!alloc && strcmp(name,"bpf_arena_free_pages"))return 0;
	const char *reason="symbol is not a unique GLOBAL/NOTYPE/UNDEF/default extern";unsigned count=0;
	struct bml_live view={0};struct bml_requirements *req=NULL;struct bml_req_elf_error re={0};unsigned char *seen=NULL;
	for(size_t i=0;i<ns;i++)count+=!strcmp(syms[i].name,name);
	const struct bml_elf_sym *sym=&syms[candidate];
	if(count!=1 || sym->info!=0x10 || sym->other || sym->shndx!=BML_SHN_UNDEF || sym->value || sym->size)goto fail;
	uint64_t metadata=0;reason="BTF extern/prototype/.ksyms proof is missing or mismatched";
	if(!btf_proof(e,name,&view,&metadata))goto fail;
	reason="actual-ELF requirements/profile proof is missing or mismatched";
	if(bml_req_from_elf(e->data,e->len,&req,&re))goto fail;
	seen=calloc(req->n_kfuncs?req->n_kfuncs:1,1);if(!seen)goto fail;
	unsigned tables=0;size_t table=0;for(size_t i=0;i<e->n_sections;i++)if(e->sections[i].type==BML_SHT_SYMTAB){tables++;table=i;}
	if(tables!=1)goto fail;
	unsigned calls=0,metas=0;
	for(size_t i=0;i<e->n_sections;i++){
		const struct bml_elf_shdr *rel=&e->sections[i];if(rel->type!=BML_SHT_REL)continue;
		reason="relocation section linkage/target is invalid";
		if(rel->link!=table || rel->info>=e->n_sections)goto fail;
		const uint8_t *bytes;size_t len;char *err=NULL;
		if(bml_elf_section_data(e,rel,&bytes,&len,&err) || len%16){free(err);goto fail;}
		for(size_t k=0;k<len;k+=16){
			uint64_t info=bml_elf_u64(e,bytes+k+8),offset=bml_elf_u64(e,bytes+k);
			if((info>>32)!=candidate+1)continue;
			uint32_t type=(uint32_t)info;const struct bml_elf_shdr *target=&e->sections[rel->info];
			const uint8_t *data;size_t size;err=NULL;reason="relocation target cannot be read";
			if(bml_elf_section_data(e,target,&data,&size,&err)){free(err);goto fail;}
			if(!strcmp(target->name,".BTF")){
				reason="BTF metadata relocation is outside the finite .ksyms offset proof";
				if(type!=3 || offset!=metadata || !unique_relocation(e,rel->info,offset,4))goto fail;
				metas++;continue;
			}
			reason="call relocation/opcode/caller/requirements proof is missing or mismatched";
			if(type!=10 || !(target->flags&BML_SHF_EXECINSTR) || offset%8 || size<8 || offset>size-8 ||
				memcmp(data+offset,"\x85\x10\x00\x00\xff\xff\xff\xff",8) ||
				!unique_relocation(e,rel->info,offset,8) || !caller(e,syms,ns,rel->info,offset,req,name,alloc,seen))goto fail;
			calls++;
		}
	}
	reason="an actual call and one metadata relocation are required";
	if(!calls || metas!=1)goto fail;
	reason="a requirements row has no matching actual caller";
	for(size_t i=0;i<req->n_kfuncs;i++)if(equal(&req->kfuncs[i].name,name) && !seen[i])goto fail;
	free(seen);bml_requirements_free(req);bml_req_elf_error_free(&re);bml_live_free(&view);return 1;
fail:
	free(seen);bml_requirements_free(req);bml_req_elf_error_free(&re);bml_live_free(&view);
	return lb_fail(result,BML_LOAD_SHAPE,"arena kfunc extern %s: %s",name,reason);
}
