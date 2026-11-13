#include "load/internal.h"
#include "load/arena.h"
#include "load/arena_reserve.h"
#include "maps/arena.h"
#include "util/mutation.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct lb_arena {
	struct bpf_map *map;
	struct bml_arena_spec spec;
	struct lb_arena_reservation reservation;
	void *base;
	int transferred, checked;
};

int lb_arena_prepare(struct bml_obj *o, const void *elf, size_t len, struct bml_load_result *r)
{
	struct bpf_map *m, *arena=NULL;
	bpf_object__for_each_map(m,o->obj) if(bpf_map__type(m)==BPF_MAP_TYPE_ARENA) {
		if(arena) return lb_fail(r,BML_LOAD_ARENA,"exactly one arena is supported");
		arena=m;
	}
	if(!arena) return 0;
	struct lb_arena *a=calloc(1,sizeof *a);
	if(!a) return lb_fail(r,BML_LOAD_ENV,"out of memory");
	o->arena=a; a->map=arena;
	char *err=NULL;
	if(bml_arena_elf(elf,len,bpf_map__name(arena),&a->spec,&err)) {
		int rc=lb_fail(r,BML_LOAD_ARENA,"%s",err?err:"arena ELF validation failed"); free(err); return rc;
	}
	if(sysconf(_SC_PAGESIZE)!=4096 || bpf_map__key_size(arena) || bpf_map__value_size(arena)
		|| bpf_map__max_entries(arena)!=a->spec.pages || bpf_map__map_flags(arena)!=a->spec.flags
		|| bpf_map__map_extra(arena)!=a->spec.address)
		return lb_fail(r,BML_LOAD_ARENA,"arena libbpf definition differs from ELF/BTF or page size is not 4096");
	size_t initial=0;
	if(bpf_map__initial_value(arena,&initial) || initial)
		return lb_fail(r,BML_LOAD_ARENA,"arena_data globals are outside the arena copy contract");
	if(lb_arena_reserve(&a->reservation,a->spec.address,a->spec.length,&err)) {
		int rc=lb_fail(r,BML_LOAD_ENV,"%s",err?err:"arena reservation failed"); free(err); return rc;
	}
	return 0;
}

void lb_arena_observe(struct bml_obj *o)
{
	if(!o->arena) return;
	struct lb_arena *a=o->arena; size_t initial=0;
	a->base=bpf_map__initial_value(a->map,&initial);
	/* CONTRACT: Pinned libbpf unload closes FDs but keeps mmaped until object close,
 * even when load fails. Thus a non-NULL initial_value identifies ownership. */
	if(a->base==a->reservation.base && a->base) {
		a->transferred=1;
		a->reservation.base=NULL; a->reservation.length=0;
	}
}

int lb_arena_check(struct bml_obj *o, struct bml_load_result *r)
{
	if(!o->arena) return 0;
	struct lb_arena *a=o->arena; struct bpf_map_info info={0}; uint32_t n=sizeof info;
	if(bpf_obj_get_info_by_fd(bpf_map__fd(a->map),&info,&n))
		return lb_fail(r,BML_LOAD_ENV,"cannot read loaded arena map info");
	if(!a->transferred || (uintptr_t)a->base!=a->spec.address || info.type!=BPF_MAP_TYPE_ARENA
		|| info.key_size || info.value_size || info.max_entries!=a->spec.pages
		|| (info.map_flags!=a->spec.flags && !BML_MUT("arena.ignore_loaded_flags")) || info.map_extra!=a->spec.address)
		return lb_fail(r,BML_LOAD_ARENA,"arena kernel map info/address/length differs from ELF/BTF");
	a->checked=1; return 0;
}

void lb_arena_cleanup(struct bml_obj *o)
{
	if(!o->arena) return;

	char *err=NULL;
	lb_arena_release(&o->arena->reservation,&err);
	free(err); free(o->arena); o->arena=NULL;
}

int bml_obj_arena_span(struct bml_obj *o, struct bpf_map *map, void **base, size_t *length, char **err)
{
	*base=NULL; *length=0; *err=NULL;
	if(!o || !o->arena || !o->arena->checked || o->arena->map!=map) {
		*err=strdup("loaded arena mapping is unavailable"); return -1;
	}
	*base=o->arena->base; *length=(size_t)o->arena->spec.length; return 0;
}
