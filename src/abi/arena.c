
#include "abi/map_internal.h"
#include "load/arena.h"
#include "util/mutation.h"
#include <stdlib.h>
#include <string.h>

static int64_t copy(int64_t obj, const char *decl, int64_t decl_len, uint64_t off, uint64_t len,
	void *buffer, int64_t capacity, int write)
{
	if(capacity<0 || (!buffer && len))
		return abi_fail(BML_OTHER,"bml: arena copy has a negative capacity or NULL buffer with nonzero length");
	struct abi_map m;
	static const char *const kinds[]={"arena",NULL};
	int64_t rc=abi_map_open_kind(obj,decl,decl_len,kinds,"an arena",NULL,NULL,0,&m);
	if(rc) return rc;
	void *base=NULL; size_t size=0; char *err=NULL;
	if(bml_obj_arena_span(m.o->lo,m.map,&base,&size,&err)) {
		rc=abi_fail(BML_OTHER,"bml: %s",err?err:"arena mapping is unavailable"); free(err);
	} else if(len>(uint64_t)capacity || len>SIZE_MAX || len>size
		|| off>size-len+(BML_MUT("arena.boundary_plus_one") && len && size-len<SIZE_MAX)) {
		rc=abi_fail(BML_VALUE_RANGE,"bml: arena copy exceeds buffer capacity or mapping bounds");
	} else {
		if(len) {
			void *p=(uint8_t *)base+(size_t)off;
			if(write) memmove(p,buffer,(size_t)len);
			else memmove(buffer,p,(size_t)len);
		}
		rc=abi_ok(0);
	}
	abi_map_close(&m); return rc;
}

int64_t bml_arena_read(int64_t obj, const char *decl, int64_t decl_len, uint64_t off, uint64_t len,
	uint8_t *dst, int64_t capacity)
{ return copy(obj,decl,decl_len,off,len,dst,capacity,0); }

int64_t bml_arena_write(int64_t obj, const char *decl, int64_t decl_len, uint64_t off, uint64_t len,
	const uint8_t *src, int64_t capacity)
{ return copy(obj,decl,decl_len,off,len,(void *)src,capacity,1); }
