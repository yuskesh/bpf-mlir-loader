
#define _GNU_SOURCE
#include "load/arena_reserve.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int fail(char **err, const char *operation, int error)
{
	if(asprintf(err,"arena %s: %s",operation,strerror(error))<0) *err=NULL;
	return -1;
}

int lb_arena_reserve(struct lb_arena_reservation *r, uint64_t address, uint64_t length, char **err)
{
	*err=NULL;
	if(r->base) return fail(err,"reservation already owned",EBUSY);
	if(sysconf(_SC_PAGESIZE)!=4096 || !address || (address&4095) || !length || (length&4095)
		|| address>UINTPTR_MAX || length>SIZE_MAX || address>UINT64_MAX-length)
		return fail(err,"invalid reservation range",EINVAL);
	void *want=(void *)(uintptr_t)address;
	void *p=mmap(want,(size_t)length,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
	if(p==MAP_FAILED) return fail(err,"reservation failed (address must be unused)",errno);

	if(p!=want) {
		int rc=munmap(p,(size_t)length);
		return fail(err,rc?"unexpected reservation cleanup failed":"reservation address changed",rc?errno:EINVAL);
	}
	r->base=p; r->length=(size_t)length;
	return 0;
}

int lb_arena_release(struct lb_arena_reservation *r, char **err)
{
	*err=NULL;
	if(!r->base) return 0;
	if(munmap(r->base,r->length)) return fail(err,"reservation release failed",errno);
	r->base=NULL; r->length=0;
	return 0;
}
