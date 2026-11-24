/* abi/iter.h — the iterator over the entries of a map (used by hash.c and percpu.c). */
#ifndef BML_ABI_ITER_H
#define BML_ABI_ITER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "abi/map_internal.h"

struct abi_iter {
	pthread_mutex_t mu;
	int64_t obj; /* The owning object. A call to next counts as a running call of the object, so closing the object during it is refused. */
	int fd; /* A dup of the map fd, held until the iterator is closed. */
	char *name;
	size_t klen, vlen; /* For a per-CPU map vlen is the number of possible CPUs times the size of one value. */
	int percpu;        /* The number of possible CPUs (0 means the map is not per-CPU). */
	size_t elem;       /* The size of one per-CPU value. */
	uint32_t max_entries, count;
	uint8_t *cursor;
	int started, done, closed;
};

/* Opens an iterator and returns the result carrying its handle (the map of m is dup-ed). */
int64_t abi_iter_open(struct abi_map *m, int64_t obj, int64_t klen, int64_t vlen, int percpu);

#endif
