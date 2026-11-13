#ifndef BML_ABI_ITER_H
#define BML_ABI_ITER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "abi/map_internal.h"

struct abi_iter {
	pthread_mutex_t mu;
	int64_t obj;
	int fd;
	char *name;
	size_t klen, vlen;
	int percpu;
	size_t elem;
	uint32_t max_entries, count;
	uint8_t *cursor;
	int started, done, closed;
};


int64_t abi_iter_open(struct abi_map *m, int64_t obj, int64_t klen, int64_t vlen, int percpu);

#endif
