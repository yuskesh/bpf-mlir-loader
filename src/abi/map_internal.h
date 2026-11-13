#ifndef BML_ABI_MAP_INTERNAL_H
#define BML_ABI_MAP_INTERNAL_H

#include "abi/internal.h"

struct bpf_map;



struct abi_map {
	struct abi_object *o;
	struct bml_map_decl d;
	int has_d;
	struct bpf_map *map;
	int fd;
	uint32_t key_size, value_size;
};



int64_t abi_map_open(int64_t h, const char *decl, int64_t decl_len, const char *const *records, const int64_t *records_len,
		     size_t n_records, struct abi_map *m);

int64_t abi_map_open_kind(int64_t h, const char *decl, int64_t decl_len, const char *const *kinds, const char *what,
			  const char *const *records, const int64_t *records_len, size_t n_records, struct abi_map *m);
void abi_map_close(struct abi_map *m);


void abi_reader_free(void *p);
void abi_iter_free(void *p);

#endif
