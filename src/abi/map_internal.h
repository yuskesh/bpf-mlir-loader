/* abi/map_internal.h — what the map operations share (map.c, hash.c, percpu.c and ringbuf.c). */
#ifndef BML_ABI_MAP_INTERNAL_H
#define BML_ABI_MAP_INTERNAL_H

#include "abi/internal.h"

struct bpf_map;

/* A map whose declaration was read and checked against the ELF. The registry owns the object.
 * abi_map_open counts m->o as a running call of the object (abi_object_acquire) and abi_map_close
 * gives the count back; closing the same object while the count is not 0 reports STATE. */
struct abi_map {
	struct abi_object *o;
	struct bml_map_decl d;
	int has_d;
	struct bpf_map *map;
	int fd;
	uint32_t key_size, value_size;
};

/* Reads the declaration (decl) and the records documents (zero or more; an empty one is skipped),
 * checks the one declaration in one direction only (AllowUndeclared) and opens the map.
 * Success is 0; on failure the result handle is returned and the caller returns it. */
int64_t abi_map_open(int64_t h, const char *decl, int64_t decl_len, const char *const *records, const int64_t *records_len,
		     size_t n_records, struct abi_map *m);
/* The same, but the kind of the declaration is checked first. kinds is a NULL-terminated list of
 * the allowed kinds and what names the expected map ("a hash map" and the like); a different kind
 * reports MAP_MISMATCH. The order of the downstream checks is: kind, then the match. */
int64_t abi_map_open_kind(int64_t h, const char *decl, int64_t decl_len, const char *const *kinds, const char *what,
			  const char *const *records, const int64_t *records_len, size_t n_records, struct abi_map *m);
void abi_map_close(struct abi_map *m);

/* Closing the object closes these first (defined in ringbuf.c and hash.c). */
void abi_reader_free(void *p);
void abi_iter_free(void *p);

#endif
